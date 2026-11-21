//! Bitcoin-side tooling: the pre-signed covenant chain, and the CPFP child
//! that anchors a namespace block to it.
//!
//! Each covenant transaction `T_i` is a zero-fee TRUC (v3) transaction that
//! spends `T_{i-1}`'s covenant output with a key-path signature and creates
//!
//! - output 0, the covenant output: the same amount, to the same key, and
//! - output 1, a zero-value pay-to-anchor (P2A) output anyone can spend.
//!
//! The input's `nSequence` is a relative timelock of `COVENANT_DELAY` blocks
//! (BIP68 applies to every transaction version 2 and up), so at most one `T_i`
//! confirms every `COVENANT_DELAY` Bitcoin blocks. All of them are signed up
//! front and the key is deleted, so `T_i` is the only possible spend of
//! `T_{i-1}`'s covenant output.
//!
//! `T_i` pays no fee and its P2A output is dust, so it relays only as a
//! package with a child that spends the P2A output (ephemeral dust). The
//! builder's child pays for both and carries the commitment.

use anyhow::{Context, Result, bail, ensure};
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    absolute, taproot,
};
use namespace_core::anchor::COVENANT_DELAY;
use serde::{Deserialize, Serialize};

pub const COVENANT_VOUT: u32 = 0;
pub const ANCHOR_VOUT: u32 = 1;

/// Below this the covenant output would be dust and couldn't relay.
pub const MIN_COVENANT_VALUE: Amount = Amount::from_sat(330);

/// A generated covenant chain, as written to disk.
#[derive(Serialize, Deserialize)]
pub struct ChainFile {
    /// The funding output the first covenant transaction spends.
    pub start: OutPoint,
    pub value: Amount,
    pub covenant_vout: u32,
    pub anchor_vout: u32,
    /// Raw transactions, hex, in order.
    pub txs: Vec<String>,
}

impl ChainFile {
    /// The covenant transaction that spends `outpoint`.
    pub fn spending(&self, outpoint: OutPoint) -> Result<Option<Transaction>> {
        for hex in &self.txs {
            let tx: Transaction = bitcoin::consensus::encode::deserialize_hex(hex)?;
            if tx.input.iter().any(|i| i.previous_output == outpoint) {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }
}

/// The script every covenant output pays to: a key-path-only taproot output.
pub fn covenant_script<C: Verification>(secp: &Secp256k1<C>, keypair: &Keypair) -> ScriptBuf {
    ScriptBuf::new_p2tr(secp, keypair.x_only_public_key().0, None)
}

/// Signs `count` covenant transactions, the first spending `funding`, which
/// must hold `value` at [`covenant_script`].
pub fn generate<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    keypair: &Keypair,
    funding: OutPoint,
    value: Amount,
    count: u32,
) -> Result<Vec<Transaction>> {
    ensure!(
        value >= MIN_COVENANT_VALUE,
        "covenant value must be at least {MIN_COVENANT_VALUE}"
    );
    let script = covenant_script(secp, keypair);
    let tweaked = keypair.tap_tweak(secp, None).to_keypair();
    let prevout = TxOut {
        value,
        script_pubkey: script.clone(),
    };
    let mut prev = funding;
    let mut txs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(COVENANT_DELAY),
                witness: Witness::new(),
            }],
            output: vec![
                prevout.clone(),
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_p2a(),
                },
            ],
        };
        let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[&prevout]),
            TapSighashType::Default,
        )?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = taproot::Signature {
            signature: secp.sign_schnorr(&msg, &tweaked),
            sighash_type: TapSighashType::Default,
        };
        tx.input[0].witness = Witness::p2tr_key_spend(&sig);
        prev = OutPoint::new(tx.compute_txid(), COVENANT_VOUT);
        txs.push(tx);
    }
    Ok(txs)
}

fn is_p2a(script: &ScriptBuf) -> bool {
    *script == ScriptBuf::new_p2a()
}

/// The witness a wallet input will carry once signed, for fee estimation.
fn dummy_witness(script: &ScriptBuf) -> Result<Witness> {
    if script.is_p2tr() {
        Ok(Witness::from_slice(&[[0u8; 64].as_slice()]))
    } else if script.is_p2wpkh() {
        Ok(Witness::from_slice(&[
            [0u8; 72].as_slice(),
            [0u8; 33].as_slice(),
        ]))
    } else {
        bail!("the funding UTXO must be P2TR (key path) or P2WPKH")
    }
}

/// Builds the child that anchors a block: it spends `parent`'s anchor
/// output and the builder's `utxo`, and pays the fee for both transactions
/// at `fee_rate` sat/vB out of `utxo`, with the rest going to `change`.
///
/// Returns a PSBT for the builder's wallet to sign. The anchor input needs
/// no signature and is already finalized.
pub fn anchor_child(
    parent: &Transaction,
    anchor_vout: u32,
    op_return: ScriptBuf,
    utxo: OutPoint,
    utxo_out: TxOut,
    change: ScriptBuf,
    fee_rate: f64,
) -> Result<Psbt> {
    let anchor_out = parent
        .output
        .get(anchor_vout as usize)
        .context("covenant transaction has no anchor output")?
        .clone();
    ensure!(
        is_p2a(&anchor_out.script_pubkey),
        "covenant anchor output is not P2A"
    );
    ensure!(fee_rate > 0.0, "fee rate must be positive");
    let mut tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(parent.compute_txid(), anchor_vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: utxo,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: dummy_witness(&utxo_out.script_pubkey)?,
            },
        ],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: change.clone(),
            },
        ],
    };
    // The child pays for the whole package.
    let vsize = parent.vsize() + tx.vsize();
    let fee = Amount::from_sat((fee_rate * vsize as f64).ceil() as u64);
    let change_value = utxo_out
        .value
        .checked_sub(fee)
        .with_context(|| format!("funding UTXO can't cover the {fee} fee"))?;
    ensure!(
        change_value >= change.minimal_non_dust(),
        "change of {change_value} after the {fee} fee would be dust"
    );
    tx.output[1].value = change_value;
    tx.input[1].witness = Witness::new();
    ensure!(tx.vsize() <= 1_000, "child is too big for a TRUC package");

    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(anchor_out);
    psbt.inputs[0].final_script_witness = Some(Witness::new());
    psbt.inputs[1].witness_utxo = Some(utxo_out);
    Ok(psbt)
}

/// Finalizes a signed anchoring PSBT and extracts the child. Handles what
/// [`anchor_child`] produces: the P2A input, and a key-path P2TR or P2WPKH
/// input, whether or not the signing wallet finalized them.
pub fn finalize(mut psbt: Psbt) -> Result<Transaction> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        if input.final_script_witness.is_some() {
            continue;
        }
        let script = &input
            .witness_utxo
            .as_ref()
            .with_context(|| format!("input {i} has no witness UTXO"))?
            .script_pubkey;
        let witness = if is_p2a(script) {
            Witness::new()
        } else if let Some(sig) = input.tap_key_sig {
            Witness::p2tr_key_spend(&sig)
        } else if let Some((key, sig)) = input.partial_sigs.iter().next() {
            Witness::p2wpkh(sig, &key.inner)
        } else {
            bail!("input {i} isn't signed");
        };
        input.final_script_witness = Some(witness);
        input.partial_sigs.clear();
        input.tap_key_sig = None;
    }
    let mut tx = psbt.unsigned_tx;
    for (txin, input) in tx.input.iter_mut().zip(psbt.inputs) {
        txin.witness = input.final_script_witness.unwrap_or_default();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{CompactTarget, TxMerkleNode, Txid};
    use namespace_core::Hash256;
    use namespace_core::anchor::{CovenantConfig, commitment_script, scan_block};

    use super::*;

    fn keypair(n: u8) -> Keypair {
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[n; 32]).unwrap())
    }

    fn btc_block(txdata: Vec<Transaction>) -> bitcoin::Block {
        bitcoin::Block {
            header: Header {
                version: BlockVersion::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    /// Checks a covenant transaction's key-path signature.
    fn verify(tx: &Transaction, prevout: &TxOut) {
        let secp = Secp256k1::verification_only();
        let sighash = SighashCache::new(tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                TapSighashType::Default,
            )
            .unwrap();
        let sig = taproot::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
        let key =
            bitcoin::XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..]).unwrap();
        secp.verify_schnorr(
            &sig.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &key,
        )
        .unwrap();
    }

    #[test]
    fn chain_links_and_scans() {
        let secp = Secp256k1::new();
        let kp = keypair(1);
        let funding = OutPoint::new(Txid::all_zeros(), 3);
        let value = Amount::from_sat(1_000);
        let txs = generate(&secp, &kp, funding, value, 3).unwrap();
        let prevout = TxOut {
            value,
            script_pubkey: covenant_script(&secp, &kp),
        };
        let mut prev = funding;
        for tx in &txs {
            assert_eq!(tx.input[0].previous_output, prev);
            assert_eq!(tx.input[0].sequence, Sequence::from_height(COVENANT_DELAY));
            assert_eq!(tx.output[0], prevout);
            assert!(is_p2a(&tx.output[1].script_pubkey));
            verify(tx, &prevout);
            prev = OutPoint::new(tx.compute_txid(), COVENANT_VOUT);
        }

        // A child anchoring a block on T_1 is what the node's scanner finds.
        let config = CovenantConfig {
            start: funding,
            start_height: 0,
            covenant_vout: COVENANT_VOUT,
            anchor_vout: ANCHOR_VOUT,
        };
        let hash = Hash256::tagged("test", b"block");
        let utxo_out = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, keypair(2).x_only_public_key().0, None),
        };
        let utxo = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
        let psbt = anchor_child(
            &txs[0],
            ANCHOR_VOUT,
            commitment_script(&hash),
            utxo,
            utxo_out.clone(),
            utxo_out.script_pubkey.clone(),
            2.0,
        )
        .unwrap();
        let child = psbt.unsigned_tx.clone();
        let scan = scan_block(&config, funding, 5, &btc_block(vec![txs[0].clone(), child]));
        assert_eq!(scan.anchor.unwrap().block_hash, hash);
        assert_eq!(scan.next, txs[1].input[0].previous_output);
    }

    #[test]
    fn anchor_child_fee_and_finalize() {
        let secp = Secp256k1::new();
        let txs = generate(
            &secp,
            &keypair(1),
            OutPoint::null(),
            Amount::from_sat(330),
            1,
        )
        .unwrap();
        let wallet = keypair(2);
        let utxo_out = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, wallet.x_only_public_key().0, None),
        };
        let mut psbt = anchor_child(
            &txs[0],
            ANCHOR_VOUT,
            commitment_script(&Hash256::ZERO),
            OutPoint::new(Txid::from_byte_array([9; 32]), 1),
            utxo_out.clone(),
            utxo_out.script_pubkey.clone(),
            10.0,
        )
        .unwrap();

        // Sign the wallet input the way a wallet would.
        let prevouts = [
            psbt.inputs[0].witness_utxo.clone().unwrap(),
            utxo_out.clone(),
        ];
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = wallet.tap_tweak(&secp, None).to_keypair();
        psbt.inputs[1].tap_key_sig = Some(taproot::Signature {
            signature: secp.sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &tweaked),
            sighash_type: TapSighashType::Default,
        });
        let child = finalize(psbt).unwrap();
        assert!(child.input[0].witness.is_empty());
        assert_eq!(child.input[1].witness.len(), 1);

        // The package pays at least 10 sat/vB, and not much more.
        let fee = 10_000 - child.output[1].value.to_sat();
        let vsize = (txs[0].vsize() + child.vsize()) as u64;
        assert!(
            fee >= 10 * vsize && fee <= 10 * vsize + 10,
            "fee {fee} for {vsize} vB"
        );
    }

    #[test]
    fn refuses_dust_and_unsupported_inputs() {
        let secp = Secp256k1::new();
        assert!(
            generate(
                &secp,
                &keypair(1),
                OutPoint::null(),
                Amount::from_sat(100),
                1
            )
            .is_err()
        );
        let txs = generate(
            &secp,
            &keypair(1),
            OutPoint::null(),
            Amount::from_sat(330),
            1,
        )
        .unwrap();
        let p2tr = ScriptBuf::new_p2tr(&secp, keypair(2).x_only_public_key().0, None);
        let child = |value, script: ScriptBuf| {
            anchor_child(
                &txs[0],
                ANCHOR_VOUT,
                commitment_script(&Hash256::ZERO),
                OutPoint::null(),
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: script,
                },
                p2tr.clone(),
                5.0,
            )
        };
        assert!(child(10_000, p2tr.clone()).is_ok());
        assert!(child(1_000, p2tr.clone()).is_err());
        assert!(child(10_000, ScriptBuf::new_op_return([1u8; 4])).is_err());
    }
}
