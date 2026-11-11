//! Finding namespace block commitments in Bitcoin blocks.
//!
//! This follows Ruben Somsen's spacechain blind merged mining design. A chain
//! of transactions is pre-signed and the signing key is deleted, so each one
//! can only be spent by the next one. Each covenant transaction `T_i` spends
//! the covenant output of `T_{i-1}` and creates two outputs:
//!
//! - a covenant output, which only `T_{i+1}` can spend, and
//! - an anchor output, which anyone can spend.
//!
//! Someone who wants to anchor a namespace block broadcasts a child that
//! spends `T_i`'s anchor output, pays the Bitcoin fee for both by CPFP, and
//! carries `OP_RETURN <MAGIC> <block hash>`. Only one child can spend the
//! anchor output, so at most one namespace block is anchored per covenant
//! transaction. A relative timelock on the covenant inputs limits it to one
//! covenant transaction per Bitcoin block. Bitcoin miners pick the
//! highest-paying child without having to know anything about the namespace.

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::{OutPoint, Script, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};

use crate::block::BlockHash;
use crate::hash::Hash256;

/// Identifies namespace anchors among other OP_RETURN outputs.
pub const MAGIC: [u8; 4] = *b"NSPC";

/// Where the covenant chain lives on Bitcoin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CovenantConfig {
    /// The output the first covenant transaction spends.
    pub start: OutPoint,
    /// The first Bitcoin height that can contain a covenant transaction.
    pub start_height: u32,
    /// Index of the covenant output in each covenant transaction.
    pub covenant_vout: u32,
    /// Index of the anchor output in each covenant transaction.
    pub anchor_vout: u32,
}

/// A namespace block hash committed to by a Bitcoin transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub btc_height: u32,
    pub btc_block: bitcoin::BlockHash,
    /// The child transaction that carries the commitment.
    pub txid: Txid,
    pub block_hash: BlockHash,
}

/// The result of scanning one Bitcoin block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    /// The covenant outpoint to look for in the next Bitcoin block.
    pub next: OutPoint,
    /// The block hash anchored in this Bitcoin block, if any.
    pub anchor: Option<Anchor>,
}

/// Scans a Bitcoin block for the transaction that spends the covenant output
/// `current`.
///
/// If it isn't spent here, the covenant doesn't advance. If it is, the
/// covenant advances whether or not this block carries a valid anchor: an
/// anchor output that is left unspent, spent in a later block, or spent
/// without a well-formed commitment is an empty slot.
pub fn scan_block(
    config: &CovenantConfig,
    current: OutPoint,
    btc_height: u32,
    block: &bitcoin::Block,
) -> ScanResult {
    let Some(covenant_tx) = block.txdata.iter().find(|tx| spends(tx, current)) else {
        return ScanResult {
            next: current,
            anchor: None,
        };
    };
    let covenant_txid = covenant_tx.compute_txid();
    let next = OutPoint::new(covenant_txid, config.covenant_vout);
    let anchor_out = OutPoint::new(covenant_txid, config.anchor_vout);

    let anchor = block
        .txdata
        .iter()
        .find(|tx| spends(tx, anchor_out))
        .and_then(|child| {
            let block_hash = child
                .output
                .iter()
                .find_map(|out| parse_commitment(&out.script_pubkey))?;
            Some(Anchor {
                btc_height,
                btc_block: block.block_hash(),
                txid: child.compute_txid(),
                block_hash,
            })
        });
    ScanResult { next, anchor }
}

fn spends(tx: &Transaction, outpoint: OutPoint) -> bool {
    tx.input.iter().any(|i| i.previous_output == outpoint)
}

/// The `OP_RETURN <MAGIC || block hash>` script that commits to `hash`.
pub fn commitment_script(hash: &BlockHash) -> ScriptBuf {
    let mut data = [0u8; 36];
    data[..4].copy_from_slice(&MAGIC);
    data[4..].copy_from_slice(&hash.0);
    ScriptBuf::new_op_return(data)
}

/// Parses a script produced by [`commitment_script`].
pub fn parse_commitment(script: &Script) -> Option<BlockHash> {
    let mut ins = script.instructions();
    match ins.next()? {
        Ok(Instruction::Op(op)) if op == OP_RETURN => {}
        _ => return None,
    }
    let Ok(Instruction::PushBytes(data)) = ins.next()? else {
        return None;
    };
    if ins.next().is_some() {
        return None;
    }
    let data = data.as_bytes();
    if data.len() != 36 || data[..4] != MAGIC {
        return None;
    }
    Some(Hash256(data[4..].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, CompactTarget, Sequence, TxIn, TxMerkleNode, TxOut, Witness};

    use super::*;

    fn tx(inputs: &[OutPoint], outputs: Vec<ScriptBuf>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_height(1),
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::from_sat(330),
                    script_pubkey,
                })
                .collect(),
        }
    }

    fn btc_block(txdata: Vec<Transaction>) -> bitcoin::Block {
        bitcoin::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    fn config() -> CovenantConfig {
        CovenantConfig {
            start: OutPoint::new(Txid::all_zeros(), 0),
            start_height: 0,
            covenant_vout: 0,
            anchor_vout: 1,
        }
    }

    #[test]
    fn commitment_roundtrip() {
        let h = Hash256::tagged("test", b"x");
        assert_eq!(parse_commitment(&commitment_script(&h)), Some(h));
        assert_eq!(parse_commitment(&ScriptBuf::new_op_return([0u8; 36])), None);
    }

    #[test]
    fn finds_anchor_and_advances() {
        let cfg = config();
        let covenant = tx(&[cfg.start], vec![ScriptBuf::new(), ScriptBuf::new()]);
        let cov_txid = covenant.compute_txid();
        let h = Hash256::tagged("test", b"block");
        let child = tx(&[OutPoint::new(cov_txid, 1)], vec![commitment_script(&h)]);
        // A decoy commitment that doesn't spend the anchor output is ignored.
        let decoy = tx(&[], vec![commitment_script(&Hash256::ZERO)]);
        let block = btc_block(vec![decoy, covenant, child.clone()]);

        let r = scan_block(&cfg, cfg.start, 7, &block);
        assert_eq!(r.next, OutPoint::new(cov_txid, 0));
        let a = r.anchor.unwrap();
        assert_eq!(a.block_hash, h);
        assert_eq!(a.txid, child.compute_txid());
        assert_eq!(a.btc_height, 7);
    }

    #[test]
    fn covenant_without_child_is_empty_slot() {
        let cfg = config();
        let covenant = tx(&[cfg.start], vec![ScriptBuf::new(), ScriptBuf::new()]);
        let r = scan_block(&cfg, cfg.start, 1, &btc_block(vec![covenant.clone()]));
        assert_eq!(r.next, OutPoint::new(covenant.compute_txid(), 0));
        assert_eq!(r.anchor, None);

        let r = scan_block(&cfg, cfg.start, 1, &btc_block(vec![]));
        assert_eq!(r.next, cfg.start);
    }
}
