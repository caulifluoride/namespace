use std::sync::LazyLock;

use bitcoin::secp256k1::{Keypair, Secp256k1, Verification, schnorr};
use serde::{Deserialize, Serialize};

use crate::encode::{Decode, DecodeError, Encode, Reader, put_u32, put_u64};
use crate::hash::{Hash256, merkle_root};
use crate::tx::{OwnerKey, Tx, decode_key, decode_sig, sign, verify};

pub type BlockHash = Hash256;

pub const BLOCK_VERSION: u32 = 1;

/// Upper bound on an encoded block. Enforced when decoding, before any other
/// validation, so peers can't make us buffer arbitrary amounts of data.
pub const MAX_BLOCK_BYTES: usize = 1 << 20;

/// The smallest encoded transaction: an `Announce` of a 1-character name.
const MIN_TX_BYTES: usize = 6;

/// What gets hashed and anchored in Bitcoin. Commits to its parent (forming
/// the chain), to its builder, to its transactions through `tx_root`, and to
/// the state after applying them through `state_root`, so a light client
/// holding a header can check proofs about names (see
/// [`crate::state::NameProof`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub parent: BlockHash,
    pub height: u64,
    /// The key of whoever built the block. Names announced in the block
    /// belong to this builder, and only its blocks can register them.
    pub builder: OwnerKey,
    pub tx_root: Hash256,
    pub state_root: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    /// The builder's signature over the header hash. It isn't part of the
    /// hash: the anchor commits to the builder key, and only the builder can
    /// make a signature that verifies against it.
    pub sig: schnorr::Signature,
    pub txs: Vec<Tx>,
}

/// Genesis is never built by anyone. Its builder is the x coordinate of the
/// secp256k1 generator, and its signature is all zeros.
const GENESIS_BUILDER: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

impl BlockHeader {
    pub fn hash(&self) -> BlockHash {
        Hash256::tagged("namespace/block", &self.to_bytes())
    }
}

impl Block {
    /// Builds a block on top of `parent` (at `parent_height`) with the given
    /// transactions, filling in the header and signing it as `builder`.
    /// `state_root` is the state after applying them;
    /// [`crate::State::next_block`] works it out.
    pub fn new(
        parent: BlockHash,
        parent_height: u64,
        builder: &Keypair,
        txs: Vec<Tx>,
        state_root: Hash256,
    ) -> Self {
        let header = BlockHeader {
            version: BLOCK_VERSION,
            parent,
            height: parent_height + 1,
            builder: builder.x_only_public_key().0,
            tx_root: tx_root(&txs),
            state_root,
        };
        let sig = sign(builder, &header.hash());
        Self { header, sig, txs }
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Whether `sig` is the builder's signature over the header.
    pub fn verify_sig<C: Verification>(&self, secp: &Secp256k1<C>) -> bool {
        verify(secp, &self.header.builder, &self.hash(), &self.sig)
    }

    /// The fixed root of every chain. It is never anchored: the first
    /// anchored block builds on it.
    pub fn genesis() -> &'static Block {
        static GENESIS: LazyLock<Block> = LazyLock::new(|| Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                parent: Hash256::ZERO,
                height: 0,
                builder: OwnerKey::from_slice(&GENESIS_BUILDER).expect("generator is on the curve"),
                tx_root: tx_root(&[]),
                state_root: crate::tree::empty_root(),
            },
            sig: schnorr::Signature::from_slice(&[0; 64]).expect("64 bytes"),
            txs: Vec::new(),
        });
        &GENESIS
    }
}

pub fn tx_root(txs: &[Tx]) -> Hash256 {
    let ids: Vec<Hash256> = txs.iter().map(Tx::txid).collect();
    merkle_root(&ids)
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.version);
        self.parent.encode(out);
        put_u64(out, self.height);
        out.extend_from_slice(&self.builder.serialize());
        self.tx_root.encode(out);
        self.state_root.encode(out);
    }
}

impl Decode for BlockHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            version: r.u32()?,
            parent: Hash256::decode(r)?,
            height: r.u64()?,
            builder: decode_key(r)?,
            tx_root: Hash256::decode(r)?,
            state_root: Hash256::decode(r)?,
        })
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        out.extend_from_slice(self.sig.as_ref());
        put_u32(
            out,
            u32::try_from(self.txs.len()).expect("tx count fits in u32"),
        );
        for tx in &self.txs {
            tx.encode(out);
        }
    }
}

impl Decode for Block {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let header = BlockHeader::decode(r)?;
        let sig = decode_sig(r)?;
        let count = r.u32()? as usize;
        // Every tx is at least MIN_TX_BYTES, which bounds `count` by the block size.
        let max = MAX_BLOCK_BYTES / MIN_TX_BYTES;
        if count > max {
            return Err(DecodeError::TooLong(count, max));
        }
        let txs = (0..count)
            .map(|_| Tx::decode(r))
            .collect::<Result<_, _>>()?;
        Ok(Self { header, sig, txs })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(DecodeError::TooLong(bytes.len(), MAX_BLOCK_BYTES));
        }
        let mut r = Reader::new(bytes);
        let block = Self::decode(&mut r)?;
        r.finish()?;
        Ok(block)
    }
}
