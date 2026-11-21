use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::encode::{Decode, DecodeError, Encode, Reader, put_u32, put_u64};
use crate::hash::{Hash256, merkle_root};
use crate::tx::Tx;

pub type BlockHash = Hash256;

pub const BLOCK_VERSION: u32 = 1;

/// Upper bound on an encoded block. Enforced when decoding, before any other
/// validation, so peers can't make us buffer arbitrary amounts of data.
pub const MAX_BLOCK_BYTES: usize = 1 << 20;

/// What gets hashed and anchored in Bitcoin. Commits to its parent (forming
/// the chain), to its transactions through `tx_root`, and to the state after
/// applying them through `state_root`, so a light client holding a header can
/// check proofs about names (see [`crate::state::NameProof`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub parent: BlockHash,
    pub height: u64,
    pub tx_root: Hash256,
    pub state_root: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl BlockHeader {
    pub fn hash(&self) -> BlockHash {
        Hash256::tagged("namespace/block", &self.to_bytes())
    }
}

impl Block {
    /// Builds a block on top of `parent` (at `parent_height`) with the given
    /// transactions, filling in the header. `state_root` is the state after
    /// applying them; [`crate::State::next_block`] works it out.
    pub fn new(parent: BlockHash, parent_height: u64, txs: Vec<Tx>, state_root: Hash256) -> Self {
        let header = BlockHeader {
            version: BLOCK_VERSION,
            parent,
            height: parent_height + 1,
            tx_root: tx_root(&txs),
            state_root,
        };
        Self { header, txs }
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// The fixed root of every chain. It is never anchored: the first
    /// anchored block builds on it.
    pub fn genesis() -> &'static Block {
        static GENESIS: LazyLock<Block> = LazyLock::new(|| Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                parent: Hash256::ZERO,
                height: 0,
                tx_root: tx_root(&[]),
                state_root: crate::tree::empty_root(),
            },
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
            tx_root: Hash256::decode(r)?,
            state_root: Hash256::decode(r)?,
        })
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
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
        let count = r.u32()? as usize;
        // Every tx is at least 33 bytes, which bounds `count` by the block size.
        if count > MAX_BLOCK_BYTES / 33 {
            return Err(DecodeError::TooLong(count, MAX_BLOCK_BYTES / 33));
        }
        let txs = (0..count)
            .map(|_| Tx::decode(r))
            .collect::<Result<_, _>>()?;
        Ok(Self { header, txs })
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
