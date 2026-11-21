//! Consensus core for the namespace chain: a Bitcoin-anchored chain whose
//! only asset is names.
//!
//! Nothing in this crate does IO. The node feeds it Bitcoin blocks and
//! namespace blocks and asks it what the chain and its state are.

pub mod anchor;
pub mod block;
pub mod chain;
pub mod encode;
pub mod hash;
pub mod name;
pub mod params;
pub mod state;
pub mod tree;
pub mod tx;

pub use anchor::{Anchor, CovenantConfig};
pub use block::{Block, BlockHash, BlockHeader};
pub use chain::ChainIndex;
pub use encode::{Decode, Encode};
pub use hash::Hash256;
pub use name::Name;
pub use params::{Params, TierRate};
pub use state::{BlockBuilder, NameProof, NameRecord, State};
pub use tx::{OwnerKey, Tx};

#[cfg(test)]
mod tests;
