//! Where the node reads Bitcoin blocks from.
//!
//! The node only needs to walk the Bitcoin chain by height and fetch full
//! blocks, so any backend that can do that works. The three backends below
//! are placeholders for now.

use std::future::Future;

use anyhow::{Result, bail};

pub trait BitcoinSource: Send + Sync + 'static {
    /// Height of the current Bitcoin tip.
    fn tip_height(&self) -> impl Future<Output = Result<u32>> + Send;
    /// Hash of the block at `height` on the current best chain.
    fn block_hash(&self, height: u32) -> impl Future<Output = Result<bitcoin::BlockHash>> + Send;
    fn block(
        &self,
        hash: bitcoin::BlockHash,
    ) -> impl Future<Output = Result<bitcoin::Block>> + Send;
}

/// Bitcoin Core over JSON-RPC (`getblockcount`, `getblockhash`, `getblock <hash> 0`).
#[allow(dead_code)] // Read once the backend is implemented.
pub struct BitcoinCore {
    pub url: String,
    pub auth: Option<(String, String)>,
}

/// An Esplora HTTP API (`/blocks/tip/height`, `/block-height/:h`, `/block/:hash/raw`).
#[allow(dead_code)] // Read once the backend is implemented.
pub struct Esplora {
    pub url: String,
}

/// A libbitcoin server.
#[allow(dead_code)] // Read once the backend is implemented.
pub struct Libbitcoin {
    pub url: String,
}

macro_rules! placeholder {
    ($ty:ty, $name:literal) => {
        impl BitcoinSource for $ty {
            async fn tip_height(&self) -> Result<u32> {
                bail!(concat!($name, " backend is not implemented yet"))
            }
            async fn block_hash(&self, _height: u32) -> Result<bitcoin::BlockHash> {
                bail!(concat!($name, " backend is not implemented yet"))
            }
            async fn block(&self, _hash: bitcoin::BlockHash) -> Result<bitcoin::Block> {
                bail!(concat!($name, " backend is not implemented yet"))
            }
        }
    };
}

placeholder!(BitcoinCore, "Bitcoin Core");
placeholder!(Esplora, "Esplora");
placeholder!(Libbitcoin, "libbitcoin");
