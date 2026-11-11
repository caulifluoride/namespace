//! Shared node state and the iroh peer protocol.
//!
//! Peers exchange three kinds of request, each on its own bidirectional
//! QUIC stream: fetch a block body by hash, push a block, and push a
//! transaction. Consensus comes from Bitcoin, so the network only has to
//! move data around: block bodies for anchored hashes, and transactions on
//! their way to block builders.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use namespace_core::block::MAX_BLOCK_BYTES;
use namespace_core::encode::{Decode, Encode, Reader};
use namespace_core::{Block, BlockHash, Hash256, Tx};
use tracing::{debug, info, warn};

use crate::chain::{AddBlock, Chain};
use crate::store::Store;

pub const ALPN: &[u8] = b"namespace/0";

const MAX_MESSAGE_BYTES: usize = MAX_BLOCK_BYTES + 1;
const MAX_PEERS: usize = 128;

pub struct Node {
    pub chain: Mutex<Chain>,
    pub store: Store,
    pub endpoint: Endpoint,
    peers: Mutex<HashSet<EndpointId>>,
}

enum Request {
    GetBlock(BlockHash),
    PushBlock(Block),
    PushTx(Tx),
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Request::GetBlock(h) => {
                out.push(0);
                h.encode(&mut out);
            }
            Request::PushBlock(b) => {
                out.push(1);
                b.encode(&mut out);
            }
            Request::PushTx(t) => {
                out.push(2);
                t.encode(&mut out);
            }
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let (&tag, rest) = bytes
            .split_first()
            .ok_or_else(|| anyhow!("empty request"))?;
        Ok(match tag {
            0 => Request::GetBlock(Hash256::from_bytes(rest)?),
            1 => Request::PushBlock(Block::from_bytes(rest)?),
            2 => Request::PushTx(Tx::from_bytes(rest)?),
            _ => bail!("unknown request tag {tag}"),
        })
    }
}

impl Node {
    pub fn new(
        chain: Chain,
        store: Store,
        endpoint: Endpoint,
        peers: Vec<EndpointId>,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain: Mutex::new(chain),
            store,
            endpoint,
            peers: Mutex::new(peers.into_iter().collect()),
        })
    }

    pub fn chain(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain lock poisoned")
    }

    fn peers_except(&self, except: Option<EndpointId>) -> Vec<EndpointId> {
        let peers = self.peers.lock().expect("peers lock poisoned");
        peers
            .iter()
            .copied()
            .filter(|p| Some(*p) != except)
            .collect()
    }

    fn remember_peer(&self, id: EndpointId) {
        let mut peers = self.peers.lock().expect("peers lock poisoned");
        if peers.len() < MAX_PEERS && peers.insert(id) {
            info!(peer = %id.fmt_short(), "new peer");
        }
    }

    pub fn add_block(self: &Arc<Self>, block: Block, from: Option<EndpointId>) -> Result<AddBlock> {
        let outcome = {
            let mut chain = self.chain();
            chain.add_block(&self.store, block.clone())?
        };
        if outcome.is_new() {
            self.broadcast(Request::PushBlock(block), from);
        }
        Ok(outcome)
    }

    pub fn submit_tx(self: &Arc<Self>, tx: Tx, from: Option<EndpointId>) -> Result<(), String> {
        let new = self.chain().submit_tx(tx.clone())?;
        if new {
            self.broadcast(Request::PushTx(tx), from);
        }
        Ok(())
    }

    /// Builds a block from the mempool and sends it to peers ahead of its
    /// anchor, so they can follow the chain as soon as the anchor confirms.
    pub fn build_block(self: &Arc<Self>) -> Block {
        let block = self.chain().build_block();
        self.broadcast(Request::PushBlock(block.clone()), None);
        block
    }

    fn broadcast(self: &Arc<Self>, req: Request, except: Option<EndpointId>) {
        let bytes = Arc::new(req.encode());
        for peer in self.peers_except(except) {
            let node = self.clone();
            let bytes = bytes.clone();
            tokio::spawn(async move {
                if let Err(e) = node.request(peer, &bytes).await {
                    debug!(peer = %peer.fmt_short(), error = %e, "push failed");
                }
            });
        }
    }

    async fn request(&self, peer: EndpointId, bytes: &[u8]) -> Result<Vec<u8>> {
        let conn = self.endpoint.connect(peer, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(bytes).await?;
        send.finish()?;
        let response = recv.read_to_end(MAX_MESSAGE_BYTES).await?;
        conn.close(0u32.into(), b"done");
        Ok(response)
    }

    /// Asks peers for anchored blocks whose bodies we don't have.
    pub async fn fetch_missing(self: &Arc<Self>) {
        let missing = self.chain().missing_bodies();
        for hash in missing {
            for peer in self.peers_except(None) {
                match self.fetch_block(peer, hash).await {
                    Ok(Some(block)) => {
                        if let Err(e) = self.add_block(block, Some(peer)) {
                            warn!(error = %e, "storing fetched block");
                        }
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => debug!(peer = %peer.fmt_short(), error = %e, "fetch failed"),
                }
            }
        }
    }

    async fn fetch_block(&self, peer: EndpointId, hash: BlockHash) -> Result<Option<Block>> {
        let response = self
            .request(peer, &Request::GetBlock(hash).encode())
            .await?;
        let mut r = Reader::new(&response);
        if r.u8()? == 0 {
            return Ok(None);
        }
        let block = Block::from_bytes(&response[1..])?;
        if block.hash() != hash {
            bail!("peer sent the wrong block");
        }
        Ok(Some(block))
    }

    async fn handle(self: &Arc<Self>, from: EndpointId, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(match Request::decode(bytes)? {
            Request::GetBlock(hash) => {
                let block = self.chain().block(&self.store, &hash)?;
                match block {
                    Some(b) => {
                        let mut out = vec![1];
                        b.encode(&mut out);
                        out
                    }
                    None => vec![0],
                }
            }
            Request::PushBlock(block) => {
                let hash = block.hash();
                let outcome = self.add_block(block, Some(from))?;
                debug!(block = %hash, ?outcome, "pushed block");
                Vec::new()
            }
            Request::PushTx(tx) => {
                if let Err(e) = self.submit_tx(tx, Some(from)) {
                    debug!(error = %e, "rejected pushed tx");
                }
                Vec::new()
            }
        })
    }
}

/// Accepts peer connections for [`ALPN`].
#[derive(Clone)]
pub struct Protocol(pub Arc<Node>);

impl std::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("namespace::Protocol")
    }
}

impl ProtocolHandler for Protocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        self.0.remember_peer(peer);
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let node = self.0.clone();
            tokio::spawn(async move {
                let result = async {
                    let bytes = recv.read_to_end(MAX_MESSAGE_BYTES).await?;
                    let response = node.handle(peer, &bytes).await?;
                    send.write_all(&response).await?;
                    send.finish()?;
                    anyhow::Ok(())
                };
                if let Err(e) = result.await {
                    debug!(peer = %peer.fmt_short(), error = %e, "request failed");
                }
            });
        }
        Ok(())
    }
}
