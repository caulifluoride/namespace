//! Shared node state and the iroh peer protocol.
//!
//! Peers exchange four kinds of request, each on its own bidirectional
//! QUIC stream: fetch a block body by hash, push a block, push a
//! transaction, and ask for peers. Consensus comes from Bitcoin, so the
//! network only has to move data around: block bodies for anchored hashes,
//! and transactions on their way to block builders.
//!
//! Peers are found from `--peer`, from peers that connect to us, and by
//! asking known peers for theirs. Endpoint ids are enough to connect: iroh
//! looks up addresses and relays them. Known peers are stored, so a restart
//! doesn't need `--peer` again, and ones that keep failing are dropped.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use bitcoin::secp256k1::Keypair;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use namespace_core::block::MAX_BLOCK_BYTES;
use namespace_core::encode::{Decode, Encode, Reader, put_u32};
use namespace_core::{Block, BlockHash, Hash256, Tx};
use tracing::{debug, info, warn};

use crate::chain::{AddBlock, Chain};
use crate::store::Store;

pub const ALPN: &[u8] = b"namespace/0";

const MAX_MESSAGE_BYTES: usize = MAX_BLOCK_BYTES + 1;
const MAX_PEERS: usize = 128;
/// Peers returned for one `GetPeers`.
const MAX_SHARED_PEERS: usize = 32;
/// New peers tried per discovery round.
const MAX_NEW_PEERS_PER_ROUND: usize = 16;
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(120);
/// A peer is dropped after this many failed requests in a row. Bootstrap
/// peers from `--peer` never are.
const MAX_FAILURES: u32 = 5;

pub struct Node {
    pub chain: Mutex<Chain>,
    /// Signs the blocks this node builds. Names it announces belong to it.
    builder: Keypair,
    pub store: Store,
    pub endpoint: Endpoint,
    peers: Mutex<Peers>,
}

#[derive(Default)]
struct Peers {
    known: HashSet<EndpointId>,
    bootstrap: HashSet<EndpointId>,
    /// Consecutive failures.
    failures: HashMap<EndpointId, u32>,
}

enum Request {
    GetBlock(BlockHash),
    PushBlock(Block),
    PushTx(Tx),
    GetPeers,
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
            Request::GetPeers => out.push(3),
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
            3 if rest.is_empty() => Request::GetPeers,
            _ => bail!("unknown request tag {tag}"),
        })
    }
}

impl Node {
    /// `bootstrap` are the peers from `--peer`; stored peers are added to them.
    pub fn new(
        chain: Chain,
        builder: Keypair,
        store: Store,
        endpoint: Endpoint,
        bootstrap: Vec<EndpointId>,
    ) -> Result<Arc<Self>> {
        let mut peers = Peers {
            bootstrap: bootstrap.iter().copied().collect(),
            ..Peers::default()
        };
        peers.known.extend(bootstrap);
        for bytes in store.peers()? {
            match EndpointId::from_bytes(&bytes) {
                Ok(id) if peers.known.len() < MAX_PEERS => {
                    peers.known.insert(id);
                }
                _ => {}
            }
        }
        peers.known.remove(&endpoint.id());
        info!(peers = peers.known.len(), "known peers");
        Ok(Arc::new(Self {
            chain: Mutex::new(chain),
            builder,
            store,
            endpoint,
            peers: Mutex::new(peers),
        }))
    }

    pub fn chain(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain lock poisoned")
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, Peers> {
        self.peers.lock().expect("peers lock poisoned")
    }

    pub fn peer_count(&self) -> usize {
        self.peers().known.len()
    }

    fn peers_except(&self, except: Option<EndpointId>) -> Vec<EndpointId> {
        self.peers()
            .known
            .iter()
            .copied()
            .filter(|p| Some(*p) != except)
            .collect()
    }

    fn remember_peer(&self, id: EndpointId) {
        if id == self.endpoint.id() {
            return;
        }
        let mut peers = self.peers();
        peers.failures.remove(&id);
        if peers.known.len() < MAX_PEERS && peers.known.insert(id) {
            info!(peer = %id.fmt_short(), "new peer");
            if let Err(e) = self.store.put_peer(id.as_bytes()) {
                warn!(error = %e, "storing peer");
            }
        }
    }

    fn peer_failed(&self, id: EndpointId) {
        let mut peers = self.peers();
        let failures = peers.failures.entry(id).or_default();
        *failures += 1;
        if *failures >= MAX_FAILURES && !peers.bootstrap.contains(&id) {
            peers.failures.remove(&id);
            if peers.known.remove(&id) {
                info!(peer = %id.fmt_short(), "dropping unreachable peer");
                if let Err(e) = self.store.remove_peer(id.as_bytes()) {
                    warn!(error = %e, "removing peer");
                }
            }
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
        let block = self.chain().build_block(&self.builder);
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
        let result = self.request_once(peer, bytes).await;
        match &result {
            Ok(_) => {
                self.peers().failures.remove(&peer);
            }
            Err(_) => self.peer_failed(peer),
        }
        result
    }

    async fn request_once(&self, peer: EndpointId, bytes: &[u8]) -> Result<Vec<u8>> {
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

    async fn get_peers(&self, peer: EndpointId) -> Result<Vec<EndpointId>> {
        let response = self.request(peer, &Request::GetPeers.encode()).await?;
        let mut r = Reader::new(&response);
        let count = r.u32()? as usize;
        if count > MAX_SHARED_PEERS {
            bail!("peer sent {count} peers");
        }
        let ids = (0..count)
            .map(|_| Ok(EndpointId::from_bytes(&r.array()?)?))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(ids)
    }

    /// Asks every known peer for theirs and keeps the new ones that answer.
    pub async fn discover_peers(self: &Arc<Self>) {
        let mut candidates = HashSet::new();
        for peer in self.peers_except(None) {
            match self.get_peers(peer).await {
                Ok(ids) => candidates.extend(ids),
                Err(e) => debug!(peer = %peer.fmt_short(), error = %e, "get peers failed"),
            }
        }
        let new: Vec<_> = {
            let peers = self.peers();
            candidates
                .into_iter()
                .filter(|id| *id != self.endpoint.id() && !peers.known.contains(id))
                .take(MAX_NEW_PEERS_PER_ROUND)
                .collect()
        };
        for id in new {
            if self.peer_count() >= MAX_PEERS {
                break;
            }
            // Only keep peers we can actually reach.
            if self
                .request_once(id, &Request::GetPeers.encode())
                .await
                .is_ok()
            {
                self.remember_peer(id);
            }
        }
    }

    pub async fn run_discovery(self: Arc<Self>) {
        loop {
            self.discover_peers().await;
            tokio::time::sleep(DISCOVERY_INTERVAL).await;
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
            Request::GetPeers => {
                let peers = self.peers_except(Some(from));
                let peers = &peers[..peers.len().min(MAX_SHARED_PEERS)];
                let mut out = Vec::new();
                put_u32(&mut out, peers.len() as u32);
                for p in peers {
                    out.extend_from_slice(p.as_bytes());
                }
                out
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
