//! The node's view of the chain: Bitcoin scans, known blocks, the applied
//! state, and the mempool, kept consistent with each other.

use std::collections::{BTreeMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use bitcoin::OutPoint;
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use namespace_core::encode::Decode;
use namespace_core::state::{AddTxError, Undo};
use namespace_core::{
    Block, BlockBuilder, BlockHash, ChainIndex, CovenantConfig, Hash256, Params, State, Tx,
};
use tracing::{info, warn};

use crate::store::{ScanRecord, Store};

/// Unanchored blocks kept around so they can be served while their anchor
/// is waiting to confirm. They're held in memory and capped, since anyone
/// can make them.
const MAX_PENDING_BLOCKS: usize = 64;
const MAX_MEMPOOL_TXS: usize = 50_000;
/// Snapshot the state every this many blocks.
const SNAPSHOT_INTERVAL: u64 = 1_000;

pub struct Chain {
    params: Params,
    secp: Secp256k1<VerifyOnly>,
    covenant: CovenantConfig,
    index: ChainIndex,
    state: State,
    /// The applied chain after genesis, with what's needed to revert it.
    /// Blocks loaded from a snapshot have no undo: reverting past them means
    /// replaying from genesis.
    active: Vec<(BlockHash, Option<Undo>)>,
    /// Height of the last snapshot taken or loaded.
    snapshot_height: u64,
    scans: BTreeMap<u32, ScanRecord>,
    pending: VecDeque<Block>,
    mempool: Vec<Tx>,
    mempool_ids: HashSet<Hash256>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddBlock {
    /// Anchored, and now stored.
    Stored,
    /// Not anchored yet, but valid on top of the tip, so kept as pending.
    Pending,
    AlreadyKnown,
    Rejected(String),
}

impl AddBlock {
    pub fn is_new(&self) -> bool {
        matches!(self, AddBlock::Stored | AddBlock::Pending)
    }
}

impl Chain {
    /// Loads everything from `store` and replays the best chain, starting
    /// from the newest snapshot on it.
    pub fn load(params: Params, covenant: CovenantConfig, store: &Store) -> Result<Self> {
        let mut chain = Self {
            params,
            secp: Secp256k1::verification_only(),
            covenant,
            index: ChainIndex::new(),
            state: State::new(),
            active: Vec::new(),
            snapshot_height: 0,
            scans: BTreeMap::new(),
            pending: VecDeque::new(),
            mempool: Vec::new(),
            mempool_ids: HashSet::new(),
        };
        for block in store.all_blocks()? {
            chain.index.add_header(block.header);
        }
        for (height, record) in store.all_scans()? {
            if let Some(anchor) = record.anchor {
                chain.index.push_anchor(anchor);
            }
            chain.scans.insert(height, record);
        }
        for hash in store.invalid_blocks()? {
            chain.index.mark_invalid(hash);
        }
        chain.load_snapshot(store)?;
        chain.update_tip(store)?;
        Ok(chain)
    }

    /// Starts from the newest snapshot whose block is on the best chain and
    /// whose contents match that block's state root.
    fn load_snapshot(&mut self, store: &Store) -> Result<()> {
        let best = self.index.best_chain();
        for (height, bytes) in store.snapshots()? {
            let state = match State::from_bytes(&bytes) {
                Ok(s) if s.height() == height => s,
                Ok(_) => continue,
                Err(e) => {
                    warn!(height, error = %e, "unreadable snapshot");
                    continue;
                }
            };
            let Some(pos) = height.checked_sub(1) else {
                continue;
            };
            if best.get(pos as usize) != Some(&state.tip()) {
                continue;
            }
            let block = store
                .block(&state.tip())?
                .with_context(|| format!("indexed block {} missing from store", state.tip()))?;
            if block.header.state_root != state.state_root() {
                warn!(height, "snapshot does not match its block's state root");
                continue;
            }
            info!(height, tip = %state.tip(), "loaded snapshot");
            self.active = best[..height as usize].iter().map(|h| (*h, None)).collect();
            self.state = state;
            self.snapshot_height = height;
            break;
        }
        Ok(())
    }

    /// Stores a snapshot of the current state.
    pub fn save_snapshot(&mut self, store: &Store) -> Result<()> {
        let height = self.state.height();
        if height > 0 {
            store.put_snapshot(height, &self.state)?;
            self.snapshot_height = height;
        }
        Ok(())
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    pub fn last_scan(&self) -> Option<(u32, &ScanRecord)> {
        self.scans.iter().next_back().map(|(h, r)| (*h, r))
    }

    /// The Bitcoin height to scan next.
    pub fn next_scan_height(&self) -> u32 {
        self.last_scan()
            .map_or(self.covenant.start_height, |(h, _)| h + 1)
    }

    /// The covenant output the next covenant transaction will spend.
    pub fn covenant_outpoint(&self) -> OutPoint {
        self.last_scan()
            .map_or(self.covenant.start, |(_, r)| r.next)
    }

    pub fn covenant(&self) -> &CovenantConfig {
        &self.covenant
    }

    pub fn scan_hash(&self, height: u32) -> Option<bitcoin::BlockHash> {
        self.scans.get(&height).map(|r| r.btc_hash)
    }

    pub fn add_scan(&mut self, store: &Store, height: u32, record: ScanRecord) -> Result<()> {
        store.put_scan(height, &record)?;
        self.scans.insert(height, record);
        if let Some(anchor) = record.anchor {
            info!(btc_height = height, block = %anchor.block_hash, "anchor");
            self.index.push_anchor(anchor);
            if let Some(i) = self
                .pending
                .iter()
                .position(|b| b.hash() == anchor.block_hash)
            {
                let block = self.pending.remove(i).expect("index in range");
                store.put_block(&block)?;
                self.index.add_header(block.header);
            }
            self.update_tip(store)?;
        }
        Ok(())
    }

    /// Forgets Bitcoin blocks at and above `height` after a Bitcoin reorg.
    pub fn rollback_scans(&mut self, store: &Store, height: u32) -> Result<()> {
        warn!(btc_height = height, "bitcoin reorg");
        store.truncate_scans(height)?;
        self.scans.retain(|h, _| *h < height);
        self.index.truncate_anchors(height);
        self.update_tip(store)
    }

    pub fn missing_bodies(&self) -> Vec<BlockHash> {
        self.index.missing_bodies()
    }

    /// A block by hash, stored or pending.
    pub fn block(&self, store: &Store, hash: &BlockHash) -> Result<Option<Block>> {
        if let Some(b) = self.pending.iter().find(|b| b.hash() == *hash) {
            return Ok(Some(b.clone()));
        }
        store.block(hash)
    }

    pub fn add_block(&mut self, store: &Store, block: Block) -> Result<AddBlock> {
        let hash = block.hash();
        if self.index.has_body(&hash) || self.pending.iter().any(|b| b.hash() == hash) {
            return Ok(AddBlock::AlreadyKnown);
        }
        if self.index.anchors().iter().any(|a| a.block_hash == hash) {
            // Full validation happens when fork choice reaches it.
            if block.header.tx_root != namespace_core::block::tx_root(&block.txs) {
                return Ok(AddBlock::Rejected("tx root mismatch".into()));
            }
            store.put_block(&block)?;
            self.index.add_header(block.header);
            self.update_tip(store)?;
            return Ok(AddBlock::Stored);
        }
        // Unanchored: only keep it if it's valid on top of our tip.
        match self.state.apply_block(&block, &self.params, &self.secp) {
            Ok(undo) => self.state.revert(undo),
            Err(e) => return Ok(AddBlock::Rejected(e.to_string())),
        }
        if self.pending.len() == MAX_PENDING_BLOCKS {
            self.pending.pop_front();
        }
        self.pending.push_back(block);
        Ok(AddBlock::Pending)
    }

    /// Admits a transaction to the mempool. Returns `false` if it was
    /// already there.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<bool, String> {
        let id = tx.txid();
        if self.mempool_ids.contains(&id) {
            return Ok(false);
        }
        if self.mempool.len() >= MAX_MEMPOOL_TXS {
            return Err("mempool is full".into());
        }
        self.state
            .check_tx(&tx, &self.params, &self.secp)
            .map_err(|e| e.to_string())?;
        self.mempool_ids.insert(id);
        self.mempool.push(tx);
        Ok(true)
    }

    /// Builds a block on the tip from the mempool and keeps it as pending.
    /// Anchoring it in Bitcoin is up to the caller.
    pub fn build_block(&mut self) -> Block {
        let mut builder = BlockBuilder::new(&self.state, &self.params, &self.secp);
        // Mempool txs were valid alone but may conflict with each other, and
        // the block may fill up. Either way the tx just stays in the mempool.
        for tx in &self.mempool {
            let _: Result<(), AddTxError> = builder.try_add(tx.clone());
        }
        let block = builder.finish();
        if !self.pending.iter().any(|b| b.hash() == block.hash()) {
            if self.pending.len() == MAX_PENDING_BLOCKS {
                self.pending.pop_front();
            }
            self.pending.push_back(block.clone());
        }
        block
    }

    /// Moves the applied state to the best chain, marking blocks that fail
    /// validation as invalid and choosing again.
    fn update_tip(&mut self, store: &Store) -> Result<()> {
        let before = self.state.tip();
        // Transactions from blocks that get disconnected go back to the mempool.
        let mut disconnected = Vec::new();
        loop {
            let best = self.index.best_chain();
            let mut common = self
                .active
                .iter()
                .zip(&best)
                .take_while(|((a, _), b)| a == *b)
                .count();
            if self.active[common..].iter().any(|(_, undo)| undo.is_none()) {
                warn!(
                    height = common,
                    "reorg below the snapshot; replaying from genesis"
                );
                for (hash, _) in self.active[common..].iter().rev() {
                    if let Some(block) = store.block(hash)? {
                        disconnected.push(block.txs);
                    }
                }
                self.state = State::new();
                self.active.clear();
                common = 0;
            }
            while self.active.len() > common {
                let (hash, undo) = self.active.pop().expect("non-empty");
                self.state.revert(undo.expect("checked above"));
                if let Some(block) = store.block(&hash)? {
                    disconnected.push(block.txs);
                }
            }
            let mut failed = false;
            for hash in &best[common..] {
                let block = store
                    .block(hash)?
                    .with_context(|| format!("indexed block {hash} missing from store"))?;
                match self.state.apply_block(&block, &self.params, &self.secp) {
                    Ok(undo) => self.active.push((*hash, Some(undo))),
                    Err(e) => {
                        warn!(block = %hash, error = %e, "invalid block");
                        self.index.mark_invalid(*hash);
                        store.put_invalid(hash)?;
                        failed = true;
                        break;
                    }
                }
            }
            if !failed {
                break;
            }
        }
        if self.state.tip() != before {
            info!(height = self.state.height(), tip = %self.state.tip(), "new tip");
            // Oldest disconnected block first, so commits come before reveals.
            let resurrected = disconnected.into_iter().rev().flatten();
            let pending = std::mem::take(&mut self.mempool);
            self.refill_mempool(resurrected.chain(pending));
        }
        if self.state.height() >= self.snapshot_height + SNAPSHOT_INTERVAL {
            self.save_snapshot(store)?;
        }
        Ok(())
    }

    /// Replaces the mempool with whichever of `txs` are valid on the tip.
    fn refill_mempool(&mut self, txs: impl IntoIterator<Item = Tx>) {
        self.mempool.clear();
        self.mempool_ids.clear();
        for tx in txs {
            let _ = self.submit_tx(tx);
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use namespace_core::Encode;
    use namespace_core::tx::commitment_hash;
    use namespace_core::{Anchor, Name};

    use super::*;

    struct Fixture {
        _dir: TempDir,
        path: std::path::PathBuf,
        store: Store,
        chain: Chain,
        btc_height: u32,
    }

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn covenant() -> CovenantConfig {
        CovenantConfig {
            start: OutPoint::new(Txid::all_zeros(), 0),
            start_height: 1,
            covenant_vout: 0,
            anchor_vout: 1,
        }
    }

    impl Fixture {
        fn new(test: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("namespace-test-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("chain.redb");
            let store = Store::open(&path).unwrap();
            let chain = Chain::load(Params::regtest(), covenant(), &store).unwrap();
            Self {
                _dir: TempDir(dir),
                path,
                store,
                chain,
                btc_height: 0,
            }
        }

        /// Scans a Bitcoin block that anchors `block`, or an empty slot.
        fn mine(&mut self, block: Option<&Block>) {
            self.btc_height += 1;
            let btc_hash = bitcoin::BlockHash::from_byte_array([self.btc_height as u8; 32]);
            let record = ScanRecord {
                btc_hash,
                next: OutPoint::new(Txid::from_byte_array([self.btc_height as u8; 32]), 0),
                anchor: block.map(|b| Anchor {
                    btc_height: self.btc_height,
                    btc_block: btc_hash,
                    txid: Txid::all_zeros(),
                    block_hash: b.hash(),
                }),
            };
            self.chain
                .add_scan(&self.store, self.btc_height, record)
                .unwrap();
        }

        /// The valid block on the current tip with exactly `txs`.
        fn next_block(&self, txs: Vec<Tx>) -> Block {
            self.chain
                .state
                .next_block(txs, &self.chain.params, &self.chain.secp)
                .unwrap()
        }

        /// Builds a block from the mempool, anchors it, and returns it.
        fn build_and_mine(&mut self) -> Block {
            let block = self.chain.build_block();
            self.mine(Some(&block));
            block
        }

        fn reload(&mut self) {
            // redb locks the file, so the old handle has to go first.
            self.store = Store::open(&self.path.with_extension("scratch")).unwrap();
            self.store = Store::open(&self.path).unwrap();
            self.chain = Chain::load(Params::regtest(), covenant(), &self.store).unwrap();
        }
    }

    fn register_txs(name: &str, kp: &Keypair) -> (Tx, Tx) {
        let name = Name::new(name).unwrap();
        let owner = kp.x_only_public_key().0;
        let salt = Hash256([5; 32]);
        let commit = Tx::Commit {
            commitment: commitment_hash(&name, &owner, &salt),
        };
        (commit, Tx::Register { name, owner, salt })
    }

    fn keypair() -> Keypair {
        Keypair::from_secret_key(
            &Secp256k1::signing_only(),
            &SecretKey::from_slice(&[1; 32]).unwrap(),
        )
    }

    #[test]
    fn build_anchor_register() {
        let mut f = Fixture::new("register");
        let (commit, register) = register_txs("alice", &keypair());

        // Reveal before the commit is in the chain is refused by the mempool.
        assert!(f.chain.submit_tx(register.clone()).is_err());
        f.chain.submit_tx(commit).unwrap();
        f.build_and_mine();
        assert_eq!(f.chain.state().height(), 1);
        assert_eq!(f.chain.mempool_len(), 0);

        f.chain.submit_tx(register).unwrap();
        f.mine(None);
        f.build_and_mine();
        assert_eq!(f.chain.state().height(), 2);
        assert!(
            f.chain
                .state()
                .lookup(&Name::new("alice").unwrap())
                .is_some()
        );

        // Everything survives a restart.
        let tip = f.chain.state().tip();
        f.reload();
        assert_eq!(f.chain.state().tip(), tip);
        assert!(
            f.chain
                .state()
                .lookup(&Name::new("alice").unwrap())
                .is_some()
        );
    }

    #[test]
    fn withheld_block_stalls_then_is_reorged_out() {
        let mut f = Fixture::new("withheld");
        let a = f.build_and_mine();

        // Someone anchors a block but never publishes it.
        let withheld = f.next_block(vec![Tx::Commit {
            commitment: Hash256([9; 32]),
        }]);
        f.mine(Some(&withheld));
        assert_eq!(f.chain.missing_bodies(), vec![withheld.hash()]);
        assert_eq!(f.chain.state().tip(), a.hash());

        // Builders keep building on `a` and overtake it.
        let b1 = f.build_and_mine();
        assert_eq!(b1.header.parent, a.hash());
        assert_eq!(f.chain.state().tip(), b1.hash());
        let b2 = f.build_and_mine();
        assert_eq!(f.chain.state().tip(), b2.hash());

        // The body turning up late changes nothing.
        assert_eq!(
            f.chain.add_block(&f.store, withheld).unwrap(),
            AddBlock::Stored
        );
        assert_eq!(f.chain.state().tip(), b2.hash());
    }

    #[test]
    fn late_body_is_applied() {
        let mut f = Fixture::new("late");
        let (commit, _) = register_txs("alice", &keypair());
        let block = f.next_block(vec![commit]);
        f.mine(Some(&block));
        assert_eq!(f.chain.state().height(), 0);
        assert_eq!(
            f.chain.add_block(&f.store, block.clone()).unwrap(),
            AddBlock::Stored
        );
        assert_eq!(f.chain.state().tip(), block.hash());
    }

    #[test]
    fn invalid_anchored_block_is_skipped() {
        let mut f = Fixture::new("invalid");
        let (_, register) = register_txs("alice", &keypair());
        // Registers without a commitment: anchored, but invalid.
        let bad = Block::new(Block::genesis().hash(), 0, vec![register], Hash256::ZERO);
        f.mine(Some(&bad));
        assert_eq!(f.chain.add_block(&f.store, bad).unwrap(), AddBlock::Stored);
        assert_eq!(f.chain.state().height(), 0);
        let good = f.build_and_mine();
        assert_eq!(f.chain.state().tip(), good.hash());
    }

    #[test]
    fn bitcoin_reorg_unwinds_namespace_blocks() {
        let mut f = Fixture::new("btc-reorg");
        let a = f.build_and_mine();
        let (commit, _) = register_txs("alice", &keypair());
        f.chain.submit_tx(commit).unwrap();
        f.build_and_mine();
        assert_eq!(f.chain.state().height(), 2);

        f.chain.rollback_scans(&f.store, 2).unwrap();
        f.btc_height = 1;
        assert_eq!(f.chain.state().tip(), a.hash());
        // The commit is back in the mempool.
        assert_eq!(f.chain.mempool_len(), 1);
        assert_eq!(f.chain.next_scan_height(), 2);
    }

    #[test]
    fn unanchored_blocks_must_extend_tip() {
        let mut f = Fixture::new("pending");
        f.build_and_mine();
        let stale = Block::new(
            Block::genesis().hash(),
            0,
            vec![Tx::Commit {
                commitment: Hash256([1; 32]),
            }],
            Hash256::ZERO,
        );
        assert!(matches!(
            f.chain.add_block(&f.store, stale).unwrap(),
            AddBlock::Rejected(_)
        ));
        let next = f.next_block(vec![]);
        assert_eq!(
            f.chain.add_block(&f.store, next.clone()).unwrap(),
            AddBlock::Pending
        );
        // Served while pending, persisted once anchored.
        assert!(f.chain.block(&f.store, &next.hash()).unwrap().is_some());
        f.mine(Some(&next));
        assert_eq!(f.chain.state().tip(), next.hash());
        assert!(f.store.block(&next.hash()).unwrap().is_some());
    }

    #[test]
    fn restart_resumes_from_snapshot() {
        let mut f = Fixture::new("snapshot");
        let (commit, register) = register_txs("alice", &keypair());
        f.chain.submit_tx(commit).unwrap();
        f.build_and_mine();
        f.chain.submit_tx(register).unwrap();
        f.build_and_mine();
        f.chain.save_snapshot(&f.store).unwrap();
        f.build_and_mine();
        let tip = f.chain.state().tip();

        f.reload();
        assert_eq!(f.chain.state().tip(), tip);
        assert_eq!(f.chain.state().height(), 3);
        // Blocks 1-2 came from the snapshot, block 3 was replayed.
        let undos: Vec<_> = f.chain.active.iter().map(|(_, u)| u.is_some()).collect();
        assert_eq!(undos, vec![false, false, true]);
        assert!(
            f.chain
                .state()
                .lookup(&Name::new("alice").unwrap())
                .is_some()
        );
    }

    #[test]
    fn tampered_snapshot_is_ignored() {
        let mut f = Fixture::new("bad-snapshot");
        f.build_and_mine();
        let (commit, _) = register_txs("alice", &keypair());
        f.chain.submit_tx(commit).unwrap();
        f.build_and_mine();
        // A snapshot claiming block 2's tip, but with block 1's contents.
        let mut wrong = f.chain.state().clone();
        let undo = f.chain.active.last().unwrap().1.clone().unwrap();
        wrong.revert(undo);
        let tip = f.chain.state().tip();
        let bytes = wrong.to_bytes();
        let wrong =
            State::from_bytes(&[&tip.0[..], &2u64.to_le_bytes(), &bytes[40..]].concat()).unwrap();
        assert_eq!((wrong.tip(), wrong.height()), (tip, 2));
        f.store.put_snapshot(2, &wrong).unwrap();

        let root = f.chain.state().state_root();
        f.reload();
        assert_eq!(f.chain.state().state_root(), root);
        assert!(f.chain.active.iter().all(|(_, u)| u.is_some()));
    }

    #[test]
    fn reorg_below_snapshot_replays_from_genesis() {
        let mut f = Fixture::new("snapshot-reorg");
        let a = f.build_and_mine();
        let (commit, _) = register_txs("alice", &keypair());
        f.chain.submit_tx(commit).unwrap();
        f.build_and_mine();
        f.chain.save_snapshot(&f.store).unwrap();
        f.reload();
        assert!(f.chain.active.iter().all(|(_, u)| u.is_none()));

        f.chain.rollback_scans(&f.store, 2).unwrap();
        f.btc_height = 1;
        assert_eq!(f.chain.state().tip(), a.hash());
        assert_eq!(f.chain.mempool_len(), 1);
    }

    #[test]
    fn invalid_blocks_are_remembered() {
        let mut f = Fixture::new("invalid-persist");
        let (_, register) = register_txs("alice", &keypair());
        let bad = Block::new(Block::genesis().hash(), 0, vec![register], Hash256::ZERO);
        f.mine(Some(&bad));
        f.chain.add_block(&f.store, bad.clone()).unwrap();
        assert_eq!(f.store.invalid_blocks().unwrap(), vec![bad.hash()]);
    }
}
