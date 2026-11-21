use std::collections::BTreeMap;

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::block::{Block, BlockHash, tx_root};
use crate::encode::{Decode, DecodeError, Encode, Reader, put_u32, put_u64};
use crate::hash::Hash256;
use crate::name::Name;
use crate::params::Params;
use crate::tree::{InvalidProof, Proof, Tree};
use crate::tx::{OwnerKey, SignedOp, Tx, sighash, verify};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub owner: OwnerKey,
    /// Height of the `Register` that created this registration.
    pub registered_at: u64,
    /// The name is active while the chain height is below this.
    pub expires_at: u64,
    /// The `seq` the next renew or transfer must carry.
    pub seq: u64,
}

impl NameRecord {
    pub fn is_active(&self, height: u64) -> bool {
        height < self.expires_at
    }
}

impl Encode for NameRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.owner.serialize());
        put_u64(out, self.registered_at);
        put_u64(out, self.expires_at);
        put_u64(out, self.seq);
    }
}

impl Decode for NameRecord {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            owner: OwnerKey::from_slice(r.take(32)?)
                .map_err(|_| DecodeError::Invalid("public key"))?,
            registered_at: r.u64()?,
            expires_at: r.u64()?,
            seq: r.u64()?,
        })
    }
}

// Where names and announcements live in the state tree. Distinct tags keep
// the two kinds of key apart.

fn name_key(name: &Name) -> Hash256 {
    Hash256::tagged("namespace/state-name", &name.to_bytes())
}

fn name_value(record: &NameRecord) -> Hash256 {
    Hash256::tagged("namespace/state-name-record", &record.to_bytes())
}

fn announcement_key(name: &Name) -> Hash256 {
    Hash256::tagged("namespace/state-announcement", &name.to_bytes())
}

fn announcement_value(height: u64) -> Hash256 {
    Hash256::tagged("namespace/state-announcement-height", &height.to_le_bytes())
}

/// Proves a name's record (or that it has none) against a header's
/// `state_root`. The record may have expired: compare `expires_at` against
/// the header's height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameProof {
    pub record: Option<NameRecord>,
    pub proof: Proof,
}

impl NameProof {
    /// Checks the proof and returns the proven record.
    pub fn verify(
        &self,
        name: &Name,
        state_root: &Hash256,
    ) -> Result<Option<NameRecord>, InvalidProof> {
        let proven = self.proof.verify(state_root, &name_key(name))?;
        if proven != self.record.as_ref().map(name_value) {
            return Err(InvalidProof);
        }
        Ok(self.record)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockError {
    #[error("block does not extend the current tip")]
    WrongParent,
    #[error("block height {got}, expected {expected}")]
    WrongHeight { got: u64, expected: u64 },
    #[error("unsupported block version {0}")]
    Version(u32),
    #[error("tx root does not match transactions")]
    TxRoot,
    #[error("state root does not match the resulting state")]
    StateRoot,
    #[error("{kind} limit exceeded: {count} > {cap}")]
    Limit {
        kind: &'static str,
        count: u32,
        cap: u32,
    },
    #[error("too many announcements of {lengths}-character names: {count} > {cap}")]
    TierLimit {
        lengths: String,
        count: u32,
        cap: u32,
    },
    #[error("tx {index}: {error}")]
    Tx { index: usize, error: TxError },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    #[error("name has already been announced")]
    AlreadyAnnounced,
    #[error("name has not been announced")]
    NotAnnounced,
    #[error("name can't be registered until height {0}")]
    AnnouncementTooRecent(u64),
    #[error("name is already registered")]
    NameTaken,
    #[error("name is not registered or has expired")]
    NameNotActive,
    #[error("wrong sequence number: got {got}, expected {expected}")]
    WrongSeq { got: u64, expected: u64 },
    #[error("invalid signature")]
    BadSignature,
}

/// The state after applying a chain of blocks: every name's record plus the
/// announced names waiting to be registered.
#[derive(Clone, Debug)]
pub struct State {
    tip: BlockHash,
    height: u64,
    names: BTreeMap<Name, NameRecord>,
    /// Announced names and the height they were announced at.
    announcements: BTreeMap<Name, u64>,
    /// Both of the above, authenticated. Its root is the header's `state_root`.
    tree: Tree,
}

/// What `State::apply_block` changed, so it can be reverted on a reorg.
#[derive(Clone, Debug)]
pub struct Undo {
    prev_tip: BlockHash,
    /// Applied in reverse order on revert.
    entries: Vec<UndoEntry>,
}

#[derive(Clone, Debug)]
enum UndoEntry {
    Name(Name, Option<NameRecord>),
    AnnouncementAdded(Name),
    AnnouncementRemoved(Name, u64),
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// The state at genesis.
    pub fn new() -> Self {
        Self {
            tip: Block::genesis().hash(),
            height: 0,
            names: BTreeMap::new(),
            announcements: BTreeMap::new(),
            tree: Tree::new(),
        }
    }

    pub fn tip(&self) -> BlockHash {
        self.tip
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// The record for `name`, if it is currently registered and not expired.
    pub fn lookup(&self, name: &Name) -> Option<&NameRecord> {
        self.names.get(name).filter(|r| r.is_active(self.height))
    }

    /// The height `name` was announced at, if it is waiting to be registered.
    pub fn announced_at(&self, name: &Name) -> Option<u64> {
        self.announcements.get(name).copied()
    }

    /// The root a block leaving this state must carry.
    pub fn state_root(&self) -> Hash256 {
        self.tree.root()
    }

    pub fn prove_name(&self, name: &Name) -> NameProof {
        NameProof {
            record: self.names.get(name).copied(),
            proof: self.tree.prove(&name_key(name)),
        }
    }

    /// Builds the block on the tip that contains exactly `txs`, filling in
    /// its state root. Fails if any of them is invalid. Unlike
    /// [`BlockBuilder`] this doesn't check the block's limits.
    pub fn next_block(
        &self,
        txs: Vec<Tx>,
        params: &Params,
        secp: &Secp256k1<VerifyOnly>,
    ) -> Result<Block, BlockError> {
        let mut next = self.clone();
        let mut undo = Undo {
            prev_tip: self.tip,
            entries: Vec::new(),
        };
        next.height += 1;
        let height = next.height;
        for (index, tx) in txs.iter().enumerate() {
            next.apply_tx(tx, height, params, secp, &mut undo)
                .map_err(|error| BlockError::Tx { index, error })?;
        }
        Ok(Block::new(self.tip, self.height, txs, next.state_root()))
    }

    /// Validates `block` against this state and applies it. On error the
    /// state is left unchanged.
    pub fn apply_block(
        &mut self,
        block: &Block,
        params: &Params,
        secp: &Secp256k1<VerifyOnly>,
    ) -> Result<Undo, BlockError> {
        let h = &block.header;
        if h.version != crate::block::BLOCK_VERSION {
            return Err(BlockError::Version(h.version));
        }
        if h.parent != self.tip {
            return Err(BlockError::WrongParent);
        }
        let height = self.height + 1;
        if h.height != height {
            return Err(BlockError::WrongHeight {
                got: h.height,
                expected: height,
            });
        }
        if h.tx_root != tx_root(&block.txs) {
            return Err(BlockError::TxRoot);
        }
        check_limits(block, params, height)?;

        let mut undo = Undo {
            prev_tip: self.tip,
            entries: Vec::new(),
        };
        self.tip = block.hash();
        self.height = height;

        for (index, tx) in block.txs.iter().enumerate() {
            if let Err(error) = self.apply_tx(tx, height, params, secp, &mut undo) {
                self.revert(undo);
                return Err(BlockError::Tx { index, error });
            }
        }
        if self.state_root() != h.state_root {
            self.revert(undo);
            return Err(BlockError::StateRoot);
        }
        Ok(undo)
    }

    /// Reverts the most recently applied block. `undo` must be the value its
    /// `apply_block` returned.
    pub fn revert(&mut self, undo: Undo) {
        for entry in undo.entries.into_iter().rev() {
            match entry {
                UndoEntry::Name(name, prev) => {
                    self.put_name(&name, prev);
                }
                UndoEntry::AnnouncementAdded(name) => self.remove_announcement(&name),
                UndoEntry::AnnouncementRemoved(name, at) => self.insert_announcement(&name, at),
            }
        }
        self.tip = undo.prev_tip;
        self.height -= 1;
    }

    /// Validates `tx` as if it were included in the next block, without
    /// changing the state. Used for mempool admission.
    pub fn check_tx(
        &mut self,
        tx: &Tx,
        params: &Params,
        secp: &Secp256k1<VerifyOnly>,
    ) -> Result<(), TxError> {
        let mut undo = Undo {
            prev_tip: self.tip,
            entries: Vec::new(),
        };
        let height = self.height + 1;
        self.height = height;
        let result = self.apply_tx(tx, height, params, secp, &mut undo);
        self.revert(undo);
        result
    }

    // The only places that change names and announcements, so the tree always
    // matches them.

    fn insert_announcement(&mut self, name: &Name, at: u64) {
        self.announcements.insert(name.clone(), at);
        self.tree.insert(announcement_key(name), announcement_value(at));
    }

    fn remove_announcement(&mut self, name: &Name) {
        self.announcements.remove(name);
        self.tree.remove(&announcement_key(name));
    }

    /// Sets or clears a name's record, returning the previous one.
    fn put_name(&mut self, name: &Name, record: Option<NameRecord>) -> Option<NameRecord> {
        match record {
            Some(r) => {
                self.tree.insert(name_key(name), name_value(&r));
                self.names.insert(name.clone(), r)
            }
            None => {
                self.tree.remove(&name_key(name));
                self.names.remove(name)
            }
        }
    }

    fn set_name(&mut self, name: &Name, record: NameRecord, undo: &mut Undo) {
        let prev = self.put_name(name, Some(record));
        undo.entries.push(UndoEntry::Name(name.clone(), prev));
    }

    fn apply_tx(
        &mut self,
        tx: &Tx,
        height: u64,
        params: &Params,
        secp: &Secp256k1<VerifyOnly>,
        undo: &mut Undo,
    ) -> Result<(), TxError> {
        match tx {
            Tx::Announce { name } => {
                if self.names.get(name).is_some_and(|r| r.is_active(height)) {
                    return Err(TxError::NameTaken);
                }
                if self.announcements.contains_key(name) {
                    return Err(TxError::AlreadyAnnounced);
                }
                self.insert_announcement(name, height);
                undo.entries.push(UndoEntry::AnnouncementAdded(name.clone()));
            }
            Tx::Register { name, owner } => {
                // An announced name has no active record: announcing requires
                // that, and registering removes the announcement.
                let at = self
                    .announcements
                    .get(name)
                    .copied()
                    .ok_or(TxError::NotAnnounced)?;
                let opens_at = at + params.announce_delay;
                if height < opens_at {
                    return Err(TxError::AnnouncementTooRecent(opens_at));
                }
                self.remove_announcement(name);
                undo.entries
                    .push(UndoEntry::AnnouncementRemoved(name.clone(), at));
                let record = NameRecord {
                    owner: *owner,
                    registered_at: height,
                    expires_at: height + params.expiry_period,
                    seq: 0,
                };
                self.set_name(name, record, undo);
            }
            Tx::Renew { name, seq, sig } => {
                let mut record = self.authorize(name, *seq, SignedOp::Renew, sig, height, secp)?;
                record.seq += 1;
                record.expires_at = height + params.expiry_period;
                self.set_name(name, record, undo);
            }
            Tx::Transfer {
                name,
                new_owner,
                seq,
                sig,
            } => {
                let op = SignedOp::Transfer { new_owner };
                let mut record = self.authorize(name, *seq, op, sig, height, secp)?;
                record.seq += 1;
                record.owner = *new_owner;
                self.set_name(name, record, undo);
            }
        }
        Ok(())
    }

    /// Checks that `sig` is the current owner's signature over `op` and
    /// returns the name's record.
    fn authorize(
        &self,
        name: &Name,
        seq: u64,
        op: SignedOp<'_>,
        sig: &bitcoin::secp256k1::schnorr::Signature,
        height: u64,
        secp: &Secp256k1<VerifyOnly>,
    ) -> Result<NameRecord, TxError> {
        let record = *self
            .names
            .get(name)
            .filter(|r| r.is_active(height))
            .ok_or(TxError::NameNotActive)?;
        if seq != record.seq {
            return Err(TxError::WrongSeq {
                got: seq,
                expected: record.seq,
            });
        }
        let digest = sighash(name, record.registered_at, seq, op);
        if !verify(secp, &record.owner, &digest, sig) {
            return Err(TxError::BadSignature);
        }
        Ok(record)
    }
}

/// Assembles the next block from candidate transactions, keeping the ones
/// that are valid in sequence and fit the block's limits.
pub struct BlockBuilder<'a> {
    state: State,
    params: &'a Params,
    secp: &'a Secp256k1<VerifyOnly>,
    undo: Undo,
    txs: Vec<Tx>,
    /// Announcements so far, by tier.
    announcements: BTreeMap<u32, u32>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddTxError {
    #[error("block is full for this kind of transaction")]
    Full,
    #[error(transparent)]
    Invalid(#[from] TxError),
}

impl<'a> BlockBuilder<'a> {
    pub fn new(state: &State, params: &'a Params, secp: &'a Secp256k1<VerifyOnly>) -> Self {
        let mut state = state.clone();
        let undo = Undo {
            prev_tip: state.tip,
            entries: Vec::new(),
        };
        state.height += 1;
        Self {
            state,
            params,
            secp,
            undo,
            txs: Vec::new(),
            announcements: BTreeMap::new(),
        }
    }

    pub fn try_add(&mut self, tx: Tx) -> Result<(), AddTxError> {
        let height = self.state.height;
        let tier = self.params.tier(tx.name().as_str().len());
        let announce = matches!(tx, Tx::Announce { .. });
        let full = self.txs.len() as u32 >= self.params.max_txs_per_block
            || announce
                && self.announcements.get(&tier).copied().unwrap_or(0)
                    >= self.params.tier_cap(height, tier);
        if full {
            return Err(AddTxError::Full);
        }
        self.state
            .apply_tx(&tx, height, self.params, self.secp, &mut self.undo)?;
        if announce {
            *self.announcements.entry(tier).or_default() += 1;
        }
        self.txs.push(tx);
        Ok(())
    }

    pub fn finish(self) -> Block {
        let root = self.state.state_root();
        Block::new(self.undo.prev_tip, self.state.height - 1, self.txs, root)
    }
}

/// A snapshot of the whole state, so a node can restart without replaying
/// the chain from genesis. Not consensus: the node checks a decoded snapshot
/// against its block's `state_root` before using it.
impl Encode for State {
    fn encode(&self, out: &mut Vec<u8>) {
        self.tip.encode(out);
        put_u64(out, self.height);
        put_u32(
            out,
            u32::try_from(self.names.len()).expect("name count fits in u32"),
        );
        for (name, record) in &self.names {
            name.encode(out);
            record.encode(out);
        }
        put_u32(
            out,
            u32::try_from(self.announcements.len()).expect("announcement count fits in u32"),
        );
        for (name, at) in &self.announcements {
            name.encode(out);
            put_u64(out, *at);
        }
    }
}

impl Decode for State {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut state = State {
            tip: Hash256::decode(r)?,
            height: r.u64()?,
            ..State::new()
        };
        for _ in 0..r.u32()? {
            let name = Name::decode(r)?;
            let record = NameRecord::decode(r)?;
            if state.put_name(&name, Some(record)).is_some() {
                return Err(DecodeError::Invalid("duplicate name"));
            }
        }
        for _ in 0..r.u32()? {
            let name = Name::decode(r)?;
            let at = r.u64()?;
            if state.announcements.contains_key(&name) {
                return Err(DecodeError::Invalid("duplicate announcement"));
            }
            state.insert_announcement(&name, at);
        }
        Ok(state)
    }
}

fn check_limits(block: &Block, params: &Params, height: u64) -> Result<(), BlockError> {
    let count = block.txs.len() as u32;
    let cap = params.max_txs_per_block;
    if count > cap {
        return Err(BlockError::Limit {
            kind: "transaction",
            count,
            cap,
        });
    }
    let mut by_tier = BTreeMap::<u32, u32>::new();
    for tx in &block.txs {
        if let Tx::Announce { name } = tx {
            *by_tier.entry(params.tier(name.as_str().len())).or_default() += 1;
        }
    }
    for (tier, count) in by_tier {
        let cap = params.tier_cap(height, tier);
        if count > cap {
            return Err(BlockError::TierLimit {
                lengths: params.tier_lengths(tier),
                count,
                cap,
            });
        }
    }
    Ok(())
}
