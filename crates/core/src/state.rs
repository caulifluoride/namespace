use std::collections::{BTreeMap, BTreeSet};

use bitcoin::secp256k1::{Keypair, Secp256k1, VerifyOnly};
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

/// A name waiting to be registered by the builder that announced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub announced_at: u64,
    /// The builder of the block that announced the name. Only its blocks can
    /// register it.
    pub builder: OwnerKey,
    /// The builder's first block from `announced_at + announce_delay` on went
    /// by without registering the name, so it can't be registered anymore.
    /// It stays until it is released.
    pub lapsed: bool,
}

impl Announcement {
    /// The first height a registration of the name can be in.
    pub fn opens_at(&self, params: &Params) -> u64 {
        self.announced_at + params.announce_delay
    }

    /// The height the announcement is dropped at, so anyone can announce the
    /// name again.
    pub fn released_at(&self, params: &Params) -> u64 {
        self.announced_at + 2 * params.announce_delay
    }
}

impl Encode for Announcement {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.announced_at);
        out.extend_from_slice(&self.builder.serialize());
        out.push(u8::from(self.lapsed));
    }
}

impl Decode for Announcement {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            announced_at: r.u64()?,
            builder: OwnerKey::from_slice(r.take(32)?)
                .map_err(|_| DecodeError::Invalid("public key"))?,
            lapsed: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::Invalid("lapsed flag")),
            },
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

fn announcement_value(a: &Announcement) -> Hash256 {
    Hash256::tagged("namespace/state-announcement-record", &a.to_bytes())
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
    #[error("block is not signed by its builder")]
    Signature,
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
    #[error("name was announced by another builder")]
    WrongBuilder,
    #[error("name can't be registered until height {0}")]
    AnnouncementTooRecent(u64),
    #[error("the announcing builder's chance to register the name has passed")]
    AnnouncementLapsed,
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
    announcements: BTreeMap<Name, Announcement>,
    /// `(announced_at, name)` for every announcement, for releasing them in
    /// height order.
    announcements_by_height: BTreeSet<(u64, Name)>,
    /// `(announced_at, name)` for each builder's announcements that haven't
    /// lapsed, for lapsing them when the builder's next block goes by.
    open_by_builder: BTreeMap<OwnerKey, BTreeSet<(u64, Name)>>,
    /// Names and announcements, authenticated. Its root is the header's
    /// `state_root`.
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
    Announcement(Name, Option<Announcement>),
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
            announcements_by_height: BTreeSet::new(),
            open_by_builder: BTreeMap::new(),
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

    /// The announcement of `name`, if it is waiting to be registered.
    pub fn announcement(&self, name: &Name) -> Option<&Announcement> {
        self.announcements.get(name)
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
        builder: &Keypair,
        params: &Params,
        secp: &Secp256k1<VerifyOnly>,
    ) -> Result<Block, BlockError> {
        let key = builder.x_only_public_key().0;
        let mut next = self.clone();
        let mut undo = Undo {
            prev_tip: self.tip,
            entries: Vec::new(),
        };
        next.height += 1;
        let height = next.height;
        next.begin_block(height, params, &mut undo);
        for (index, tx) in txs.iter().enumerate() {
            next.apply_tx(tx, height, &key, params, secp, &mut undo)
                .map_err(|error| BlockError::Tx { index, error })?;
        }
        next.end_block(height, &key, params, &mut undo);
        Ok(Block::new(
            self.tip,
            self.height,
            builder,
            txs,
            next.state_root(),
        ))
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
        if !block.verify_sig(secp) {
            return Err(BlockError::Signature);
        }
        check_limits(block, params, height)?;

        let mut undo = Undo {
            prev_tip: self.tip,
            entries: Vec::new(),
        };
        self.tip = block.hash();
        self.height = height;
        self.begin_block(height, params, &mut undo);

        for (index, tx) in block.txs.iter().enumerate() {
            if let Err(error) = self.apply_tx(tx, height, &h.builder, params, secp, &mut undo) {
                self.revert(undo);
                return Err(BlockError::Tx { index, error });
            }
        }
        self.end_block(height, &h.builder, params, &mut undo);
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
                UndoEntry::Announcement(name, prev) => {
                    self.put_announcement(&name, prev);
                }
            }
        }
        self.tip = undo.prev_tip;
        self.height -= 1;
    }

    /// Validates `tx` as if it were included in the next block, without
    /// changing the state. Used for mempool admission, where it isn't known
    /// who will build the block: a registration is checked as if its
    /// announcing builder were building it, so it can be relayed to them.
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
        self.begin_block(height, params, &mut undo);
        let builder = match tx {
            Tx::Register { name, .. } => self.announcements.get(name).map(|a| a.builder),
            _ => None,
        }
        .unwrap_or(Block::genesis().header.builder);
        let result = self.apply_tx(tx, height, &builder, params, secp, &mut undo);
        self.revert(undo);
        result
    }

    /// Releases announcements that are `2 * announce_delay` old, before the
    /// block's transactions.
    fn begin_block(&mut self, height: u64, params: &Params, undo: &mut Undo) {
        let Some(cutoff) = height.checked_sub(2 * params.announce_delay) else {
            return;
        };
        let released: Vec<_> = self
            .announcements_by_height
            .iter()
            .take_while(|(at, _)| *at <= cutoff)
            .map(|(_, name)| name.clone())
            .collect();
        for name in released {
            self.set_announcement(&name, None, undo);
        }
    }

    /// Lapses the builder's announcements that were open in this block but
    /// weren't registered in it, after the block's transactions.
    fn end_block(&mut self, height: u64, builder: &OwnerKey, params: &Params, undo: &mut Undo) {
        let Some(cutoff) = height.checked_sub(params.announce_delay) else {
            return;
        };
        let Some(open) = self.open_by_builder.get(builder) else {
            return;
        };
        let lapsing: Vec<_> = open
            .iter()
            .take_while(|(at, _)| *at <= cutoff)
            .map(|(_, name)| name.clone())
            .collect();
        for name in lapsing {
            let mut a = self.announcements[&name];
            a.lapsed = true;
            self.set_announcement(&name, Some(a), undo);
        }
    }

    // The only places that change names and announcements, so the tree and
    // the indexes always match them.

    /// Sets or clears a name's announcement, returning the previous one.
    fn put_announcement(
        &mut self,
        name: &Name,
        announcement: Option<Announcement>,
    ) -> Option<Announcement> {
        let prev = match announcement {
            Some(a) => {
                self.tree
                    .insert(announcement_key(name), announcement_value(&a));
                self.announcements.insert(name.clone(), a)
            }
            None => {
                self.tree.remove(&announcement_key(name));
                self.announcements.remove(name)
            }
        };
        if let Some(p) = prev {
            self.announcements_by_height
                .remove(&(p.announced_at, name.clone()));
            if let Some(open) = self.open_by_builder.get_mut(&p.builder) {
                open.remove(&(p.announced_at, name.clone()));
                if open.is_empty() {
                    self.open_by_builder.remove(&p.builder);
                }
            }
        }
        if let Some(a) = announcement {
            self.announcements_by_height
                .insert((a.announced_at, name.clone()));
            if !a.lapsed {
                self.open_by_builder
                    .entry(a.builder)
                    .or_default()
                    .insert((a.announced_at, name.clone()));
            }
        }
        prev
    }

    fn set_announcement(&mut self, name: &Name, a: Option<Announcement>, undo: &mut Undo) {
        let prev = self.put_announcement(name, a);
        undo.entries
            .push(UndoEntry::Announcement(name.clone(), prev));
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
        builder: &OwnerKey,
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
                let a = Announcement {
                    announced_at: height,
                    builder: *builder,
                    lapsed: false,
                };
                self.set_announcement(name, Some(a), undo);
            }
            Tx::Register { name, owner } => {
                // An announced name has no active record: announcing requires
                // that, and registering removes the announcement.
                let a = *self
                    .announcements
                    .get(name)
                    .ok_or(TxError::NotAnnounced)?;
                if a.builder != *builder {
                    return Err(TxError::WrongBuilder);
                }
                if a.lapsed {
                    return Err(TxError::AnnouncementLapsed);
                }
                let opens_at = a.opens_at(params);
                if height < opens_at {
                    return Err(TxError::AnnouncementTooRecent(opens_at));
                }
                self.set_announcement(name, None, undo);
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
    builder: &'a Keypair,
    key: OwnerKey,
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
    pub fn new(
        state: &State,
        builder: &'a Keypair,
        params: &'a Params,
        secp: &'a Secp256k1<VerifyOnly>,
    ) -> Self {
        let mut state = state.clone();
        let mut undo = Undo {
            prev_tip: state.tip,
            entries: Vec::new(),
        };
        state.height += 1;
        let height = state.height;
        state.begin_block(height, params, &mut undo);
        Self {
            state,
            builder,
            key: builder.x_only_public_key().0,
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
        self.state.apply_tx(
            &tx,
            height,
            &self.key,
            self.params,
            self.secp,
            &mut self.undo,
        )?;
        if announce {
            *self.announcements.entry(tier).or_default() += 1;
        }
        self.txs.push(tx);
        Ok(())
    }

    pub fn finish(mut self) -> Block {
        let height = self.state.height;
        self.state
            .end_block(height, &self.key, self.params, &mut self.undo);
        let root = self.state.state_root();
        Block::new(self.undo.prev_tip, height - 1, self.builder, self.txs, root)
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
        for (name, a) in &self.announcements {
            name.encode(out);
            a.encode(out);
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
            let a = Announcement::decode(r)?;
            if state.put_announcement(&name, Some(a)).is_some() {
                return Err(DecodeError::Invalid("duplicate announcement"));
            }
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
