use std::collections::{BTreeMap, BTreeSet, HashMap};

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::block::{Block, BlockHash, tx_root};
use crate::encode::{Decode, DecodeError, Encode, Reader, put_u32, put_u64};
use crate::hash::Hash256;
use crate::name::Name;
use crate::params::Params;
use crate::tree::{InvalidProof, Proof, Tree};
use crate::tx::{OwnerKey, SignedOp, Tx, commitment_hash, sighash, verify};

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

// Where names and commitments live in the state tree. Distinct tags keep the
// two kinds of key apart.

fn name_key(name: &Name) -> Hash256 {
    Hash256::tagged("namespace/state-name", &name.to_bytes())
}

fn name_value(record: &NameRecord) -> Hash256 {
    Hash256::tagged("namespace/state-name-record", &record.to_bytes())
}

fn commitment_key(commitment: &Hash256) -> Hash256 {
    Hash256::tagged("namespace/state-commitment", &commitment.0)
}

fn commitment_value(height: u64) -> Hash256 {
    Hash256::tagged("namespace/state-commitment-height", &height.to_le_bytes())
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
    #[error("too many registrations of {lengths}-character names: {count} > {cap}")]
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
    #[error("commitment already exists")]
    DuplicateCommitment,
    #[error("no matching commitment")]
    NoCommitment,
    #[error("commitment is too recent; reveal at height {0} or later")]
    CommitmentTooRecent(u64),
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
/// commitments waiting to be revealed.
#[derive(Clone, Debug)]
pub struct State {
    tip: BlockHash,
    height: u64,
    names: BTreeMap<Name, NameRecord>,
    commitments: HashMap<Hash256, u64>,
    /// `(height, commitment)` for pruning commitments in height order.
    commitments_by_height: BTreeSet<(u64, Hash256)>,
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
    CommitmentAdded(Hash256, u64),
    CommitmentRemoved(Hash256, u64),
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
            commitments: HashMap::new(),
            commitments_by_height: BTreeSet::new(),
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

    pub fn commitment_height(&self, commitment: &Hash256) -> Option<u64> {
        self.commitments.get(commitment).copied()
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
        next.prune_commitments(height, params, &mut undo);
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
        self.prune_commitments(height, params, &mut undo);

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
                UndoEntry::CommitmentAdded(c, at) => self.remove_commitment(c, at),
                UndoEntry::CommitmentRemoved(c, at) => self.insert_commitment(c, at),
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
        self.prune_commitments(height, params, &mut undo);
        let result = self.apply_tx(tx, height, params, secp, &mut undo);
        self.revert(undo);
        result
    }

    fn prune_commitments(&mut self, height: u64, params: &Params, undo: &mut Undo) {
        // A commitment made at `at` can be revealed up to `at + max_commit_age`.
        let Some(cutoff) = height.checked_sub(params.max_commit_age) else {
            return;
        };
        let expired: Vec<_> = self
            .commitments_by_height
            .range(..(cutoff, Hash256::ZERO))
            .copied()
            .collect();
        for (at, c) in expired {
            self.remove_commitment(c, at);
            undo.entries.push(UndoEntry::CommitmentRemoved(c, at));
        }
    }

    // The only places that change names and commitments, so the tree always
    // matches them.

    fn insert_commitment(&mut self, c: Hash256, at: u64) {
        self.commitments.insert(c, at);
        self.commitments_by_height.insert((at, c));
        self.tree.insert(commitment_key(&c), commitment_value(at));
    }

    fn remove_commitment(&mut self, c: Hash256, at: u64) {
        self.commitments.remove(&c);
        self.commitments_by_height.remove(&(at, c));
        self.tree.remove(&commitment_key(&c));
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
            Tx::Commit { commitment } => {
                if self.commitments.contains_key(commitment) {
                    return Err(TxError::DuplicateCommitment);
                }
                self.insert_commitment(*commitment, height);
                undo.entries
                    .push(UndoEntry::CommitmentAdded(*commitment, height));
            }
            Tx::Register { name, owner, salt } => {
                let commitment = commitment_hash(name, owner, salt);
                let at = self
                    .commitments
                    .get(&commitment)
                    .copied()
                    .ok_or(TxError::NoCommitment)?;
                if height < at + params.min_commit_age {
                    return Err(TxError::CommitmentTooRecent(at + params.min_commit_age));
                }
                if self.names.get(name).is_some_and(|r| r.is_active(height)) {
                    return Err(TxError::NameTaken);
                }
                self.remove_commitment(commitment, at);
                undo.entries
                    .push(UndoEntry::CommitmentRemoved(commitment, at));
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
    /// Registrations so far, by tier.
    registrations: BTreeMap<u32, u32>,
    commits: u32,
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
        let mut undo = Undo {
            prev_tip: state.tip,
            entries: Vec::new(),
        };
        state.height += 1;
        let height = state.height;
        state.prune_commitments(height, params, &mut undo);
        Self {
            state,
            params,
            secp,
            undo,
            txs: Vec::new(),
            registrations: BTreeMap::new(),
            commits: 0,
        }
    }

    pub fn try_add(&mut self, tx: Tx) -> Result<(), AddTxError> {
        let height = self.state.height;
        let tier = tx.name().map(|n| self.params.tier(n.as_str().len()));
        let full = match (&tx, tier) {
            _ if self.txs.len() as u32 >= self.params.max_txs_per_block => true,
            (Tx::Register { .. }, Some(t)) => {
                self.registrations.get(&t).copied().unwrap_or(0) >= self.params.tier_cap(height, t)
            }
            (Tx::Commit { .. }, _) => self.commits >= self.params.commit_cap(height),
            _ => false,
        };
        if full {
            return Err(AddTxError::Full);
        }
        self.state
            .apply_tx(&tx, height, self.params, self.secp, &mut self.undo)?;
        match (&tx, tier) {
            (Tx::Register { .. }, Some(t)) => *self.registrations.entry(t).or_default() += 1,
            (Tx::Commit { .. }, _) => self.commits += 1,
            _ => {}
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
            u32::try_from(self.commitments_by_height.len()).expect("commitment count fits in u32"),
        );
        for (at, c) in &self.commitments_by_height {
            c.encode(out);
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
            let c = Hash256::decode(r)?;
            let at = r.u64()?;
            if state.commitments.contains_key(&c) {
                return Err(DecodeError::Invalid("duplicate commitment"));
            }
            state.insert_commitment(c, at);
        }
        Ok(state)
    }
}

fn check_limits(block: &Block, params: &Params, height: u64) -> Result<(), BlockError> {
    let count = |pred: fn(&Tx) -> bool| block.txs.iter().filter(|t| pred(t)).count() as u32;
    let checks = [
        (
            "transaction",
            block.txs.len() as u32,
            params.max_txs_per_block,
        ),
        (
            "commit",
            count(|t| matches!(t, Tx::Commit { .. })),
            params.commit_cap(height),
        ),
    ];
    for (kind, count, cap) in checks {
        if count > cap {
            return Err(BlockError::Limit { kind, count, cap });
        }
    }
    let mut by_tier = BTreeMap::<u32, u32>::new();
    for tx in &block.txs {
        if let Tx::Register { name, .. } = tx {
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
