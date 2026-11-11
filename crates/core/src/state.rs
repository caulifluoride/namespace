use std::collections::{BTreeMap, BTreeSet, HashMap};

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::block::{Block, BlockHash, tx_root};
use crate::hash::Hash256;
use crate::name::Name;
use crate::params::Params;
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
    #[error("{kind} limit exceeded: {count} > {cap}")]
    Limit {
        kind: &'static str,
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
        Ok(undo)
    }

    /// Reverts the most recently applied block. `undo` must be the value its
    /// `apply_block` returned.
    pub fn revert(&mut self, undo: Undo) {
        for entry in undo.entries.into_iter().rev() {
            match entry {
                UndoEntry::Name(name, Some(record)) => {
                    self.names.insert(name, record);
                }
                UndoEntry::Name(name, None) => {
                    self.names.remove(&name);
                }
                UndoEntry::CommitmentAdded(c, at) => {
                    self.commitments.remove(&c);
                    self.commitments_by_height.remove(&(at, c));
                }
                UndoEntry::CommitmentRemoved(c, at) => {
                    self.commitments.insert(c, at);
                    self.commitments_by_height.insert((at, c));
                }
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
            self.commitments_by_height.remove(&(at, c));
            self.commitments.remove(&c);
            undo.entries.push(UndoEntry::CommitmentRemoved(c, at));
        }
    }

    fn set_name(&mut self, name: &Name, record: NameRecord, undo: &mut Undo) {
        let prev = self.names.insert(name.clone(), record);
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
                self.commitments.insert(*commitment, height);
                self.commitments_by_height.insert((height, *commitment));
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
                self.commitments.remove(&commitment);
                self.commitments_by_height.remove(&(at, commitment));
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
    registrations: u32,
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
            registrations: 0,
            commits: 0,
        }
    }

    pub fn try_add(&mut self, tx: Tx) -> Result<(), AddTxError> {
        let height = self.state.height;
        let full = match tx {
            _ if self.txs.len() as u32 >= self.params.max_txs_per_block => true,
            Tx::Register { .. } => self.registrations >= self.params.registration_cap(height),
            Tx::Commit { .. } => self.commits >= self.params.commit_cap(height),
            _ => false,
        };
        if full {
            return Err(AddTxError::Full);
        }
        self.state
            .apply_tx(&tx, height, self.params, self.secp, &mut self.undo)?;
        match tx {
            Tx::Register { .. } => self.registrations += 1,
            Tx::Commit { .. } => self.commits += 1,
            _ => {}
        }
        self.txs.push(tx);
        Ok(())
    }

    pub fn finish(self) -> Block {
        Block::new(self.undo.prev_tip, self.state.height - 1, self.txs)
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
            "registration",
            count(|t| matches!(t, Tx::Register { .. })),
            params.registration_cap(height),
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
    Ok(())
}
