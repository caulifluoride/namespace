//! State transition tests.

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, VerifyOnly};

use crate::block::Block;
use crate::encode::{Decode, Encode};
use crate::hash::Hash256;
use crate::name::Name;
use crate::params::Params;
use crate::state::{BlockBuilder, BlockError, NameProof, State, TxError, Undo};
use crate::tx::{OwnerKey, SignedOp, Tx, commitment_hash, sighash, sign};

struct Harness {
    state: State,
    params: Params,
    secp: Secp256k1<VerifyOnly>,
    undos: Vec<Undo>,
}

fn keypair(n: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::signing_only(),
        &SecretKey::from_slice(&[n; 32]).unwrap(),
    )
}

fn owner(kp: &Keypair) -> OwnerKey {
    kp.x_only_public_key().0
}

fn name(s: &str) -> Name {
    Name::new(s).unwrap()
}

impl Harness {
    fn new() -> Self {
        Self {
            state: State::new(),
            params: Params::regtest(),
            secp: Secp256k1::verification_only(),
            undos: Vec::new(),
        }
    }

    /// The next block with `txs`. If they're invalid there's no state root
    /// to compute, so it's left zero and applying the block reports why.
    fn block(&self, txs: Vec<Tx>) -> Block {
        self.state
            .next_block(txs.clone(), &self.params, &self.secp)
            .unwrap_or_else(|_| {
                Block::new(self.state.tip(), self.state.height(), txs, Hash256::ZERO)
            })
    }

    fn apply(&mut self, txs: Vec<Tx>) -> Result<(), BlockError> {
        let block = self.block(txs);
        let undo = self.state.apply_block(&block, &self.params, &self.secp)?;
        self.undos.push(undo);
        Ok(())
    }

    fn empty_blocks(&mut self, n: u64) {
        for _ in 0..n {
            self.apply(vec![]).unwrap();
        }
    }

    /// Commits, waits out the minimum age, and registers.
    fn register(&mut self, n: &str, kp: &Keypair) {
        let salt = Hash256([7; 32]);
        let commitment = commitment_hash(&name(n), &owner(kp), &salt);
        self.apply(vec![Tx::Commit { commitment }]).unwrap();
        self.empty_blocks(self.params.min_commit_age - 1);
        self.apply(vec![Tx::Register {
            name: name(n),
            owner: owner(kp),
            salt,
        }])
        .unwrap();
    }

    fn renew_tx(&self, n: &str, kp: &Keypair) -> Tx {
        let rec = self.state.lookup(&name(n)).unwrap();
        let digest = sighash(&name(n), rec.registered_at, rec.seq, SignedOp::Renew);
        Tx::Renew {
            name: name(n),
            seq: rec.seq,
            sig: sign(kp, &digest),
        }
    }

    fn transfer_tx(&self, n: &str, kp: &Keypair, to: OwnerKey) -> Tx {
        let rec = self.state.lookup(&name(n)).unwrap();
        let op = SignedOp::Transfer { new_owner: &to };
        let digest = sighash(&name(n), rec.registered_at, rec.seq, op);
        Tx::Transfer {
            name: name(n),
            new_owner: to,
            seq: rec.seq,
            sig: sign(kp, &digest),
        }
    }
}

fn tx_error(r: Result<(), BlockError>) -> TxError {
    match r {
        Err(BlockError::Tx { error, .. }) => error,
        other => panic!("expected tx error, got {other:?}"),
    }
}

#[test]
fn commit_then_register() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    let rec = h.state.lookup(&name("alice")).unwrap();
    assert_eq!(rec.owner, owner(&alice));
    assert_eq!(rec.seq, 0);
}

#[test]
fn reveal_in_same_block_as_commit_is_rejected() {
    let mut h = Harness::new();
    let alice = keypair(1);
    let salt = Hash256([7; 32]);
    let commitment = commitment_hash(&name("alice"), &owner(&alice), &salt);
    let r = h.apply(vec![
        Tx::Commit { commitment },
        Tx::Register {
            name: name("alice"),
            owner: owner(&alice),
            salt,
        },
    ]);
    assert_eq!(tx_error(r), TxError::CommitmentTooRecent(2));
}

#[test]
fn register_without_commit_or_with_wrong_salt() {
    let mut h = Harness::new();
    let alice = keypair(1);
    let commitment = commitment_hash(&name("alice"), &owner(&alice), &Hash256([7; 32]));
    h.apply(vec![Tx::Commit { commitment }]).unwrap();
    let r = h.apply(vec![Tx::Register {
        name: name("alice"),
        owner: owner(&alice),
        salt: Hash256([8; 32]),
    }]);
    assert_eq!(tx_error(r), TxError::NoCommitment);
}

#[test]
fn taken_name_cannot_be_registered_until_expiry() {
    let mut h = Harness::new();
    let (alice, bob) = (keypair(1), keypair(2));
    h.register("alice", &alice);

    let salt = Hash256([9; 32]);
    let commitment = commitment_hash(&name("alice"), &owner(&bob), &salt);
    h.apply(vec![Tx::Commit { commitment }]).unwrap();
    let steal = Tx::Register {
        name: name("alice"),
        owner: owner(&bob),
        salt,
    };
    assert_eq!(tx_error(h.apply(vec![steal.clone()])), TxError::NameTaken);

    // Let alice's registration lapse. Bob's commitment would have expired by
    // then, so he commits again.
    let expires = h.state.lookup(&name("alice")).unwrap().expires_at;
    h.empty_blocks(expires - h.state.height() - 1);
    assert!(h.state.lookup(&name("alice")).is_some());
    h.empty_blocks(1);
    assert!(h.state.lookup(&name("alice")).is_none());
    assert_eq!(h.state.commitment_height(&commitment), None);

    h.register("alice", &bob);
    assert_eq!(h.state.lookup(&name("alice")).unwrap().owner, owner(&bob));
}

#[test]
fn commitments_expire() {
    let mut h = Harness::new();
    let alice = keypair(1);
    let salt = Hash256([7; 32]);
    let commitment = commitment_hash(&name("alice"), &owner(&alice), &salt);
    h.apply(vec![Tx::Commit { commitment }]).unwrap();
    // Revealable up to height 1 + max_commit_age.
    h.empty_blocks(h.params.max_commit_age);
    assert_eq!(h.state.commitment_height(&commitment), Some(1));
    h.empty_blocks(1);
    assert_eq!(h.state.commitment_height(&commitment), None);
}

#[test]
fn duplicate_commitment_rejected() {
    let mut h = Harness::new();
    let commitment = Hash256([1; 32]);
    h.apply(vec![Tx::Commit { commitment }]).unwrap();
    assert_eq!(
        tx_error(h.apply(vec![Tx::Commit { commitment }])),
        TxError::DuplicateCommitment
    );
}

#[test]
fn renew_extends_expiry_and_bumps_seq() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    h.empty_blocks(5);
    let tx = h.renew_tx("alice", &alice);
    h.apply(vec![tx.clone()]).unwrap();
    let rec = h.state.lookup(&name("alice")).unwrap();
    assert_eq!(rec.expires_at, h.state.height() + h.params.expiry_period);
    assert_eq!(rec.seq, 1);

    // Replaying the same renewal fails on seq.
    assert_eq!(
        tx_error(h.apply(vec![tx])),
        TxError::WrongSeq {
            got: 0,
            expected: 1
        }
    );
}

#[test]
fn transfer_moves_ownership() {
    let mut h = Harness::new();
    let (alice, bob) = (keypair(1), keypair(2));
    h.register("alice", &alice);

    // Bob can't sign for alice's name.
    let forged = h.transfer_tx("alice", &bob, owner(&bob));
    assert_eq!(tx_error(h.apply(vec![forged])), TxError::BadSignature);

    let tx = h.transfer_tx("alice", &alice, owner(&bob));
    h.apply(vec![tx]).unwrap();
    assert_eq!(h.state.lookup(&name("alice")).unwrap().owner, owner(&bob));

    // Now only bob can renew.
    let tx = h.renew_tx("alice", &alice);
    assert_eq!(tx_error(h.apply(vec![tx])), TxError::BadSignature);
    let tx = h.renew_tx("alice", &bob);
    h.apply(vec![tx]).unwrap();
}

#[test]
fn signatures_do_not_survive_reregistration() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    // A renewal alice signed but never broadcast.
    let old = h.renew_tx("alice", &alice);

    let expires = h.state.lookup(&name("alice")).unwrap().expires_at;
    h.empty_blocks(expires - h.state.height());
    h.register("alice", &alice);
    // Same owner and seq 0, but a different registration.
    assert_eq!(tx_error(h.apply(vec![old])), TxError::BadSignature);
}

#[test]
fn registration_cap_enforced() {
    let mut h = Harness::new();
    let kp = keypair(1);
    let salt = Hash256([7; 32]);
    let names = ["a", "b", "c"];
    let commits = names
        .iter()
        .map(|n| Tx::Commit {
            commitment: commitment_hash(&name(n), &owner(&kp), &salt),
        })
        .collect();
    h.apply(commits).unwrap();
    let regs: Vec<_> = names
        .iter()
        .map(|n| Tx::Register {
            name: name(n),
            owner: owner(&kp),
            salt,
        })
        .collect();
    // Height 2 allows 2 registrations.
    assert_eq!(
        h.apply(regs.clone()),
        Err(BlockError::Limit {
            kind: "registration",
            count: 3,
            cap: 2
        })
    );
    h.apply(regs[..2].to_vec()).unwrap();
}

#[test]
fn failed_block_leaves_state_untouched() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    let before = format!("{:?}", h.state);
    let tx = h.renew_tx("alice", &alice);
    // The renewal applies, then the duplicate fails and everything rolls back.
    let r = h.apply(vec![tx.clone(), tx]);
    assert!(r.is_err());
    assert_eq!(format!("{:?}", h.state), before);
}

#[test]
fn revert_restores_previous_state() {
    let mut h = Harness::new();
    let (alice, bob) = (keypair(1), keypair(2));
    h.register("alice", &alice);
    let snapshot = format!("{:?}", h.state);
    let (tip, height) = (h.state.tip(), h.state.height());
    let applied = h.undos.len();

    let tx = h.transfer_tx("alice", &alice, owner(&bob));
    h.apply(vec![tx]).unwrap();
    h.register("bob", &bob);
    for undo in h.undos.drain(applied..).rev() {
        h.state.revert(undo);
    }
    assert_eq!((h.state.tip(), h.state.height()), (tip, height));
    assert_eq!(format!("{:?}", h.state), snapshot);
}

#[test]
fn builder_skips_invalid_and_overflowing_txs() {
    let mut h = Harness::new();
    let kp = keypair(1);
    let salt = Hash256([7; 32]);
    let commits: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|n| Tx::Commit {
            commitment: commitment_hash(&name(n), &owner(&kp), &salt),
        })
        .collect();
    h.apply(commits).unwrap();

    let mut builder = BlockBuilder::new(&h.state, &h.params, &h.secp);
    for n in ["a", "a", "b", "c"] {
        let _ = builder.try_add(Tx::Register {
            name: name(n),
            owner: owner(&kp),
            salt,
        });
    }
    let block = builder.finish();
    // The second "a" has no commitment left; "c" exceeds the cap of 2.
    assert_eq!(block.txs.len(), 2);
    h.state.apply_block(&block, &h.params, &h.secp).unwrap();
    assert!(h.state.lookup(&name("a")).is_some());
    assert!(h.state.lookup(&name("b")).is_some());
    assert!(h.state.lookup(&name("c")).is_none());
}

#[test]
fn encoding_roundtrip() {
    let alice = keypair(1);
    let mut h = Harness::new();
    h.register("alice", &alice);
    let txs = vec![
        Tx::Commit {
            commitment: Hash256([3; 32]),
        },
        Tx::Register {
            name: name("x"),
            owner: owner(&alice),
            salt: Hash256([4; 32]),
        },
        h.renew_tx("alice", &alice),
        h.transfer_tx("alice", &alice, owner(&keypair(2))),
    ];
    let block = h.block(txs);
    let bytes = block.to_bytes();
    assert_eq!(Block::from_bytes(&bytes).unwrap(), block);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Block::from_bytes(&trailing).is_err());
    assert!(Block::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn wrong_state_root_rejected() {
    let mut h = Harness::new();
    let mut block = h.block(vec![Tx::Commit {
        commitment: Hash256([1; 32]),
    }]);
    let before = format!("{:?}", h.state);
    block.header.state_root = Hash256::ZERO;
    assert_eq!(
        h.state.apply_block(&block, &h.params, &h.secp).unwrap_err(),
        BlockError::StateRoot
    );
    assert_eq!(format!("{:?}", h.state), before);
}

#[test]
fn state_root_follows_reverts() {
    let mut h = Harness::new();
    let (alice, bob) = (keypair(1), keypair(2));
    h.register("alice", &alice);
    let root = h.state.state_root();
    let applied = h.undos.len();
    let tx = h.transfer_tx("alice", &alice, owner(&bob));
    h.apply(vec![tx]).unwrap();
    assert_ne!(h.state.state_root(), root);
    for undo in h.undos.drain(applied..).rev() {
        h.state.revert(undo);
    }
    assert_eq!(h.state.state_root(), root);
}

#[test]
fn name_proofs() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    h.apply(vec![Tx::Commit {
        commitment: Hash256([1; 32]),
    }])
    .unwrap();
    let root = h.state.state_root();

    let proof = h.state.prove_name(&name("alice"));
    let rec = proof.verify(&name("alice"), &root).unwrap().unwrap();
    assert_eq!(rec.owner, owner(&alice));
    // The same proof says nothing about another name.
    assert!(proof.verify(&name("bob"), &root).is_err());

    let absent = h.state.prove_name(&name("bob"));
    assert_eq!(absent.verify(&name("bob"), &root), Ok(None));

    // Claiming a different record, or no record, fails.
    let mut forged = proof.clone();
    forged.record.as_mut().unwrap().owner = owner(&keypair(2));
    assert!(forged.verify(&name("alice"), &root).is_err());
    let hidden = NameProof {
        record: None,
        ..proof
    };
    assert!(hidden.verify(&name("alice"), &root).is_err());
}

#[test]
fn snapshot_roundtrip() {
    let mut h = Harness::new();
    let alice = keypair(1);
    h.register("alice", &alice);
    h.apply(vec![Tx::Commit {
        commitment: Hash256([1; 32]),
    }])
    .unwrap();
    let bytes = h.state.to_bytes();
    let restored = State::from_bytes(&bytes).unwrap();
    assert_eq!(format!("{restored:?}"), format!("{:?}", h.state));
    assert_eq!(restored.state_root(), h.state.state_root());
    assert_eq!(restored.tip(), h.state.tip());

    // It carries on like the original.
    h.state = restored;
    h.register("bob", &keypair(2));
    assert!(h.state.lookup(&name("bob")).is_some());
}
