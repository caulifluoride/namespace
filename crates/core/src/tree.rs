//! The authenticated map behind a block's state root.
//!
//! A compact sparse Merkle tree over 256-bit keys. Conceptually every key is
//! a leaf at depth 256, but a subtree holding a single leaf hashes as that
//! leaf and an empty subtree hashes as a constant, so a path is only as long
//! as it takes to separate a key from its neighbours (about `log2(n)`).
//! The root depends only on the set of `(key, value)` pairs, not on the order
//! they were inserted in.
//!
//! Internal node hashes are cached and invalidated along a key's path when
//! it changes, so updating the root after a block costs `O(changes * log n)`.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::hash::Hash256;

/// Longer paths can't occur: two distinct keys differ in one of 256 bits.
pub const MAX_DEPTH: usize = 256;

#[derive(Clone, Default)]
pub struct Tree {
    leaves: BTreeMap<Hash256, Hash256>,
    /// `(depth, prefix)` -> hash, for subtrees holding at least two leaves.
    cache: RefCell<HashMap<(u16, Hash256), Hash256>>,
}

/// Shows the contents only: the cache depends on access history.
impl std::fmt::Debug for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(&self.leaves).finish()
    }
}

/// Proves what a tree holds at one key: either a value, or nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Sibling hashes from the root down.
    pub siblings: Vec<Hash256>,
    /// The single leaf `(key, value)` in the subtree the path ends at, or
    /// `None` if that subtree is empty.
    pub leaf: Option<(Hash256, Hash256)>,
}

pub fn empty_root() -> Hash256 {
    Hash256::tagged("namespace/state-empty", &[])
}

fn leaf_hash(key: &Hash256, value: &Hash256) -> Hash256 {
    let mut buf = [0; 64];
    buf[..32].copy_from_slice(&key.0);
    buf[32..].copy_from_slice(&value.0);
    Hash256::tagged("namespace/state-leaf", &buf)
}

fn node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = [0; 64];
    buf[..32].copy_from_slice(&left.0);
    buf[32..].copy_from_slice(&right.0);
    Hash256::tagged("namespace/state-node", &buf)
}

fn bit(key: &Hash256, depth: usize) -> bool {
    key.0[depth / 8] & (0x80 >> (depth % 8)) != 0
}

fn set_bit(key: &mut Hash256, depth: usize) {
    key.0[depth / 8] |= 0x80 >> (depth % 8);
}

/// `key` with every bit from `depth` on cleared (`fill = false`) or set.
fn prefix(key: &Hash256, depth: usize, fill: bool) -> Hash256 {
    let mut out = *key;
    for (i, byte) in out.0.iter_mut().enumerate() {
        let keep = depth.saturating_sub(i * 8).min(8);
        let mask = (0xff_u16 << (8 - keep)) as u8;
        *byte = if fill { *byte | !mask } else { *byte & mask };
    }
    out
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, key: &Hash256) -> Option<&Hash256> {
        self.leaves.get(key)
    }

    pub fn insert(&mut self, key: Hash256, value: Hash256) {
        if self.leaves.insert(key, value) != Some(value) {
            self.invalidate(&key);
        }
    }

    pub fn remove(&mut self, key: &Hash256) {
        if self.leaves.remove(key).is_some() {
            self.invalidate(key);
        }
    }

    fn invalidate(&mut self, key: &Hash256) {
        let cache = self.cache.get_mut();
        for depth in 0..MAX_DEPTH {
            cache.remove(&(depth as u16, prefix(key, depth, false)));
        }
    }

    pub fn root(&self) -> Hash256 {
        self.node(0, Hash256::ZERO)
    }

    /// The leaves under `(depth, prefix)`, up to two.
    fn subtree(&self, depth: usize, lo: Hash256) -> (usize, Option<(&Hash256, &Hash256)>) {
        let hi = prefix(&lo, depth, true);
        let mut it = self.leaves.range(lo..=hi);
        let first = it.next();
        let count = match first {
            None => 0,
            Some(_) if it.next().is_none() => 1,
            Some(_) => 2,
        };
        (count, first)
    }

    fn node(&self, depth: usize, lo: Hash256) -> Hash256 {
        match self.subtree(depth, lo) {
            (0, _) => empty_root(),
            (1, Some((k, v))) => leaf_hash(k, v),
            _ => {
                if let Some(h) = self.cache.borrow().get(&(depth as u16, lo)) {
                    return *h;
                }
                let mut right = lo;
                set_bit(&mut right, depth);
                let h = node_hash(&self.node(depth + 1, lo), &self.node(depth + 1, right));
                self.cache.borrow_mut().insert((depth as u16, lo), h);
                h
            }
        }
    }

    pub fn prove(&self, key: &Hash256) -> Proof {
        let mut siblings = Vec::new();
        let mut depth = 0;
        let mut lo = Hash256::ZERO;
        loop {
            match self.subtree(depth, lo) {
                (0, _) => {
                    return Proof {
                        siblings,
                        leaf: None,
                    };
                }
                (1, Some((k, v))) => {
                    return Proof {
                        siblings,
                        leaf: Some((*k, *v)),
                    };
                }
                _ => {
                    let mut right = lo;
                    set_bit(&mut right, depth);
                    if bit(key, depth) {
                        siblings.push(self.node(depth + 1, lo));
                        lo = right;
                    } else {
                        siblings.push(self.node(depth + 1, right));
                    }
                    depth += 1;
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid state proof")]
pub struct InvalidProof;

impl Proof {
    /// Checks the proof against `root` and returns the value at `key`, or
    /// `None` if the tree has nothing there. `Err` means the proof is invalid.
    pub fn verify(&self, root: &Hash256, key: &Hash256) -> Result<Option<Hash256>, InvalidProof> {
        let depth = self.siblings.len();
        if depth >= MAX_DEPTH {
            return Err(InvalidProof);
        }
        let mut h = match &self.leaf {
            None => empty_root(),
            Some((k, v)) => {
                // The leaf must sit in the subtree the path leads to.
                if prefix(k, depth, false) != prefix(key, depth, false) {
                    return Err(InvalidProof);
                }
                leaf_hash(k, v)
            }
        };
        for (d, sibling) in self.siblings.iter().enumerate().rev() {
            h = if bit(key, d) {
                node_hash(sibling, &h)
            } else {
                node_hash(&h, sibling)
            };
        }
        if h != *root {
            return Err(InvalidProof);
        }
        Ok(self.leaf.filter(|(k, _)| k == key).map(|(_, v)| v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> Hash256 {
        Hash256::tagged("test", &n.to_le_bytes())
    }

    /// The root computed with no cache, straight from the definition.
    fn reference_root(leaves: &BTreeMap<Hash256, Hash256>) -> Hash256 {
        fn go(leaves: &[(Hash256, Hash256)], depth: usize) -> Hash256 {
            match leaves {
                [] => empty_root(),
                [(k, v)] => leaf_hash(k, v),
                _ => {
                    let split = leaves.partition_point(|(k, _)| !bit(k, depth));
                    node_hash(
                        &go(&leaves[..split], depth + 1),
                        &go(&leaves[split..], depth + 1),
                    )
                }
            }
        }
        let leaves: Vec<_> = leaves.iter().map(|(k, v)| (*k, *v)).collect();
        go(&leaves, 0)
    }

    #[test]
    fn prefix_masks_bits() {
        let k = Hash256([0xff; 32]);
        assert_eq!(prefix(&k, 0, false), Hash256::ZERO);
        assert_eq!(prefix(&k, 3, false).0[0], 0b1110_0000);
        assert_eq!(prefix(&k, 3, false).0[1], 0);
        assert_eq!(prefix(&Hash256::ZERO, 9, true).0[1], 0b0111_1111);
        assert_eq!(prefix(&k, 256, false), k);
    }

    #[test]
    fn root_matches_reference_through_updates() {
        let mut tree = Tree::new();
        let mut model = BTreeMap::new();
        assert_eq!(tree.root(), empty_root());
        for i in 0..200 {
            tree.insert(h(i), h(i + 1000));
            model.insert(h(i), h(i + 1000));
            if i % 17 == 0 {
                assert_eq!(tree.root(), reference_root(&model));
            }
        }
        for i in (0..200).step_by(3) {
            tree.remove(&h(i));
            model.remove(&h(i));
        }
        tree.insert(h(1), h(5));
        model.insert(h(1), h(5));
        assert_eq!(tree.root(), reference_root(&model));

        // Insertion order doesn't matter.
        let mut fresh = Tree::new();
        for (k, v) in model.iter().rev() {
            fresh.insert(*k, *v);
        }
        assert_eq!(fresh.root(), tree.root());
    }

    #[test]
    fn proofs_of_presence_and_absence() {
        let mut tree = Tree::new();
        let empty = tree.prove(&h(1));
        assert_eq!(empty.verify(&tree.root(), &h(1)), Ok(None));

        for i in 0..50 {
            tree.insert(h(i), h(i + 1000));
        }
        let root = tree.root();
        for i in 0..50 {
            assert_eq!(
                tree.prove(&h(i)).verify(&root, &h(i)),
                Ok(Some(h(i + 1000)))
            );
        }
        for i in 50..80 {
            assert_eq!(tree.prove(&h(i)).verify(&root, &h(i)), Ok(None));
        }

        // A proof for one key doesn't prove anything about another.
        assert!(tree.prove(&h(3)).verify(&root, &h(4)).is_err());

        // Tampering is caught.
        let mut bad = tree.prove(&h(3));
        bad.leaf = Some((h(3), h(0)));
        assert!(bad.verify(&root, &h(3)).is_err());
        let mut bad = tree.prove(&h(3));
        bad.siblings.pop();
        assert!(bad.verify(&root, &h(3)).is_err());
        assert!(tree.prove(&h(3)).verify(&h(9), &h(3)).is_err());
    }
}
