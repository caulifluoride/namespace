//! Fork choice over anchored blocks.
//!
//! Bitcoin orders the anchors, but each anchored header picks its own
//! parent, so the anchored blocks form a tree rooted at genesis. A block is
//! *eligible* when:
//!
//! - it is anchored, and its first anchor comes after its parent's,
//! - its body is known and its header matches its parent's height,
//! - it hasn't been found invalid, and
//! - its parent is genesis or eligible.
//!
//! The canonical tip is the highest eligible block, with ties going to the
//! earliest anchor.
//!
//! A block whose body is withheld is not eligible, and neither is anything
//! built on it, so the chain stalls there. Builders get past it by anchoring
//! a block on its parent, which orphans the withheld block once that branch
//! is longer. If the body turns up later, fork choice runs again with it.
//!
//! Validity (signatures, caps, name rules) depends on the state, which this
//! module doesn't track. The node applies the chosen chain, marks the first
//! block that fails with [`ChainIndex::mark_invalid`], and asks again.

use std::collections::{HashMap, HashSet};

use crate::anchor::Anchor;
use crate::block::{Block, BlockHash, BlockHeader};

#[derive(Default, Debug)]
pub struct ChainIndex {
    /// In Bitcoin order.
    anchors: Vec<Anchor>,
    /// Headers of blocks whose bodies we have.
    headers: HashMap<BlockHash, BlockHeader>,
    invalid: HashSet<BlockHash>,
}

impl ChainIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// Appends an anchor found in a new Bitcoin block.
    pub fn push_anchor(&mut self, anchor: Anchor) {
        debug_assert!(
            self.anchors
                .last()
                .is_none_or(|a| a.btc_height < anchor.btc_height)
        );
        self.anchors.push(anchor);
    }

    /// Drops anchors from Bitcoin blocks at or above `btc_height`, after a
    /// Bitcoin reorg.
    pub fn truncate_anchors(&mut self, btc_height: u32) {
        self.anchors.retain(|a| a.btc_height < btc_height);
    }

    /// Records that we have the body of a block.
    pub fn add_header(&mut self, header: BlockHeader) {
        self.headers.insert(header.hash(), header);
    }

    pub fn has_body(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash)
    }

    pub fn mark_invalid(&mut self, hash: BlockHash) {
        self.invalid.insert(hash);
    }

    /// Anchored blocks whose bodies we still need.
    pub fn missing_bodies(&self) -> Vec<BlockHash> {
        let mut seen = HashSet::new();
        self.anchors
            .iter()
            .map(|a| a.block_hash)
            .filter(|h| !self.headers.contains_key(h) && seen.insert(*h))
            .collect()
    }

    /// The canonical chain, from the first block after genesis to the tip.
    pub fn best_chain(&self) -> Vec<BlockHash> {
        let genesis = Block::genesis().hash();
        // Eligible block -> (height, anchor position, parent).
        let mut eligible: HashMap<BlockHash, (u64, usize, BlockHash)> = HashMap::new();
        let mut best: Option<(u64, usize, BlockHash)> = None;

        for (pos, anchor) in self.anchors.iter().enumerate() {
            let hash = anchor.block_hash;
            // Only the first anchor of a hash counts.
            if eligible.contains_key(&hash) || self.invalid.contains(&hash) {
                continue;
            }
            let Some(header) = self.headers.get(&hash) else {
                continue;
            };
            let parent_height = if header.parent == genesis {
                0
            } else {
                // Parents are always anchored earlier, so they've already
                // been visited.
                match eligible.get(&header.parent) {
                    Some(&(h, _, _)) => h,
                    None => continue,
                }
            };
            if header.height != parent_height + 1 {
                continue;
            }
            eligible.insert(hash, (header.height, pos, header.parent));
            // Later anchors only win with a strictly greater height.
            if best.is_none_or(|(h, _, _)| header.height > h) {
                best = Some((header.height, pos, hash));
            }
        }

        let mut chain = Vec::new();
        let mut cursor = best.map(|(_, _, h)| h);
        while let Some(hash) = cursor {
            chain.push(hash);
            let parent = eligible[&hash].2;
            cursor = (parent != genesis).then_some(parent);
        }
        chain.reverse();
        chain
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;
    use bitcoin::hashes::Hash;

    use super::*;
    use crate::hash::Hash256;
    use crate::name::Name;
    use crate::tx::Tx;

    /// Distinct blocks on top of `parent`, made unique by a dummy announcement.
    fn child(parent: &Block, tag: u8) -> Block {
        let announce = Tx::Announce {
            name: Name::new(&format!("n{tag}")).unwrap(),
        };
        Block::new(
            parent.hash(),
            parent.header.height,
            vec![announce],
            Hash256::ZERO,
        )
    }

    fn anchor(btc_height: u32, block: &Block) -> Anchor {
        Anchor {
            btc_height,
            btc_block: bitcoin::BlockHash::all_zeros(),
            txid: Txid::all_zeros(),
            block_hash: block.hash(),
        }
    }

    #[test]
    fn longest_chain_with_known_bodies_wins() {
        let g = Block::genesis();
        let a = child(g, 1);
        let b = child(&a, 2);
        let mut idx = ChainIndex::new();
        idx.push_anchor(anchor(1, &a));
        idx.push_anchor(anchor(2, &b));
        assert!(idx.best_chain().is_empty());
        assert_eq!(idx.missing_bodies(), vec![a.hash(), b.hash()]);

        idx.add_header(a.header);
        assert_eq!(idx.best_chain(), vec![a.hash()]);
        idx.add_header(b.header);
        assert_eq!(idx.best_chain(), vec![a.hash(), b.hash()]);
    }

    #[test]
    fn withheld_block_is_reorged_out() {
        let g = Block::genesis();
        let a = child(g, 1);
        let withheld = child(&a, 2);
        let b1 = child(&a, 3);
        let b2 = child(&b1, 4);
        let mut idx = ChainIndex::new();
        for blk in [&a, &b1, &b2] {
            idx.add_header(blk.header);
        }
        idx.push_anchor(anchor(1, &a));
        idx.push_anchor(anchor(2, &withheld));
        // Stalled at `a` until someone builds around the withheld block.
        assert_eq!(idx.best_chain(), vec![a.hash()]);
        idx.push_anchor(anchor(3, &b1));
        assert_eq!(idx.best_chain(), vec![a.hash(), b1.hash()]);
        idx.push_anchor(anchor(4, &b2));
        assert_eq!(idx.best_chain(), vec![a.hash(), b1.hash(), b2.hash()]);

        // The withheld body appearing late doesn't beat the longer branch.
        idx.add_header(withheld.header);
        assert_eq!(idx.best_chain(), vec![a.hash(), b1.hash(), b2.hash()]);
    }

    #[test]
    fn ties_go_to_earliest_anchor() {
        let g = Block::genesis();
        let a = child(g, 1);
        let b = child(g, 2);
        let mut idx = ChainIndex::new();
        idx.add_header(a.header);
        idx.add_header(b.header);
        idx.push_anchor(anchor(1, &b));
        idx.push_anchor(anchor(2, &a));
        assert_eq!(idx.best_chain(), vec![b.hash()]);
    }

    #[test]
    fn invalid_blocks_and_descendants_are_skipped() {
        let g = Block::genesis();
        let a = child(g, 1);
        let b = child(&a, 2);
        let c = child(g, 3);
        let mut idx = ChainIndex::new();
        for blk in [&a, &b, &c] {
            idx.add_header(blk.header);
        }
        idx.push_anchor(anchor(1, &a));
        idx.push_anchor(anchor(2, &b));
        idx.push_anchor(anchor(3, &c));
        assert_eq!(idx.best_chain(), vec![a.hash(), b.hash()]);
        idx.mark_invalid(a.hash());
        assert_eq!(idx.best_chain(), vec![c.hash()]);
    }

    #[test]
    fn parent_must_be_anchored_first() {
        let g = Block::genesis();
        let a = child(g, 1);
        let b = child(&a, 2);
        let mut idx = ChainIndex::new();
        idx.add_header(a.header);
        idx.add_header(b.header);
        idx.push_anchor(anchor(1, &b));
        idx.push_anchor(anchor(2, &a));
        assert_eq!(idx.best_chain(), vec![a.hash()]);
    }

    #[test]
    fn bitcoin_reorg_drops_anchors() {
        let g = Block::genesis();
        let a = child(g, 1);
        let b = child(&a, 2);
        let mut idx = ChainIndex::new();
        idx.add_header(a.header);
        idx.add_header(b.header);
        idx.push_anchor(anchor(1, &a));
        idx.push_anchor(anchor(2, &b));
        idx.truncate_anchors(2);
        assert_eq!(idx.best_chain(), vec![a.hash()]);
    }
}
