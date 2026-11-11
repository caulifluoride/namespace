//! Follows Bitcoin: scans new blocks for covenant spends and handles reorgs.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use namespace_core::anchor::scan_block;
use tracing::warn;

use crate::bitcoin_source::BitcoinSource;
use crate::node::Node;
use crate::store::ScanRecord;

const POLL_INTERVAL: Duration = Duration::from_secs(10);

pub async fn run<S: BitcoinSource>(node: Arc<Node>, source: S) {
    loop {
        if let Err(e) = sync(&node, &source).await {
            warn!(error = %e, "bitcoin sync failed");
        }
        node.fetch_missing().await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn sync<S: BitcoinSource>(node: &Arc<Node>, source: &S) -> Result<()> {
    rewind_to_common_ancestor(node, source).await?;
    let tip = source.tip_height().await?;
    loop {
        let (height, current, config) = {
            let chain = node.chain();
            (
                chain.next_scan_height(),
                chain.covenant_outpoint(),
                chain.covenant().clone(),
            )
        };
        if height > tip {
            return Ok(());
        }
        let hash = source.block_hash(height).await?;
        let block = source.block(hash).await?;
        if height > config.start_height {
            let prev = node.chain().scan_hash(height - 1);
            if prev.is_some_and(|p| p != block.header.prev_blockhash) {
                // The chain moved under us mid-sync; start over.
                return Ok(());
            }
        }
        let result = scan_block(&config, current, height, &block);
        let record = ScanRecord {
            btc_hash: hash,
            next: result.next,
            anchor: result.anchor,
        };
        node.chain().add_scan(&node.store, height, record)?;
    }
}

/// Walks back from our last scanned block until it matches Bitcoin's best
/// chain, and drops everything after.
async fn rewind_to_common_ancestor<S: BitcoinSource>(node: &Arc<Node>, source: &S) -> Result<()> {
    let Some((mut height, _)) = node.chain().last_scan().map(|(h, r)| (h, r.btc_hash)) else {
        return Ok(());
    };
    let tip = source.tip_height().await?;
    let mut first_bad = None;
    loop {
        let Some(ours) = node.chain().scan_hash(height) else {
            break;
        };
        if height <= tip && source.block_hash(height).await? == ours {
            break;
        }
        first_bad = Some(height);
        let Some(h) = height.checked_sub(1) else {
            break;
        };
        height = h;
    }
    if let Some(h) = first_bad {
        node.chain().rollback_scans(&node.store, h)?;
    }
    Ok(())
}
