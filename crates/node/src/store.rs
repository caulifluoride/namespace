//! On-disk storage. Only what can't be recomputed is stored: block bodies
//! and the record of scanned Bitcoin blocks. The name state is rebuilt by
//! replaying the best chain on startup.

use std::path::Path;

use anyhow::{Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use namespace_core::encode::{Decode, Reader};
use namespace_core::{Anchor, Block, BlockHash, Encode, Hash256};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

/// Block hash -> encoded block.
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
/// Bitcoin height -> encoded [`ScanRecord`].
const SCANS: TableDefinition<u32, &[u8]> = TableDefinition::new("scans");

/// What the follower learned from one Bitcoin block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanRecord {
    pub btc_hash: bitcoin::BlockHash,
    /// The covenant outpoint after this block.
    pub next: OutPoint,
    pub anchor: Option<Anchor>,
}

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        let tx = db.begin_write()?;
        tx.open_table(BLOCKS)?;
        tx.open_table(SCANS)?;
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn put_block(&self, block: &Block) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(BLOCKS)?
            .insert(&block.hash().0[..], &block.to_bytes()[..])?;
        tx.commit()?;
        Ok(())
    }

    pub fn block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(BLOCKS)?;
        let Some(bytes) = table.get(&hash.0[..])? else {
            return Ok(None);
        };
        Ok(Some(Block::from_bytes(bytes.value())?))
    }

    pub fn all_blocks(&self) -> Result<Vec<Block>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(BLOCKS)?;
        table
            .iter()?
            .map(|entry| Ok(Block::from_bytes(entry?.1.value())?))
            .collect()
    }

    pub fn put_scan(&self, height: u32, record: &ScanRecord) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(SCANS)?
            .insert(height, &encode_scan(record)[..])?;
        tx.commit()?;
        Ok(())
    }

    /// Forgets scans at and above `height`, after a Bitcoin reorg.
    pub fn truncate_scans(&self, height: u32) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(SCANS)?.retain_in(height.., |_, _| false)?;
        tx.commit()?;
        Ok(())
    }

    pub fn all_scans(&self) -> Result<Vec<(u32, ScanRecord)>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SCANS)?;
        table
            .iter()?
            .map(|entry| {
                let (k, v) = entry?;
                let height = k.value();
                Ok((height, decode_scan(height, v.value())?))
            })
            .collect()
    }
}

fn encode_scan(r: &ScanRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 36 + 1 + 64);
    out.extend_from_slice(r.btc_hash.as_byte_array());
    out.extend_from_slice(r.next.txid.as_byte_array());
    out.extend_from_slice(&r.next.vout.to_le_bytes());
    match &r.anchor {
        None => out.push(0),
        Some(a) => {
            out.push(1);
            out.extend_from_slice(a.txid.as_byte_array());
            a.block_hash.encode(&mut out);
        }
    }
    out
}

fn decode_scan(height: u32, bytes: &[u8]) -> Result<ScanRecord> {
    let mut r = Reader::new(bytes);
    let btc_hash = bitcoin::BlockHash::from_byte_array(r.array()?);
    let next = OutPoint::new(Txid::from_byte_array(r.array()?), r.u32()?);
    let anchor = match r.u8()? {
        0 => None,
        _ => Some(Anchor {
            btc_height: height,
            btc_block: btc_hash,
            txid: Txid::from_byte_array(r.array()?),
            block_hash: Hash256::decode(&mut r)?,
        }),
    };
    r.finish()?;
    Ok(ScanRecord {
        btc_hash,
        next,
        anchor,
    })
}
