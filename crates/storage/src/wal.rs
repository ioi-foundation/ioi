// Path: crates/storage/src/wal.rs
//! Write-Ahead Log (WAL) for decoupled state persistence.
//!
//! This module allows `commit_block` to return as soon as the state diff is appended
//! to a sequential log file, allowing complex B-tree indexing to happen asynchronously.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
// [FIX] Added BufRead for fill_buf; Removed Seek, SeekFrom
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Mutex;

/// Header for a WAL entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct WalEntryHeader {
    pub height: u64,
    pub root_hash: [u8; 32],
    pub data_len: u64,
    pub crc: u32,
}

/// A diff payload to be persisted.
#[derive(Serialize, Deserialize, Debug)]
pub struct StateDiff {
    /// New nodes to insert.
    pub new_nodes: Vec<([u8; 32], Vec<u8>)>,
    /// Nodes referenced in this block (for refcounting).
    pub touched_nodes: Vec<[u8; 32]>,
}

pub struct WalWriter {
    file: Mutex<BufWriter<File>>,
}

impl WalWriter {
    pub fn new(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn append_block(&self, height: u64, root: [u8; 32], diff: &StateDiff) -> Result<()> {
        let data = bincode::serialize(diff)?;
        let header = WalEntryHeader {
            height,
            root_hash: root,
            data_len: data.len() as u64,
            crc: 0, // Placeholder for CRC32
        };

        let mut writer = self.file.lock().map_err(|_| anyhow!("WAL lock poisoned"))?;

        // Write header + data
        bincode::serialize_into(&mut *writer, &header)?;
        writer.write_all(&data)?;

        // Critical: Flush and Sync to disk
        writer.flush()?;
        writer.get_ref().sync_data()?;

        Ok(())
    }
}

pub struct WalIterator {
    reader: BufReader<File>,
}

impl WalIterator {
    pub fn new(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }
}

impl Iterator for WalIterator {
    type Item = Result<(u64, [u8; 32], StateDiff)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Peek to see if we have data
        // [FIX] fill_buf requires BufRead trait to be in scope
        if self.reader.fill_buf().ok()?.is_empty() {
            return None;
        }

        let header: WalEntryHeader = match bincode::deserialize_from(&mut self.reader) {
            Ok(h) => h,
            Err(e) => return Some(Err(anyhow!("Failed to read WAL header: {}", e))),
        };

        let mut data_buf = vec![0u8; header.data_len as usize];
        if let Err(e) = self.reader.read_exact(&mut data_buf) {
            return Some(Err(anyhow!("Failed to read WAL body: {}", e)));
        }

        let diff: StateDiff = match bincode::deserialize(&data_buf) {
            Ok(d) => d,
            Err(e) => return Some(Err(anyhow!("Failed to deserialize state diff: {}", e))),
        };

        Some(Ok((header.height, header.root_hash, diff)))
    }
}
