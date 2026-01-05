// Path: crates/storage/src/wal.rs
//! Write-Ahead Log (WAL) for decoupled state persistence.
//!
//! This module allows `commit_block` to return as soon as the state diff is appended
//! to a sequential log file, allowing complex B-tree indexing to happen asynchronously.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
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
    path: PathBuf, // Store path to allow rotation
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
            path: path.to_path_buf(),
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

    /// Compacts the WAL by removing entries older than `min_height`.
    /// This is a stop-the-world operation relative to the WAL writer.
    pub fn compact(&self, min_height: u64) -> Result<()> {
        let mut guard = self.file.lock().map_err(|_| anyhow!("WAL lock poisoned"))?;

        // 1. Flush current buffer
        guard.flush()?;

        // 2. Open reader for current WAL
        let mut reader = BufReader::new(File::open(&self.path)?);

        // 3. Create temp file for new WAL
        let tmp_path = self.path.with_extension("wal.tmp");
        let mut tmp_file = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?,
        );

        let mut kept_count = 0;

        // 4. Stream and Filter
        loop {
            // Peek header
            if reader.fill_buf()?.is_empty() {
                break;
            }

            let header: WalEntryHeader = bincode::deserialize_from(&mut reader)?;
            let mut data_buf = vec![0u8; header.data_len as usize];
            reader.read_exact(&mut data_buf)?;

            if header.height >= min_height {
                // Keep this entry
                bincode::serialize_into(&mut tmp_file, &header)?;
                tmp_file.write_all(&data_buf)?;
                kept_count += 1;
            }
        }

        tmp_file.flush()?;
        tmp_file.get_ref().sync_data()?;

        // 5. Atomic Rename
        // We drop the writer guard internal reference before replacing the file
        // However, we hold the Mutex so no one else can write.
        // We need to swap the file handle inside the mutex.

        fs::rename(&tmp_path, &self.path)?;

        // Re-open the new file for the writer
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&self.path)?;

        *guard = BufWriter::new(new_file);

        tracing::info!(target: "storage", "WAL compaction complete. Kept {} entries >= {}", kept_count, min_height);

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
        // fill_buf requires BufRead trait to be in scope
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_wal_write_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let writer = WalWriter::new(&path).unwrap();

        let diff1 = StateDiff {
            new_nodes: vec![([1u8; 32], vec![0xAA])],
            touched_nodes: vec![[1u8; 32]],
        };

        let diff2 = StateDiff {
            new_nodes: vec![([2u8; 32], vec![0xBB])],
            touched_nodes: vec![[2u8; 32]],
        };

        writer.append_block(10, [0xA0; 32], &diff1).unwrap();
        writer.append_block(11, [0xA1; 32], &diff2).unwrap();

        let mut iter = WalIterator::new(&path).unwrap();

        let (h1, r1, d1) = iter.next().unwrap().unwrap();
        assert_eq!(h1, 10);
        assert_eq!(r1, [0xA0; 32]);
        assert_eq!(d1.new_nodes[0].1, vec![0xAA]);

        let (h2, r2, d2) = iter.next().unwrap().unwrap();
        assert_eq!(h2, 11);
        assert_eq!(r2, [0xA1; 32]);
        assert_eq!(d2.new_nodes[0].1, vec![0xBB]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_wal_compaction() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("compact.wal");
        let writer = WalWriter::new(&path).unwrap();

        // Write heights 10, 11, 12, 13
        for h in 10..14 {
            let diff = StateDiff {
                new_nodes: vec![],
                touched_nodes: vec![],
            };
            writer.append_block(h, [0u8; 32], &diff).unwrap();
        }

        // Check pre-compaction
        {
            let iter = WalIterator::new(&path).unwrap();
            assert_eq!(iter.count(), 4);
        }

        // Compact: Keep >= 12
        writer.compact(12).unwrap();

        // Check post-compaction
        {
            let mut iter = WalIterator::new(&path).unwrap();
            let (h1, _, _) = iter.next().unwrap().unwrap();
            assert_eq!(h1, 12);
            let (h2, _, _) = iter.next().unwrap().unwrap();
            assert_eq!(h2, 13);
            assert!(iter.next().is_none());
        }

        // Ensure we can still write after compaction
        let diff = StateDiff {
            new_nodes: vec![],
            touched_nodes: vec![],
        };
        writer.append_block(14, [0u8; 32], &diff).unwrap();

        {
            let iter = WalIterator::new(&path).unwrap();
            assert_eq!(iter.count(), 3); // 12, 13, 14
        }
    }
}
