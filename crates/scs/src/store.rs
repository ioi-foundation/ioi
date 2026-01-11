// Path: crates/scs/src/store.rs

//! The Sovereign Context Store (SCS) implementation.
//!
//! This module manages the lifecycle of the `.scs` file, including:
//! - Creating and opening files.
//! - Appending new frames.
//! - Memory-mapping for zero-copy access.
//! - Managing the Table of Contents (TOC).

use crate::format::{Frame, FrameId, FrameType, ScsHeader, Toc, VectorIndexManifest, HEADER_SIZE};
use crate::index::VectorIndex;
use anyhow::{anyhow, Result};
use fs2::FileExt;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{AccountId, ChainId};
use memmap2::Mmap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap; // [NEW] Import HashMap

/// Configuration for opening or creating a store.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// The Chain ID associated with this store.
    pub chain_id: u32,
    /// The Account ID of the owner agent.
    pub owner_id: [u8; 32],
}

/// The main interface for the Sovereign Context Substrate.
pub struct SovereignContextStore {
    file: File,
    path: PathBuf,
    header: ScsHeader,
    pub toc: Toc,
    /// Memory map for zero-copy payload access.
    mmap: Option<Mmap>,
    /// In-memory vector index (lazy loaded).
    vec_index: Arc<Mutex<Option<VectorIndex>>>,
    /// [NEW] In-memory index for fast lookup of frames by their visual hash (checksum).
    pub visual_index: HashMap<[u8; 32], FrameId>,
}

impl SovereignContextStore {
    /// Creates a new, empty .scs file.
    pub fn create(path: &Path, config: StoreConfig) -> Result<Self> {
        if path.exists() {
            return Err(anyhow!("File already exists: {:?}", path));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        file.lock_exclusive()?;

        let mut header = ScsHeader::default();
        header.chain_id = config.chain_id;
        header.owner_id = config.owner_id;

        // Write Header
        file.write_all(&header.to_bytes())?;

        // Write Empty TOC immediately after header
        let toc = Toc::default();
        let toc_bytes = bincode::serialize(&toc)?;
        let toc_offset = HEADER_SIZE;
        let toc_length = toc_bytes.len() as u64;

        file.write_all(&toc_bytes)?;

        // Update Header with TOC location
        header.toc_offset = toc_offset;
        header.toc_length = toc_length;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header.to_bytes())?;
        file.sync_all()?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            toc,
            mmap: None,
            vec_index: Arc::new(Mutex::new(None)),
            visual_index: HashMap::new(), // [NEW] Initialize empty
        })
    }

    /// Opens an existing .scs file.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.lock_exclusive()?;

        let mut header_bytes = [0u8; HEADER_SIZE as usize];
        file.read_exact(&mut header_bytes)?;
        let header = ScsHeader::from_bytes(&header_bytes).map_err(|e| anyhow!(e))?;

        // Read TOC
        file.seek(SeekFrom::Start(header.toc_offset))?;
        let mut toc_bytes = vec![0u8; header.toc_length as usize];
        file.read_exact(&mut toc_bytes)?;
        let toc: Toc = bincode::deserialize(&toc_bytes)?;

        // Verify TOC Checksum (Integrity Check)
        let computed_checksum = sha256(&toc_bytes)?;
        // We verify against the header logic or just trust it for now if header doesn't store checksum.
        // The Toc struct has an internal checksum field for self-consistency if needed.

        // Mmap the file for reading
        let mmap = unsafe { Mmap::map(&file)? };

        // [NEW] Rebuild visual index
        let mut visual_index = HashMap::new();
        for frame in &toc.frames {
            // Map checksum -> FrameId. This assumes payload checksum IS the visual hash for Observation frames.
            visual_index.insert(frame.checksum, frame.id);
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            toc,
            mmap: Some(mmap),
            vec_index: Arc::new(Mutex::new(None)),
            visual_index, // [NEW]
        })
    }

    /// Appends a new frame with the given payload.
    /// Returns the new FrameId.
    pub fn append_frame(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
        block_height: u64,
        // mhnsw_root is optional; if provided, it binds this frame to a specific index state.
        // Typically, this is the root of the index *after* adding any vectors from this frame.
        mhnsw_root: [u8; 32],
    ) -> Result<FrameId> {
        // 1. Calculate Frame Metadata
        let next_id = self.toc.frames.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let checksum = sha256(payload)?;
        let mut checksum_arr = [0u8; 32];
        checksum_arr.copy_from_slice(checksum.as_ref());

        // 2. Determine Write Position (Overwrite old TOC)
        let write_offset = self.header.toc_offset;
        self.file.seek(SeekFrom::Start(write_offset))?;

        // 3. Write Payload
        self.file.write_all(payload)?;
        let payload_length = payload.len() as u64;

        // 4. Update In-Memory TOC
        let frame = Frame {
            id: next_id,
            frame_type,
            timestamp,
            block_height,
            payload_offset: write_offset,
            payload_length,
            mhnsw_root,
            checksum: checksum_arr,
            is_encrypted: false, // Default unencrypted locally
        };
        self.toc.frames.push(frame);

        // [NEW] Update In-Memory Visual Index
        self.visual_index.insert(checksum_arr, next_id);

        // 5. Serialize and Append New TOC
        let toc_bytes = bincode::serialize(&self.toc)?;
        let new_toc_offset = write_offset + payload_length;
        self.file.write_all(&toc_bytes)?;

        // 6. Update Header
        self.header.toc_offset = new_toc_offset;
        self.header.toc_length = toc_bytes.len() as u64;

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.to_bytes())?;
        self.file.sync_all()?;

        // Remap mmap to include new data
        // Note: Remapping on every write is expensive; in prod we'd chunk or lazily remap.
        self.mmap = Some(unsafe { Mmap::map(&self.file)? });

        Ok(next_id)
    }

    /// Reads the payload of a specific frame using zero-copy mmap if available.
    pub fn read_frame_payload(&self, frame_id: FrameId) -> Result<&[u8]> {
        let frame = self
            .toc
            .frames
            .get(frame_id as usize)
            .ok_or_else(|| anyhow!("Frame ID {} not found", frame_id))?;

        if let Some(mmap) = &self.mmap {
            let start = frame.payload_offset as usize;
            let end = start + frame.payload_length as usize;
            if end > mmap.len() {
                return Err(anyhow!("Frame payload out of file bounds"));
            }
            Ok(&mmap[start..end])
        } else {
            // Fallback to file seek/read if mmap failed or not initialized
            // (Though open/create initializes it).
            Err(anyhow!("Memory map not initialized"))
        }
    }

    /// Saves the current vector index to the file as a special "System" frame (or embedded segment).
    /// Updates the TOC to point to this new index artifact.
    pub fn commit_index(&mut self, index: &VectorIndex) -> Result<()> {
        // Serialize index
        let artifact = index.serialize_to_artifact()?;

        // We write the artifact bytes just like a frame payload
        // But we don't necessarily need a Frame entry for it if we store metadata in TOC.
        // However, making it a System Frame provides a nice history of index updates.

        let payload = bincode::serialize(&artifact)?;

        // 1. Write Payload
        let write_offset = self.header.toc_offset;
        self.file.seek(SeekFrom::Start(write_offset))?;
        self.file.write_all(&payload)?;

        let length = payload.len() as u64;

        // 2. Update TOC Vector Manifest
        self.toc.vector_index = Some(VectorIndexManifest {
            offset: write_offset,
            length,
            count: artifact.count,
            dimension: artifact.dimension,
            root_hash: artifact.root_hash,
        });

        // 3. Rewrite TOC at new end
        let new_toc_offset = write_offset + length;
        let toc_bytes = bincode::serialize(&self.toc)?;
        self.file.write_all(&toc_bytes)?;

        // 4. Update Header
        self.header.toc_offset = new_toc_offset;
        self.header.toc_length = toc_bytes.len() as u64;

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.to_bytes())?;
        self.file.sync_all()?;

        self.mmap = Some(unsafe { Mmap::map(&self.file)? });

        Ok(())
    }

    /// Gets the active vector index, loading it from disk if necessary.
    pub fn get_vector_index(&self) -> Result<Arc<Mutex<Option<VectorIndex>>>> {
        let mut guard = self.vec_index.lock().unwrap();
        if guard.is_some() {
            drop(guard);
            return Ok(self.vec_index.clone());
        }

        // Load from disk
        if let Some(manifest) = &self.toc.vector_index {
            let mmap = self
                .mmap
                .as_ref()
                .ok_or_else(|| anyhow!("Mmap not ready"))?;
            let start = manifest.offset as usize;
            let end = start + manifest.length as usize;
            let bytes = &mmap[start..end];

            // Deserialize artifact
            let artifact: crate::index::VectorIndexArtifact = bincode::deserialize(bytes)?;

            // Reconstruct index
            let index = VectorIndex::from_artifact(&artifact)?;
            *guard = Some(index);
        } else {
            // Create new if none exists
            // Default params: M=16, ef=200
            *guard = Some(VectorIndex::new(16, 200));
        }

        drop(guard);
        Ok(self.vec_index.clone())
    }
}

impl Drop for SovereignContextStore {
    fn drop(&mut self) {
        // Unlock file
        let _ = self.file.unlock();
    }
}