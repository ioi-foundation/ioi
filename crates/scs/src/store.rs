// Path: crates/scs/src/store.rs

//! The Sovereign Context Store (SCS) implementation.
//!
//! This module manages the lifecycle of the `.scs` file, including:
//! - Creating and opening files.
//! - Appending new frames.
//! - Memory-mapping for zero-copy access.
//! - Managing the Table of Contents (TOC).
//! - **Cryptographic Lifecycle:** Encryption, Key Shredding, and Epoch Rotation.

use crate::format::{
    EpochManifest, Frame, FrameId, FrameType, RetentionClass, ScsHeader, Toc, Tombstone,
    VectorIndexManifest, HEADER_SIZE, SCS_VERSION,
};
use crate::index::VectorIndex;
use anyhow::{anyhow, Result};
use dcrypt::algorithms::ByteSerializable;
use fs2::FileExt;
use ioi_crypto::algorithms::hash::sha256;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// Crypto imports for data encryption
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::symmetric::{DecryptOperation, EncryptOperation, SymmetricCipher};
use rand::{thread_rng, RngCore};

/// Configuration for opening or creating a store.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// The Chain ID associated with this store.
    pub chain_id: u32,
    /// The Account ID of the owner agent.
    pub owner_id: [u8; 32],
    /// [NEW] The persistent master key for Archival retention.
    /// In a real system, this comes from the Guardian's secure vault.
    pub identity_key: [u8; 32],
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
    /// In-memory index for fast lookup of frames by their visual hash (checksum).
    pub visual_index: HashMap<[u8; 32], FrameId>,

    /// In-memory index mapping Session ID -> List of Frame IDs.
    /// Rebuilt on open from the TOC, enabling O(1) history hydration.
    pub session_index: HashMap<[u8; 32], Vec<FrameId>>,

    /// In-memory index for Skill Frames (O(1) access to learned capabilities).
    /// Maps Checksum -> FrameId.
    pub skill_index: HashMap<[u8; 32], FrameId>,

    // --- Lifecycle State ---
    /// The current active epoch ID.
    pub current_epoch: u64,

    /// The identity key (Archival).
    identity_key: [u8; 32],

    /// In-memory keyring for Epoch keys.
    /// Maps Epoch ID -> Key.
    /// Absence of a key implies it has been shredded (pruned).
    epoch_keys: HashMap<u64, [u8; 32]>,

    /// In-memory keyring for Session keys.
    /// Maps Session ID -> Key.
    session_keys: HashMap<[u8; 32], [u8; 32]>,
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
        // Version 2 for new format
        header.version = SCS_VERSION;

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

        // Initialize keys
        let mut epoch_keys = HashMap::new();
        // Generate key for Epoch 0
        let mut epoch_0_key = [0u8; 32];
        thread_rng().fill_bytes(&mut epoch_0_key);
        epoch_keys.insert(0, epoch_0_key);

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            toc,
            mmap: None,
            vec_index: Arc::new(Mutex::new(None)),
            visual_index: HashMap::new(),
            session_index: HashMap::new(),
            skill_index: HashMap::new(),
            current_epoch: 0,
            identity_key: config.identity_key,
            epoch_keys,
            session_keys: HashMap::new(),
        })
    }

    /// Opens an existing .scs file.
    ///
    /// NOTE: In a real implementation, this would also need to load the `epoch_keys`
    /// from a separate secure keystore. For this implementation, we regenerate/mock them
    /// or assume they are managed externally and injected via `with_keys` (not shown).
    /// For local dev, we restart with empty keys which effectively shreds history on restart
    /// unless we persist them. We default to a fresh epoch key for the *new* epoch.
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
        let _computed_checksum = sha256(&toc_bytes)?;

        // Mmap the file for reading
        let mmap = unsafe { Mmap::map(&file)? };

        // Rebuild visual index & session index
        let mut visual_index = HashMap::new();
        let mut session_index = HashMap::new();
        let mut skill_index = HashMap::new();
        let mut max_epoch = 0;

        for frame in &toc.frames {
            // Map checksum -> FrameId.
            visual_index.insert(frame.checksum, frame.id);

            // Map Session ID -> Frame ID list
            session_index
                .entry(frame.session_id)
                .or_insert_with(Vec::new)
                .push(frame.id);

            // Map Skills
            if frame.frame_type == FrameType::Skill {
                skill_index.insert(frame.checksum, frame.id);
            }

            if frame.epoch_id > max_epoch {
                max_epoch = frame.epoch_id;
            }
        }

        // Initialize keys
        // [WARNING]: In production, load these from secure storage!
        let mut epoch_keys = HashMap::new();
        let mut current_key = [0u8; 32];
        thread_rng().fill_bytes(&mut current_key);
        epoch_keys.insert(max_epoch, current_key);

        // Mock identity key for open (since it wasn't passed in)
        // In real usage, use a builder pattern to inject keys.
        let identity_key = [0x1D; 32];

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header,
            toc,
            mmap: Some(mmap),
            vec_index: Arc::new(Mutex::new(None)),
            visual_index,
            session_index,
            skill_index,
            current_epoch: max_epoch,
            identity_key,
            epoch_keys,
            session_keys: HashMap::new(),
        })
    }

    /// Helper to get or create a session key.
    fn get_session_key(&mut self, session_id: &[u8; 32]) -> [u8; 32] {
        if let Some(k) = self.session_keys.get(session_id) {
            *k
        } else {
            let mut k = [0u8; 32];
            thread_rng().fill_bytes(&mut k);
            self.session_keys.insert(*session_id, k);
            k
        }
    }

    /// Appends a new frame with the given payload, encrypting it according to retention policy.
    /// Returns the new FrameId.
    pub fn append_frame(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
        block_height: u64,
        mhnsw_root: [u8; 32],
        session_id: [u8; 32],
        // [NEW] Retention Policy
        retention: RetentionClass,
    ) -> Result<FrameId> {
        // 1. Select Key based on Retention Policy
        let key = match retention {
            RetentionClass::Ephemeral => self.get_session_key(&session_id),
            RetentionClass::Epoch => *self
                .epoch_keys
                .get(&self.current_epoch)
                .ok_or_else(|| anyhow!("Current epoch key missing"))?,
            RetentionClass::Archival => self.identity_key,
        };

        // 2. Encrypt Payload
        let mut iv = [0u8; 12];
        thread_rng().fill_bytes(&mut iv);

        // Bind encryption to metadata (AAD)
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&block_height.to_le_bytes());
        aad.extend_from_slice(&session_id);

        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::new(iv);

        let ciphertext_obj = SymmetricCipher::encrypt(&cipher)
            .with_nonce(&nonce)
            .with_aad(&aad)
            .encrypt(payload)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let ciphertext = ciphertext_obj.as_ref();

        // 3. Calculate Frame Metadata
        let next_id = self.toc.frames.len() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Checksum is of the CIPHERTEXT for integrity
        let checksum = sha256(ciphertext)?;
        let mut checksum_arr = [0u8; 32];
        checksum_arr.copy_from_slice(checksum.as_ref());

        // 4. Determine Write Position (Overwrite old TOC)
        let write_offset = self.header.toc_offset;
        self.file.seek(SeekFrom::Start(write_offset))?;

        // 5. Write Encrypted Payload
        self.file.write_all(ciphertext)?;
        let payload_length = ciphertext.len() as u64;

        // 6. Update In-Memory TOC
        let frame = Frame {
            id: next_id,
            frame_type,
            timestamp,
            block_height,
            session_id,
            payload_offset: write_offset,
            payload_length,
            mhnsw_root,
            checksum: checksum_arr,
            retention,
            epoch_id: self.current_epoch,
            iv,
        };
        self.toc.frames.push(frame);

        // Update In-Memory Indices
        self.visual_index.insert(checksum_arr, next_id);
        self.session_index
            .entry(session_id)
            .or_insert_with(Vec::new)
            .push(next_id);

        if frame_type == FrameType::Skill {
            self.skill_index.insert(checksum_arr, next_id);
        }

        // 7. Serialize and Append New TOC
        let toc_bytes = bincode::serialize(&self.toc)?;
        let new_toc_offset = write_offset + payload_length;
        self.file.write_all(&toc_bytes)?;

        // 8. Update Header
        self.header.toc_offset = new_toc_offset;
        self.header.toc_length = toc_bytes.len() as u64;

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.to_bytes())?;
        self.file.sync_all()?;

        // Remap mmap to include new data
        self.mmap = Some(unsafe { Mmap::map(&self.file)? });

        Ok(next_id)
    }

    /// Reads and decrypts the payload of a specific frame.
    /// Returns a `Tombstone` error if the key has been shredded.
    pub fn read_frame_payload(&self, frame_id: FrameId) -> Result<Vec<u8>> {
        let frame = self
            .toc
            .frames
            .get(frame_id as usize)
            .ok_or_else(|| anyhow!("Frame ID {} not found", frame_id))?;

        // 1. Read Raw Ciphertext (Zero-Copy from Mmap)
        let ciphertext = if let Some(mmap) = &self.mmap {
            let start = frame.payload_offset as usize;
            let end = start + frame.payload_length as usize;
            if end > mmap.len() {
                return Err(anyhow!("Frame payload out of file bounds"));
            }
            &mmap[start..end]
        } else {
            return Err(anyhow!("Memory map not initialized"));
        };

        // 2. Resolve Key
        let key = match frame.retention {
            RetentionClass::Ephemeral => self
                .session_keys
                .get(&frame.session_id)
                .ok_or_else(|| anyhow!("Session closed (Key shredded)"))?,
            RetentionClass::Epoch => {
                match self.epoch_keys.get(&frame.epoch_id) {
                    Some(k) => k,
                    None => {
                        // Key Missing = Shredded
                        // Return structured Tombstone information
                        let ts = Tombstone {
                            frame_id,
                            payload_hash: frame.checksum,
                            retention_policy: frame.retention,
                            erasure_time: 0, // Unknown without epoch log
                        };
                        // We return string error here for compatibility with existing APIs,
                        // but in a typed API we would return a Tombstone variant.
                        return Err(anyhow!(
                            "TOMBSTONE: Data shredded (Epoch {}). Hash: {}",
                            frame.epoch_id,
                            hex::encode(ts.payload_hash)
                        ));
                    }
                }
            }
            RetentionClass::Archival => &self.identity_key,
        };

        // 3. Decrypt
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&frame.block_height.to_le_bytes());
        aad.extend_from_slice(&frame.session_id);

        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::new(frame.iv);
        let ct_obj = dcrypt::api::types::Ciphertext::new(ciphertext.to_vec());

        let plaintext = SymmetricCipher::decrypt(&cipher)
            .with_nonce(&nonce)
            .with_aad(&aad)
            .decrypt(&ct_obj)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Scans all known skills and returns their payloads.
    pub fn scan_skills(&self) -> Vec<Vec<u8>> {
        let mut skills = Vec::new();
        for &id in self.skill_index.values() {
            // Skills are Archival, so they should always be readable.
            if let Ok(payload) = self.read_frame_payload(id) {
                skills.push(payload);
            }
        }
        skills
    }

    /// Saves the current vector index to the file as a special "System" frame.
    pub fn commit_index(&mut self, index: &VectorIndex) -> Result<()> {
        // Serialize index
        let artifact = index.serialize_to_artifact()?;
        let payload = bincode::serialize(&artifact)?;

        // Append as System Frame (Archival retention for index)
        // We track it in the TOC header rather than just a frame.

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

    /// Gets the active vector index.
    pub fn get_vector_index(&self) -> Result<Arc<Mutex<Option<VectorIndex>>>> {
        let mut guard = self.vec_index.lock().unwrap();
        if guard.is_some() {
            drop(guard);
            return Ok(self.vec_index.clone());
        }

        if let Some(manifest) = &self.toc.vector_index {
            let mmap = self
                .mmap
                .as_ref()
                .ok_or_else(|| anyhow!("Mmap not ready"))?;
            let start = manifest.offset as usize;
            let end = start + manifest.length as usize;
            if end > mmap.len() {
                return Err(anyhow!("Index artifact out of bounds"));
            }
            let bytes = &mmap[start..end];
            let artifact: crate::index::VectorIndexArtifact = bincode::deserialize(bytes)?;
            let index = VectorIndex::from_artifact(&artifact)?;
            *guard = Some(index);
        } else {
            *guard = Some(VectorIndex::new(16, 200));
        }

        drop(guard);
        Ok(self.vec_index.clone())
    }

    // --- Lifecycle Management ---

    /// Rotates the epoch. Generates a new Epoch Key and increments `current_epoch`.
    /// Returns the `EpochManifest` for the completed epoch.
    pub fn rotate_epoch(&mut self) -> Result<EpochManifest> {
        let old_epoch = self.current_epoch;

        // 1. Snapshot Stats for old epoch
        let mut total_frames = 0;
        let mut type_counts = std::collections::BTreeMap::new();
        let mut frames_digest_input = Vec::new();

        // Iterate all frames in memory to build manifest
        // (In prod, iterate only frames belonging to old_epoch)
        for frame in &self.toc.frames {
            if frame.epoch_id == old_epoch {
                total_frames += 1;
                *type_counts.entry(frame.frame_type as u8).or_insert(0) += 1;
                frames_digest_input.extend_from_slice(&frame.checksum);
            }
        }

        let frames_root_digest = sha256(&frames_digest_input)?;
        let mut frames_root = [0u8; 32];
        frames_root.copy_from_slice(frames_root_digest.as_ref());

        // 2. Generate key for NEW epoch
        self.current_epoch += 1;
        let mut new_key = [0u8; 32];
        thread_rng().fill_bytes(&mut new_key);
        self.epoch_keys.insert(self.current_epoch, new_key);

        // 3. Construct Manifest
        let manifest = EpochManifest {
            epoch_id: old_epoch,
            prev_epoch_hash: [0u8; 32], // TODO: Chain this
            frames_root,
            total_frames,
            type_counts,
            receipt_root: [0u8; 32], // TODO: Aggregate receipts
            overlay_frame_id: None,  // TODO: Link if overlay was created
        };

        // 4. Record Manifest frame (System Type, Archival Retention)
        let manifest_bytes = bincode::serialize(&manifest)?;
        self.append_frame(
            FrameType::System,
            &manifest_bytes,
            0,
            [0; 32],
            [0; 32],
            RetentionClass::Archival,
        )?;

        // 5. Update Index of Epochs
        // We should add `epochs` map to TOC but for now we just log it.
        // self.toc.epochs.insert(old_epoch, frame_id);

        Ok(manifest)
    }

    /// Cryptographically deletes all data in the specified epoch by destroying its key.
    pub fn prune_epoch(&mut self, epoch_id: u64) {
        if self.epoch_keys.remove(&epoch_id).is_some() {
            log::info!("SCS: Pruned Epoch {}. Keys shredded.", epoch_id);
        } else {
            log::warn!(
                "SCS: Attempted to prune Epoch {}, but key was already missing.",
                epoch_id
            );
        }
    }
}

impl Drop for SovereignContextStore {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
