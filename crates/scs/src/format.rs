// Path: crates/scs/src/format.rs

//! Defines the binary layout of the Sovereign Context Substrate (.scs) file format.
//!
//! The format is an append-only log of "Frames" with a mutable Table of Contents (TOC)
//! stored at the end of the file. This allows for efficient appending of new observations
//! while maintaining random access for retrieval.
//!
//! # Version 2: Cryptographic Epoch Lifecycle
//!
//! Version 2 introduces "Retention Classes" and "Epoch Manifests".
//! - Data is encrypted by default using keys bound to specific lifecycles (Session, Epoch, Identity).
//! - Deletion is achieved via **Key Shredding**: destroying the key renders the payload
//!   information-theoretically deleted, even if the bytes remain on disk.
//! - The integrity of the chain is preserved via `Tombstones` and `EpochManifests` which anchor
//!   the history even after the content is shredded.

use crate::SCS_MAGIC;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The version of the SCS file format.
pub const SCS_VERSION: u16 = 2;

/// The fixed size of the file header in bytes.
pub const HEADER_SIZE: u64 = 64;

/// The header located at the very beginning of the .scs file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ScsHeader {
    /// Magic bytes "IOI-SCS!".
    pub magic: [u8; 8],
    /// Format version number.
    pub version: u16,
    /// Reserved for future flags.
    pub flags: u16,
    /// The unique Chain ID this store is associated with.
    pub chain_id: u32,
    /// The Account ID of the agent owning this store (32 bytes).
    pub owner_id: [u8; 32],
    /// The absolute file offset where the Table of Contents (TOC) begins.
    /// This is updated every time the file is committed/closed.
    pub toc_offset: u64,
    /// The length of the TOC in bytes.
    pub toc_length: u64,
    /// Padding to reach 64 bytes.
    pub reserved: [u8; 8],
}

impl Default for ScsHeader {
    fn default() -> Self {
        Self {
            magic: *SCS_MAGIC,
            version: SCS_VERSION,
            flags: 0,
            chain_id: 0,
            owner_id: [0; 32],
            toc_offset: HEADER_SIZE,
            toc_length: 0,
            reserved: [0; 8],
        }
    }
}

/// A unique identifier for a frame within the store.
pub type FrameId = u64;

/// Classifies the content of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum FrameType {
    /// A raw observation from the environment (e.g., Screenshot, DOM tree).
    Observation,
    /// An internal reasoning step or thought process (e.g., LLM chain-of-thought).
    Thought,
    /// An action taken by the agent (e.g., Mouse Click, API call).
    Action,
    /// System metadata or checkpoints (e.g., Vector Index snapshot).
    System,
    /// A crystallized capability learned from successful execution.
    Skill,
    /// [NEW] A synthesized summary of a previous epoch (Cognitive Compaction).
    /// Used to retain wisdom after the raw `Observation`/`Thought` frames are shredded.
    Overlay,
}

/// Defines the cryptographic lifecycle and deletion policy for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub enum RetentionClass {
    /// Encrypted with a SessionKey. Shredded immediately upon session close.
    /// Used for transient thoughts, raw screenshots, and intermediate reasoning.
    #[default]
    Ephemeral,
    
    /// Encrypted with an EpochKey. Shredded when the Epoch rotates (e.g., hourly/daily),
    /// unless promoted to Archival via summarization.
    Epoch,
    
    /// Encrypted with the stable IdentityKey. Never shredded unless explicitly revoked.
    /// Used for Skills, Overlays (Summaries), and Receipts.
    Archival,
}

/// Metadata for a single unit of memory (a Frame).
///
/// A Frame maps to a specific point in time and contains a reference to the data payload.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Frame {
    /// Monotonically increasing ID.
    pub id: FrameId,
    /// The type of content in this frame.
    pub frame_type: FrameType,
    /// UNIX timestamp (ms) when this frame was captured.
    pub timestamp: u64,
    /// The block height of the blockchain at the time of capture.
    pub block_height: u64,
    
    /// The unique session ID this frame belongs to (0 if global).
    pub session_id: [u8; 32],

    /// The file offset where the raw payload (ciphertext) begins.
    pub payload_offset: u64,
    /// The length of the payload in bytes.
    pub payload_length: u64,
    /// The Merkle Root of the mHNSW vector index at the time this frame was committed.
    pub mhnsw_root: [u8; 32],
    /// SHA-256 checksum of the payload (Ciphertext) for integrity verification.
    pub checksum: [u8; 32],
    
    /// [NEW] The retention policy dictating which key wraps this frame.
    pub retention: RetentionClass,
    
    /// [NEW] The Epoch ID this frame belongs to. Used to look up the correct EpochKey.
    pub epoch_id: u64,
    
    /// [NEW] The Initialization Vector (Nonce) used for the encryption (12 bytes).
    pub iv: [u8; 12],
}

/// [NEW] The Anchor for a time period (Epoch).
///
/// This structure is committed as a `System` frame at the end of every epoch.
/// It creates an immutable spine of history even if the content of the epoch is shredded.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EpochManifest {
    /// The ID of this epoch.
    pub epoch_id: u64,
    /// Hash of the previous EpochManifest (Tamper-evident chain).
    pub prev_epoch_hash: [u8; 32],
    
    /// Merkle root of all frames created in this epoch.
    pub frames_root: [u8; 32],
    
    /// Statistics preserved even after key shredding (for audits).
    pub total_frames: u32,
    pub type_counts: std::collections::BTreeMap<u8, u32>, // FrameType as u8 -> count
    
    /// Merkle root of economic receipts generated in this epoch (Never pruneable).
    pub receipt_root: [u8; 32],
    
    /// Pointer to the SummaryOverlay frame that compresses this epoch's wisdom (if any).
    pub overlay_frame_id: Option<FrameId>,
}

/// [NEW] Returned when accessing a frame whose key has been shredded.
///
/// This serves as cryptographic proof that data *did* exist at this point in the timeline,
/// but has been intentionally forgotten according to policy.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Tombstone {
    /// The ID of the erased frame.
    pub frame_id: FrameId,
    /// The hash of the encrypted payload (still verifiable against the EpochManifest).
    pub payload_hash: [u8; 32],
    /// The retention class that triggered the shredding.
    pub retention_policy: RetentionClass,
    /// Timestamp of when the key was shredded.
    pub erasure_time: u64,
}

/// The Table of Contents, stored at the end of the file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Toc {
    /// List of all frames in the store, sorted by ID.
    pub frames: Vec<Frame>,
    /// Metadata about the active mHNSW vector index segment.
    pub vector_index: Option<VectorIndexManifest>,
    /// [NEW] Index of EpochManifests (Epoch ID -> Frame ID).
    pub epochs: std::collections::BTreeMap<u64, FrameId>,
    /// Checksum of the TOC itself.
    pub checksum: [u8; 32],
}

/// Metadata describing the embedded vector index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorIndexManifest {
    /// File offset where the serialized mHNSW graph begins.
    pub offset: u64,
    /// Length of the index data.
    pub length: u64,
    /// Number of vectors in the index.
    pub count: u64,
    /// The dimension of the vectors.
    pub dimension: u32,
    /// The Merkle Root of the index.
    pub root_hash: [u8; 32],
}

impl ScsHeader {
    /// Serializes the header to a fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE as usize] {
        let mut bytes = [0u8; HEADER_SIZE as usize];
        let mut offset = 0;

        bytes[offset..offset + 8].copy_from_slice(&self.magic);
        offset += 8;

        bytes[offset..offset + 2].copy_from_slice(&self.version.to_le_bytes());
        offset += 2;

        bytes[offset..offset + 2].copy_from_slice(&self.flags.to_le_bytes());
        offset += 2;

        bytes[offset..offset + 4].copy_from_slice(&self.chain_id.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 32].copy_from_slice(&self.owner_id);
        offset += 32;

        bytes[offset..offset + 8].copy_from_slice(&self.toc_offset.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.toc_length.to_le_bytes());
        offset += 8;

        // Reserved/Padding bytes remain 0
        bytes
    }

    /// Deserializes the header from a byte array.
    pub fn from_bytes(bytes: &[u8; HEADER_SIZE as usize]) -> Result<Self, String> {
        if &bytes[0..8] != SCS_MAGIC {
            return Err("Invalid magic bytes".into());
        }

        let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        // [MODIFIED] Check for Version 2 compatibility
        if version != SCS_VERSION {
            return Err(format!("Unsupported version: {}. Expected {}", version, SCS_VERSION));
        }

        let flags = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let chain_id = u32::from_le_bytes(bytes[12..16].try_into().unwrap());

        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(&bytes[16..48]);

        let toc_offset = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let toc_length = u64::from_le_bytes(bytes[56..64].try_into().unwrap());

        Ok(Self {
            magic: *SCS_MAGIC,
            version,
            flags,
            chain_id,
            owner_id,
            toc_offset,
            toc_length,
            reserved: [0; 8],
        })
    }
}