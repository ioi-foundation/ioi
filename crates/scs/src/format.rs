// Path: crates/scs/src/format.rs

//! Defines the binary layout of the Sovereign Context Substrate (.scs) file format.
//!
//! The format is an append-only log of "Frames" with a mutable Table of Contents (TOC)
//! stored at the end of the file. This allows for efficient appending of new observations
//! while maintaining random access for retrieval.

use crate::SCS_MAGIC;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};


/// The version of the SCS file format.
pub const SCS_VERSION: u16 = 1;

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
}

/// Metadata for a single unit of memory (a Frame).
///
/// A Frame maps to a specific point in time and contains a reference to the data payload.
/// Crucially, it binds this data to the blockchain state via the `mhnsw_root`.
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
    /// Used for efficient history hydration without scanning payloads.
    pub session_id: [u8; 32],

    /// The file offset where the raw payload (e.g., image bytes, JSON) begins.
    pub payload_offset: u64,
    /// The length of the payload in bytes.
    pub payload_length: u64,
    /// The Merkle Root of the mHNSW vector index at the time this frame was committed.
    /// This allows for "Proof of Retrieval" - proving that a search performed against
    /// this frame used the correct, tamper-evident index structure.
    pub mhnsw_root: [u8; 32],
    /// SHA-256 checksum of the payload for integrity verification.
    pub checksum: [u8; 32],
    /// Optional encryption metadata (if the payload is encrypted at rest).
    /// For the MVP, we assume local files are protected by OS permissions (unencrypted payload).
    pub is_encrypted: bool,
}

/// The Table of Contents, stored at the end of the file.
/// It indexes all frames and provides metadata for the vector indices.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Toc {
    /// List of all frames in the store, sorted by ID.
    pub frames: Vec<Frame>,
    /// Metadata about the active mHNSW vector index segment.
    pub vector_index: Option<VectorIndexManifest>,
    /// Checksum of the TOC itself (to detect partial writes).
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
    /// The dimension of the vectors (e.g., 384, 768).
    pub dimension: u32,
    /// The Merkle Root of the index.
    pub root_hash: [u8; 32],
}

impl ScsHeader {
    /// Serializes the header to a fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE as usize] {
        let mut bytes = [0u8; HEADER_SIZE as usize];
        // We use bincode for the header structure to ensure fixed layout if configured correctly,
        // but manual packing is safer for cross-version compatibility headers.
        // For simplicity in this v1, we'll use a manual pack helper.
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

        // Reserved/Padding
        // bytes[offset..] are already 0

        bytes
    }

    /// Deserializes the header from a byte array.
    pub fn from_bytes(bytes: &[u8; HEADER_SIZE as usize]) -> Result<Self, String> {
        if &bytes[0..8] != SCS_MAGIC {
            return Err("Invalid magic bytes".into());
        }

        let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        if version != SCS_VERSION {
            return Err(format!("Unsupported version: {}", version));
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