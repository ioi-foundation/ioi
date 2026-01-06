// Path: crates/types/src/app/agentic.rs
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The cryptographic proof that a distributed committee converged on a specific meaning.
/// This forms the "Proof of Meaning" verified by Type A (Consensus) validators.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeCertificate {
    /// The SHA-256 hash of the Canonical JSON output (RFC 8785).
    /// This is the "Intent Hash" that represents the agreed-upon semantic result.
    pub intent_hash: [u8; 32],

    /// The unique ID of the DIM (Distributed Inference Mesh) committee assigned to this task.
    pub committee_id: u64,

    /// The epoch in which this inference occurred.
    pub epoch: u64,

    /// The hash of the Model Snapshot used for inference.
    /// Ensures all committee members used the exact same model weights.
    pub model_snapshot_id: [u8; 32],

    /// The aggregated BLS signature of the quorum (>= 2/3 of committee weight).
    /// This aggregates the individual signatures of the Compute Validators.
    pub aggregated_signature: Vec<u8>,

    /// A bitfield representing which committee members contributed to the signature.
    /// Used to reconstruct the aggregate public key for verification.
    pub signers_bitfield: Vec<u8>,
}

/// The type of data being redacted from a Context Slice.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RedactionType {
    /// Personally Identifiable Information (e.g., Email, Phone).
    Pii,
    /// High-entropy secrets (e.g., API Keys, Private Keys).
    Secret,
    /// Custom pattern match (e.g., proprietary project names).
    Custom(String),
}

/// A specific redaction applied to a text segment.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RedactionEntry {
    /// Start byte index in the original UTF-8 buffer.
    pub start_index: u32,
    /// End byte index in the original UTF-8 buffer.
    pub end_index: u32,
    /// The type of data removed.
    pub redaction_type: RedactionType,
    /// SHA-256 hash of the original redacted content.
    /// Allows verifying that the rehydrated data matches the original scrubbed data.
    pub original_hash: [u8; 32],
}

/// A map of all redactions applied to a `ContextSlice`.
/// Used by the Orchestrator to "rehydrate" responses or verify the integrity of the scrubbing process.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RedactionMap {
    /// A chronological list of redactions applied to the source text.
    pub entries: Vec<RedactionEntry>,
}
