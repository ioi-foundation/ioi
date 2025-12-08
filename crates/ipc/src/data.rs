// Path: crates/ipc/src/data.rs
use rkyv::{Archive, Deserialize, Serialize};

/// A pointer to data stored on an external Data Availability layer (Celestia, EigenDA).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct DaReference {
    /// The DA provider identifier (e.g., "celestia-mocha").
    pub provider: String,
    /// The unique blob ID or namespace/height tuple.
    pub blob_id: Vec<u8>,
    /// The cryptographic commitment (Merkle root) of the blob data.
    pub commitment: Vec<u8>,
}

/// A zero-copy compatible tensor structure.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
#[repr(C)]
pub struct Tensor {
    pub shape: [u64; 4],
    pub data: Vec<f32>,
}

/// The massive context payload (e.g., RAG documents).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct AgentContext {
    pub session_id: u64,
    /// Large vector embeddings or KV caches
    pub embeddings: Vec<Tensor>,
    /// Raw tokens or text data
    pub prompt_tokens: Vec<u32>,
    /// [NEW] Optional: Pointer to data stored on a DA layer.
    /// If present, Workload must fetch this before inference.
    pub da_ref: Option<DaReference>,
}

/// The result returned by the inference engine.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct InferenceOutput {
    pub logits: Tensor,
    pub generated_tokens: Vec<u32>,
    pub stop_reason: u8,
}