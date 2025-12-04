// Path: crates/ipc/src/data.rs
use rkyv::{Archive, Deserialize, Serialize};

/// A zero-copy compatible tensor structure.
///
/// `Vec<f32>` in Rkyv is archived as a relative pointer to a contiguous slice.
/// Accessing this from a memory-mapped region involves pointer arithmetic only,
/// effectively 0 CPU cost for "deserialization".
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)] // Enforces structure validation on untrusted bytes
#[repr(C)]
pub struct Tensor {
    /// Dimensions: [batch, channels, height, width] or [batch, seq_len, hidden_dim, 0]
    pub shape: [u64; 4],
    pub data: Vec<f32>,
}

/// The massive context payload (e.g., RAG documents) that previously stalled JSON serialization.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct AgentContext {
    pub session_id: u64,
    /// Large vector embeddings or KV caches
    pub embeddings: Vec<Tensor>,
    /// Raw tokens or text data
    pub prompt_tokens: Vec<u32>,
}

/// The result returned by the inference engine.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct InferenceOutput {
    pub logits: Tensor,
    pub generated_tokens: Vec<u32>,
    pub stop_reason: u8,
}
