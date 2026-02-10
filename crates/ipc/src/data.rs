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
    /// Optional: Pointer to data stored on a DA layer.
    /// If present, Workload must fetch this before inference.
    pub da_ref: Option<DaReference>,
}

/// Deterministic parameters for LLM sampling.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct SamplingParams {
    /// Controls randomness (0.0 = deterministic, >0.0 = random).
    pub temperature: f32,
    /// Nucleus sampling probability.
    pub top_p: f32,
    /// The specific random seed used for this generation (must be pinned by Orchestrator).
    pub seed: u64,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Sequences that stop generation.
    pub stop_tokens: Vec<u32>,
}

/// A full request for inference, packaging context and parameters.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct InferenceRequest {
    /// The target model identifier (CID or Hash).
    pub model_id: String,
    /// The context/input data.
    pub context: AgentContext,
    /// Sampling configuration.
    pub sampling: SamplingParams,
}

/// The result returned by the inference engine.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct InferenceOutput {
    pub logits: Tensor,
    pub generated_tokens: Vec<u32>,
    pub stop_reason: u8,
}

/// A zero-copy optimized block structure for direct memory access by the Workload execution engine.
/// 4KB alignment ensures compatibility with page-based memory mapping.
#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(check_bytes)]
#[repr(C, align(4096))]
pub struct ZeroCopyBlock {
    /// The block height.
    pub height: u64,
    /// The block timestamp.
    pub timestamp: u64,
    /// Raw bytes of canonical transactions.
    /// The VM will parse them individually, preventing a massive allocation for the whole vector.
    pub transactions: Vec<Vec<u8>>,
}

// -----------------------------------------------------------------------------
// Context Slicing & Encryption (Whitepaper §6.2)
// -----------------------------------------------------------------------------

/// A raw slice of context (e.g. RAG chunks) to be encrypted.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct ContextSlice {
    /// Unique content-addressed identifier for this slice.
    pub slice_id: [u8; 32],

    /// The ID of the frame in the SCS that this slice corresponds to.
    /// This allows the Provider to request the surrounding context if needed.
    pub frame_id: u64,

    /// The actual data chunks (e.g. XML fragments, JSON objects).
    pub chunks: Vec<Vec<u8>>,

    /// The Merkle Root of the mHNSW index at the time this frame was captured.
    /// This is used by the Provider to verify the integrity of the vector index
    /// before performing retrieval.
    pub mhnsw_root: [u8; 32],

    /// Cryptographic proof linking this slice to the root substrate state.
    pub traversal_proof: Option<Vec<u8>>,
}

/// The transport object for context data.
/// Maps to Whitepaper §6.2.4 "EncryptedSlice".
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct EncryptedSlice {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    /// The tag is typically included in the ciphertext by ChaCha20Poly1305,
    /// but we track it logically via the slice_id binding in AAD.
    pub slice_id: [u8; 32],
}

/// Supports differential updates to context to save bandwidth (Whitepaper §6.2.2).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub enum ContextPayload {
    /// A full context upload (cold start).
    Full(EncryptedSlice),
    /// A differential update against a cached base slice.
    Delta {
        base_slice_id: [u8; 32],
        delta_slice: EncryptedSlice,
    },
}

impl EncryptedSlice {
    /// Constructs the canonical AAD for binding encryption to the session and policy.
    /// AAD = session_id || policy_hash || slice_id
    pub fn compute_aad(
        session_id: &[u8; 32],
        policy_hash: &[u8; 32],
        slice_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(96);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(policy_hash);
        aad.extend_from_slice(slice_id);
        aad
    }
}
