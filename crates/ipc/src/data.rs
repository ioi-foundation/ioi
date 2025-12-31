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
    pub slice_id: [u8; 32],
    pub chunks: Vec<Vec<u8>>,
    /// Optional proof of retrieval from the local SFS mHNSW.
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
