//! Typed first-party inference workload contracts.
//!
//! These types define the absorbed receipt surface for local text inference,
//! embeddings, rerank, and adjacent inference-class operations that should
//! become first-class kernel concepts rather than provider-shaped blobs.

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The specific inference-class operation performed by a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum InferenceOperationKind {
    /// Text generation, chat completion, or responses-style generation.
    TextGeneration,
    /// Text embedding generation.
    EmbeddingText,
    /// Image embedding generation.
    EmbeddingImage,
    /// Candidate reranking over an existing retrieval or planning set.
    Rerank,
    /// Lightweight classification or routing inference.
    Classification,
}

impl InferenceOperationKind {
    /// Returns a stable deterministic label for receipts and projections.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::TextGeneration => "text_generation",
            Self::EmbeddingText => "embedding_text",
            Self::EmbeddingImage => "embedding_image",
            Self::Rerank => "rerank",
            Self::Classification => "classification",
        }
    }
}

/// Typed receipt for an absorbed inference workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WorkloadInferenceReceipt {
    /// Tool that initiated the inference workload.
    pub tool_name: String,
    /// Specific inference-class operation executed.
    pub operation: InferenceOperationKind,
    /// Runtime backend identifier used for execution.
    pub backend: String,
    /// Canonical model identifier selected for execution.
    pub model_id: String,
    /// Optional higher-level model family or alias.
    #[serde(default)]
    pub model_family: Option<String>,
    /// Prompt or input token count when available.
    #[serde(default)]
    pub prompt_token_count: Option<u32>,
    /// Completion or output token count when available.
    #[serde(default)]
    pub completion_token_count: Option<u32>,
    /// Total token count when surfaced by the runtime.
    #[serde(default)]
    pub total_token_count: Option<u32>,
    /// Vector dimensionality when the operation returns embeddings.
    #[serde(default)]
    pub vector_dimensions: Option<u32>,
    /// Number of result items returned by the operation.
    pub result_item_count: u32,
    /// Candidate count before scoring or rerank when applicable.
    #[serde(default)]
    pub candidate_count_total: Option<u32>,
    /// Candidate count actually scored or reranked when applicable.
    #[serde(default)]
    pub candidate_count_scored: Option<u32>,
    /// Whether the operation streamed partial output.
    pub streaming: bool,
    /// End-to-end workload latency when available.
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Structured output schema hash when the invocation enforced one.
    #[serde(default)]
    pub structured_output_schema_hash: Option<[u8; 32]>,
    /// Hash of the canonical model output or result payload when available.
    #[serde(default)]
    pub output_hash: Option<[u8; 32]>,
    /// Success flag as surfaced by the runtime.
    pub success: bool,
    /// Optional machine-readable failure class.
    #[serde(default)]
    pub error_class: Option<String>,
}
