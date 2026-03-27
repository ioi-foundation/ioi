use ioi_types::app::{InferenceOptions, ModelLifecycleOperationKind, RegistrySubjectKind};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Typed request for text-generation style inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextGenerationRequest {
    /// Canonical model hash used by the current runtime substrate.
    pub model_hash: [u8; 32],
    /// Optional higher-level model identifier for registry-backed runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    /// Canonical serialized input context passed to the model.
    pub input_context: Vec<u8>,
    /// Generation options for this invocation.
    pub options: InferenceOptions,
    /// Whether the runtime should stream partial output when possible.
    #[serde(default)]
    pub stream: bool,
}

/// Typed result for text-generation style inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextGenerationResult {
    /// Canonical output payload returned by the runtime.
    pub output: Vec<u8>,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    /// Whether the runtime streamed output during execution.
    #[serde(default)]
    pub streamed: bool,
}

/// Typed request for text embeddings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEmbeddingRequest {
    /// Input text to embed.
    pub text: String,
    /// Optional higher-level model identifier for embedding selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for image embeddings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageEmbeddingRequest {
    /// Raw encoded image bytes.
    pub image_bytes: Vec<u8>,
    /// Optional MIME type for the encoded bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional higher-level model identifier for embedding selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed embedding result for a single input item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingResult {
    /// Embedding vector values.
    pub values: Vec<f32>,
    /// Cached vector dimensionality for receipt/reporting use.
    pub dimensions: u32,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for candidate reranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerankRequest {
    /// Query or instruction used to score candidates.
    pub query: String,
    /// Candidate strings to score.
    #[serde(default)]
    pub candidates: Vec<String>,
    /// Optional top-k cutoff requested by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Optional higher-level model identifier for rerank selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// One scored rerank candidate in output order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerankCandidateScore {
    /// Original candidate index in the request.
    pub index: u32,
    /// Candidate content.
    pub candidate: String,
    /// Score assigned by the runtime.
    pub score: f32,
}

/// Typed rerank result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerankResult {
    /// Candidates scored and ordered by the runtime.
    #[serde(default)]
    pub items: Vec<RerankCandidateScore>,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for audio transcription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptionRequest {
    /// Encoded audio bytes to transcribe.
    pub audio_bytes: Vec<u8>,
    /// MIME type describing the encoded input.
    pub mime_type: String,
    /// Optional language hint supplied by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Optional higher-level model identifier for transcription selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed transcription result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptionResult {
    /// Canonical transcript text.
    pub text: String,
    /// Optional language reported by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for speech synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeechSynthesisRequest {
    /// Input text to synthesize.
    pub text: String,
    /// Optional requested voice identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    /// Optional preferred output MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional higher-level model identifier for synthesis selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed speech synthesis result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeechSynthesisResult {
    /// Encoded output audio bytes.
    pub audio_bytes: Vec<u8>,
    /// MIME type for the encoded output.
    pub mime_type: String,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for vision or multimodal read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisionReadRequest {
    /// Encoded image or screenshot bytes.
    pub image_bytes: Vec<u8>,
    /// MIME type for the encoded input.
    pub mime_type: String,
    /// Optional prompt or question bound to the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Optional higher-level model identifier for vision selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed result for vision or multimodal read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisionReadResult {
    /// Canonical text output from the vision model.
    pub output_text: String,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for image generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageGenerationRequest {
    /// Prompt used to generate the image.
    pub prompt: String,
    /// Optional preferred output MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional higher-level model identifier for image generation selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for image editing or inpainting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageEditRequest {
    /// Source image bytes to edit.
    pub source_image_bytes: Vec<u8>,
    /// MIME type of the source image.
    pub source_mime_type: String,
    /// Optional prompt guiding the edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Optional mask bytes restricting editable regions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_image_bytes: Option<Vec<u8>>,
    /// Optional higher-level model identifier for image editing selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed result for image generation or editing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageGenerationResult {
    /// Encoded image bytes.
    pub image_bytes: Vec<u8>,
    /// MIME type for the encoded output.
    pub mime_type: String,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for video generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoGenerationRequest {
    /// Prompt used to generate the video.
    pub prompt: String,
    /// Optional preferred output MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional requested output duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Optional higher-level model identifier for video generation selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed result for video generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoGenerationResult {
    /// Encoded video bytes.
    pub video_bytes: Vec<u8>,
    /// MIME type for the encoded output.
    pub mime_type: String,
    /// Optional higher-level model identifier resolved by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for a model load operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLoadRequest {
    /// Canonical model hash used by the current runtime substrate.
    pub model_hash: [u8; 32],
    /// Filesystem path to the model artifact or bundle.
    pub path: PathBuf,
    /// Optional higher-level model identifier for registry-backed runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed request for a model unload operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUnloadRequest {
    /// Canonical model hash used by the current runtime substrate.
    pub model_hash: [u8; 32],
    /// Optional higher-level model identifier for registry-backed runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Typed result for a model lifecycle mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLifecycleResult {
    /// Lifecycle operation completed by the runtime.
    pub operation: ModelLifecycleOperationKind,
    /// Registry subject kind manipulated by the runtime.
    pub subject_kind: RegistrySubjectKind,
    /// Stable subject identifier reported by the runtime.
    pub subject_id: String,
}
