// Path: crates/api/src/vm/inference/mod.rs

use async_trait::async_trait;
use ioi_types::app::agentic::{EvidenceGraph, InferenceOptions};
use ioi_types::app::{
    ChatRuntimeProvenance, ChatRuntimeProvenanceKind, ModelLifecycleOperationKind,
    RegistrySubjectKind,
};
use ioi_types::error::VmError;
use std::path::Path;
use tokio::sync::mpsc::Sender;

pub mod contracts;
pub mod driver;
pub mod http_adapter;
pub mod mock;
pub mod unavailable;

pub use contracts::{
    EmbeddingResult, ImageEditRequest, ImageEmbeddingRequest, ImageGenerationRequest,
    ImageGenerationResult, ModelLifecycleResult, ModelLoadRequest, ModelUnloadRequest,
    RerankCandidateScore, RerankRequest, RerankResult, SpeechSynthesisRequest,
    SpeechSynthesisResult, TextEmbeddingRequest, TextGenerationRequest, TextGenerationResult,
    TranscriptionRequest, TranscriptionResult, VideoGenerationRequest, VideoGenerationResult,
    VisionReadRequest, VisionReadResult,
};
pub use driver::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};
pub use http_adapter::HttpInferenceRuntime;
pub use unavailable::UnavailableInferenceRuntime;

/// A kernel-owned runtime capable of executing deterministic inference plus
/// adjacent first-party media and model lifecycle operations.
#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Executes a model against an input context with specific generation options.
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError>;

    /// Executes inference, optionally streaming partial tokens to the provided channel.
    /// The default implementation delegates to `execute_inference` and ignores the channel.
    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        _token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        self.execute_inference(model_hash, input_context, options)
            .await
    }

    /// Generates a vector embedding for a given text input.
    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        // Default implementation returns an empty vector or error if not supported.
        Err(VmError::HostError(
            "Embedding not supported by this runtime".into(),
        ))
    }

    /// [NEW] Generates a vector embedding for a given image.
    /// Default implementation returns error.
    async fn embed_image(&self, _image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
        Err(VmError::HostError(
            "Image embedding not supported by this runtime".into(),
        ))
    }

    /// Executes a typed text-generation request over the kernel-owned runtime.
    async fn generate_text(
        &self,
        request: TextGenerationRequest,
    ) -> Result<TextGenerationResult, VmError> {
        let output = if request.stream {
            self.execute_inference_streaming(
                request.model_hash,
                &request.input_context,
                request.options,
                None,
            )
            .await?
        } else {
            self.execute_inference(request.model_hash, &request.input_context, request.options)
                .await?
        };

        Ok(TextGenerationResult {
            output,
            model_id: request.model_id,
            streamed: request.stream,
        })
    }

    /// Executes a typed text embedding request.
    async fn embed_text_typed(
        &self,
        request: TextEmbeddingRequest,
    ) -> Result<EmbeddingResult, VmError> {
        let values = self.embed_text(&request.text).await?;
        Ok(EmbeddingResult {
            dimensions: embedding_dimensions(&values),
            values,
            model_id: request.model_id,
        })
    }

    /// Executes a typed image embedding request.
    async fn embed_image_typed(
        &self,
        request: ImageEmbeddingRequest,
    ) -> Result<EmbeddingResult, VmError> {
        let values = self.embed_image(&request.image_bytes).await?;
        Ok(EmbeddingResult {
            dimensions: embedding_dimensions(&values),
            values,
            model_id: request.model_id,
        })
    }

    /// Reranks a set of candidates using a first-party kernel-owned runtime.
    async fn rerank(&self, _request: RerankRequest) -> Result<RerankResult, VmError> {
        Err(unsupported_runtime_operation("rerank"))
    }

    /// Transcribes encoded audio into text.
    async fn transcribe_audio(
        &self,
        _request: TranscriptionRequest,
    ) -> Result<TranscriptionResult, VmError> {
        Err(unsupported_runtime_operation("transcription"))
    }

    /// Synthesizes speech from input text.
    async fn synthesize_speech(
        &self,
        _request: SpeechSynthesisRequest,
    ) -> Result<SpeechSynthesisResult, VmError> {
        Err(unsupported_runtime_operation("speech_synthesis"))
    }

    /// Performs vision or multimodal read over an encoded image input.
    async fn vision_read(&self, _request: VisionReadRequest) -> Result<VisionReadResult, VmError> {
        Err(unsupported_runtime_operation("vision_read"))
    }

    /// Generates an image artifact from a prompt.
    async fn generate_image(
        &self,
        _request: ImageGenerationRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Err(unsupported_runtime_operation("image_generation"))
    }

    /// Edits or inpaints an existing image artifact.
    async fn edit_image(
        &self,
        _request: ImageEditRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Err(unsupported_runtime_operation("image_edit"))
    }

    /// Generates a video artifact from a prompt.
    async fn generate_video(
        &self,
        _request: VideoGenerationRequest,
    ) -> Result<VideoGenerationResult, VmError> {
        Err(unsupported_runtime_operation("video_generation"))
    }

    /// Pre-loads a model into memory/VRAM to reduce latency for subsequent calls.
    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError>;

    /// Offloads a model from memory.
    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError>;

    /// Returns truthful Chat-facing runtime provenance so product surfaces do
    /// not infer it from implementation type names.
    fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
        ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        }
    }

    /// Loads a registered model through the typed first-party lifecycle surface.
    async fn load_registered_model(
        &self,
        request: ModelLoadRequest,
    ) -> Result<ModelLifecycleResult, VmError> {
        self.load_model(request.model_hash, &request.path).await?;
        Ok(ModelLifecycleResult {
            operation: ModelLifecycleOperationKind::Load,
            subject_kind: RegistrySubjectKind::Model,
            subject_id: request
                .model_id
                .unwrap_or_else(|| hex::encode(request.model_hash)),
        })
    }

    /// Unloads a registered model through the typed first-party lifecycle surface.
    async fn unload_registered_model(
        &self,
        request: ModelUnloadRequest,
    ) -> Result<ModelLifecycleResult, VmError> {
        self.unload_model(request.model_hash).await?;
        Ok(ModelLifecycleResult {
            operation: ModelLifecycleOperationKind::Unload,
            subject_kind: RegistrySubjectKind::Model,
            subject_id: request
                .model_id
                .unwrap_or_else(|| hex::encode(request.model_hash)),
        })
    }
}

fn embedding_dimensions(values: &[f32]) -> u32 {
    values.len().min(u32::MAX as usize) as u32
}

fn unsupported_runtime_operation(label: &str) -> VmError {
    VmError::HostError(format!(
        "Operation '{}' not supported by this runtime",
        label
    ))
}

// --- NEW: Safety Traits Moved from Validator to resolve circular dependency ---

/// Represents the output of a safety check by the local BitNet engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    /// The content is safe to proceed.
    Safe,
    /// The content violates safety guidelines (e.g., jailbreak attempt, malicious intent).
    Unsafe(String),
    /// The content contains PII that must be scrubbed.
    ContainsPII,
}

/// The risk surface being evaluated by the local PII firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiRiskSurface {
    /// Content remains on-device and does not cross trust boundaries.
    LocalProcessing,
    /// Content may leave the device (network egress, clipboard, external sink).
    Egress,
}

/// Structured result of a local-only PII inspection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiInspection {
    /// Deterministic evidence produced by Stage A/C.
    pub evidence: EvidenceGraph,
    /// Indicates unresolved ambiguity after local routing/refinement.
    pub ambiguous: bool,
    /// Optional stage status string for review/event logging.
    pub stage2_status: Option<String>,
}

/// Abstract interface for the local CPU-based inference engine (BitNet b1.58).
/// This engine is optimized for low-latency classification and scrubbing.
#[async_trait]
pub trait LocalSafetyModel: Send + Sync {
    /// Classifies the intent of a prompt or action payload.
    async fn classify_intent(&self, input: &str) -> anyhow::Result<SafetyVerdict>;

    /// Identifies spans of text that contain PII or secrets.
    /// Returns a list of (start_index, end_index, category).
    async fn detect_pii(&self, input: &str) -> anyhow::Result<Vec<(usize, usize, String)>>;

    /// Runs local-only PII inspection and returns structured evidence for ontology routing.
    async fn inspect_pii(
        &self,
        input: &str,
        risk_surface: PiiRiskSurface,
    ) -> anyhow::Result<PiiInspection>;
}

// [NEW] Strategy Pattern for Provider Logic (Internal to `api` crate but used in `http_adapter`)
// We define it here or in a separate file, but it's part of the `vm` module's internal structure.
// Since `http_adapter.rs` uses it, we don't necessarily need to export it publicly unless
// we want users to implement their own strategies. For now, keep it internal to `vm`.

// Note: The trait `ProviderStrategy` is defined inside `http_adapter.rs` to keep it private/internal.
// If we wanted it public, we would export it here.
