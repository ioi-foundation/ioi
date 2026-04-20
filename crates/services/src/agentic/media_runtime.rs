use crate::agentic::web::{
    kernel_media_edit_image, kernel_media_generate_image, kernel_media_generate_video,
    kernel_media_synthesize_speech, kernel_media_transcribe_audio, kernel_media_vision_read,
};
use async_trait::async_trait;
use ioi_api::vm::inference::{
    EmbeddingResult, ImageEditRequest, ImageEmbeddingRequest, ImageGenerationRequest,
    ImageGenerationResult, InferenceRuntime, ModelLifecycleResult, ModelLoadRequest,
    ModelUnloadRequest, RerankRequest, RerankResult, SpeechSynthesisRequest, SpeechSynthesisResult,
    TextEmbeddingRequest, TextGenerationRequest, TextGenerationResult, TranscriptionRequest,
    TranscriptionResult, VideoGenerationRequest, VideoGenerationResult, VisionReadRequest,
    VisionReadResult,
};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::StudioRuntimeProvenance;
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

/// Decorates an existing inference runtime with first-party kernel media support.
///
/// This lets Autopilot and other kernel surfaces keep their current text inference backends
/// while absorbing audio transcription and speech synthesis into the shared substrate.
pub struct KernelMediaRuntime {
    inner: Arc<dyn InferenceRuntime>,
}

impl KernelMediaRuntime {
    pub fn new(inner: Arc<dyn InferenceRuntime>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl InferenceRuntime for KernelMediaRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.inner
            .execute_inference(model_hash, input_context, options)
            .await
    }

    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        self.inner
            .execute_inference_streaming(model_hash, input_context, options, token_stream)
            .await
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        self.inner.embed_text(text).await
    }

    async fn embed_image(&self, image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
        self.inner.embed_image(image_bytes).await
    }

    async fn generate_text(
        &self,
        request: TextGenerationRequest,
    ) -> Result<TextGenerationResult, VmError> {
        self.inner.generate_text(request).await
    }

    async fn embed_text_typed(
        &self,
        request: TextEmbeddingRequest,
    ) -> Result<EmbeddingResult, VmError> {
        self.inner.embed_text_typed(request).await
    }

    async fn embed_image_typed(
        &self,
        request: ImageEmbeddingRequest,
    ) -> Result<EmbeddingResult, VmError> {
        self.inner.embed_image_typed(request).await
    }

    async fn rerank(&self, request: RerankRequest) -> Result<RerankResult, VmError> {
        self.inner.rerank(request).await
    }

    async fn transcribe_audio(
        &self,
        request: TranscriptionRequest,
    ) -> Result<TranscriptionResult, VmError> {
        let result = kernel_media_transcribe_audio(
            &request.audio_bytes,
            &request.mime_type,
            request.language.as_deref(),
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(TranscriptionResult {
            text: result.text,
            language: Some(result.language),
            model_id: request.model_id.or(Some(result.model_id)),
        })
    }

    async fn synthesize_speech(
        &self,
        request: SpeechSynthesisRequest,
    ) -> Result<SpeechSynthesisResult, VmError> {
        let result = kernel_media_synthesize_speech(
            &request.text,
            request.voice.as_deref(),
            request.mime_type.as_deref(),
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(SpeechSynthesisResult {
            audio_bytes: result.audio_bytes,
            mime_type: result.mime_type,
            model_id: request.model_id.or(Some(result.backend_id)),
        })
    }

    async fn vision_read(&self, request: VisionReadRequest) -> Result<VisionReadResult, VmError> {
        let result = kernel_media_vision_read(
            self.inner.clone(),
            &request.image_bytes,
            &request.mime_type,
            request.prompt.as_deref(),
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(VisionReadResult {
            output_text: result.output_text,
            model_id: request.model_id.or(Some(result.backend_id)),
        })
    }

    async fn generate_image(
        &self,
        request: ImageGenerationRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        let result = kernel_media_generate_image(
            self.inner.clone(),
            &request.prompt,
            request.mime_type.as_deref(),
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(ImageGenerationResult {
            image_bytes: result.image_bytes,
            mime_type: result.mime_type,
            model_id: request.model_id.or(Some(result.backend_id)),
        })
    }

    async fn edit_image(
        &self,
        request: ImageEditRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        let result = kernel_media_edit_image(
            self.inner.clone(),
            &request.source_image_bytes,
            &request.source_mime_type,
            request.prompt.as_deref(),
            request.mask_image_bytes.as_deref(),
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(ImageGenerationResult {
            image_bytes: result.image_bytes,
            mime_type: result.mime_type,
            model_id: request.model_id.or(Some(result.backend_id)),
        })
    }

    async fn generate_video(
        &self,
        request: VideoGenerationRequest,
    ) -> Result<VideoGenerationResult, VmError> {
        let result = kernel_media_generate_video(
            self.inner.clone(),
            &request.prompt,
            request.mime_type.as_deref(),
            request.duration_ms,
        )
        .await
        .map_err(|error| VmError::HostError(error.to_string()))?;
        Ok(VideoGenerationResult {
            video_bytes: result.video_bytes,
            mime_type: result.mime_type,
            model_id: request.model_id.or(Some(result.backend_id)),
        })
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        self.inner.load_model(model_hash, path).await
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        self.inner.unload_model(model_hash).await
    }

    async fn load_registered_model(
        &self,
        request: ModelLoadRequest,
    ) -> Result<ModelLifecycleResult, VmError> {
        self.inner.load_registered_model(request).await
    }

    async fn unload_registered_model(
        &self,
        request: ModelUnloadRequest,
    ) -> Result<ModelLifecycleResult, VmError> {
        self.inner.unload_registered_model(request).await
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.inner.studio_runtime_provenance()
    }
}

#[cfg(test)]
#[path = "media_runtime/tests.rs"]
mod tests;
