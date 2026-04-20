use super::*;
use async_trait::async_trait;
use std::env;
use tempfile::tempdir;

struct EchoRuntime;

struct FailingInferenceRuntime;

#[async_trait]
impl InferenceRuntime for EchoRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(input_context.to_vec())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    async fn generate_image(
        &self,
        request: ImageGenerationRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Ok(ImageGenerationResult {
            image_bytes: request.prompt.into_bytes(),
            mime_type: request.mime_type.unwrap_or_else(|| "image/png".to_string()),
            model_id: Some("echo-image-runtime".to_string()),
        })
    }

    async fn edit_image(
        &self,
        request: ImageEditRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Ok(ImageGenerationResult {
            image_bytes: request
                .prompt
                .unwrap_or_else(|| "echo-edit-runtime".to_string())
                .into_bytes(),
            mime_type: request.source_mime_type,
            model_id: Some("echo-image-edit-runtime".to_string()),
        })
    }

    async fn generate_video(
        &self,
        request: VideoGenerationRequest,
    ) -> Result<VideoGenerationResult, VmError> {
        Ok(VideoGenerationResult {
            video_bytes: request.prompt.into_bytes(),
            mime_type: request.mime_type.unwrap_or_else(|| "video/mp4".to_string()),
            model_id: Some("echo-video-runtime".to_string()),
        })
    }
}

#[async_trait]
impl InferenceRuntime for FailingInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "mock runtime does not support multimodal inference".into(),
        ))
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

struct ScopedEnv {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: impl AsRef<str>) -> Self {
        let previous = env::var(key).ok();
        env::set_var(key, value.as_ref());
        Self { key, previous }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            env::set_var(self.key, previous);
        } else {
            env::remove_var(self.key);
        }
    }
}

#[tokio::test]
async fn synthesize_speech_uses_kernel_media_fallback_when_requested() {
    let temp_dir = tempdir().expect("tempdir");
    let _tool_home = ScopedEnv::set(
        "IOI_MEDIA_TOOL_HOME",
        temp_dir.path().to_string_lossy().to_string(),
    );
    let _tts_backend = ScopedEnv::set("IOI_MEDIA_TTS_BACKEND", "fallback");
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let result = runtime
        .synthesize_speech(SpeechSynthesisRequest {
            text: "hello from kernel media".to_string(),
            voice: None,
            mime_type: Some("audio/wav".to_string()),
            model_id: None,
        })
        .await
        .expect("speech synthesis should succeed");

    assert_eq!(result.mime_type, "audio/wav");
    assert_eq!(result.audio_bytes.get(0..4), Some(b"RIFF".as_slice()));
    assert_eq!(
        result.model_id.as_deref(),
        Some("kernel:tts:fallback_waveform")
    );
}

#[tokio::test]
async fn transcribe_audio_rejects_empty_audio_before_runtime_downloads() {
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let error = runtime
        .transcribe_audio(TranscriptionRequest {
            audio_bytes: Vec::new(),
            mime_type: "audio/wav".to_string(),
            language: Some("en".to_string()),
            model_id: None,
        })
        .await
        .expect_err("empty audio should fail");

    assert!(error.to_string().contains("requires non-empty audio bytes"));
}

#[tokio::test]
async fn vision_read_falls_back_to_local_summary_when_runtime_is_not_multimodal() {
    let runtime = KernelMediaRuntime::new(Arc::new(FailingInferenceRuntime));

    let result = runtime
        .vision_read(VisionReadRequest {
            image_bytes: tiny_png_bytes(),
            mime_type: "image/png".to_string(),
            prompt: Some("summarize the screenshot".to_string()),
            model_id: None,
        })
        .await
        .expect("vision read should succeed via local fallback");

    assert!(result.output_text.contains("Local fallback vision summary"));
    assert!(result.output_text.contains("2x2"));
    assert_eq!(
        result.model_id.as_deref(),
        Some("kernel:vision:fallback_summary")
    );
}

#[tokio::test]
async fn generate_image_prefers_underlying_runtime_when_available() {
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let result = runtime
        .generate_image(ImageGenerationRequest {
            prompt: "render a skyline".to_string(),
            mime_type: Some("image/jpeg".to_string()),
            model_id: None,
        })
        .await
        .expect("image generation should delegate when runtime supports it");

    assert_eq!(result.image_bytes, b"render a skyline".to_vec());
    assert_eq!(result.mime_type, "image/jpeg");
    assert_eq!(result.model_id.as_deref(), Some("echo-image-runtime"));
}

#[tokio::test]
async fn generate_image_falls_back_to_kernel_renderer_when_runtime_is_unsupported() {
    let runtime = KernelMediaRuntime::new(Arc::new(FailingInferenceRuntime));

    let result = runtime
        .generate_image(ImageGenerationRequest {
            prompt: "a wide sunset over the sea".to_string(),
            mime_type: None,
            model_id: None,
        })
        .await
        .expect("image generation should succeed via kernel fallback");

    assert_eq!(result.mime_type, "image/png");
    assert_eq!(
        result.image_bytes.get(0..8),
        Some(b"\x89PNG\r\n\x1a\n".as_slice())
    );
    let image = image::load_from_memory(&result.image_bytes).expect("fallback bytes should decode");
    assert_eq!(image.width(), 1_280);
    assert_eq!(image.height(), 768);
    assert_eq!(
        result.model_id.as_deref(),
        Some("kernel:image:fallback_landscape")
    );
}

#[tokio::test]
async fn edit_image_prefers_underlying_runtime_when_available() {
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let result = runtime
        .edit_image(ImageEditRequest {
            source_image_bytes: tiny_png_bytes(),
            source_mime_type: "image/png".to_string(),
            prompt: Some("sepia".to_string()),
            mask_image_bytes: None,
            model_id: None,
        })
        .await
        .expect("image edit should delegate when runtime supports it");

    assert_eq!(result.image_bytes, b"sepia".to_vec());
    assert_eq!(result.mime_type, "image/png");
    assert_eq!(result.model_id.as_deref(), Some("echo-image-edit-runtime"));
}

#[tokio::test]
async fn edit_image_falls_back_to_masked_kernel_renderer_when_runtime_is_unsupported() {
    let runtime = KernelMediaRuntime::new(Arc::new(FailingInferenceRuntime));
    let source = solid_png_bytes([32, 90, 220], 4, 4);
    let mask = half_mask_png_bytes(4, 4);

    let result = runtime
        .edit_image(ImageEditRequest {
            source_image_bytes: source,
            source_mime_type: "image/png".to_string(),
            prompt: Some("warm and brighten the portrait".to_string()),
            mask_image_bytes: Some(mask),
            model_id: None,
        })
        .await
        .expect("image edit should succeed via kernel fallback");

    assert_eq!(result.mime_type, "image/png");
    let image = image::load_from_memory(&result.image_bytes).expect("fallback edit should decode");
    let rgba = image.to_rgba8();
    assert_eq!(rgba.width(), 4);
    assert_eq!(rgba.height(), 4);
    assert_ne!(&rgba.get_pixel(0, 0).0[..3], &[32, 90, 220]);
    assert_eq!(&rgba.get_pixel(3, 0).0[..3], &[32, 90, 220]);
    assert_eq!(
        result.model_id.as_deref(),
        Some("kernel:image_edit:fallback_warm_masked")
    );
}

#[tokio::test]
async fn generate_video_prefers_underlying_runtime_when_available() {
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let result = runtime
        .generate_video(VideoGenerationRequest {
            prompt: "make waves move".to_string(),
            mime_type: Some("video/mp4".to_string()),
            duration_ms: Some(1_800),
            model_id: None,
        })
        .await
        .expect("video generation should delegate when runtime supports it");

    assert_eq!(result.video_bytes, b"make waves move".to_vec());
    assert_eq!(result.mime_type, "video/mp4");
    assert_eq!(result.model_id.as_deref(), Some("echo-video-runtime"));
}

#[tokio::test]
async fn generate_video_falls_back_to_kernel_animated_gif_when_runtime_is_unsupported() {
    let runtime = KernelMediaRuntime::new(Arc::new(FailingInferenceRuntime));

    let result = runtime
        .generate_video(VideoGenerationRequest {
            prompt: "an orbital galaxy looping in motion".to_string(),
            mime_type: Some("video/mp4".to_string()),
            duration_ms: Some(2_200),
            model_id: None,
        })
        .await
        .expect("video generation should succeed via kernel fallback");

    assert_eq!(result.mime_type, "image/gif");
    assert_eq!(result.video_bytes.get(0..6), Some(b"GIF89a".as_slice()));
    let decoder = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(&result.video_bytes))
        .expect("fallback gif should decode");
    let frames = image::AnimationDecoder::into_frames(decoder)
        .collect_frames()
        .expect("fallback gif frames should decode");
    assert!(frames.len() >= 6);
    assert_eq!(
        result.model_id.as_deref(),
        Some("kernel:video:fallback_gif_orbital")
    );
}

#[tokio::test]
async fn execute_inference_delegates_to_inner_runtime() {
    let runtime = KernelMediaRuntime::new(Arc::new(EchoRuntime));

    let result = runtime
        .execute_inference([7_u8; 32], b"echo", InferenceOptions::default())
        .await
        .expect("delegated inference should succeed");

    assert_eq!(result, b"echo".to_vec());
}

fn tiny_png_bytes() -> Vec<u8> {
    let image = image::DynamicImage::ImageRgb8(image::ImageBuffer::from_fn(2, 2, |x, y| {
        if (x + y) % 2 == 0 {
            image::Rgb([240, 240, 240])
        } else {
            image::Rgb([16, 48, 220])
        }
    }));
    let mut bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut bytes);
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .expect("encode png");
    bytes
}

fn solid_png_bytes(color: [u8; 3], width: u32, height: u32) -> Vec<u8> {
    let image = image::DynamicImage::ImageRgb8(image::ImageBuffer::from_pixel(
        width,
        height,
        image::Rgb(color),
    ));
    let mut bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut bytes);
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .expect("encode solid png");
    bytes
}

fn half_mask_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let image =
        image::DynamicImage::ImageLuma8(image::ImageBuffer::from_fn(width, height, |x, _| {
            if x < width / 2 {
                image::Luma([255])
            } else {
                image::Luma([0])
            }
        }));
    let mut bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut bytes);
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .expect("encode mask png");
    bytes
}
