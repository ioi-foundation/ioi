pub async fn edge_media_extract_transcript(
    url: &str,
    language: Option<&str>,
    max_chars: Option<u32>,
    browser: Arc<BrowserDriver>,
) -> Result<MediaTranscriptBundle> {
    let requested_url = validate_media_url(url, "media__extract_transcript")?;
    let requested_language = normalize_requested_language(language);
    let transcript_max_chars = max_chars
        .unwrap_or(MEDIA_DEFAULT_MAX_CHARS)
        .clamp(1, MEDIA_MAX_CHARS_LIMIT) as usize;
    let tool_home = ensure_media_tool_home()?;
    let (ytdlp_discovery, ytdlp_failure_reason) =
        discover_optional_ytdlp(requested_url.as_str(), &tool_home).await;
    let (watch_page, watch_page_failure_reason) =
        match discover_youtube_watch_page_context(requested_url.as_str()).await {
            Ok(value) => (value, None),
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        };
    let (_, artifact) = extract_transcript_artifact(
        requested_url.as_str(),
        &requested_language,
        transcript_max_chars,
        &tool_home,
        browser,
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        true,
    )
    .await?;
    let artifact = artifact.ok_or_else(|| {
        anyhow!(
            "ERROR_CLASS=DiscoveryMissing media transcript discovery found no admissible provider candidates for requested_language={} url={}",
            requested_language,
            requested_url
        )
    })?;
    write_run_receipt(&tool_home, &artifact.receipt)?;
    Ok(artifact.bundle)
}

pub async fn edge_media_extract_multimodal_evidence(
    url: &str,
    language: Option<&str>,
    max_chars: Option<u32>,
    frame_limit: Option<u32>,
    browser: Arc<BrowserDriver>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<MediaMultimodalBundle> {
    let requested_url = validate_media_url(url, "media__extract_evidence")?;
    let requested_language = normalize_requested_language(language);
    let transcript_max_chars = max_chars
        .unwrap_or(MEDIA_MULTIMODAL_DEFAULT_MAX_CHARS)
        .clamp(1, MEDIA_MAX_CHARS_LIMIT) as usize;
    let visual_frame_limit = frame_limit
        .unwrap_or(MEDIA_VISUAL_DEFAULT_FRAME_LIMIT)
        .clamp(1, MEDIA_VISUAL_MAX_FRAME_LIMIT);
    let tool_home = ensure_media_tool_home()?;
    let (ytdlp_discovery, ytdlp_failure_reason) =
        discover_optional_ytdlp(requested_url.as_str(), &tool_home).await;
    let (watch_page, watch_page_failure_reason) =
        match discover_youtube_watch_page_context(requested_url.as_str()).await {
            Ok(value) => (value, None),
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        };

    let (mut provider_candidates, transcript_artifact) = extract_transcript_artifact(
        requested_url.as_str(),
        &requested_language,
        transcript_max_chars,
        &tool_home,
        browser.clone(),
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        false,
    )
    .await?;
    let (timeline_candidates, timeline_artifact) = extract_timeline_artifact(
        requested_url.as_str(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
    );
    provider_candidates.extend(timeline_candidates);

    let transcript_segments = transcript_artifact
        .as_ref()
        .map(|artifact| artifact.segments.as_slice());
    let (visual_candidates, visual_artifact) = extract_visual_artifact(
        requested_url.as_str(),
        visual_frame_limit,
        &tool_home,
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        transcript_segments,
        inference,
    )
    .await?;
    provider_candidates.extend(visual_candidates);

    let mut selected_modalities = Vec::new();
    let mut selected_provider_ids = Vec::new();
    if let Some(artifact) = transcript_artifact.as_ref() {
        selected_modalities.push("transcript".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }
    if let Some(artifact) = timeline_artifact.as_ref() {
        selected_modalities.push("timeline".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }
    if let Some(artifact) = visual_artifact.as_ref() {
        selected_modalities.push("visual".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }

    if selected_modalities.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=DiscoveryMissing media multimodal discovery found no admissible transcript, timeline, or visual providers for url={}",
            requested_url
        ));
    }

    let canonical_url = media_canonical_url(
        requested_url.as_str(),
        ytdlp_discovery.as_ref(),
        watch_page.as_ref(),
    );
    let title = media_title(ytdlp_discovery.as_ref(), watch_page.as_ref());
    let duration_seconds = media_duration_seconds(ytdlp_discovery.as_ref(), watch_page.as_ref());
    let retrieved_at_ms = now_ms();

    let transcript_bundle = transcript_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let timeline_bundle = timeline_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let visual_bundle = visual_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let bundle = MediaMultimodalBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_evidence".to_string(),
        requested_url: requested_url.to_string(),
        canonical_url: canonical_url.clone(),
        title: title.clone(),
        duration_seconds,
        requested_language: requested_language.clone(),
        provider_candidates: provider_candidates.clone(),
        selected_modalities: selected_modalities.clone(),
        selected_provider_ids: selected_provider_ids.clone(),
        transcript: transcript_bundle.clone(),
        timeline: timeline_bundle.clone(),
        visual: visual_bundle.clone(),
    };

    let mut receipt = MediaMultimodalRunReceipt {
        schema_version: 1,
        requested_url: requested_url.to_string(),
        canonical_url,
        title,
        duration_seconds,
        requested_language,
        selected_modalities,
        selected_provider_ids,
        retrieved_at_ms,
        ..MediaMultimodalRunReceipt::default()
    };
    if let Some(artifact) = transcript_artifact {
        receipt.transcript_provider_id = Some(artifact.receipt.provider_id);
        receipt.transcript_provider_version = Some(artifact.receipt.provider_version);
        receipt.transcript_provider_binary_path = Some(artifact.receipt.provider_binary_path);
        receipt.transcript_provider_model_id = artifact.receipt.provider_model_id;
        receipt.transcript_provider_model_path = artifact.receipt.provider_model_path;
        receipt.transcript_selected_audio_format_id = artifact.receipt.selected_audio_format_id;
        receipt.transcript_selected_audio_ext = artifact.receipt.selected_audio_ext;
        receipt.transcript_selected_audio_acodec = artifact.receipt.selected_audio_acodec;
        receipt.transcript_language = Some(artifact.receipt.transcript_language);
        receipt.transcript_source_kind = Some(artifact.receipt.transcript_source_kind);
        receipt.transcript_char_count = Some(artifact.receipt.transcript_char_count);
        receipt.transcript_segment_count = Some(artifact.receipt.segment_count);
        receipt.transcript_hash = Some(artifact.receipt.transcript_hash);
    }
    if let Some(artifact) = timeline_artifact {
        receipt.timeline_provider_id = artifact.receipt.timeline_provider_id;
        receipt.timeline_provider_version = artifact.receipt.timeline_provider_version;
        receipt.timeline_source_kind = artifact.receipt.timeline_source_kind;
        receipt.timeline_cue_count = artifact.receipt.timeline_cue_count;
        receipt.timeline_char_count = artifact.receipt.timeline_char_count;
        receipt.timeline_hash = artifact.receipt.timeline_hash;
    }
    if let Some(artifact) = visual_artifact {
        receipt.visual_provider_id = artifact.receipt.visual_provider_id;
        receipt.visual_provider_version = artifact.receipt.visual_provider_version;
        receipt.visual_provider_binary_path = artifact.receipt.visual_provider_binary_path;
        receipt.visual_ffprobe_path = artifact.receipt.visual_ffprobe_path;
        receipt.visual_selected_video_format_id = artifact.receipt.visual_selected_video_format_id;
        receipt.visual_selected_video_ext = artifact.receipt.visual_selected_video_ext;
        receipt.visual_selected_video_codec = artifact.receipt.visual_selected_video_codec;
        receipt.visual_frame_count = artifact.receipt.visual_frame_count;
        receipt.visual_char_count = artifact.receipt.visual_char_count;
        receipt.visual_hash = artifact.receipt.visual_hash;
        receipt.visual_summary_char_count = artifact.receipt.visual_summary_char_count;
    }
    write_multimodal_run_receipt(&tool_home, &receipt)?;
    Ok(bundle)
}

use std::f32::consts::TAU;
use std::io::Write;
use tempfile::Builder as TempFileBuilder;

const MEDIA_TTS_BACKEND_ENV: &str = "IOI_MEDIA_TTS_BACKEND";
const MEDIA_TTS_TIMEOUT_SECS: u64 = 45;
const MEDIA_IMAGE_TIMEOUT_SECS: u64 = 75;
const MEDIA_VIDEO_TIMEOUT_SECS: u64 = 90;
const MEDIA_IMAGE_JPEG_QUALITY: u8 = 88;
const MEDIA_VISION_MAX_DIM: u32 = 1_024;
const MEDIA_VISION_JPEG_QUALITY: u8 = 72;
const MEDIA_VIDEO_DEFAULT_DURATION_MS: u64 = 2_400;
const MEDIA_VIDEO_MIN_DURATION_MS: u64 = 1_200;
const MEDIA_VIDEO_MAX_DURATION_MS: u64 = 6_000;
const MEDIA_VIDEO_FRAME_MAX_DIM: u32 = 480;
const FALLBACK_TTS_SAMPLE_RATE: u32 = 16_000;
const FALLBACK_TTS_CHAR_LIMIT: usize = 480;
const FALLBACK_TTS_TONE_MS: usize = 42;
const FALLBACK_TTS_GAP_MS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMediaTranscription {
    pub text: String,
    pub language: String,
    pub model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMediaSpeechSynthesis {
    pub audio_bytes: Vec<u8>,
    pub mime_type: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMediaVisionRead {
    pub output_text: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMediaImageGeneration {
    pub image_bytes: Vec<u8>,
    pub mime_type: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMediaVideoGeneration {
    pub video_bytes: Vec<u8>,
    pub mime_type: String,
    pub backend_id: String,
}

pub async fn kernel_media_transcribe_audio(
    audio_bytes: &[u8],
    mime_type: &str,
    language: Option<&str>,
) -> Result<KernelMediaTranscription> {
    if audio_bytes.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media transcription requires non-empty audio bytes."
        ));
    }

    let mime_type = compact_ws(mime_type);
    if mime_type.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media transcription requires a non-empty mime_type."
        ));
    }

    let tool_home = ensure_media_tool_home()?;
    let runtime_dir = tool_home.join("runtime").join("transcription");
    fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create transcription runtime dir {}",
            runtime_dir.display()
        )
    })?;

    let suffix = format!(".{}", audio_extension_for_mime(&mime_type));
    let mut input_file = TempFileBuilder::new()
        .prefix("kernel-transcription-")
        .suffix(&suffix)
        .tempfile_in(&runtime_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to create temporary transcription input under {}",
                runtime_dir.display()
            )
        })?;
    input_file
        .write_all(audio_bytes)
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to persist transcription input")?;
    input_file
        .flush()
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to flush transcription input")?;

    let requested_language = normalize_requested_language(language);
    let whisper_language = whisper_language_code(&requested_language).to_string();
    let model = ensure_managed_whisper_model(&tool_home).await?;
    let segments =
        transcribe_audio_with_managed_whisper(&model, input_file.path(), &whisper_language).await?;
    if segments.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing audio transcription produced no transcript segments."
        ));
    }

    let text = compact_ws(
        &segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
    if text.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing audio transcription produced an empty transcript."
        ));
    }

    Ok(KernelMediaTranscription {
        text,
        language: whisper_language,
        model_id: format!("managed_whisper:{}@{}", model.model_id, model.revision),
    })
}

pub async fn kernel_media_synthesize_speech(
    text: &str,
    voice: Option<&str>,
    preferred_mime_type: Option<&str>,
) -> Result<KernelMediaSpeechSynthesis> {
    let text = compact_ws(text);
    if text.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media speech synthesis requires non-empty text."
        ));
    }

    let tool_home = ensure_media_tool_home()?;
    let runtime_dir = tool_home.join("runtime").join("speech");
    fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create speech runtime dir {}",
            runtime_dir.display()
        )
    })?;

    let normalized_preference = preferred_mime_type
        .map(compact_ws)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    if let Some(forced_backend) = configured_tts_backend() {
        if forced_backend == "fallback" {
            return Ok(fallback_speech_synthesis(&text));
        }
        return run_forced_tts_backend(
            &forced_backend,
            &text,
            voice,
            normalized_preference.as_deref(),
            &runtime_dir,
        )
        .await;
    }

    let mut failures = Vec::new();
    for backend in auto_tts_backends() {
        match run_tts_backend(backend, &text, voice, normalized_preference.as_deref(), &runtime_dir)
            .await
        {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => continue,
            Err(error) => failures.push(format!("{}: {}", backend, error)),
        }
    }

    if failures.is_empty() {
        Ok(fallback_speech_synthesis(&text))
    } else {
        let mut fallback = fallback_speech_synthesis(&text);
        fallback.backend_id = format!(
            "{}+fallback",
            failures
                .first()
                .map(|value| value.split(':').next().unwrap_or("kernel:tts:auto"))
                .unwrap_or("kernel:tts:auto")
        );
        Ok(fallback)
    }
}

pub async fn kernel_media_vision_read(
    inference: Arc<dyn InferenceRuntime>,
    image_bytes: &[u8],
    mime_type: &str,
    prompt: Option<&str>,
) -> Result<KernelMediaVisionRead> {
    if image_bytes.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media vision read requires non-empty image bytes."
        ));
    }

    let requested_prompt = prompt.map(compact_ws).filter(|value| !value.is_empty());
    let normalized_prompt = requested_prompt
        .clone()
        .unwrap_or_else(|| "Describe the visible image literally. Include readable text, interface layout, objects, and notable colors without speculation.".to_string());
    let (encoded_bytes, encoded_mime_type, fallback_summary) =
        prepare_vision_image_payload(image_bytes, mime_type, requested_prompt.as_deref())?;
    let messages = build_kernel_vision_messages(&encoded_bytes, &encoded_mime_type, &normalized_prompt);
    let payload = serde_json::to_vec(&messages)
        .context("ERROR_CLASS=SynthesisFailed failed to serialize kernel vision prompt")?;
    let options = InferenceOptions {
        tools: Vec::new(),
        temperature: 0.0,
        json_mode: true,
        max_tokens: 500,
        stop_sequences: Vec::new(),
        required_finality_tier: Default::default(),
        sealed_finality_proof: None,
        canonical_collapse_object: None,
    };

    match timeout(
        Duration::from_secs(VISION_PROBE_TIMEOUT_SECS),
        inference.execute_inference([0u8; 32], &payload, options),
    )
    .await
    {
        Ok(Ok(raw)) => {
            if let Some(output_text) = parse_kernel_vision_output(&raw) {
                return Ok(KernelMediaVisionRead {
                    output_text,
                    backend_id: "kernel:vision:multimodal_runtime".to_string(),
                });
            }
        }
        Ok(Err(_)) | Err(_) => {}
    }

    Ok(KernelMediaVisionRead {
        output_text: fallback_summary,
        backend_id: "kernel:vision:fallback_summary".to_string(),
    })
}

pub async fn kernel_media_generate_image(
    inference: Arc<dyn InferenceRuntime>,
    prompt: &str,
    preferred_mime_type: Option<&str>,
) -> Result<KernelMediaImageGeneration> {
    let prompt = compact_ws(prompt);
    if prompt.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media image generation requires non-empty prompt."
        ));
    }

    let normalized_preference = normalize_image_output_mime_type(preferred_mime_type);
    let runtime_request = ImageGenerationRequest {
        prompt: prompt.clone(),
        mime_type: normalized_preference.clone(),
        model_id: None,
    };

    match timeout(
        Duration::from_secs(MEDIA_IMAGE_TIMEOUT_SECS),
        inference.generate_image(runtime_request),
    )
    .await
    {
        Ok(Ok(result)) if !result.image_bytes.is_empty() => {
            let mime_type = compact_ws(&result.mime_type);
            return Ok(KernelMediaImageGeneration {
                image_bytes: result.image_bytes,
                mime_type: if mime_type.is_empty() {
                    normalized_preference
                        .clone()
                        .unwrap_or_else(|| "image/png".to_string())
                } else {
                    mime_type
                },
                backend_id: result
                    .model_id
                    .unwrap_or_else(|| "kernel:image:runtime".to_string()),
            });
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }

    generate_fallback_image(&prompt, normalized_preference.as_deref())
}

pub async fn kernel_media_edit_image(
    inference: Arc<dyn InferenceRuntime>,
    source_image_bytes: &[u8],
    source_mime_type: &str,
    prompt: Option<&str>,
    mask_image_bytes: Option<&[u8]>,
) -> Result<KernelMediaImageGeneration> {
    if source_image_bytes.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media image edit requires non-empty source image bytes."
        ));
    }

    let normalized_source_mime = normalize_image_output_mime_type(Some(source_mime_type))
        .unwrap_or_else(|| "image/png".to_string());
    let normalized_prompt = prompt.map(compact_ws).filter(|value| !value.is_empty());
    let runtime_request = ImageEditRequest {
        source_image_bytes: source_image_bytes.to_vec(),
        source_mime_type: normalized_source_mime.clone(),
        prompt: normalized_prompt.clone(),
        mask_image_bytes: mask_image_bytes.map(|bytes| bytes.to_vec()),
        model_id: None,
    };

    match timeout(
        Duration::from_secs(MEDIA_IMAGE_TIMEOUT_SECS),
        inference.edit_image(runtime_request),
    )
    .await
    {
        Ok(Ok(result)) if !result.image_bytes.is_empty() => {
            let mime_type = compact_ws(&result.mime_type);
            return Ok(KernelMediaImageGeneration {
                image_bytes: result.image_bytes,
                mime_type: if mime_type.is_empty() {
                    normalized_source_mime.clone()
                } else {
                    mime_type
                },
                backend_id: result
                    .model_id
                    .unwrap_or_else(|| "kernel:image_edit:runtime".to_string()),
            });
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }

    fallback_edit_image(
        source_image_bytes,
        &normalized_source_mime,
        normalized_prompt.as_deref(),
        mask_image_bytes,
    )
}

pub async fn kernel_media_generate_video(
    inference: Arc<dyn InferenceRuntime>,
    prompt: &str,
    preferred_mime_type: Option<&str>,
    duration_ms: Option<u64>,
) -> Result<KernelMediaVideoGeneration> {
    let prompt = compact_ws(prompt);
    if prompt.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media video generation requires non-empty prompt."
        ));
    }

    let normalized_duration = duration_ms
        .unwrap_or(MEDIA_VIDEO_DEFAULT_DURATION_MS)
        .clamp(MEDIA_VIDEO_MIN_DURATION_MS, MEDIA_VIDEO_MAX_DURATION_MS);
    let normalized_preference = normalize_video_output_mime_type(preferred_mime_type);
    let runtime_request = VideoGenerationRequest {
        prompt: prompt.clone(),
        mime_type: normalized_preference.clone(),
        duration_ms: Some(normalized_duration),
        model_id: None,
    };

    match timeout(
        Duration::from_secs(MEDIA_VIDEO_TIMEOUT_SECS),
        inference.generate_video(runtime_request),
    )
    .await
    {
        Ok(Ok(result)) if !result.video_bytes.is_empty() => {
            let mime_type = compact_ws(&result.mime_type);
            return Ok(KernelMediaVideoGeneration {
                video_bytes: result.video_bytes,
                mime_type: if mime_type.is_empty() {
                    normalized_preference
                        .clone()
                        .unwrap_or_else(|| "video/mp4".to_string())
                } else {
                    mime_type
                },
                backend_id: result
                    .model_id
                    .unwrap_or_else(|| "kernel:video:runtime".to_string()),
            });
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }

    generate_fallback_video(&prompt, normalized_duration)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackImageScene {
    Abstract,
    Diagram,
    Landscape,
    Orbital,
    Portrait,
}

#[derive(Debug, Clone, Copy)]
struct FallbackImagePalette {
    background_top: [u8; 3],
    background_bottom: [u8; 3],
    accent_primary: [u8; 3],
    accent_secondary: [u8; 3],
    accent_tertiary: [u8; 3],
    ink: [u8; 3],
}

#[derive(Debug, Clone, Copy)]
struct FallbackImageEditProfile {
    grayscale: bool,
    sepia: bool,
    invert: bool,
    blur_sigma: f32,
    brightness: i32,
    contrast: f32,
    saturation: f32,
    hue_rotate: i32,
    tint_strength: f32,
    vignette_strength: f32,
    tint_color: [u8; 3],
    label: &'static str,
}

fn normalize_image_output_mime_type(preferred_mime_type: Option<&str>) -> Option<String> {
    preferred_mime_type
        .map(compact_ws)
        .map(|value| value.to_ascii_lowercase())
        .and_then(|value| match value.as_str() {
            "image/jpeg" | "image/jpg" => Some("image/jpeg".to_string()),
            "image/png" => Some("image/png".to_string()),
            _ if value.is_empty() => None,
            _ => Some("image/png".to_string()),
        })
}

fn normalize_video_output_mime_type(preferred_mime_type: Option<&str>) -> Option<String> {
    preferred_mime_type
        .map(compact_ws)
        .map(|value| value.to_ascii_lowercase())
        .and_then(|value| match value.as_str() {
            "image/gif" | "video/gif" | "gif" => Some("image/gif".to_string()),
            "video/mp4" | "video/webm" | "video/quicktime" => Some(value),
            _ if value.is_empty() => None,
            _ => Some("image/gif".to_string()),
        })
}

fn fallback_edit_image(
    source_image_bytes: &[u8],
    source_mime_type: &str,
    prompt: Option<&str>,
    mask_image_bytes: Option<&[u8]>,
) -> Result<KernelMediaImageGeneration> {
    let source_image = image::load_from_memory(source_image_bytes).with_context(|| {
        "ERROR_CLASS=TargetNotFound media image edit fallback could not decode source image bytes."
    })?;
    let prompt_text = prompt.unwrap_or("");
    let prompt_lower = prompt_text.to_ascii_lowercase();
    let mut seed_input = Vec::with_capacity(source_image_bytes.len().min(512) + prompt_text.len());
    seed_input.extend_from_slice(&source_image_bytes[..source_image_bytes.len().min(512)]);
    seed_input.extend_from_slice(prompt_text.as_bytes());
    let seed = Sha256::digest(&seed_input);
    let palette = fallback_image_palette(&prompt_lower, &seed);
    let profile =
        fallback_image_edit_profile(&prompt_lower, &seed, palette, mask_image_bytes.is_some());
    let source_rgba = source_image.to_rgba8();
    let edited_rgba = apply_fallback_edit_profile(&source_image, profile);
    let output_rgba = if let Some(mask_bytes) = mask_image_bytes {
        composite_masked_edit(&source_rgba, &edited_rgba, mask_bytes)?
    } else {
        edited_rgba
    };
    let output_image = DynamicImage::ImageRgba8(output_rgba);
    let (image_bytes, mime_type) = encode_generated_image(&output_image, source_mime_type)?;
    let mut backend_id = format!("kernel:image_edit:fallback_{}", profile.label);
    if mask_image_bytes.is_some() {
        backend_id.push_str("_masked");
    }
    Ok(KernelMediaImageGeneration {
        image_bytes,
        mime_type,
        backend_id,
    })
}

fn generate_fallback_image(
    prompt: &str,
    preferred_mime_type: Option<&str>,
) -> Result<KernelMediaImageGeneration> {
    let prompt_lower = prompt.to_ascii_lowercase();
    let scene = classify_fallback_image_scene(&prompt_lower);
    let seed = Sha256::digest(prompt.as_bytes());
    let palette = fallback_image_palette(&prompt_lower, &seed);
    let (width, height) = fallback_image_dimensions(&prompt_lower);
    let canvas = build_fallback_scene_canvas(scene, palette, &seed, width, height);

    let image = DynamicImage::ImageRgb8(canvas);
    let (image_bytes, mime_type) =
        encode_generated_image(&image, preferred_mime_type.unwrap_or("image/png"))?;
    Ok(KernelMediaImageGeneration {
        image_bytes,
        mime_type,
        backend_id: format!("kernel:image:fallback_{:?}", scene).to_ascii_lowercase(),
    })
}

fn generate_fallback_video(
    prompt: &str,
    duration_ms: u64,
) -> Result<KernelMediaVideoGeneration> {
    let prompt_lower = prompt.to_ascii_lowercase();
    let scene = classify_fallback_image_scene(&prompt_lower);
    let seed = Sha256::digest(prompt.as_bytes());
    let palette = fallback_image_palette(&prompt_lower, &seed);
    let (image_width, image_height) = fallback_image_dimensions(&prompt_lower);
    let (frame_width, frame_height) =
        scale_video_dimensions(image_width, image_height, MEDIA_VIDEO_FRAME_MAX_DIM);
    let base_canvas = build_fallback_scene_canvas(scene, palette, &seed, frame_width, frame_height);
    let base_rgba = DynamicImage::ImageRgb8(base_canvas).to_rgba8();
    let frame_count = ((duration_ms / 220).clamp(6, 14)) as usize;
    let delay_ms = (duration_ms / frame_count as u64).clamp(70, 400) as u32;
    let mut frames = Vec::with_capacity(frame_count);

    for frame_index in 0..frame_count {
        let buffer =
            build_fallback_video_frame(&base_rgba, scene, palette, &seed, frame_index, frame_count);
        frames.push(Frame::from_parts(
            buffer,
            0,
            0,
            Delay::from_numer_denom_ms(delay_ms, 1),
        ));
    }

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut encoder = GifEncoder::new(&mut cursor);
        encoder
            .set_repeat(Repeat::Infinite)
            .context("ERROR_CLASS=SynthesisFailed failed to configure fallback GIF repeat mode")?;
        encoder
            .encode_frames(frames)
            .context("ERROR_CLASS=SynthesisFailed failed to encode fallback animated GIF")?;
    }

    Ok(KernelMediaVideoGeneration {
        video_bytes: cursor.into_inner(),
        mime_type: "image/gif".to_string(),
        backend_id: format!("kernel:video:fallback_gif_{:?}", scene).to_ascii_lowercase(),
    })
}

fn build_fallback_scene_canvas(
    scene: FallbackImageScene,
    palette: FallbackImagePalette,
    seed: &[u8],
    width: u32,
    height: u32,
) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
    let mut canvas = ImageBuffer::from_pixel(width, height, Rgb([0, 0, 0]));
    paint_fallback_background(&mut canvas, palette, seed);
    match scene {
        FallbackImageScene::Abstract => paint_abstract_scene(&mut canvas, palette, seed),
        FallbackImageScene::Diagram => paint_diagram_scene(&mut canvas, palette, seed),
        FallbackImageScene::Landscape => paint_landscape_scene(&mut canvas, palette, seed),
        FallbackImageScene::Orbital => paint_orbital_scene(&mut canvas, palette, seed),
        FallbackImageScene::Portrait => paint_portrait_scene(&mut canvas, palette, seed),
    }
    paint_prompt_signature(&mut canvas, palette, seed);
    canvas
}

fn scale_video_dimensions(width: u32, height: u32, max_dim: u32) -> (u32, u32) {
    let scale = (max_dim as f32 / width.max(height) as f32).min(1.0);
    let scaled_width = ((width as f32 * scale).round() as u32).max(96);
    let scaled_height = ((height as f32 * scale).round() as u32).max(96);
    (scaled_width, scaled_height)
}

fn build_fallback_video_frame(
    base_rgba: &RgbaImage,
    scene: FallbackImageScene,
    palette: FallbackImagePalette,
    seed: &[u8],
    frame_index: usize,
    frame_count: usize,
) -> RgbaImage {
    let width = base_rgba.width();
    let height = base_rgba.height();
    let width_i32 = width.saturating_sub(1) as i32;
    let height_i32 = height.saturating_sub(1) as i32;
    let phase = frame_index as f32 / frame_count.max(1) as f32;
    let theta = phase * std::f32::consts::TAU;
    let (shift_x, shift_y) = match scene {
        FallbackImageScene::Landscape => (
            (theta.sin() * 8.0).round() as i32,
            ((theta * 0.5).cos() * 2.0).round() as i32,
        ),
        FallbackImageScene::Diagram => (0, 0),
        FallbackImageScene::Orbital => (
            (theta.cos() * 4.0).round() as i32,
            (theta.sin() * 4.0).round() as i32,
        ),
        FallbackImageScene::Portrait => (
            (theta.sin() * 3.0).round() as i32,
            ((theta + std::f32::consts::FRAC_PI_2).sin() * 2.0).round() as i32,
        ),
        FallbackImageScene::Abstract => (
            (theta.sin() * 6.0).round() as i32,
            ((theta * 1.3).cos() * 4.0).round() as i32,
        ),
    };
    let pulse = 0.94 + 0.10 * ((theta + f32::from(seed[10]) / 255.0 * std::f32::consts::TAU).sin() * 0.5 + 0.5);
    let mut frame = RgbaImage::from_pixel(width, height, Rgba([0, 0, 0, 255]));

    for y in 0..height {
        for x in 0..width {
            let source_x = (x as i32 + shift_x).clamp(0, width_i32) as u32;
            let source_y = (y as i32 + shift_y).clamp(0, height_i32) as u32;
            let source = base_rgba.get_pixel(source_x, source_y).0;
            let mut rgb = [
                f32::from(source[0]) * pulse,
                f32::from(source[1]) * pulse,
                f32::from(source[2]) * pulse,
            ];
            if matches!(scene, FallbackImageScene::Diagram) {
                let scan_x = width as f32 * phase;
                let distance = ((x as f32 - scan_x).abs() / width.max(1) as f32).min(1.0);
                rgb = blend_rgb(rgb, palette.accent_primary, (1.0 - distance) * 0.18);
            }
            frame.put_pixel(
                x,
                y,
                Rgba([
                    clamp_color_component(rgb[0]),
                    clamp_color_component(rgb[1]),
                    clamp_color_component(rgb[2]),
                    source[3],
                ]),
            );
        }
    }

    overlay_fallback_video_motion(&mut frame, scene, palette, theta, phase, seed);
    frame
}

fn overlay_fallback_video_motion(
    frame: &mut RgbaImage,
    scene: FallbackImageScene,
    palette: FallbackImagePalette,
    theta: f32,
    phase: f32,
    seed: &[u8],
) {
    let width = frame.width() as f32;
    let height = frame.height() as f32;
    match scene {
        FallbackImageScene::Landscape => {
            fill_circle_rgba(
                frame,
                width * (0.15 + phase * 0.7),
                height * 0.24,
                height * 0.06,
                palette.accent_primary,
                0.18,
            );
            draw_line_rgba(
                frame,
                0.0,
                height * 0.72,
                width,
                height * (0.72 + theta.sin() * 0.02),
                palette.accent_secondary,
                0.12,
                10.0,
            );
        }
        FallbackImageScene::Diagram => {
            let scan_x = width * phase;
            draw_line_rgba(
                frame,
                scan_x,
                0.0,
                scan_x,
                height,
                palette.accent_secondary,
                0.22,
                6.0,
            );
            fill_circle_rgba(
                frame,
                width * 0.28,
                height * (0.28 + theta.sin() * 0.04),
                7.0 + f32::from(seed[11] % 5),
                palette.accent_tertiary,
                0.42,
            );
        }
        FallbackImageScene::Orbital => {
            let orbit_x = width * 0.5 + theta.cos() * width * 0.18;
            let orbit_y = height * 0.45 + theta.sin() * height * 0.1;
            fill_circle_rgba(frame, orbit_x, orbit_y, height * 0.03, palette.accent_primary, 0.58);
            fill_circle_rgba(
                frame,
                width * 0.28 + (theta * 0.7).sin() * width * 0.05,
                height * 0.24,
                height * 0.025,
                palette.accent_tertiary,
                0.34,
            );
        }
        FallbackImageScene::Portrait => {
            fill_circle_rgba(
                frame,
                width * (0.48 + theta.sin() * 0.08),
                height * 0.32,
                width.min(height) * 0.14,
                palette.accent_primary,
                0.12,
            );
            draw_line_rgba(
                frame,
                width * 0.22,
                height * 0.84,
                width * 0.78,
                height * 0.84,
                palette.accent_secondary,
                0.12,
                8.0,
            );
        }
        FallbackImageScene::Abstract => {
            fill_circle_rgba(
                frame,
                width * (0.2 + phase * 0.6),
                height * (0.25 + theta.cos() * 0.08),
                width.min(height) * 0.07,
                palette.accent_secondary,
                0.24,
            );
            draw_line_rgba(
                frame,
                width * 0.08,
                height * (0.18 + phase * 0.58),
                width * 0.92,
                height * (0.28 + phase * 0.48),
                palette.accent_primary,
                0.18,
                12.0,
            );
        }
    }
}

fn blend_rgba_pixel(frame: &mut RgbaImage, x: i32, y: i32, color: [u8; 3], alpha: f32) {
    if x < 0 || y < 0 {
        return;
    }
    let (x, y) = (x as u32, y as u32);
    if x >= frame.width() || y >= frame.height() {
        return;
    }
    let base = frame.get_pixel(x, y).0;
    let blended = [
        lerp_u8(base[0], color[0], alpha),
        lerp_u8(base[1], color[1], alpha),
        lerp_u8(base[2], color[2], alpha),
        base[3],
    ];
    frame.put_pixel(x, y, Rgba(blended));
}

fn fill_circle_rgba(
    frame: &mut RgbaImage,
    center_x: f32,
    center_y: f32,
    radius: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = (center_x - radius).floor() as i32;
    let max_x = (center_x + radius).ceil() as i32;
    let min_y = (center_y - radius).floor() as i32;
    let max_y = (center_y + radius).ceil() as i32;
    let radius_sq = radius * radius;
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance_sq = dx * dx + dy * dy;
            if distance_sq <= radius_sq {
                let edge_alpha = 1.0 - (distance_sq.sqrt() / radius.max(1.0));
                blend_rgba_pixel(frame, x, y, color, alpha * (0.45 + edge_alpha * 0.55));
            }
        }
    }
}

fn draw_line_rgba(
    frame: &mut RgbaImage,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    color: [u8; 3],
    alpha: f32,
    thickness: f32,
) {
    let steps = ((x1 - x0).abs().max((y1 - y0).abs()) as i32).max(1);
    for step in 0..=steps {
        let t = step as f32 / steps as f32;
        let x = x0 + (x1 - x0) * t;
        let y = y0 + (y1 - y0) * t;
        fill_circle_rgba(frame, x, y, thickness / 2.0, color, alpha);
    }
}

fn classify_fallback_image_scene(prompt_lower: &str) -> FallbackImageScene {
    if contains_any(
        prompt_lower,
        &["diagram", "wireframe", "blueprint", "dashboard", "ui", "interface", "schematic"],
    ) {
        FallbackImageScene::Diagram
    } else if contains_any(
        prompt_lower,
        &[
            "landscape", "mountain", "forest", "ocean", "sea", "sunset", "skyline", "desert",
            "river", "valley", "city",
        ],
    ) {
        FallbackImageScene::Landscape
    } else if contains_any(
        prompt_lower,
        &["portrait", "face", "person", "character", "avatar", "headshot"],
    ) {
        FallbackImageScene::Portrait
    } else if contains_any(
        prompt_lower,
        &["space", "galaxy", "nebula", "planet", "cosmic", "orbital", "starfield"],
    ) {
        FallbackImageScene::Orbital
    } else {
        FallbackImageScene::Abstract
    }
}

fn contains_any(prompt_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| prompt_lower.contains(needle))
}

fn fallback_image_dimensions(prompt_lower: &str) -> (u32, u32) {
    if contains_any(prompt_lower, &["portrait", "poster", "phone", "vertical", "headshot"]) {
        (896, 1_152)
    } else if contains_any(prompt_lower, &["landscape", "panorama", "wide", "banner", "skyline"])
    {
        (1_280, 768)
    } else {
        (1_024, 1_024)
    }
}

fn fallback_image_palette(prompt_lower: &str, seed: &[u8]) -> FallbackImagePalette {
    let base = if contains_any(prompt_lower, &["sunset", "dawn", "golden", "warm"]) {
        FallbackImagePalette {
            background_top: [255, 199, 116],
            background_bottom: [138, 72, 130],
            accent_primary: [255, 245, 214],
            accent_secondary: [251, 124, 98],
            accent_tertiary: [70, 74, 146],
            ink: [44, 29, 52],
        }
    } else if contains_any(prompt_lower, &["ocean", "sea", "water", "coast", "lagoon"]) {
        FallbackImagePalette {
            background_top: [127, 209, 230],
            background_bottom: [22, 66, 118],
            accent_primary: [214, 250, 255],
            accent_secondary: [48, 161, 201],
            accent_tertiary: [10, 35, 84],
            ink: [7, 24, 48],
        }
    } else if contains_any(prompt_lower, &["forest", "nature", "garden", "moss", "jungle"]) {
        FallbackImagePalette {
            background_top: [166, 216, 151],
            background_bottom: [35, 82, 62],
            accent_primary: [235, 250, 213],
            accent_secondary: [89, 164, 96],
            accent_tertiary: [28, 56, 49],
            ink: [16, 32, 29],
        }
    } else if contains_any(prompt_lower, &["space", "galaxy", "nebula", "night", "cosmic"]) {
        FallbackImagePalette {
            background_top: [27, 23, 65],
            background_bottom: [4, 7, 24],
            accent_primary: [248, 231, 255],
            accent_secondary: [120, 89, 255],
            accent_tertiary: [44, 209, 223],
            ink: [235, 236, 255],
        }
    } else if contains_any(prompt_lower, &["mono", "monochrome", "black and white", "grayscale"])
    {
        FallbackImagePalette {
            background_top: [235, 236, 240],
            background_bottom: [87, 92, 102],
            accent_primary: [252, 252, 252],
            accent_secondary: [163, 168, 177],
            accent_tertiary: [42, 46, 56],
            ink: [21, 24, 31],
        }
    } else if contains_any(prompt_lower, &["diagram", "wireframe", "dashboard", "blueprint"]) {
        FallbackImagePalette {
            background_top: [228, 241, 255],
            background_bottom: [173, 201, 238],
            accent_primary: [255, 255, 255],
            accent_secondary: [72, 128, 201],
            accent_tertiary: [23, 68, 136],
            ink: [15, 39, 77],
        }
    } else {
        FallbackImagePalette {
            background_top: [240, 205, 158],
            background_bottom: [78, 116, 169],
            accent_primary: [255, 244, 228],
            accent_secondary: [230, 113, 91],
            accent_tertiary: [38, 62, 112],
            ink: [22, 29, 47],
        }
    };

    FallbackImagePalette {
        background_top: perturb_color(base.background_top, seed[0], 18),
        background_bottom: perturb_color(base.background_bottom, seed[1], 18),
        accent_primary: perturb_color(base.accent_primary, seed[2], 14),
        accent_secondary: perturb_color(base.accent_secondary, seed[3], 20),
        accent_tertiary: perturb_color(base.accent_tertiary, seed[4], 20),
        ink: perturb_color(base.ink, seed[5], 10),
    }
}

fn fallback_image_edit_profile(
    prompt_lower: &str,
    seed: &[u8],
    palette: FallbackImagePalette,
    has_mask: bool,
) -> FallbackImageEditProfile {
    let has_prompt = !prompt_lower.trim().is_empty();
    let grayscale = contains_any(
        prompt_lower,
        &["grayscale", "greyscale", "black and white", "monochrome"],
    );
    let sepia = contains_any(prompt_lower, &["sepia", "vintage", "retro", "aged"]);
    let invert = contains_any(prompt_lower, &["invert", "negative", "xray", "x-ray"]);
    let remove_style = contains_any(
        prompt_lower,
        &["remove", "erase", "cleanup", "clean up", "inpaint"],
    );
    let blur_sigma = if contains_any(prompt_lower, &["blur", "soften", "defocus", "dreamy"]) {
        3.2
    } else if remove_style && has_mask {
        5.0
    } else {
        0.0
    };
    let brightness = if contains_any(
        prompt_lower,
        &["bright", "brighten", "light", "sunlit", "daylight", "glow"],
    ) {
        20
    } else if contains_any(
        prompt_lower,
        &["dark", "darken", "moody", "night", "noir", "shadow"],
    ) {
        -22
    } else if has_prompt {
        i32::from(seed[6] % 9) - 4
    } else {
        0
    };
    let contrast = if contains_any(
        prompt_lower,
        &["dramatic", "high contrast", "neon", "sharp", "crisp"],
    ) {
        22.0
    } else if contains_any(prompt_lower, &["soft", "pastel", "washed", "faded"]) {
        -10.0
    } else if has_prompt {
        6.0 + f32::from(seed[7] % 6)
    } else {
        0.0
    };
    let saturation = if grayscale {
        -1.0
    } else if contains_any(
        prompt_lower,
        &["vibrant", "saturated", "colorful", "rich", "neon"],
    ) {
        0.45
    } else if contains_any(prompt_lower, &["muted", "desaturated", "subtle", "washed"]) {
        -0.45
    } else if sepia {
        -0.18
    } else if has_prompt {
        0.12 + f32::from(seed[8] % 10) / 100.0
    } else {
        0.0
    };
    let hue_rotate = if contains_any(prompt_lower, &["warm", "golden", "sunset", "amber"]) {
        12
    } else if contains_any(
        prompt_lower,
        &["cool", "moonlight", "cyan", "blue", "twilight", "night"],
    ) {
        -14
    } else if contains_any(prompt_lower, &["magenta", "cyberpunk", "ultravivid"]) {
        22
    } else if has_prompt {
        i32::from(seed[9] % 13) - 6
    } else {
        0
    };
    let tint_strength = if !has_prompt {
        0.0
    } else if remove_style && has_mask {
        0.06
    } else if grayscale || sepia {
        0.08
    } else {
        0.14
    };
    let vignette_strength = if contains_any(prompt_lower, &["portrait", "cinematic", "noir"]) {
        0.18
    } else if has_prompt {
        0.08
    } else {
        0.0
    };
    let (tint_color, label) = if remove_style {
        (palette.accent_primary, "inpaint")
    } else if grayscale {
        ([214, 214, 214], "monochrome")
    } else if sepia {
        ([197, 154, 102], "sepia")
    } else if invert {
        (palette.accent_tertiary, "negative")
    } else if blur_sigma > 0.0 {
        (palette.accent_primary, "soften")
    } else if hue_rotate > 6 {
        (palette.accent_secondary, "warm")
    } else if hue_rotate < -6 {
        (palette.accent_tertiary, "cool")
    } else {
        (palette.accent_secondary, "stylize")
    };

    FallbackImageEditProfile {
        grayscale,
        sepia,
        invert,
        blur_sigma,
        brightness,
        contrast,
        saturation,
        hue_rotate,
        tint_strength,
        vignette_strength,
        tint_color,
        label,
    }
}

fn apply_fallback_edit_profile(
    source_image: &DynamicImage,
    profile: FallbackImageEditProfile,
) -> RgbaImage {
    let mut working = source_image.to_rgba8();
    if profile.blur_sigma > 0.05 {
        working = image::imageops::blur(&working, profile.blur_sigma);
    }

    let mut dynamic = DynamicImage::ImageRgba8(working);
    if profile.grayscale {
        dynamic = dynamic.grayscale();
    }
    if profile.hue_rotate != 0 {
        dynamic = dynamic.huerotate(profile.hue_rotate);
    }
    if profile.brightness != 0 {
        dynamic = dynamic.brighten(profile.brightness);
    }
    if profile.contrast.abs() > 0.05 {
        dynamic = dynamic.adjust_contrast(profile.contrast);
    }

    let mut output = dynamic.to_rgba8();
    let width = output.width().max(1) as f32;
    let height = output.height().max(1) as f32;

    for (x, y, pixel) in output.enumerate_pixels_mut() {
        let alpha = pixel.0[3];
        let x_ratio = x as f32 / (width - 1.0).max(1.0);
        let y_ratio = y as f32 / (height - 1.0).max(1.0);
        let mut rgb = [pixel.0[0] as f32, pixel.0[1] as f32, pixel.0[2] as f32];

        if profile.saturation.abs() > 0.01 {
            rgb = saturate_rgb(rgb, profile.saturation);
        }
        if profile.sepia {
            rgb = apply_sepia_rgb(rgb);
        }
        if profile.invert {
            rgb = [255.0 - rgb[0], 255.0 - rgb[1], 255.0 - rgb[2]];
        }
        if profile.tint_strength > 0.01 {
            let tint_alpha = profile.tint_strength
                * (0.45 + y_ratio * 0.35 + (0.5 - (x_ratio - 0.5).abs()).max(0.0) * 0.2);
            rgb = blend_rgb(rgb, profile.tint_color, tint_alpha);
        }
        if profile.vignette_strength > 0.01 {
            let dx = (x_ratio - 0.5) * 2.0;
            let dy = (y_ratio - 0.5) * 2.0;
            let distance = (dx * dx + dy * dy).sqrt().min(1.4);
            let factor = 1.0 - distance.powf(1.35) * profile.vignette_strength;
            rgb = [
                rgb[0] * factor.max(0.0),
                rgb[1] * factor.max(0.0),
                rgb[2] * factor.max(0.0),
            ];
        }

        *pixel = Rgba([
            clamp_color_component(rgb[0]),
            clamp_color_component(rgb[1]),
            clamp_color_component(rgb[2]),
            alpha,
        ]);
    }

    output
}

fn composite_masked_edit(
    source_rgba: &RgbaImage,
    edited_rgba: &RgbaImage,
    mask_image_bytes: &[u8],
) -> Result<RgbaImage> {
    if mask_image_bytes.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound media image edit received an empty mask payload."
        ));
    }

    let mask_image = image::load_from_memory(mask_image_bytes).with_context(|| {
        "ERROR_CLASS=TargetNotFound media image edit fallback could not decode mask image bytes."
    })?;
    let resized_mask = if mask_image.width() != source_rgba.width()
        || mask_image.height() != source_rgba.height()
    {
        mask_image
            .resize_exact(
                source_rgba.width(),
                source_rgba.height(),
                image::imageops::FilterType::Triangle,
            )
            .to_luma8()
    } else {
        mask_image.to_luma8()
    };

    let mut output = source_rgba.clone();
    for (x, y, pixel) in output.enumerate_pixels_mut() {
        let alpha = f32::from(resized_mask.get_pixel(x, y).0[0]) / 255.0;
        if alpha <= 0.0 {
            continue;
        }
        let source = source_rgba.get_pixel(x, y).0;
        let edited = edited_rgba.get_pixel(x, y).0;
        *pixel = Rgba([
            lerp_u8(source[0], edited[0], alpha),
            lerp_u8(source[1], edited[1], alpha),
            lerp_u8(source[2], edited[2], alpha),
            lerp_u8(source[3], edited[3], alpha),
        ]);
    }

    Ok(output)
}

fn saturate_rgb(rgb: [f32; 3], delta: f32) -> [f32; 3] {
    let luma = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    let factor = (1.0 + delta).max(0.0);
    [
        luma + (rgb[0] - luma) * factor,
        luma + (rgb[1] - luma) * factor,
        luma + (rgb[2] - luma) * factor,
    ]
}

fn apply_sepia_rgb(rgb: [f32; 3]) -> [f32; 3] {
    [
        (rgb[0] * 0.393) + (rgb[1] * 0.769) + (rgb[2] * 0.189),
        (rgb[0] * 0.349) + (rgb[1] * 0.686) + (rgb[2] * 0.168),
        (rgb[0] * 0.272) + (rgb[1] * 0.534) + (rgb[2] * 0.131),
    ]
}

fn blend_rgb(rgb: [f32; 3], tint_color: [u8; 3], alpha: f32) -> [f32; 3] {
    let alpha = alpha.clamp(0.0, 1.0);
    [
        lerp_f32(rgb[0], f32::from(tint_color[0]), alpha),
        lerp_f32(rgb[1], f32::from(tint_color[1]), alpha),
        lerp_f32(rgb[2], f32::from(tint_color[2]), alpha),
    ]
}

fn lerp_u8(left: u8, right: u8, alpha: f32) -> u8 {
    clamp_color_component(lerp_f32(f32::from(left), f32::from(right), alpha))
}

fn lerp_f32(left: f32, right: f32, alpha: f32) -> f32 {
    left + (right - left) * alpha.clamp(0.0, 1.0)
}

fn clamp_color_component(value: f32) -> u8 {
    value.round().clamp(0.0, 255.0) as u8
}

fn perturb_color(color: [u8; 3], seed: u8, amplitude: i16) -> [u8; 3] {
    let delta = i16::from(seed % ((amplitude as u8).saturating_mul(2).saturating_add(1))) - amplitude;
    [
        clamp_channel(i16::from(color[0]) + delta / 2),
        clamp_channel(i16::from(color[1]) + delta),
        clamp_channel(i16::from(color[2]) - delta / 2),
    ]
}

fn clamp_channel(value: i16) -> u8 {
    value.clamp(0, 255) as u8
}

fn paint_fallback_background(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let width = canvas.width().max(1);
    let height = canvas.height().max(1);
    let wave_phase = f32::from(seed[6]) / 255.0 * std::f32::consts::TAU;

    for y in 0..height {
        let t = y as f32 / height.saturating_sub(1).max(1) as f32;
        let gradient = lerp_color(palette.background_top, palette.background_bottom, t);
        for x in 0..width {
            let x_ratio = x as f32 / width.saturating_sub(1).max(1) as f32;
            let wave = ((x_ratio * std::f32::consts::TAU * 2.5) + wave_phase).sin() * 0.08;
            let glow = ((1.0 - t) * 0.12 + wave).clamp(0.0, 0.2);
            let color = lerp_color(gradient, palette.accent_primary, glow);
            canvas.put_pixel(x, y, Rgb(color));
        }
    }
}

fn paint_landscape_scene(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let width = canvas.width() as f32;
    let height = canvas.height() as f32;
    let sun_x = width * (0.22 + f32::from(seed[7]) / 255.0 * 0.56);
    let sun_y = height * 0.24;
    let sun_radius = height * 0.1;
    fill_circle(
        canvas,
        sun_x,
        sun_y,
        sun_radius,
        palette.accent_primary,
        0.95,
    );
    stroke_circle(
        canvas,
        sun_x,
        sun_y,
        sun_radius * 1.35,
        4.0,
        palette.accent_secondary,
        0.32,
    );
    paint_sine_band(
        canvas,
        height * 0.64,
        height * 0.12,
        2.8,
        f32::from(seed[8]) / 255.0 * std::f32::consts::TAU,
        palette.accent_tertiary,
        0.94,
    );
    paint_sine_band(
        canvas,
        height * 0.73,
        height * 0.08,
        4.0,
        f32::from(seed[9]) / 255.0 * std::f32::consts::TAU,
        palette.accent_secondary,
        0.9,
    );
    paint_sine_band(
        canvas,
        height * 0.82,
        height * 0.05,
        5.4,
        f32::from(seed[10]) / 255.0 * std::f32::consts::TAU,
        palette.ink,
        0.88,
    );
}

fn paint_diagram_scene(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let width = canvas.width() as i32;
    let height = canvas.height() as i32;
    let grid = 64_i32;

    for x in (0..width).step_by(grid as usize) {
        draw_line(
            canvas,
            x as f32,
            0.0,
            x as f32,
            height as f32,
            palette.accent_primary,
            0.18,
            1.0,
        );
    }
    for y in (0..height).step_by(grid as usize) {
        draw_line(
            canvas,
            0.0,
            y as f32,
            width as f32,
            y as f32,
            palette.accent_primary,
            0.18,
            1.0,
        );
    }

    let cards = [
        (width / 8, height / 5, width / 3, height / 3),
        (width / 2, height / 4, width * 5 / 6, height / 2),
        (width / 3, height * 3 / 5, width * 3 / 4, height * 5 / 6),
    ];
    for (index, (x0, y0, x1, y1)) in cards.iter().enumerate() {
        fill_rect(canvas, *x0, *y0, *x1, *y1, palette.accent_primary, 0.86);
        stroke_rect(canvas, *x0, *y0, *x1, *y1, palette.ink, 0.72, 3.0);
        let marker_x = x0 + 36;
        let marker_y = y0 + 34;
        fill_circle(
            canvas,
            marker_x as f32,
            marker_y as f32,
            12.0,
            if index % 2 == 0 {
                palette.accent_secondary
            } else {
                palette.accent_tertiary
            },
            0.95,
        );
    }
    draw_line(
        canvas,
        width as f32 / 3.0,
        height as f32 / 3.0,
        width as f32 * 2.0 / 3.0,
        height as f32 * 2.0 / 3.0,
        palette.accent_secondary,
        0.75,
        4.0,
    );
    draw_line(
        canvas,
        width as f32 * 2.0 / 3.0,
        height as f32 / 2.0,
        width as f32 * 0.46,
        height as f32 * 0.72,
        palette.accent_tertiary,
        0.78,
        4.0 + f32::from(seed[11] % 3),
    );
}

fn paint_orbital_scene(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let mut rng = PromptRng::new(seed);
    let width = canvas.width() as f32;
    let height = canvas.height() as f32;

    for _ in 0..180 {
        let x = rng.next_f32() * width;
        let y = rng.next_f32() * height;
        let radius = 0.8 + rng.next_f32() * 1.9;
        fill_circle(canvas, x, y, radius, palette.accent_primary, 0.75);
    }

    let planet_x = width * (0.35 + rng.next_f32() * 0.25);
    let planet_y = height * (0.45 + rng.next_f32() * 0.1);
    let planet_radius = height * 0.18;
    fill_circle(
        canvas,
        planet_x,
        planet_y,
        planet_radius,
        palette.accent_secondary,
        0.95,
    );
    stroke_ellipse(
        canvas,
        planet_x,
        planet_y,
        planet_radius * 1.45,
        planet_radius * 0.42,
        5.0,
        palette.accent_primary,
        0.68,
    );
    fill_circle(
        canvas,
        width * 0.74,
        height * 0.27,
        height * 0.07,
        palette.accent_tertiary,
        0.92,
    );
}

fn paint_portrait_scene(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let width = canvas.width() as f32;
    let height = canvas.height() as f32;
    let center_x = width * 0.5;
    let head_y = height * 0.34;
    let head_rx = width * 0.17;
    let head_ry = height * 0.2;
    fill_circle(
        canvas,
        center_x,
        height * 0.3,
        width.min(height) * 0.23,
        palette.accent_primary,
        0.16,
    );
    fill_ellipse(
        canvas,
        center_x,
        head_y,
        head_rx,
        head_ry,
        palette.accent_primary,
        0.92,
    );
    fill_ellipse(
        canvas,
        center_x,
        height * 0.78,
        width * 0.23,
        height * 0.22,
        palette.accent_secondary,
        0.9,
    );
    let eye_offset = head_rx * 0.36;
    fill_circle(
        canvas,
        center_x - eye_offset,
        head_y - head_ry * 0.08,
        10.0 + f32::from(seed[12] % 4),
        palette.ink,
        0.8,
    );
    fill_circle(
        canvas,
        center_x + eye_offset,
        head_y - head_ry * 0.08,
        10.0 + f32::from(seed[13] % 4),
        palette.ink,
        0.8,
    );
}

fn paint_abstract_scene(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let mut rng = PromptRng::new(seed);
    let width = canvas.width() as f32;
    let height = canvas.height() as f32;
    for index in 0..6 {
        let x = rng.next_f32() * width;
        let y = rng.next_f32() * height;
        let radius = height.min(width) * (0.05 + rng.next_f32() * 0.14);
        let color = if index % 2 == 0 {
            palette.accent_secondary
        } else {
            palette.accent_tertiary
        };
        fill_circle(canvas, x, y, radius, color, 0.42);
    }
    for index in 0..5 {
        let y0 = height * (0.12 + index as f32 * 0.16);
        draw_line(
            canvas,
            width * 0.08,
            y0,
            width * (0.82 + rng.next_f32() * 0.1),
            y0 + height * (0.06 + rng.next_f32() * 0.08),
            if index % 2 == 0 {
                palette.accent_primary
            } else {
                palette.ink
            },
            0.45,
            10.0 + rng.next_f32() * 10.0,
        );
    }
}

fn paint_prompt_signature(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    palette: FallbackImagePalette,
    seed: &[u8],
) {
    let width = canvas.width() as i32;
    let height = canvas.height() as i32;
    let base_y = height - 42;
    let segment_width = (width - 96).max(120) / 12;
    for index in 0_usize..12 {
        let x0 = 48 + index as i32 * segment_width;
        let x1 = x0 + (segment_width - 8).max(10);
        let height_variation = 8 + i32::from(seed[index] % 20);
        fill_rect(
            canvas,
            x0,
            base_y - height_variation,
            x1,
            base_y,
            if index % 3 == 0 {
                palette.accent_primary
            } else if index % 3 == 1 {
                palette.accent_secondary
            } else {
                palette.accent_tertiary
            },
            0.72,
        );
    }
}

fn encode_generated_image(
    image: &DynamicImage,
    preferred_mime_type: &str,
) -> Result<(Vec<u8>, String)> {
    let normalized = normalize_image_output_mime_type(Some(preferred_mime_type))
        .unwrap_or_else(|| "image/png".to_string());
    let mut cursor = Cursor::new(Vec::new());
    if normalized == "image/jpeg" {
        JpegEncoder::new_with_quality(&mut cursor, MEDIA_IMAGE_JPEG_QUALITY)
            .encode_image(image)
            .context("ERROR_CLASS=SynthesisFailed failed to encode fallback JPEG image")?;
        Ok((cursor.into_inner(), normalized))
    } else {
        image
            .write_to(&mut cursor, ImageFormat::Png)
            .context("ERROR_CLASS=SynthesisFailed failed to encode fallback PNG image")?;
        Ok((cursor.into_inner(), "image/png".to_string()))
    }
}

fn lerp_color(left: [u8; 3], right: [u8; 3], t: f32) -> [u8; 3] {
    let clamped = t.clamp(0.0, 1.0);
    [
        ((left[0] as f32) + ((right[0] as f32) - (left[0] as f32)) * clamped).round() as u8,
        ((left[1] as f32) + ((right[1] as f32) - (left[1] as f32)) * clamped).round() as u8,
        ((left[2] as f32) + ((right[2] as f32) - (left[2] as f32)) * clamped).round() as u8,
    ]
}

fn blend_pixel(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    x: i32,
    y: i32,
    color: [u8; 3],
    alpha: f32,
) {
    if x < 0 || y < 0 {
        return;
    }
    let (x, y) = (x as u32, y as u32);
    if x >= canvas.width() || y >= canvas.height() {
        return;
    }

    let base = canvas.get_pixel(x, y).0;
    let blended = lerp_color(base, color, alpha.clamp(0.0, 1.0));
    canvas.put_pixel(x, y, Rgb(blended));
}

fn fill_circle(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    center_x: f32,
    center_y: f32,
    radius: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = (center_x - radius).floor() as i32;
    let max_x = (center_x + radius).ceil() as i32;
    let min_y = (center_y - radius).floor() as i32;
    let max_y = (center_y + radius).ceil() as i32;
    let radius_sq = radius * radius;
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance_sq = dx * dx + dy * dy;
            if distance_sq <= radius_sq {
                let edge_alpha = 1.0 - (distance_sq.sqrt() / radius.max(1.0));
                blend_pixel(canvas, x, y, color, alpha * (0.45 + edge_alpha * 0.55));
            }
        }
    }
}

fn stroke_circle(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    center_x: f32,
    center_y: f32,
    radius: f32,
    thickness: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = (center_x - radius - thickness).floor() as i32;
    let max_x = (center_x + radius + thickness).ceil() as i32;
    let min_y = (center_y - radius - thickness).floor() as i32;
    let max_y = (center_y + radius + thickness).ceil() as i32;
    let inner = (radius - thickness / 2.0).max(0.0);
    let outer = radius + thickness / 2.0;
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance = (dx * dx + dy * dy).sqrt();
            if distance >= inner && distance <= outer {
                let closeness =
                    1.0 - ((distance - radius).abs() / (thickness / 2.0).max(1.0)).clamp(0.0, 1.0);
                blend_pixel(canvas, x, y, color, alpha * closeness);
            }
        }
    }
}

fn fill_ellipse(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    center_x: f32,
    center_y: f32,
    radius_x: f32,
    radius_y: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = (center_x - radius_x).floor() as i32;
    let max_x = (center_x + radius_x).ceil() as i32;
    let min_y = (center_y - radius_y).floor() as i32;
    let max_y = (center_y + radius_y).ceil() as i32;
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = (x as f32 - center_x) / radius_x.max(1.0);
            let dy = (y as f32 - center_y) / radius_y.max(1.0);
            let distance = dx * dx + dy * dy;
            if distance <= 1.0 {
                blend_pixel(canvas, x, y, color, alpha * (1.0 - distance * 0.55));
            }
        }
    }
}

fn stroke_ellipse(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    center_x: f32,
    center_y: f32,
    radius_x: f32,
    radius_y: f32,
    thickness: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = (center_x - radius_x - thickness).floor() as i32;
    let max_x = (center_x + radius_x + thickness).ceil() as i32;
    let min_y = (center_y - radius_y - thickness).floor() as i32;
    let max_y = (center_y + radius_y + thickness).ceil() as i32;
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance = ((dx * dx) / radius_x.powi(2).max(1.0))
                + ((dy * dy) / radius_y.powi(2).max(1.0));
            let edge = (distance - 1.0).abs();
            if edge <= (thickness / radius_x.max(radius_y).max(1.0)) {
                blend_pixel(canvas, x, y, color, alpha * (1.0 - edge.min(1.0)));
            }
        }
    }
}

fn fill_rect(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    color: [u8; 3],
    alpha: f32,
) {
    let min_x = x0.min(x1).max(0);
    let max_x = x0.max(x1);
    let min_y = y0.min(y1).max(0);
    let max_y = y0.max(y1);
    for y in min_y..max_y {
        for x in min_x..max_x {
            blend_pixel(canvas, x, y, color, alpha);
        }
    }
}

fn stroke_rect(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    color: [u8; 3],
    alpha: f32,
    thickness: f32,
) {
    let thickness = thickness.max(1.0).round() as i32;
    fill_rect(canvas, x0, y0, x1, y0 + thickness, color, alpha);
    fill_rect(canvas, x0, y1 - thickness, x1, y1, color, alpha);
    fill_rect(canvas, x0, y0, x0 + thickness, y1, color, alpha);
    fill_rect(canvas, x1 - thickness, y0, x1, y1, color, alpha);
}

fn draw_line(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    color: [u8; 3],
    alpha: f32,
    thickness: f32,
) {
    let steps = ((x1 - x0).abs().max((y1 - y0).abs()) as i32).max(1);
    for step in 0..=steps {
        let t = step as f32 / steps as f32;
        let x = x0 + (x1 - x0) * t;
        let y = y0 + (y1 - y0) * t;
        fill_circle(canvas, x, y, thickness / 2.0, color, alpha);
    }
}

fn paint_sine_band(
    canvas: &mut ImageBuffer<Rgb<u8>, Vec<u8>>,
    baseline: f32,
    amplitude: f32,
    frequency: f32,
    phase: f32,
    color: [u8; 3],
    alpha: f32,
) {
    let width = canvas.width().max(1);
    let height = canvas.height();
    for x in 0..width {
        let t = x as f32 / width.saturating_sub(1).max(1) as f32;
        let contour = baseline + (t * std::f32::consts::TAU * frequency + phase).sin() * amplitude;
        for y in contour.max(0.0) as u32..height {
            blend_pixel(canvas, x as i32, y as i32, color, alpha);
        }
    }
}

struct PromptRng(u64);

impl PromptRng {
    fn new(seed: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        let state = u64::from_le_bytes(bytes) | 1;
        Self(state)
    }

    fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }

    fn next_f32(&mut self) -> f32 {
        self.next_u32() as f32 / u32::MAX as f32
    }
}

fn configured_tts_backend() -> Option<String> {
    std::env::var(MEDIA_TTS_BACKEND_ENV)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn auto_tts_backends() -> &'static [&'static str] {
    match std::env::consts::OS {
        "macos" => &["say", "espeak-ng", "espeak"],
        "windows" => &["pwsh", "powershell", "espeak-ng", "espeak"],
        _ => &["espeak-ng", "espeak", "pwsh", "powershell"],
    }
}

async fn run_forced_tts_backend(
    backend: &str,
    text: &str,
    voice: Option<&str>,
    preferred_mime_type: Option<&str>,
    runtime_dir: &Path,
) -> Result<KernelMediaSpeechSynthesis> {
    match run_tts_backend(backend, text, voice, preferred_mime_type, runtime_dir).await {
        Ok(Some(result)) => Ok(result),
        Ok(None) => Err(anyhow!(
            "ERROR_CLASS=TargetNotFound configured speech backend '{}' was not available.",
            backend
        )),
        Err(error) => Err(error),
    }
}

async fn run_tts_backend(
    backend: &str,
    text: &str,
    voice: Option<&str>,
    preferred_mime_type: Option<&str>,
    runtime_dir: &Path,
) -> Result<Option<KernelMediaSpeechSynthesis>> {
    match backend {
        "espeak-ng" | "espeak" => {
            run_espeak_backend(backend, text, voice, runtime_dir).await
        }
        "say" => run_say_backend(text, voice, preferred_mime_type, runtime_dir).await,
        "powershell" | "pwsh" => run_powershell_backend(backend, text, voice, runtime_dir).await,
        other => Err(anyhow!(
            "ERROR_CLASS=TargetNotFound unknown speech backend '{}'",
            other
        )),
    }
}

async fn run_espeak_backend(
    program: &str,
    text: &str,
    voice: Option<&str>,
    runtime_dir: &Path,
) -> Result<Option<KernelMediaSpeechSynthesis>> {
    let output_file = TempFileBuilder::new()
        .prefix("kernel-speech-")
        .suffix(".wav")
        .tempfile_in(runtime_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to allocate temporary {} output under {}",
                program,
                runtime_dir.display()
            )
        })?;
    let output_path = output_file.path().to_path_buf();
    let mut args = Vec::new();
    if let Some(selected_voice) = voice.filter(|value| !value.trim().is_empty()) {
        args.push("-v".to_string());
        args.push(selected_voice.trim().to_string());
    }
    args.push("-w".to_string());
    args.push(output_path.to_string_lossy().to_string());
    args.push(text.to_string());

    match run_tts_command(program, &args).await {
        Ok(CommandExecution::Succeeded) => {}
        Ok(CommandExecution::MissingBinary) => return Ok(None),
        Ok(CommandExecution::Failed(message)) if voice.is_some() => {
            let fallback_args = vec![
                "-w".to_string(),
                output_path.to_string_lossy().to_string(),
                text.to_string(),
            ];
            match run_tts_command(program, &fallback_args).await {
                Ok(CommandExecution::Succeeded) => {}
                Ok(CommandExecution::MissingBinary) => return Ok(None),
                Ok(CommandExecution::Failed(fallback_message)) => {
                    return Err(anyhow!(
                        "ERROR_CLASS=ExecutionFailedTerminal {} failed with requested voice and without voice: {}; {}",
                        program,
                        message,
                        fallback_message
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(CommandExecution::Failed(message)) => {
            return Err(anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal {} failed: {}",
                program,
                message
            ));
        }
        Err(error) => return Err(error),
    }

    let audio_bytes = fs::read(&output_path).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to read synthesized speech artifact {}",
            output_path.display()
        )
    })?;
    Ok(Some(KernelMediaSpeechSynthesis {
        audio_bytes,
        mime_type: "audio/wav".to_string(),
        backend_id: format!("kernel:tts:{}", program.replace('-', "_")),
    }))
}

async fn run_say_backend(
    text: &str,
    voice: Option<&str>,
    preferred_mime_type: Option<&str>,
    runtime_dir: &Path,
) -> Result<Option<KernelMediaSpeechSynthesis>> {
    let mime_type = if preferred_mime_type == Some("audio/x-aiff") {
        "audio/x-aiff"
    } else {
        "audio/aiff"
    };
    let suffix = if mime_type == "audio/x-aiff" {
        ".aiff"
    } else {
        ".aiff"
    };
    let output_file = TempFileBuilder::new()
        .prefix("kernel-speech-")
        .suffix(suffix)
        .tempfile_in(runtime_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to allocate temporary say output under {}",
                runtime_dir.display()
            )
        })?;
    let output_path = output_file.path().to_path_buf();
    let mut args = Vec::new();
    if let Some(selected_voice) = voice.filter(|value| !value.trim().is_empty()) {
        args.push("-v".to_string());
        args.push(selected_voice.trim().to_string());
    }
    args.push("-o".to_string());
    args.push(output_path.to_string_lossy().to_string());
    args.push(text.to_string());

    match run_tts_command("say", &args).await {
        Ok(CommandExecution::Succeeded) => {}
        Ok(CommandExecution::MissingBinary) => return Ok(None),
        Ok(CommandExecution::Failed(message)) if voice.is_some() => {
            let fallback_args = vec![
                "-o".to_string(),
                output_path.to_string_lossy().to_string(),
                text.to_string(),
            ];
            match run_tts_command("say", &fallback_args).await {
                Ok(CommandExecution::Succeeded) => {}
                Ok(CommandExecution::MissingBinary) => return Ok(None),
                Ok(CommandExecution::Failed(fallback_message)) => {
                    return Err(anyhow!(
                        "ERROR_CLASS=ExecutionFailedTerminal say failed with requested voice and without voice: {}; {}",
                        message,
                        fallback_message
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(CommandExecution::Failed(message)) => {
            return Err(anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal say failed: {}",
                message
            ));
        }
        Err(error) => return Err(error),
    }

    let audio_bytes = fs::read(&output_path).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to read synthesized speech artifact {}",
            output_path.display()
        )
    })?;
    Ok(Some(KernelMediaSpeechSynthesis {
        audio_bytes,
        mime_type: mime_type.to_string(),
        backend_id: "kernel:tts:say".to_string(),
    }))
}

async fn run_powershell_backend(
    program: &str,
    text: &str,
    voice: Option<&str>,
    runtime_dir: &Path,
) -> Result<Option<KernelMediaSpeechSynthesis>> {
    let output_file = TempFileBuilder::new()
        .prefix("kernel-speech-")
        .suffix(".wav")
        .tempfile_in(runtime_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to allocate temporary {} output under {}",
                program,
                runtime_dir.display()
            )
        })?;
    let output_path = output_file.path().to_path_buf();

    let mut script = String::from(
        "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer;",
    );
    if let Some(selected_voice) = voice.filter(|value| !value.trim().is_empty()) {
        script.push_str("$s.SelectVoice('");
        script.push_str(&escape_powershell_single_quoted(selected_voice.trim()));
        script.push_str("');");
    }
    script.push_str("$s.SetOutputToWaveFile('");
    script.push_str(&escape_powershell_single_quoted(
        &output_path.to_string_lossy(),
    ));
    script.push_str("');$s.Speak('");
    script.push_str(&escape_powershell_single_quoted(text));
    script.push_str("');$s.Dispose();");

    match run_tts_command(program, &["-NoProfile".to_string(), "-Command".to_string(), script])
        .await
    {
        Ok(CommandExecution::Succeeded) => {}
        Ok(CommandExecution::MissingBinary) => return Ok(None),
        Ok(CommandExecution::Failed(message)) if voice.is_some() => {
            let fallback_script = format!(
                "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.SetOutputToWaveFile('{}'); $s.Speak('{}'); $s.Dispose();",
                escape_powershell_single_quoted(&output_path.to_string_lossy()),
                escape_powershell_single_quoted(text)
            );
            match run_tts_command(
                program,
                &[
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    fallback_script,
                ],
            )
            .await
            {
                Ok(CommandExecution::Succeeded) => {}
                Ok(CommandExecution::MissingBinary) => return Ok(None),
                Ok(CommandExecution::Failed(fallback_message)) => {
                    return Err(anyhow!(
                        "ERROR_CLASS=ExecutionFailedTerminal {} failed with requested voice and without voice: {}; {}",
                        program,
                        message,
                        fallback_message
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(CommandExecution::Failed(message)) => {
            return Err(anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal {} failed: {}",
                program,
                message
            ));
        }
        Err(error) => return Err(error),
    }

    let audio_bytes = fs::read(&output_path).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to read synthesized speech artifact {}",
            output_path.display()
        )
    })?;
    Ok(Some(KernelMediaSpeechSynthesis {
        audio_bytes,
        mime_type: "audio/wav".to_string(),
        backend_id: format!("kernel:tts:{}", program),
    }))
}

enum CommandExecution {
    Succeeded,
    MissingBinary,
    Failed(String),
}

async fn run_tts_command(program: &str, args: &[String]) -> Result<CommandExecution> {
    let mut command = Command::new(program);
    command.args(args).stdout(Stdio::null()).stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(CommandExecution::MissingBinary),
        Err(error) => {
            return Err(anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to spawn {}: {}",
                program,
                error
            ));
        }
    };
    let output = match timeout(Duration::from_secs(MEDIA_TTS_TIMEOUT_SECS), child.wait_with_output()).await
    {
        Ok(result) => result.map_err(|error| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to wait for {}: {}",
                program,
                error
            )
        })?,
        Err(_) => {
            return Err(anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal {} timed out after {}s",
                program,
                MEDIA_TTS_TIMEOUT_SECS
            ));
        }
    };
    if output.status.success() {
        Ok(CommandExecution::Succeeded)
    } else {
        let stderr = compact_ws(&String::from_utf8_lossy(&output.stderr));
        let message = if stderr.is_empty() {
            format!("exit status {}", output.status)
        } else {
            format!("{} ({})", stderr, output.status)
        };
        Ok(CommandExecution::Failed(message))
    }
}

fn fallback_speech_synthesis(text: &str) -> KernelMediaSpeechSynthesis {
    KernelMediaSpeechSynthesis {
        audio_bytes: render_fallback_tts_wav(text),
        mime_type: "audio/wav".to_string(),
        backend_id: "kernel:tts:fallback_waveform".to_string(),
    }
}

fn render_fallback_tts_wav(text: &str) -> Vec<u8> {
    let normalized = text
        .chars()
        .filter(|value| !value.is_control())
        .take(FALLBACK_TTS_CHAR_LIMIT)
        .collect::<String>();
    let tone_samples = ((FALLBACK_TTS_SAMPLE_RATE as usize) * FALLBACK_TTS_TONE_MS) / 1000;
    let gap_samples = ((FALLBACK_TTS_SAMPLE_RATE as usize) * FALLBACK_TTS_GAP_MS) / 1000;
    let amplitude = i16::MAX as f32 * 0.18;
    let mut pcm = Vec::new();

    for (index, ch) in normalized.chars().enumerate() {
        let frequency = 220.0 + ((u32::from(ch) % 31) as f32 * 17.5) + ((index % 7) as f32 * 9.0);
        for sample_index in 0..tone_samples {
            let phase = sample_index as f32 / FALLBACK_TTS_SAMPLE_RATE as f32;
            let envelope = 0.35
                + 0.65
                    * (1.0 - (sample_index as f32 / tone_samples.max(1) as f32 - 0.5).abs() * 2.0)
                        .max(0.0);
            let value = (phase * frequency * TAU).sin() * amplitude * envelope;
            pcm.push(value.clamp(i16::MIN as f32, i16::MAX as f32) as i16);
        }
        pcm.extend(std::iter::repeat_n(0_i16, gap_samples));
    }

    if pcm.is_empty() {
        pcm.extend(std::iter::repeat_n(
            0_i16,
            (FALLBACK_TTS_SAMPLE_RATE / 5) as usize,
        ));
    }

    encode_wav_pcm_i16(FALLBACK_TTS_SAMPLE_RATE, &pcm)
}

fn encode_wav_pcm_i16(sample_rate: u32, pcm: &[i16]) -> Vec<u8> {
    let data_len = pcm.len().min((u32::MAX as usize) / 2) as u32 * 2;
    let riff_len = 36_u32.saturating_add(data_len);
    let mut bytes = Vec::with_capacity((44_u32.saturating_add(data_len)) as usize);
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&riff_len.to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    bytes.extend_from_slice(b"fmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&sample_rate.to_le_bytes());
    bytes.extend_from_slice(&(sample_rate.saturating_mul(2)).to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&data_len.to_le_bytes());
    for sample in pcm.iter().take((data_len / 2) as usize) {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    bytes
}

fn audio_extension_for_mime(mime_type: &str) -> &'static str {
    match mime_type.trim().to_ascii_lowercase().as_str() {
        "audio/wav" | "audio/x-wav" | "audio/wave" => "wav",
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/flac" => "flac",
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/aac" => "aac",
        "audio/mp4" | "audio/x-m4a" => "m4a",
        "audio/webm" => "webm",
        _ => "bin",
    }
}

fn escape_powershell_single_quoted(input: &str) -> String {
    input.replace('\'', "''")
}

fn build_kernel_vision_messages(
    image_bytes: &[u8],
    mime_type: &str,
    prompt: &str,
) -> Value {
    json!([
        {
            "role": "system",
            "content": "You are a strict kernel vision reader. Return JSON only."
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": format!(
                        "Inspect the provided image or screenshot. Return JSON only with this schema: {{\"output_text\":\"<literal answer>\"}}. Be concise but complete. Read visible text when possible, describe layout and objects literally, and do not speculate beyond the image. User request: {}",
                        prompt
                    )
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:{};base64,{}", mime_type, BASE64.encode(image_bytes))
                    }
                }
            ]
        }
    ])
}

fn parse_kernel_vision_output(raw: &[u8]) -> Option<String> {
    if let Ok(value) = parse_json_value(raw) {
        if let Some(output_text) = value.get("output_text").and_then(Value::as_str) {
            let compact = compact_ws(output_text);
            if !compact.is_empty() {
                return Some(compact);
            }
        }
        for key in ["answer", "description", "result", "text"] {
            if let Some(output_text) = value.get(key).and_then(Value::as_str) {
                let compact = compact_ws(output_text);
                if !compact.is_empty() {
                    return Some(compact);
                }
            }
        }
    }

    let raw_text = String::from_utf8_lossy(raw);
    let compact = compact_ws(&raw_text);
    (!compact.is_empty()).then_some(compact)
}

fn prepare_vision_image_payload(
    image_bytes: &[u8],
    mime_type: &str,
    prompt: Option<&str>,
) -> Result<(Vec<u8>, String, String)> {
    let image = image::load_from_memory(image_bytes).with_context(|| {
        "ERROR_CLASS=VerificationMissing failed to decode image bytes for kernel vision read"
    })?;
    let width = image.width();
    let height = image.height();
    let processed = if width <= MEDIA_VISION_MAX_DIM && height <= MEDIA_VISION_MAX_DIM {
        image
    } else {
        image.thumbnail(MEDIA_VISION_MAX_DIM, MEDIA_VISION_MAX_DIM)
    };

    let mut jpeg_bytes = Vec::new();
    let mut cursor = Cursor::new(&mut jpeg_bytes);
    JpegEncoder::new_with_quality(&mut cursor, MEDIA_VISION_JPEG_QUALITY)
        .encode_image(&processed)
        .context("ERROR_CLASS=SynthesisFailed failed to encode kernel vision jpeg payload")?;

    let fallback = build_local_vision_fallback_summary(&processed, mime_type, prompt);
    Ok((jpeg_bytes, "image/jpeg".to_string(), fallback))
}

fn build_local_vision_fallback_summary(
    image: &DynamicImage,
    source_mime_type: &str,
    prompt: Option<&str>,
) -> String {
    let rgb = image.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut total_r = 0_f64;
    let mut total_g = 0_f64;
    let mut total_b = 0_f64;
    let mut total_luma = 0_f64;
    let mut total_luma_sq = 0_f64;
    let pixel_count = f64::from(width.max(1)) * f64::from(height.max(1));

    for pixel in rgb.pixels() {
        let [r, g, b] = pixel.0;
        let r = f64::from(r);
        let g = f64::from(g);
        let b = f64::from(b);
        let luma = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        total_r += r;
        total_g += g;
        total_b += b;
        total_luma += luma;
        total_luma_sq += luma * luma;
    }

    let avg_r = (total_r / pixel_count).round() as u8;
    let avg_g = (total_g / pixel_count).round() as u8;
    let avg_b = (total_b / pixel_count).round() as u8;
    let avg_luma = total_luma / pixel_count;
    let variance = (total_luma_sq / pixel_count) - (avg_luma * avg_luma);
    let contrast = variance.max(0.0).sqrt();
    let aspect = if width >= height {
        "landscape"
    } else {
        "portrait"
    };
    let brightness = if avg_luma < 75.0 {
        "dark"
    } else if avg_luma > 180.0 {
        "bright"
    } else {
        "mid-tone"
    };
    let contrast_label = if contrast < 28.0 {
        "low contrast"
    } else if contrast > 72.0 {
        "high contrast"
    } else {
        "moderate contrast"
    };
    let color_spread = f64::from(
        avg_r.max(avg_g).max(avg_b) - avg_r.min(avg_g).min(avg_b)
    );
    let colorfulness = if color_spread < 18.0 {
        "near-monochrome"
    } else if color_spread > 80.0 {
        "color-rich"
    } else {
        "moderately colorful"
    };

    let mut summary = format!(
        "Local fallback vision summary: {} image, {}x{}, {}, {}, {}, average color rgb({}, {}, {}). OCR and fine semantic recognition are unavailable in fallback mode.",
        compact_ws(source_mime_type),
        width,
        height,
        aspect,
        brightness,
        format!("{} and {}", contrast_label, colorfulness),
        avg_r,
        avg_g,
        avg_b
    );
    if let Some(request) = prompt {
        summary.push_str(" Requested inspection: ");
        summary.push_str(request.trim());
        summary.push('.');
    }
    summary
}
