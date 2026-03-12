mod receipts;
mod selection;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use image::{DynamicImage, GenericImageView, ImageBuffer, ImageFormat, Rgb};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{
    InferenceOptions, MediaFrameEvidence, MediaMultimodalBundle, MediaProviderCandidate,
    MediaTimelineCue, MediaTimelineOutlineBundle, MediaTranscriptBundle,
    MediaTranscriptProviderCandidate, MediaVisualEvidenceBundle, WebRetrievalAffordance,
};
use reqwest::{header, redirect};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::fs::File;
use std::io::Cursor;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::DecoderOptions;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;
use tokio::process::Command;
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use url::Url;
use walkdir::WalkDir;
use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};
use xz2::read::XzDecoder;
use zip::ZipArchive;

use super::util::{compact_ws, now_ms, sha256_hex};
pub(crate) use receipts::media_provider_candidate_receipt;
use receipts::{
    media_provider_candidate_receipt_with_modality, write_multimodal_run_receipt, write_run_receipt,
};
use selection::{
    discover_audio_stt_candidate, discover_subtitle_candidate,
    discover_youtube_watch_transcript_candidate, normalize_requested_language,
    provider_reason_from_error, select_provider_plans, select_video_format, whisper_language_code,
};
#[cfg(test)]
use selection::{select_audio_format, select_subtitle_track, select_track_from_bucket};

const MEDIA_TOOL_HOME_ENV: &str = "IOI_MEDIA_TOOL_HOME";
const MEDIA_RECEIPT_DIR_NAME: &str = "receipts";
const MEDIA_RECEIPT_FILE_NAME: &str = "last_success.json";

const SUBTITLE_PROVIDER_ID: &str = "yt_dlp.managed_subtitles";
const AUDIO_STT_PROVIDER_ID: &str = "yt_dlp.whisper_rs_audio";
const VISUAL_PROVIDER_ID: &str = "ffmpeg.managed_frames_vision";
const YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID: &str = "youtube.watch_transcript";
const YOUTUBE_TIMELINE_PROVIDER_ID: &str = "youtube.key_moments_timeline";
const YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID: &str = "youtube.chapter_thumbnails_vision";
const YTDLP_PROVIDER_VERSION: &str = "2026.03.03";
const YTDLP_SUMS_URL: &str =
    "https://github.com/yt-dlp/yt-dlp/releases/download/2026.03.03/SHA2-256SUMS";
const FFMPEG_PROVIDER_VERSION: &str = "autobuild-2026-03-06-13-02";
const FFMPEG_SUMS_URL: &str = "https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-03-06-13-02/checksums.sha256";

const WHISPER_MODEL_ID: &str = "ggml-tiny-q5_1";
const WHISPER_MODEL_FILE_NAME: &str = "ggml-tiny-q5_1.bin";
const WHISPER_MODEL_REVISION: &str = "5359861c739e955e79d9a303bcbc70fb988958b1";
const WHISPER_MODEL_URL: &str = "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-tiny-q5_1.bin";
const WHISPER_TARGET_SAMPLE_RATE: u32 = 16_000;

const MEDIA_DEFAULT_MAX_CHARS: u32 = 72_000;
const MEDIA_MAX_CHARS_LIMIT: u32 = 160_000;
const MEDIA_MULTIMODAL_DEFAULT_MAX_CHARS: u32 = 48_000;
const MEDIA_VISUAL_DEFAULT_FRAME_LIMIT: u32 = 6;
const MEDIA_VISUAL_MAX_FRAME_LIMIT: u32 = 10;
const MEDIA_VISUAL_BATCH_SIZE: usize = 3;
const YTDLP_METADATA_TIMEOUT_SECS: u64 = 90;
const YTDLP_SUBTITLE_TIMEOUT_SECS: u64 = 120;
const YTDLP_AUDIO_TIMEOUT_SECS: u64 = 240;
const YTDLP_VIDEO_TIMEOUT_SECS: u64 = 480;
const MODEL_DOWNLOAD_TIMEOUT_SECS: u64 = 180;
const WHISPER_TRANSCRIBE_TIMEOUT_SECS: u64 = 900;
const FFMPEG_DOWNLOAD_TIMEOUT_SECS: u64 = 180;
const FFMPEG_FRAME_TIMEOUT_SECS: u64 = 90;
const VISION_PROBE_TIMEOUT_SECS: u64 = 45;
const YOUTUBE_WATCH_PAGE_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
struct ManagedYtDlpProvider {
    binary_path: PathBuf,
    asset_name: &'static str,
    version: &'static str,
}

#[derive(Debug, Clone)]
struct ManagedWhisperModel {
    model_path: PathBuf,
    model_id: &'static str,
    revision: &'static str,
}

#[derive(Debug, Clone)]
struct ManagedFfmpegProvider {
    ffmpeg_path: PathBuf,
    ffprobe_path: PathBuf,
    version: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum FfmpegArchiveKind {
    TarXz,
    Zip,
}

#[derive(Debug, Clone, Copy)]
struct ManagedFfmpegAsset {
    asset_name: &'static str,
    archive_kind: FfmpegArchiveKind,
}

#[derive(Debug, Clone)]
struct SubtitleSelection {
    language_key: String,
    source_kind: &'static str,
}

#[derive(Debug, Clone)]
struct AudioFormatSelection {
    format_id: String,
    ext: String,
    acodec: String,
}

#[derive(Debug, Clone)]
struct YouTubeWatchTranscriptSelection {
    api_key: String,
    client_context: Value,
    transcript_params: String,
}

#[derive(Debug, Clone)]
struct YouTubeChapterThumbnail {
    title: String,
    start_ms: u64,
    thumbnail_url: String,
}

#[derive(Debug, Clone)]
struct YouTubeWatchPageContext {
    api_key: String,
    client_context: Value,
    transcript_params: Option<String>,
    transcript_challenge_reason: Option<String>,
    title: Option<String>,
    canonical_url: String,
    duration_seconds: Option<u64>,
    chapter_thumbnails: Vec<YouTubeChapterThumbnail>,
}

#[derive(Debug, Clone)]
struct VideoFormatSelection {
    format_id: String,
    ext: String,
    vcodec: String,
    width: u32,
    height: u32,
}

#[derive(Debug, Clone)]
struct TranscriptSegment {
    start_ms: u64,
    text: String,
}

#[derive(Debug, Clone)]
enum ProviderExecutionPlan {
    Subtitle(SubtitleSelection),
    AudioStt(AudioFormatSelection),
    YouTubeWatchTranscript(YouTubeWatchTranscriptSelection),
}

#[derive(Debug, Clone)]
enum VisualProviderExecutionPlan {
    ManagedFrames {
        ffmpeg: ManagedFfmpegProvider,
        video_format: VideoFormatSelection,
    },
    YouTubeChapterThumbnails {
        provider_version: String,
        title: Option<String>,
        canonical_url: String,
        duration_seconds: Option<u64>,
        chapter_thumbnails: Vec<YouTubeChapterThumbnail>,
    },
}

#[derive(Debug, Clone)]
struct MediaProviderCandidateState {
    candidate: MediaProviderCandidate,
    plan: Option<ProviderExecutionPlan>,
}

#[derive(Debug, Clone)]
struct VisualProviderCandidateState {
    candidate: MediaProviderCandidate,
    plan: Option<VisualProviderExecutionPlan>,
}

#[derive(Debug, Clone)]
struct ExecutedTranscript {
    provider_id: &'static str,
    provider_version: String,
    backend: &'static str,
    transcript_language: String,
    transcript_source_kind: String,
    provider_model_id: Option<String>,
    provider_model_path: Option<String>,
    selected_audio_format_id: Option<String>,
    selected_audio_ext: Option<String>,
    selected_audio_acodec: Option<String>,
    segments: Vec<TranscriptSegment>,
}

#[derive(Debug, Clone)]
struct TranscriptArtifact {
    bundle: MediaTranscriptBundle,
    receipt: MediaTranscriptRunReceipt,
    segments: Vec<TranscriptSegment>,
}

#[derive(Debug)]
struct TranscriptExecutionFailure {
    provider_id: &'static str,
    error: anyhow::Error,
}

#[derive(Debug, Clone)]
struct TimelineArtifact {
    bundle: MediaTimelineOutlineBundle,
    receipt: MediaMultimodalRunReceipt,
}

#[derive(Debug, Clone)]
struct ManagedYtDlpDiscovery {
    provider: ManagedYtDlpProvider,
    metadata: Value,
}

#[derive(Debug, Clone)]
struct VisualFrameSample {
    timestamp_ms: u64,
    timestamp_label: String,
    frame_hash: String,
    mime_type: String,
    width: u32,
    height: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct VisualArtifact {
    bundle: MediaVisualEvidenceBundle,
    receipt: MediaMultimodalRunReceipt,
}

#[derive(Debug)]
struct VisualExecutionFailure {
    provider_id: &'static str,
    error: anyhow::Error,
}

#[derive(Debug, Clone)]
struct ExecutedVisualEvidence {
    provider_id: &'static str,
    provider_version: String,
    backend: &'static str,
    provider_binary_path: Option<String>,
    ffprobe_path: Option<String>,
    selected_video_format_id: Option<String>,
    selected_video_ext: Option<String>,
    selected_video_codec: Option<String>,
    canonical_url: String,
    title: Option<String>,
    duration_seconds: Option<u64>,
    frame_evidence: Vec<MediaFrameEvidence>,
}

#[derive(Debug, Clone, Serialize)]
struct MediaTranscriptRunReceipt {
    schema_version: u32,
    provider_id: String,
    provider_version: String,
    provider_binary_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_model_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_audio_format_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_audio_ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_audio_acodec: Option<String>,
    requested_url: String,
    canonical_url: String,
    title: Option<String>,
    duration_seconds: Option<u64>,
    requested_language: String,
    transcript_language: String,
    transcript_source_kind: String,
    transcript_char_count: u32,
    segment_count: u32,
    transcript_hash: String,
    retrieved_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
struct MediaMultimodalRunReceipt {
    schema_version: u32,
    requested_url: String,
    canonical_url: String,
    title: Option<String>,
    duration_seconds: Option<u64>,
    requested_language: String,
    #[serde(default)]
    selected_modalities: Vec<String>,
    #[serde(default)]
    selected_provider_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_provider_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_provider_binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_provider_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_provider_model_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_selected_audio_format_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_selected_audio_ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_selected_audio_acodec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_source_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_char_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_segment_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transcript_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_provider_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_source_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_cue_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_char_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeline_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_provider_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_provider_binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_ffprobe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_selected_video_format_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_selected_video_ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_selected_video_codec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_frame_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_char_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    visual_summary_char_count: Option<u32>,
    retrieved_at_ms: u64,
}

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
    let requested_url = validate_media_url(url, "media__extract_multimodal_evidence")?;
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
        tool: "media__extract_multimodal_evidence".to_string(),
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

fn validate_media_url(url: &str, tool_name: &str) -> Result<String> {
    let requested_url = url.trim();
    if requested_url.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound {} requires a non-empty url.",
            tool_name
        ));
    }
    let parsed = Url::parse(requested_url)
        .map_err(|err| anyhow!("ERROR_CLASS=TargetNotFound invalid media url: {}", err))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound {} only supports http/https urls.",
            tool_name
        ));
    }
    Ok(requested_url.to_string())
}

fn ensure_media_tool_home() -> Result<PathBuf> {
    let tool_home = media_tool_home();
    fs::create_dir_all(&tool_home).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create media tool home {}",
            tool_home.display()
        )
    })?;
    Ok(tool_home)
}

async fn extract_transcript_artifact(
    requested_url: &str,
    requested_language: &str,
    transcript_max_chars: usize,
    tool_home: &Path,
    browser: Arc<BrowserDriver>,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
    require_candidate: bool,
) -> Result<(Vec<MediaProviderCandidate>, Option<TranscriptArtifact>)> {
    let mut subtitle_candidate = ytdlp_discovery
        .map(|value| {
            discover_subtitle_candidate(requested_url, &value.metadata, requested_language)
        })
        .unwrap_or_else(|| {
            failed_transcript_candidate_state(
                SUBTITLE_PROVIDER_ID,
                requested_url,
                ytdlp_failure_reason.map(str::to_string),
            )
        });
    let mut youtube_watch_candidate = if let Some(context) = watch_page {
        discover_youtube_watch_transcript_candidate(requested_url, Some(context))
    } else {
        failed_transcript_candidate_state(
            YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
            requested_url,
            watch_page_failure_reason.map(str::to_string),
        )
    };
    if youtube_watch_candidate.plan.is_none()
        && youtube_watch_candidate.candidate.challenge_reason.is_none()
        && watch_page_failure_reason.is_some()
    {
        youtube_watch_candidate.candidate.challenge_reason =
            watch_page_failure_reason.map(str::to_string);
    }
    let mut audio_candidate = ytdlp_discovery
        .map(|value| discover_audio_stt_candidate(requested_url, &value.metadata))
        .unwrap_or_else(|| {
            failed_transcript_candidate_state(
                AUDIO_STT_PROVIDER_ID,
                requested_url,
                ytdlp_failure_reason.map(str::to_string),
            )
        });
    let selected_plans = select_provider_plans(
        &subtitle_candidate,
        &audio_candidate,
        &youtube_watch_candidate,
    );
    if selected_plans.is_empty() {
        let provider_candidates = vec![
            subtitle_candidate.candidate.clone(),
            youtube_watch_candidate.candidate.clone(),
            audio_candidate.candidate.clone(),
        ];
        if require_candidate {
            return Err(anyhow!(
                "ERROR_CLASS=DiscoveryMissing media transcript discovery found no admissible provider candidates for requested_language={} url={}",
                requested_language,
                requested_url
            ));
        }
        return Ok((provider_candidates, None));
    }

    let run_dir = prepare_run_dir(tool_home)?;
    let mut last_failure = None::<TranscriptExecutionFailure>;
    let mut executed = None::<ExecutedTranscript>;
    for selected_plan in selected_plans {
        let selected_candidate = transcript_candidate_state_mut(
            &mut subtitle_candidate,
            &mut audio_candidate,
            &mut youtube_watch_candidate,
            &selected_plan,
        );
        selected_candidate.candidate.execution_attempted = Some(true);
        match execute_transcript_plan(
            requested_url,
            requested_language,
            tool_home,
            browser.clone(),
            ytdlp_discovery,
            &run_dir,
            selected_plan.clone(),
        )
        .await
        {
            Ok(value) => {
                selected_candidate.candidate.selected = true;
                selected_candidate.candidate.execution_satisfied = Some(true);
                selected_candidate.candidate.execution_failure_reason = None;
                executed = Some(value);
                break;
            }
            Err(err) => {
                selected_candidate.candidate.execution_satisfied = Some(false);
                selected_candidate.candidate.execution_failure_reason =
                    Some(provider_reason_from_error(&err));
                last_failure = Some(TranscriptExecutionFailure {
                    provider_id: transcript_provider_id(&selected_plan),
                    error: err,
                });
            }
        }
    }

    let Some(executed) = executed else {
        let failure = last_failure.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal media transcript execution exhausted admissible providers for requested_language={} url={}",
                requested_language,
                requested_url
            )
        })?;
        return Err(failure.error.context(format!(
            "transcript provider execution exhausted admissible plan set after provider_id={}",
            failure.provider_id
        )));
    };

    let full_transcript = executed
        .segments
        .iter()
        .map(|segment| format!("[{}] {}", render_timestamp(segment.start_ms), segment.text))
        .collect::<Vec<_>>()
        .join("\n");
    let truncated_transcript = truncate_chars(&full_transcript, transcript_max_chars);
    if truncated_transcript.trim().is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing transcript text was empty after truncation."
        ));
    }

    let canonical_url = media_canonical_url(requested_url, ytdlp_discovery, watch_page);
    let title = media_title(ytdlp_discovery, watch_page);
    let duration_seconds = media_duration_seconds(ytdlp_discovery, watch_page);
    let transcript_hash = sha256_hex(truncated_transcript.as_bytes());
    let retrieved_at_ms = now_ms();
    let provider_candidates = vec![
        subtitle_candidate.candidate.clone(),
        youtube_watch_candidate.candidate.clone(),
        audio_candidate.candidate.clone(),
    ];
    let bundle = MediaTranscriptBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_transcript".to_string(),
        backend: executed.backend.to_string(),
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: canonical_url.clone(),
        provider_candidates: provider_candidates.clone(),
        title: title.clone(),
        duration_seconds,
        requested_language: requested_language.to_string(),
        transcript_language: executed.transcript_language.clone(),
        transcript_source_kind: executed.transcript_source_kind.clone(),
        segment_count: executed.segments.len() as u32,
        transcript_char_count: truncated_transcript.chars().count() as u32,
        transcript_hash: transcript_hash.clone(),
        transcript_text: truncated_transcript,
    };
    let receipt = MediaTranscriptRunReceipt {
        schema_version: 1,
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version,
        provider_binary_path: transcript_provider_binary_path(ytdlp_discovery),
        provider_model_id: executed.provider_model_id,
        provider_model_path: executed.provider_model_path,
        selected_audio_format_id: executed.selected_audio_format_id,
        selected_audio_ext: executed.selected_audio_ext,
        selected_audio_acodec: executed.selected_audio_acodec,
        requested_url: requested_url.to_string(),
        canonical_url,
        title,
        duration_seconds,
        requested_language: requested_language.to_string(),
        transcript_language: bundle.transcript_language.clone(),
        transcript_source_kind: bundle.transcript_source_kind.clone(),
        transcript_char_count: bundle.transcript_char_count,
        segment_count: bundle.segment_count,
        transcript_hash,
        retrieved_at_ms,
    };

    Ok((
        provider_candidates,
        Some(TranscriptArtifact {
            bundle,
            receipt,
            segments: executed.segments,
        }),
    ))
}

fn transcript_provider_id(selected_plan: &ProviderExecutionPlan) -> &'static str {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(_) => SUBTITLE_PROVIDER_ID,
        ProviderExecutionPlan::AudioStt(_) => AUDIO_STT_PROVIDER_ID,
        ProviderExecutionPlan::YouTubeWatchTranscript(_) => YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
    }
}

fn transcript_candidate_state_mut<'a>(
    subtitle_candidate: &'a mut MediaProviderCandidateState,
    audio_candidate: &'a mut MediaProviderCandidateState,
    youtube_watch_candidate: &'a mut MediaProviderCandidateState,
    selected_plan: &ProviderExecutionPlan,
) -> &'a mut MediaProviderCandidateState {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(_) => subtitle_candidate,
        ProviderExecutionPlan::AudioStt(_) => audio_candidate,
        ProviderExecutionPlan::YouTubeWatchTranscript(_) => youtube_watch_candidate,
    }
}

async fn execute_transcript_plan(
    requested_url: &str,
    requested_language: &str,
    tool_home: &Path,
    browser: Arc<BrowserDriver>,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    run_dir: &Path,
    selected_plan: ProviderExecutionPlan,
) -> Result<ExecutedTranscript> {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(selection) => {
            let ytdlp = ytdlp_discovery
                .map(|value| &value.provider)
                .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing subtitle execution selected without yt-dlp discovery"))?;
            let subtitle_path =
                download_selected_subtitle(ytdlp, requested_url, &selection, run_dir).await?;
            let raw_vtt = fs::read_to_string(&subtitle_path).with_context(|| {
                format!(
                    "ERROR_CLASS=VerificationMissing failed to read subtitle file {}",
                    subtitle_path.display()
                )
            })?;
            let segments = parse_webvtt_segments(&raw_vtt);
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing parsed transcript contained no subtitle segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: SUBTITLE_PROVIDER_ID,
                provider_version: ytdlp.version.to_string(),
                backend: "edge:media:yt_dlp_subtitles",
                transcript_language: selection.language_key,
                transcript_source_kind: selection.source_kind.to_string(),
                provider_model_id: None,
                provider_model_path: None,
                selected_audio_format_id: None,
                selected_audio_ext: None,
                selected_audio_acodec: None,
                segments,
            })
        }
        ProviderExecutionPlan::AudioStt(selection) => {
            let ytdlp = ytdlp_discovery
                .map(|value| &value.provider)
                .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing audio transcription selected without yt-dlp discovery"))?;
            let audio_path =
                download_selected_audio(ytdlp, requested_url, &selection, run_dir).await?;
            let model = ensure_managed_whisper_model(tool_home).await?;
            let segments = transcribe_audio_with_managed_whisper(
                &model,
                &audio_path,
                whisper_language_code(requested_language),
            )
            .await?;
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing audio transcription produced no transcript segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: AUDIO_STT_PROVIDER_ID,
                provider_version: format!(
                    "yt-dlp={};model={}@{}",
                    ytdlp.version, model.model_id, model.revision
                ),
                backend: "edge:media:yt_dlp_whisper_rs",
                transcript_language: whisper_language_code(requested_language).to_string(),
                transcript_source_kind: "stt".to_string(),
                provider_model_id: Some(model.model_id.to_string()),
                provider_model_path: Some(model.model_path.to_string_lossy().to_string()),
                selected_audio_format_id: Some(selection.format_id),
                selected_audio_ext: Some(selection.ext),
                selected_audio_acodec: Some(selection.acodec),
                segments,
            })
        }
        ProviderExecutionPlan::YouTubeWatchTranscript(selection) => {
            let transcript_json =
                fetch_youtube_watch_transcript_json(browser.as_ref(), requested_url, &selection)
                    .await?;
            let segments = parse_youtube_transcript_segments(&transcript_json);
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing youtube watch transcript returned no transcript segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
                provider_version: youtube_watch_provider_version(&selection.client_context),
                backend: "edge:media:youtube_watch_transcript",
                transcript_language: requested_language.to_string(),
                transcript_source_kind: "watch_transcript".to_string(),
                provider_model_id: None,
                provider_model_path: None,
                selected_audio_format_id: None,
                selected_audio_ext: None,
                selected_audio_acodec: None,
                segments,
            })
        }
    }
}

fn extract_timeline_artifact(
    requested_url: &str,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
) -> (Vec<MediaProviderCandidate>, Option<TimelineArtifact>) {
    let Some(context) = watch_page else {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                watch_page_failure_reason.map(str::to_string),
            )],
            None,
        );
    };
    if context.chapter_thumbnails.is_empty() {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                Some("timeline_cues_unavailable".to_string()),
            )],
            None,
        );
    }

    let cues = context
        .chapter_thumbnails
        .iter()
        .map(|chapter| MediaTimelineCue {
            timestamp_ms: chapter.start_ms,
            timestamp_label: render_timestamp(chapter.start_ms),
            title: chapter.title.clone(),
            thumbnail_url: Some(chapter.thumbnail_url.clone()),
        })
        .collect::<Vec<_>>();
    let timeline_text = cues
        .iter()
        .map(|cue| format!("[{}] {}", cue.timestamp_label, cue.title))
        .collect::<Vec<_>>()
        .join("\n");
    if timeline_text.trim().is_empty() {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                Some("timeline_text_empty".to_string()),
            )],
            None,
        );
    }

    let provider_version = youtube_watch_provider_version(&context.client_context);
    let retrieved_at_ms = now_ms();
    let timeline_hash = sha256_hex(timeline_text.as_bytes());
    let mut provider_candidate = media_provider_candidate_receipt_with_modality(
        YOUTUBE_TIMELINE_PROVIDER_ID,
        requested_url,
        "timeline",
        true,
        true,
        None,
    );
    provider_candidate.execution_attempted = Some(true);
    provider_candidate.execution_satisfied = Some(true);

    let bundle = MediaTimelineOutlineBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_multimodal_evidence".to_string(),
        backend: "edge:media:youtube_key_moments_timeline".to_string(),
        provider_id: YOUTUBE_TIMELINE_PROVIDER_ID.to_string(),
        provider_version: provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: context.canonical_url.clone(),
        provider_candidates: vec![provider_candidate.clone()],
        title: context.title.clone(),
        duration_seconds: context.duration_seconds,
        timeline_source_kind: "key_moments".to_string(),
        cue_count: cues.len() as u32,
        timeline_char_count: timeline_text.chars().count() as u32,
        timeline_hash: timeline_hash.clone(),
        timeline_text,
        cues,
    };
    let receipt = MediaMultimodalRunReceipt {
        timeline_provider_id: Some(YOUTUBE_TIMELINE_PROVIDER_ID.to_string()),
        timeline_provider_version: Some(provider_version),
        timeline_source_kind: Some("key_moments".to_string()),
        timeline_cue_count: Some(bundle.cue_count),
        timeline_char_count: Some(bundle.timeline_char_count),
        timeline_hash: Some(timeline_hash),
        ..MediaMultimodalRunReceipt::default()
    };
    (
        vec![provider_candidate],
        Some(TimelineArtifact { bundle, receipt }),
    )
}

async fn extract_visual_artifact(
    requested_url: &str,
    frame_limit: u32,
    tool_home: &Path,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
    transcript_segments: Option<&[TranscriptSegment]>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<(Vec<MediaProviderCandidate>, Option<VisualArtifact>)> {
    let vision_probe = match probe_vision_runtime(inference.clone()).await {
        Ok(value) => value,
        Err(err) => {
            let challenge_reason = provider_reason_from_error(&err);
            return Ok((
                vec![
                    failed_visual_candidate_state(
                        VISUAL_PROVIDER_ID,
                        requested_url,
                        Some(challenge_reason.clone()),
                    ),
                    failed_visual_candidate_state(
                        YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                        requested_url,
                        Some(challenge_reason),
                    ),
                ]
                .into_iter()
                .map(|state| state.candidate)
                .collect(),
                None,
            ));
        }
    };
    if !vision_probe {
        return Ok((
            vec![
                failed_visual_candidate_state(
                    VISUAL_PROVIDER_ID,
                    requested_url,
                    Some("vision_runtime_probe_unsatisfied".to_string()),
                ),
                failed_visual_candidate_state(
                    YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                    requested_url,
                    Some("vision_runtime_probe_unsatisfied".to_string()),
                ),
            ]
            .into_iter()
            .map(|state| state.candidate)
            .collect(),
            None,
        ));
    }

    let mut managed_frames_candidate = discover_managed_frames_candidate(
        requested_url,
        tool_home,
        ytdlp_discovery,
        ytdlp_failure_reason,
    )
    .await?;
    let mut chapter_thumbnail_candidate = discover_youtube_chapter_thumbnail_candidate(
        requested_url,
        watch_page,
        watch_page_failure_reason,
    );

    let selected_plans =
        select_visual_provider_plans(&managed_frames_candidate, &chapter_thumbnail_candidate);
    let provider_candidates_without_execution = vec![
        managed_frames_candidate.candidate.clone(),
        chapter_thumbnail_candidate.candidate.clone(),
    ];
    if selected_plans.is_empty() {
        return Ok((provider_candidates_without_execution, None));
    }

    let run_dir = prepare_run_dir(tool_home)?;
    let mut last_failure = None::<VisualExecutionFailure>;
    let mut executed = None::<ExecutedVisualEvidence>;
    for selected_plan in selected_plans {
        let selected_candidate = visual_candidate_state_mut(
            &mut managed_frames_candidate,
            &mut chapter_thumbnail_candidate,
            &selected_plan,
        );
        selected_candidate.candidate.execution_attempted = Some(true);
        match execute_visual_plan(
            requested_url,
            frame_limit,
            ytdlp_discovery,
            transcript_segments,
            &run_dir,
            selected_plan.clone(),
            inference.clone(),
        )
        .await
        {
            Ok(value) => {
                selected_candidate.candidate.selected = true;
                selected_candidate.candidate.execution_satisfied = Some(true);
                selected_candidate.candidate.execution_failure_reason = None;
                executed = Some(value);
                break;
            }
            Err(err) => {
                selected_candidate.candidate.execution_satisfied = Some(false);
                selected_candidate.candidate.execution_failure_reason =
                    Some(provider_reason_from_error(&err));
                last_failure = Some(VisualExecutionFailure {
                    provider_id: visual_provider_id(&selected_plan),
                    error: err,
                });
            }
        }
    }

    let Some(executed) = executed else {
        let failure = last_failure.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal media visual execution exhausted admissible providers for url={}",
                requested_url
            )
        })?;
        return Err(failure.error.context(format!(
            "visual provider execution exhausted admissible plan set after provider_id={}",
            failure.provider_id
        )));
    };

    let provider_candidates = vec![
        managed_frames_candidate.candidate.clone(),
        chapter_thumbnail_candidate.candidate.clone(),
    ];
    let visual_summary = build_visual_summary(&executed.frame_evidence);
    let visual_hash = sha256_hex(visual_summary.as_bytes());
    let visual_char_count = executed
        .frame_evidence
        .iter()
        .map(|frame| frame.scene_summary.chars().count() + frame.visible_text.chars().count())
        .sum::<usize>() as u32;
    let retrieved_at_ms = now_ms();
    let bundle = MediaVisualEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_multimodal_evidence".to_string(),
        backend: executed.backend.to_string(),
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: executed.canonical_url.clone(),
        provider_candidates: provider_candidates.clone(),
        title: executed.title.clone(),
        duration_seconds: executed.duration_seconds,
        frame_count: executed.frame_evidence.len() as u32,
        visual_char_count,
        visual_hash: visual_hash.clone(),
        visual_summary: visual_summary.clone(),
        frames: executed.frame_evidence,
    };
    let receipt = MediaMultimodalRunReceipt {
        visual_provider_id: Some(executed.provider_id.to_string()),
        visual_provider_version: Some(executed.provider_version),
        visual_provider_binary_path: executed.provider_binary_path,
        visual_ffprobe_path: executed.ffprobe_path,
        visual_selected_video_format_id: executed.selected_video_format_id,
        visual_selected_video_ext: executed.selected_video_ext,
        visual_selected_video_codec: executed.selected_video_codec,
        visual_frame_count: Some(bundle.frame_count),
        visual_char_count: Some(visual_char_count),
        visual_hash: Some(visual_hash),
        visual_summary_char_count: Some(visual_summary.chars().count() as u32),
        ..MediaMultimodalRunReceipt::default()
    };

    Ok((
        provider_candidates,
        Some(VisualArtifact { bundle, receipt }),
    ))
}

async fn discover_managed_frames_candidate(
    request_url: &str,
    tool_home: &Path,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
) -> Result<VisualProviderCandidateState> {
    let Some(ytdlp_discovery) = ytdlp_discovery else {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            ytdlp_failure_reason.map(str::to_string),
        ));
    };
    let ffmpeg = match ensure_managed_ffmpeg_provider(tool_home).await {
        Ok(provider) => provider,
        Err(err) => {
            return Ok(failed_visual_candidate_state(
                VISUAL_PROVIDER_ID,
                request_url,
                Some(provider_reason_from_error(&err)),
            ));
        }
    };
    let Some(video_format) = select_video_format(&ytdlp_discovery.metadata) else {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            Some("supported_video_format_unavailable".to_string()),
        ));
    };
    let duration_seconds = ytdlp_discovery
        .metadata
        .get("duration")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if duration_seconds == 0 {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            Some("duration_unavailable".to_string()),
        ));
    }

    Ok(VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            VISUAL_PROVIDER_ID,
            request_url,
            "visual",
            false,
            true,
            None,
        ),
        plan: Some(VisualProviderExecutionPlan::ManagedFrames {
            ffmpeg,
            video_format,
        }),
    })
}

fn discover_youtube_chapter_thumbnail_candidate(
    request_url: &str,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
) -> VisualProviderCandidateState {
    let Some(context) = watch_page else {
        return failed_visual_candidate_state(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            watch_page_failure_reason.map(str::to_string),
        );
    };
    if context.chapter_thumbnails.is_empty() {
        return failed_visual_candidate_state(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            Some("chapter_thumbnails_unavailable".to_string()),
        );
    }
    VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            "visual",
            false,
            true,
            None,
        ),
        plan: Some(VisualProviderExecutionPlan::YouTubeChapterThumbnails {
            provider_version: youtube_watch_provider_version(&context.client_context),
            title: context.title.clone(),
            canonical_url: context.canonical_url.clone(),
            duration_seconds: context.duration_seconds,
            chapter_thumbnails: context.chapter_thumbnails.clone(),
        }),
    }
}

fn failed_visual_candidate_state(
    provider_id: &str,
    request_url: &str,
    challenge_reason: Option<String>,
) -> VisualProviderCandidateState {
    VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            provider_id,
            request_url,
            "visual",
            false,
            false,
            challenge_reason,
        ),
        plan: None,
    }
}

fn select_visual_provider_plans(
    managed_frames_candidate: &VisualProviderCandidateState,
    chapter_thumbnail_candidate: &VisualProviderCandidateState,
) -> Vec<VisualProviderExecutionPlan> {
    let mut plans = Vec::new();
    if let Some(plan) = managed_frames_candidate.plan.clone() {
        plans.push(plan);
    }
    if let Some(plan) = chapter_thumbnail_candidate.plan.clone() {
        plans.push(plan);
    }
    plans
}

fn visual_provider_id(plan: &VisualProviderExecutionPlan) -> &'static str {
    match plan {
        VisualProviderExecutionPlan::ManagedFrames { .. } => VISUAL_PROVIDER_ID,
        VisualProviderExecutionPlan::YouTubeChapterThumbnails { .. } => {
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID
        }
    }
}

fn visual_candidate_state_mut<'a>(
    managed_frames_candidate: &'a mut VisualProviderCandidateState,
    chapter_thumbnail_candidate: &'a mut VisualProviderCandidateState,
    selected_plan: &VisualProviderExecutionPlan,
) -> &'a mut VisualProviderCandidateState {
    match selected_plan {
        VisualProviderExecutionPlan::ManagedFrames { .. } => managed_frames_candidate,
        VisualProviderExecutionPlan::YouTubeChapterThumbnails { .. } => chapter_thumbnail_candidate,
    }
}

async fn execute_visual_plan(
    requested_url: &str,
    frame_limit: u32,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    transcript_segments: Option<&[TranscriptSegment]>,
    run_dir: &Path,
    selected_plan: VisualProviderExecutionPlan,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutedVisualEvidence> {
    match selected_plan {
        VisualProviderExecutionPlan::ManagedFrames {
            ffmpeg,
            video_format,
        } => {
            let ytdlp_discovery = ytdlp_discovery.ok_or_else(|| {
                anyhow!(
                    "ERROR_CLASS=DiscoveryMissing visual managed-frames execution selected without yt-dlp discovery"
                )
            })?;
            let video_path = download_selected_video(
                &ytdlp_discovery.provider,
                requested_url,
                &video_format,
                run_dir,
            )
            .await?;
            let duration_seconds = ytdlp_discovery
                .metadata
                .get("duration")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    anyhow!(
                        "ERROR_CLASS=VerificationMissing visual sampling requires a positive media duration."
                    )
                })?;
            let timestamps_ms =
                sample_visual_frame_timestamps(duration_seconds, frame_limit as usize);
            if timestamps_ms.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual sampling produced no frame timestamps."
                ));
            }
            let frame_samples =
                extract_visual_frame_samples(&ffmpeg, &video_path, &timestamps_ms, run_dir).await?;
            let frame_evidence =
                analyze_visual_frame_samples(&frame_samples, transcript_segments, inference)
                    .await?;
            if frame_evidence.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis produced no observations."
                ));
            }
            Ok(ExecutedVisualEvidence {
                provider_id: VISUAL_PROVIDER_ID,
                provider_version: ffmpeg.version.to_string(),
                backend: "edge:media:ffmpeg_vision",
                provider_binary_path: Some(ffmpeg.ffmpeg_path.to_string_lossy().to_string()),
                ffprobe_path: Some(ffmpeg.ffprobe_path.to_string_lossy().to_string()),
                selected_video_format_id: Some(video_format.format_id),
                selected_video_ext: Some(video_format.ext),
                selected_video_codec: Some(video_format.vcodec),
                canonical_url: ytdlp_discovery
                    .metadata
                    .get("webpage_url")
                    .or_else(|| ytdlp_discovery.metadata.get("original_url"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(requested_url)
                    .to_string(),
                title: ytdlp_discovery
                    .metadata
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                duration_seconds: Some(duration_seconds),
                frame_evidence,
            })
        }
        VisualProviderExecutionPlan::YouTubeChapterThumbnails {
            provider_version,
            title,
            canonical_url,
            duration_seconds,
            chapter_thumbnails,
        } => {
            let selected_chapters = sample_chapter_thumbnails(&chapter_thumbnails, frame_limit);
            if selected_chapters.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing chapter thumbnail sampling produced no frames."
                ));
            }
            let frame_samples = download_chapter_thumbnail_samples(&selected_chapters).await?;
            let frame_evidence =
                analyze_visual_frame_samples(&frame_samples, transcript_segments, inference)
                    .await?;
            if frame_evidence.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis produced no observations."
                ));
            }
            Ok(ExecutedVisualEvidence {
                provider_id: YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                provider_version,
                backend: "edge:media:youtube_chapter_thumbnails_vision",
                provider_binary_path: None,
                ffprobe_path: None,
                selected_video_format_id: None,
                selected_video_ext: None,
                selected_video_codec: None,
                canonical_url,
                title,
                duration_seconds,
                frame_evidence,
            })
        }
    }
}

fn media_tool_home() -> PathBuf {
    if let Ok(raw) = std::env::var(MEDIA_TOOL_HOME_ENV) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(".cache")
                .join("ioi")
                .join("media_tooling");
        }
    }

    std::env::temp_dir().join("ioi_media_tooling")
}

async fn ensure_managed_ytdlp_provider(tool_home: &Path) -> Result<ManagedYtDlpProvider> {
    let asset_name = select_ytdlp_asset_name()?;
    let expected_sha = fetch_expected_ytdlp_sha(asset_name).await?;
    let binary_dir = tool_home.join("bin");
    fs::create_dir_all(&binary_dir)?;
    let binary_path = binary_dir.join(asset_name);

    let needs_download = fs::read(&binary_path)
        .map(|bytes| sha256_hex(&bytes) != expected_sha)
        .unwrap_or(true);
    if needs_download {
        let asset_url = format!(
            "https://github.com/yt-dlp/yt-dlp/releases/download/{}/{}",
            YTDLP_PROVIDER_VERSION, asset_name
        );
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(45))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize yt-dlp download client")?;
        let bytes = client
            .get(asset_url)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download yt-dlp asset")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed yt-dlp asset request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read yt-dlp asset bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing managed yt-dlp checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&binary_path, &bytes, true)?;
    }

    Ok(ManagedYtDlpProvider {
        binary_path,
        asset_name,
        version: YTDLP_PROVIDER_VERSION,
    })
}

async fn ensure_managed_ffmpeg_provider(tool_home: &Path) -> Result<ManagedFfmpegProvider> {
    let asset = select_ffmpeg_asset()?;
    let expected_sha = fetch_expected_ffmpeg_sha(asset.asset_name).await?;
    let provider_root = tool_home.join("ffmpeg").join(FFMPEG_PROVIDER_VERSION);
    let archive_path = provider_root.join(asset.asset_name);
    let extract_root = provider_root.join("extract");
    let checksum_pin = provider_root.join("sha256.pin");
    let mut needs_download = true;
    if let Ok(bytes) = fs::read(&archive_path) {
        needs_download = sha256_hex(&bytes) != expected_sha;
    }
    fs::create_dir_all(&provider_root)?;
    if needs_download {
        let asset_url = format!(
            "https://github.com/BtbN/FFmpeg-Builds/releases/download/{}/{}",
            FFMPEG_PROVIDER_VERSION, asset.asset_name
        );
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(FFMPEG_DOWNLOAD_TIMEOUT_SECS))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize ffmpeg download client")?;
        let bytes = client
            .get(asset_url)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download ffmpeg asset")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed ffmpeg asset request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read ffmpeg asset bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing managed ffmpeg checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&archive_path, &bytes, false)?;
        if extract_root.exists() {
            fs::remove_dir_all(&extract_root)?;
        }
    }

    let pin_matches = fs::read_to_string(&checksum_pin)
        .ok()
        .map(|raw| raw.trim().eq_ignore_ascii_case(&expected_sha))
        .unwrap_or(false);
    let binaries_ready = locate_ffmpeg_binary(&extract_root, "ffmpeg").and_then(|ffmpeg_path| {
        locate_ffmpeg_binary(&extract_root, "ffprobe")
            .map(|ffprobe_path| (ffmpeg_path, ffprobe_path))
    });

    let (ffmpeg_path, ffprobe_path) = if pin_matches {
        binaries_ready.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing managed ffmpeg extraction missing binaries under {}",
                extract_root.display()
            )
        })?
    } else {
        if extract_root.exists() {
            fs::remove_dir_all(&extract_root)?;
        }
        fs::create_dir_all(&extract_root)?;
        extract_ffmpeg_archive(&archive_path, &extract_root, asset.archive_kind)?;
        let ffmpeg_path = locate_ffmpeg_binary(&extract_root, "ffmpeg").ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing extracted ffmpeg archive did not contain ffmpeg binary."
            )
        })?;
        let ffprobe_path = locate_ffmpeg_binary(&extract_root, "ffprobe").ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing extracted ffmpeg archive did not contain ffprobe binary."
            )
        })?;
        fs::write(&checksum_pin, format!("{}\n", expected_sha)).with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to write ffmpeg checksum pin {}",
                checksum_pin.display()
            )
        })?;
        (ffmpeg_path, ffprobe_path)
    };

    Ok(ManagedFfmpegProvider {
        ffmpeg_path,
        ffprobe_path,
        version: FFMPEG_PROVIDER_VERSION,
    })
}

async fn ensure_managed_whisper_model(tool_home: &Path) -> Result<ManagedWhisperModel> {
    let model_dir = tool_home.join("models");
    fs::create_dir_all(&model_dir)?;
    let model_path = model_dir.join(WHISPER_MODEL_FILE_NAME);
    let expected_sha = fetch_expected_model_sha().await?;
    let needs_download = fs::read(&model_path)
        .map(|bytes| sha256_hex(&bytes) != expected_sha)
        .unwrap_or(true);
    if needs_download {
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::limited(5))
            .timeout(Duration::from_secs(MODEL_DOWNLOAD_TIMEOUT_SECS))
            .build()
            .context("ERROR_CLASS=SynthesisFailed failed to initialize whisper model client")?;
        let bytes = client
            .get(WHISPER_MODEL_URL)
            .send()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to download whisper model")?
            .error_for_status()
            .context("ERROR_CLASS=SynthesisFailed whisper model request returned error status")?
            .bytes()
            .await
            .context("ERROR_CLASS=SynthesisFailed failed to read whisper model bytes")?;
        let observed_sha = sha256_hex(&bytes);
        if observed_sha != expected_sha {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing whisper model checksum mismatch expected={} observed={}",
                expected_sha,
                observed_sha
            ));
        }
        persist_downloaded_asset(&model_path, &bytes, false)?;
    }

    Ok(ManagedWhisperModel {
        model_path,
        model_id: WHISPER_MODEL_ID,
        revision: WHISPER_MODEL_REVISION,
    })
}

fn persist_downloaded_asset(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal asset path had no parent {}",
            path.display()
        ));
    };
    fs::create_dir_all(parent)?;
    let temp_path = path.with_extension("download");
    fs::write(&temp_path, bytes)?;
    #[cfg(unix)]
    if executable {
        let mut perms = fs::metadata(&temp_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&temp_path, perms)?;
    }
    fs::rename(&temp_path, path)?;
    Ok(())
}

fn select_ytdlp_asset_name() -> Result<&'static str> {
    match std::env::consts::OS {
        "linux" => Ok("yt-dlp"),
        "windows" => Ok("yt-dlp.exe"),
        "macos" => Ok("yt-dlp_macos"),
        other => Err(anyhow!(
            "ERROR_CLASS=SynthesisFailed unsupported managed yt-dlp host os '{}'",
            other
        )),
    }
}

fn select_ffmpeg_asset() -> Result<ManagedFfmpegAsset> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-linux64-gpl.tar.xz",
            archive_kind: FfmpegArchiveKind::TarXz,
        }),
        ("linux", "aarch64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-linuxarm64-gpl.tar.xz",
            archive_kind: FfmpegArchiveKind::TarXz,
        }),
        ("windows", "x86_64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-win64-gpl.zip",
            archive_kind: FfmpegArchiveKind::Zip,
        }),
        ("windows", "aarch64") => Ok(ManagedFfmpegAsset {
            asset_name: "ffmpeg-N-123196-gba38fa206e-winarm64-gpl.zip",
            archive_kind: FfmpegArchiveKind::Zip,
        }),
        (os, arch) => Err(anyhow!(
            "ERROR_CLASS=SynthesisFailed unsupported managed ffmpeg host os='{}' arch='{}'",
            os,
            arch
        )),
    }
}

async fn fetch_expected_ytdlp_sha(asset_name: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize checksum client")?;
    let sums = client
        .get(YTDLP_SUMS_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch yt-dlp checksum manifest")?
        .error_for_status()
        .context("ERROR_CLASS=SynthesisFailed yt-dlp checksum manifest returned error status")?
        .text()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to read yt-dlp checksum manifest")?;
    sums.lines()
        .find_map(|line| parse_sha256sum_line(line, asset_name))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing checksum manifest did not contain asset '{}'",
                asset_name
            )
        })
}

async fn fetch_expected_ffmpeg_sha(asset_name: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize ffmpeg checksum client")?;
    let sums = client
        .get(FFMPEG_SUMS_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch ffmpeg checksum manifest")?
        .error_for_status()
        .context("ERROR_CLASS=SynthesisFailed ffmpeg checksum manifest returned error status")?
        .text()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to read ffmpeg checksum manifest")?;
    sums.lines()
        .find_map(|line| parse_sha256sum_line(line, asset_name))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing ffmpeg checksum manifest did not contain asset '{}'",
                asset_name
            )
        })
}

async fn fetch_expected_model_sha() -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize whisper metadata client")?;
    let response = client
        .head(WHISPER_MODEL_URL)
        .send()
        .await
        .context("ERROR_CLASS=SynthesisFailed failed to fetch whisper model metadata")?;
    response
        .headers()
        .get("x-linked-etag")
        .or_else(|| response.headers().get(header::ETAG))
        .and_then(parse_header_hex_sha256)
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing whisper model metadata did not expose a sha256 etag"
            )
        })
}

fn parse_sha256sum_line(line: &str, asset_name: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let sha = parts.next()?;
    let name = parts.next()?.trim_start_matches('*');
    (name == asset_name).then(|| sha.to_ascii_lowercase())
}

fn parse_header_hex_sha256(value: &header::HeaderValue) -> Option<String> {
    let parsed = value
        .to_str()
        .ok()?
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase();
    (parsed.len() == 64 && parsed.chars().all(|ch| ch.is_ascii_hexdigit())).then_some(parsed)
}

fn extract_ffmpeg_archive(
    archive_path: &Path,
    extract_root: &Path,
    kind: FfmpegArchiveKind,
) -> Result<()> {
    match kind {
        FfmpegArchiveKind::TarXz => {
            let file = File::open(archive_path).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to open ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
            let decoder = XzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            archive.unpack(extract_root).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to unpack ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
        }
        FfmpegArchiveKind::Zip => {
            let file = File::open(archive_path).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to open ffmpeg archive {}",
                    archive_path.display()
                )
            })?;
            let mut archive = ZipArchive::new(file).with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to inspect ffmpeg zip archive {}",
                    archive_path.display()
                )
            })?;
            for idx in 0..archive.len() {
                let mut entry = archive.by_index(idx)?;
                let out_path = extract_root.join(entry.name());
                if entry.name().ends_with('/') {
                    fs::create_dir_all(&out_path)?;
                    continue;
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&out_path)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }
    }
    Ok(())
}

fn locate_ffmpeg_binary(extract_root: &Path, stem: &str) -> Option<PathBuf> {
    let expected = if cfg!(windows) {
        format!("{}.exe", stem)
    } else {
        stem.to_string()
    };
    WalkDir::new(extract_root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().to_path_buf())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case(&expected))
        })
}

fn prepare_run_dir(tool_home: &Path) -> Result<PathBuf> {
    let run_dir = tool_home.join("run");
    if run_dir.exists() {
        fs::remove_dir_all(&run_dir)?;
    }
    fs::create_dir_all(run_dir.join("cache"))?;
    Ok(run_dir)
}

fn youtube_video_id_from_url(request_url: &str) -> Option<String> {
    let parsed = Url::parse(request_url).ok()?;
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    if host.ends_with("youtu.be") {
        return parsed
            .path_segments()?
            .find(|segment| !segment.trim().is_empty())
            .map(|segment| segment.trim().to_string());
    }
    if host.ends_with("youtube.com") || host.ends_with("youtube-nocookie.com") {
        if parsed.path().eq_ignore_ascii_case("/watch") {
            return parsed
                .query_pairs()
                .find(|(key, value)| key.eq_ignore_ascii_case("v") && !value.trim().is_empty())
                .map(|(_, value)| value.to_string());
        }
        let mut segments = parsed.path_segments()?;
        let first = segments.next()?.trim();
        let second = segments.next()?.trim();
        if matches!(first, "embed" | "shorts" | "live") && !second.is_empty() {
            return Some(second.to_string());
        }
    }
    None
}

async fn discover_youtube_watch_page_context(
    request_url: &str,
) -> Result<Option<YouTubeWatchPageContext>> {
    let Some(video_id) = youtube_video_id_from_url(request_url) else {
        return Ok(None);
    };
    let watch_url = format!("https://www.youtube.com/watch?v={video_id}");
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(YOUTUBE_WATCH_PAGE_TIMEOUT_SECS))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize youtube watch-page client")?;
    let response = client
        .get(&watch_url)
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to fetch youtube watch page")?
        .error_for_status()
        .context("ERROR_CLASS=ExecutionFailedTerminal youtube watch page returned error status")?;
    let resolved_url = response.url().to_string();
    let html = response
        .text()
        .await
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to read youtube watch page html")?;
    parse_youtube_watch_page_context(&resolved_url, &html).map(Some)
}

fn parse_youtube_watch_page_context(
    resolved_url: &str,
    html: &str,
) -> Result<YouTubeWatchPageContext> {
    let initial_data =
        extract_inline_json_after_prefix(html, "var ytInitialData = ").ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing ytInitialData")
        })?;
    let api_key =
        extract_quoted_value_after_prefix(html, "\"INNERTUBE_API_KEY\":\"").ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing innertube api key")
        })?;
    let initial_player_response =
        extract_inline_json_after_prefix(html, "var ytInitialPlayerResponse = ");
    let client_context = extract_inline_json_after_prefix(html, "\"INNERTUBE_CONTEXT\":")
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing innertube context")
        })?;
    let transcript_params = youtube_watch_transcript_params(&initial_data);
    let transcript_challenge_reason = initial_player_response
        .as_ref()
        .and_then(youtube_watch_transcript_challenge_reason);
    let title = youtube_watch_title(&initial_data);
    let chapter_thumbnails = youtube_watch_chapter_thumbnails(&initial_data);
    let duration_seconds = extract_quoted_value_after_prefix(html, "\"lengthSeconds\":\"")
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            chapter_thumbnails
                .iter()
                .map(|chapter| chapter.start_ms / 1_000)
                .max()
        });

    if transcript_params.is_none() && chapter_thumbnails.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=DiscoveryMissing youtube watch page exposed neither transcript endpoint nor chapter thumbnails"
        ));
    }

    Ok(YouTubeWatchPageContext {
        api_key,
        client_context,
        transcript_params,
        transcript_challenge_reason,
        title,
        canonical_url: resolved_url.to_string(),
        duration_seconds,
        chapter_thumbnails,
    })
}

fn youtube_watch_transcript_challenge_reason(player_response: &Value) -> Option<String> {
    let status = player_response
        .get("playabilityStatus")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if status.eq_ignore_ascii_case("OK") {
        return None;
    }
    let reason = player_response
        .get("playabilityStatus")
        .and_then(|value| value.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("transcript_surface_unavailable");
    Some(format!(
        "youtube_watch_playability_block:{}:{}",
        status.to_ascii_lowercase(),
        compact_ws(reason)
    ))
}

fn extract_inline_json_after_prefix(raw: &str, prefix: &str) -> Option<Value> {
    let start = raw.find(prefix)? + prefix.len();
    let mut idx = start;
    while let Some(ch) = raw[idx..].chars().next() {
        if ch.is_whitespace() {
            idx += ch.len_utf8();
            continue;
        }
        if ch != '{' && ch != '[' {
            return None;
        }
        let end = matching_json_end(&raw[idx..])?;
        return serde_json::from_str::<Value>(&raw[idx..idx + end]).ok();
    }
    None
}

fn matching_json_end(raw: &str) -> Option<usize> {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' => stack.push(ch),
            '}' => {
                if stack.pop() != Some('{') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_quoted_value_after_prefix(raw: &str, prefix: &str) -> Option<String> {
    let start = raw.find(prefix)? + prefix.len();
    let tail = &raw[start..];
    let end = tail.find('"')?;
    Some(tail[..end].replace("\\u003d", "=").replace("\\u0026", "&"))
}

fn youtube_watch_transcript_params(initial_data: &Value) -> Option<String> {
    find_first_object_by_key(initial_data, "getTranscriptEndpoint")
        .and_then(Value::as_object)
        .and_then(|value| value.get("params"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn youtube_watch_title(initial_data: &Value) -> Option<String> {
    find_first_object_by_key(initial_data, "videoPrimaryInfoRenderer")
        .and_then(Value::as_object)
        .and_then(|value| value.get("title"))
        .and_then(value_text)
}

fn youtube_watch_chapter_thumbnails(initial_data: &Value) -> Vec<YouTubeChapterThumbnail> {
    let Some(renderer) = find_first_object_by_key(initial_data, "macroMarkersListRenderer") else {
        return Vec::new();
    };
    let mut chapters = renderer
        .get("contents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("macroMarkersListItemRenderer"))
        .filter_map(|renderer| {
            let title = renderer.get("title").and_then(value_text)?;
            let start_seconds = renderer
                .get("onTap")
                .and_then(|value| value.get("watchEndpoint"))
                .and_then(|value| value.get("startTimeSeconds"))
                .and_then(Value::as_f64)
                .filter(|value| *value >= 0.0)?;
            let thumbnail_url = renderer
                .get("thumbnail")
                .and_then(|value| value.get("thumbnails"))
                .and_then(Value::as_array)
                .and_then(|value| value.last())
                .and_then(|value| value.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?
                .to_string();
            Some(YouTubeChapterThumbnail {
                title,
                start_ms: (start_seconds * 1_000.0).round() as u64,
                thumbnail_url,
            })
        })
        .collect::<Vec<_>>();
    chapters.sort_by_key(|chapter| chapter.start_ms);
    chapters.dedup_by(|left, right| left.start_ms == right.start_ms);
    chapters
}

fn find_first_object_by_key<'a>(value: &'a Value, needle: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(needle) {
                return Some(found);
            }
            map.values()
                .find_map(|candidate| find_first_object_by_key(candidate, needle))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|candidate| find_first_object_by_key(candidate, needle)),
        _ => None,
    }
}

fn value_text(value: &Value) -> Option<String> {
    if let Some(simple) = value.get("simpleText").and_then(Value::as_str) {
        let trimmed = simple.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let runs = value.get("runs").and_then(Value::as_array)?;
    let text = runs
        .iter()
        .filter_map(|run| run.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("");
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

async fn discover_optional_ytdlp(
    requested_url: &str,
    tool_home: &Path,
) -> (Option<ManagedYtDlpDiscovery>, Option<String>) {
    match ensure_managed_ytdlp_provider(tool_home).await {
        Ok(provider) => match prepare_run_dir(tool_home) {
            Ok(run_dir) => match fetch_ytdlp_metadata(&provider, requested_url, &run_dir).await {
                Ok(metadata) => (Some(ManagedYtDlpDiscovery { provider, metadata }), None),
                Err(err) => (None, Some(provider_reason_from_error(&err))),
            },
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        },
        Err(err) => (None, Some(provider_reason_from_error(&err))),
    }
}

fn transcript_provider_binary_path(discovery: Option<&ManagedYtDlpDiscovery>) -> String {
    discovery
        .map(|value| value.provider.binary_path.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn failed_transcript_candidate_state(
    provider_id: &str,
    request_url: &str,
    challenge_reason: Option<String>,
) -> MediaProviderCandidateState {
    MediaProviderCandidateState {
        candidate: media_provider_candidate_receipt(
            provider_id,
            request_url,
            false,
            false,
            challenge_reason,
        ),
        plan: None,
    }
}

fn media_canonical_url(
    requested_url: &str,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> String {
    ytdlp_discovery
        .and_then(|value| {
            value
                .metadata
                .get("webpage_url")
                .or_else(|| value.metadata.get("original_url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| watch_page.map(|value| value.canonical_url.clone()))
        .unwrap_or_else(|| requested_url.to_string())
}

fn media_title(
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> Option<String> {
    ytdlp_discovery
        .and_then(|value| {
            value
                .metadata
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| watch_page.and_then(|value| value.title.clone()))
}

fn media_duration_seconds(
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> Option<u64> {
    ytdlp_discovery
        .and_then(|value| value.metadata.get("duration").and_then(Value::as_u64))
        .or_else(|| watch_page.and_then(|value| value.duration_seconds))
}

fn youtube_watch_provider_version(client_context: &Value) -> String {
    client_context
        .get("client")
        .and_then(|value| value.get("clientVersion"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("youtube-web@{value}"))
        .unwrap_or_else(|| "youtube-web".to_string())
}

async fn fetch_ytdlp_metadata(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    run_dir: &Path,
) -> Result<Value> {
    let args = vec![
        "--dump-single-json".to_string(),
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--skip-download".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let output = run_managed_ytdlp(provider, &args, run_dir, YTDLP_METADATA_TIMEOUT_SECS).await?;
    serde_json::from_slice::<Value>(&output.stdout).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse yt-dlp metadata json stdout={} stderr={}",
            truncate_log(&String::from_utf8_lossy(&output.stdout), 300),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 300)
        )
    })
}

#[derive(Debug, Deserialize)]
struct BrowserFetchJsonResponse {
    status: u16,
    body: String,
}

async fn fetch_youtube_watch_transcript_json(
    browser: &BrowserDriver,
    request_url: &str,
    selection: &YouTubeWatchTranscriptSelection,
) -> Result<Value> {
    browser
        .navigate_retrieval(request_url)
        .await
        .map_err(|err| anyhow!("ERROR_CLASS=ExecutionFailedTerminal failed to load youtube watch page in browser context: {}", err))?;

    let endpoint = format!(
        "/youtubei/v1/get_transcript?prettyPrint=false&key={}",
        selection.api_key
    );
    let payload = json!({
        "context": selection.client_context,
        "params": selection.transcript_params,
    });
    let script = format!(
        r#"(async () => {{
            const ytcfgGet =
                typeof window !== "undefined" && window.ytcfg && typeof window.ytcfg.get === "function"
                    ? (key) => window.ytcfg.get(key)
                    : () => undefined;
            const clientName =
                ytcfgGet("INNERTUBE_CONTEXT_CLIENT_NAME")
                ?? ytcfgGet("INNERTUBE_CONTEXT_CLIENT_NAME_INT")
                ?? {client_name};
            const clientVersion =
                ytcfgGet("INNERTUBE_CONTEXT_CLIENT_VERSION")
                ?? {client_version};
            const visitorData =
                ytcfgGet("VISITOR_DATA")
                ?? {visitor_data};
            const authUser =
                ytcfgGet("SESSION_INDEX")
                ?? ytcfgGet("LOGGED_IN_USER_INDEX");
            const delegatedSessionId = ytcfgGet("DELEGATED_SESSION_ID");
            const payload = {payload};
            if (delegatedSessionId) {{
                payload.context = payload.context || {{}};
                payload.context.user = payload.context.user || {{}};
                payload.context.user.delegatedSessionId = String(delegatedSessionId);
            }}
            const headers = {{
                "content-type": "application/json"
            }};
            if (clientName !== undefined && clientName !== null && String(clientName).trim() !== "") {{
                headers["x-youtube-client-name"] = String(clientName);
            }}
            if (clientVersion !== undefined && clientVersion !== null && String(clientVersion).trim() !== "") {{
                headers["x-youtube-client-version"] = String(clientVersion);
            }}
            if (visitorData !== undefined && visitorData !== null && String(visitorData).trim() !== "") {{
                headers["x-goog-visitor-id"] = String(visitorData);
            }}
            if (authUser !== undefined && authUser !== null && String(authUser).trim() !== "") {{
                headers["x-goog-authuser"] = String(authUser);
            }}
            if (typeof location !== "undefined" && location.origin) {{
                headers["x-origin"] = location.origin;
            }}
            const response = await fetch({endpoint}, {{
                method: "POST",
                credentials: "include",
                headers,
                body: JSON.stringify(payload)
            }});
            return {{
                status: response.status,
                body: await response.text()
            }};
        }})()"#,
        endpoint = serde_json::to_string(&endpoint).unwrap_or_else(|_| "\"\"".to_string()),
        payload = payload,
        client_name = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("clientName"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string()),
        client_version = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("clientVersion"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string()),
        visitor_data = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("visitorData"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string())
    );
    let response: BrowserFetchJsonResponse =
        browser
            .evaluate_retrieval_js(&script)
            .await
            .map_err(|err| {
                anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal browser transcript fetch failed: {}",
                    err
                )
            })?;
    if response.status != 200 {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal youtube watch transcript request failed status={} body={}",
            response.status,
            truncate_log(&response.body, 300)
        ));
    }
    serde_json::from_str::<Value>(&response.body).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse youtube transcript json {}",
            truncate_log(&response.body, 300)
        )
    })
}

fn parse_youtube_transcript_segments(payload: &Value) -> Vec<TranscriptSegment> {
    let mut segments = Vec::new();
    collect_youtube_transcript_segments(payload, &mut segments);
    segments.sort_by_key(|segment| segment.start_ms);
    segments.dedup_by(|left, right| left.start_ms == right.start_ms || left.text == right.text);
    segments
}

fn collect_youtube_transcript_segments(value: &Value, output: &mut Vec<TranscriptSegment>) {
    match value {
        Value::Object(map) => {
            if let Some(renderer) = map.get("transcriptSegmentRenderer") {
                let start_ms = renderer
                    .get("startMs")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok());
                let text = renderer
                    .get("snippet")
                    .and_then(value_text)
                    .map(|value| compact_ws(&value))
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                if let (Some(start_ms), Some(text)) = (start_ms, text) {
                    output.push(TranscriptSegment { start_ms, text });
                }
            }
            for nested in map.values() {
                collect_youtube_transcript_segments(nested, output);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_youtube_transcript_segments(nested, output);
            }
        }
        _ => {}
    }
}

fn sample_chapter_thumbnails(
    chapter_thumbnails: &[YouTubeChapterThumbnail],
    frame_limit: u32,
) -> Vec<YouTubeChapterThumbnail> {
    sample_sequence_indices(chapter_thumbnails.len(), frame_limit as usize)
        .into_iter()
        .filter_map(|index| chapter_thumbnails.get(index).cloned())
        .collect()
}

fn sample_sequence_indices(total: usize, count: usize) -> Vec<usize> {
    if total == 0 || count == 0 {
        return Vec::new();
    }
    if count >= total {
        return (0..total).collect();
    }
    if count == 1 {
        return vec![0];
    }

    let span = total.saturating_sub(1);
    let denominator = count.saturating_sub(1);
    let mut indices = (0..count)
        .map(|idx| ((idx * span) + (denominator / 2)) / denominator)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

async fn download_chapter_thumbnail_samples(
    chapter_thumbnails: &[YouTubeChapterThumbnail],
) -> Result<Vec<VisualFrameSample>> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(45))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize chapter thumbnail client")?;
    let mut samples = Vec::with_capacity(chapter_thumbnails.len());
    for chapter in chapter_thumbnails {
        let response = client
            .get(&chapter.thumbnail_url)
            .header(
                header::USER_AGENT,
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            )
            .send()
            .await
            .with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to fetch chapter thumbnail {}",
                    chapter.thumbnail_url
                )
            })?
            .error_for_status()
            .with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal chapter thumbnail request returned error status {}",
                    chapter.thumbnail_url
                )
            })?;
        let bytes = response.bytes().await.context(
            "ERROR_CLASS=ExecutionFailedTerminal failed to read chapter thumbnail bytes",
        )?;
        if bytes.is_empty() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing chapter thumbnail bytes were empty."
            ));
        }
        let image = image::load_from_memory(&bytes)
            .context("ERROR_CLASS=VerificationMissing failed to decode chapter thumbnail bytes")?;
        let (width, height) = image.dimensions();
        let format = image::guess_format(&bytes).unwrap_or(ImageFormat::Jpeg);
        samples.push(VisualFrameSample {
            timestamp_ms: chapter.start_ms,
            timestamp_label: render_timestamp(chapter.start_ms),
            frame_hash: sha256_hex(bytes.as_ref()),
            mime_type: image_format_mime_type(format).to_string(),
            width,
            height,
            bytes: bytes.to_vec(),
        });
    }
    Ok(samples)
}

fn image_format_mime_type(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Gif => "image/gif",
        ImageFormat::WebP => "image/webp",
        ImageFormat::Bmp => "image/bmp",
        _ => "image/jpeg",
    }
}

async fn download_selected_subtitle(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &SubtitleSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let mut args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--skip-download".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "--convert-subs".to_string(),
        "vtt".to_string(),
        "--sub-langs".to_string(),
        selection.language_key.clone(),
        "-o".to_string(),
        run_dir
            .join("transcript.%(ext)s")
            .to_string_lossy()
            .to_string(),
    ];
    if selection.source_kind == "manual" {
        args.push("--write-subs".to_string());
    } else {
        args.push("--write-auto-subs".to_string());
    }
    args.push(request_url.to_string());

    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_SUBTITLE_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect subtitle directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("vtt"))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing yt-dlp did not materialize a .vtt subtitle file."
            )
        })
}

async fn download_selected_audio(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &AudioFormatSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "-f".to_string(),
        selection.format_id.clone(),
        "-o".to_string(),
        run_dir.join("audio.%(ext)s").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_AUDIO_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect audio directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("audio.")
                            && !name.ends_with(".part")
                            && !name.ends_with(".ytdl")
                    })
        })
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing yt-dlp did not materialize an audio file.")
        })
}

async fn download_selected_video(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &VideoFormatSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "-f".to_string(),
        selection.format_id.clone(),
        "-o".to_string(),
        run_dir.join("video.%(ext)s").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_VIDEO_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect video directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("video.")
                            && !name.ends_with(".part")
                            && !name.ends_with(".ytdl")
                    })
        })
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing yt-dlp did not materialize a video file.")
        })
}

struct CommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_managed_ytdlp(
    provider: &ManagedYtDlpProvider,
    args: &[String],
    run_dir: &Path,
    timeout_secs: u64,
) -> Result<CommandOutput> {
    let mut command = Command::new(&provider.binary_path);
    command
        .args(args)
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(timeout_secs), command.output())
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal yt-dlp timed out after {}s asset={}",
                timeout_secs,
                provider.asset_name
            )
        })?
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to launch managed yt-dlp binary {}",
                provider.binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal managed yt-dlp failed status={} stdout={} stderr={}",
            output.status,
            truncate_log(&String::from_utf8_lossy(&output.stdout), 400),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 400)
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

async fn run_managed_ffmpeg(
    binary_path: &Path,
    args: &[String],
    run_dir: &Path,
    timeout_secs: u64,
) -> Result<CommandOutput> {
    let mut command = Command::new(binary_path);
    command
        .args(args)
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(timeout_secs), command.output())
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal ffmpeg timed out after {}s binary={}",
                timeout_secs,
                binary_path.display()
            )
        })?
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to launch managed ffmpeg binary {}",
                binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal managed ffmpeg failed status={} stdout={} stderr={}",
            output.status,
            truncate_log(&String::from_utf8_lossy(&output.stdout), 400),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 400)
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn sample_visual_frame_timestamps(duration_seconds: u64, frame_count: usize) -> Vec<u64> {
    if duration_seconds == 0 || frame_count == 0 {
        return Vec::new();
    }
    let duration_ms = duration_seconds.saturating_mul(1_000);
    let start_ms = duration_ms / 20;
    let end_ms = duration_ms.saturating_sub(duration_ms / 20);
    if frame_count == 1 || start_ms >= end_ms {
        return vec![start_ms.min(duration_ms.saturating_sub(1))];
    }

    let span = end_ms.saturating_sub(start_ms);
    (0..frame_count)
        .map(|idx| {
            let ratio = idx as f64 / (frame_count.saturating_sub(1)) as f64;
            start_ms.saturating_add((span as f64 * ratio).round() as u64)
        })
        .collect()
}

async fn extract_visual_frame_samples(
    provider: &ManagedFfmpegProvider,
    video_path: &Path,
    timestamps_ms: &[u64],
    run_dir: &Path,
) -> Result<Vec<VisualFrameSample>> {
    let mut samples = Vec::with_capacity(timestamps_ms.len());
    for (idx, timestamp_ms) in timestamps_ms.iter().copied().enumerate() {
        let output_path = run_dir.join(format!("frame_{idx:02}.jpg"));
        let args = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "error".to_string(),
            "-nostdin".to_string(),
            "-y".to_string(),
            "-ss".to_string(),
            ffmpeg_seek_timestamp(timestamp_ms),
            "-i".to_string(),
            video_path.to_string_lossy().to_string(),
            "-frames:v".to_string(),
            "1".to_string(),
            "-vf".to_string(),
            "scale=w=960:h=-2:force_original_aspect_ratio=decrease".to_string(),
            "-q:v".to_string(),
            "3".to_string(),
            output_path.to_string_lossy().to_string(),
        ];
        let _ = run_managed_ffmpeg(
            &provider.ffmpeg_path,
            &args,
            run_dir,
            FFMPEG_FRAME_TIMEOUT_SECS,
        )
        .await?;
        let bytes = fs::read(&output_path).with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to read extracted frame {}",
                output_path.display()
            )
        })?;
        if bytes.is_empty() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing extracted frame bytes were empty."
            ));
        }
        let image = image::load_from_memory(&bytes).context(
            "ERROR_CLASS=VerificationMissing failed to decode extracted frame image bytes",
        )?;
        let (width, height) = image.dimensions();
        samples.push(VisualFrameSample {
            timestamp_ms,
            timestamp_label: render_timestamp(timestamp_ms),
            frame_hash: sha256_hex(&bytes),
            mime_type: "image/jpeg".to_string(),
            width,
            height,
            bytes,
        });
    }
    Ok(samples)
}

async fn analyze_visual_frame_samples(
    samples: &[VisualFrameSample],
    transcript_segments: Option<&[TranscriptSegment]>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<Vec<MediaFrameEvidence>> {
    let mut observations = Vec::with_capacity(samples.len());
    for batch in samples.chunks(MEDIA_VISUAL_BATCH_SIZE) {
        let messages = build_visual_analysis_messages(batch);
        let payload = serde_json::to_vec(&messages)
            .context("ERROR_CLASS=SynthesisFailed failed to serialize visual analysis prompt")?;
        let options = InferenceOptions {
            tools: Vec::new(),
            temperature: 0.0,
            json_mode: true,
            max_tokens: 700,
        };
        let raw = timeout(
            Duration::from_secs(VISION_PROBE_TIMEOUT_SECS),
            inference.execute_inference([0u8; 32], &payload, options),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal visual frame analysis timed out after {}s",
                VISION_PROBE_TIMEOUT_SECS
            )
        })?
        .map_err(|err| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal visual frame analysis failed: {}",
                err
            )
        })?;
        let value = parse_json_value(&raw)?;
        let observations_value = value
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis returned no observations array."
                )
            })?;
        if observations_value.len() != batch.len() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing visual frame analysis expected {} observations but received {}.",
                batch.len(),
                observations_value.len()
            ));
        }
        for (sample, observation) in batch.iter().zip(observations_value.iter()) {
            let timestamp_ms = observation
                .get("timestamp_ms")
                .and_then(Value::as_u64)
                .unwrap_or(sample.timestamp_ms);
            let scene_summary = compact_ws(
                observation
                    .get("scene_summary")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            if scene_summary.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis returned an empty scene summary."
                ));
            }
            let visible_text = compact_ws(
                observation
                    .get("visible_text")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            let transcript_excerpt = transcript_segments
                .and_then(|segments| transcript_excerpt_near(segments, sample.timestamp_ms));
            observations.push(MediaFrameEvidence {
                timestamp_ms,
                timestamp_label: sample.timestamp_label.clone(),
                frame_hash: sample.frame_hash.clone(),
                mime_type: sample.mime_type.clone(),
                width: sample.width,
                height: sample.height,
                scene_summary,
                visible_text,
                transcript_excerpt,
            });
        }
    }
    Ok(observations)
}

fn build_visual_analysis_messages(samples: &[VisualFrameSample]) -> Value {
    let mut content = Vec::new();
    content.push(json!({
        "type": "text",
        "text": format!(
            "Analyze these sampled video frames and return JSON only with this schema: {{\"observations\":[{{\"timestamp_ms\":<u64>,\"scene_summary\":\"<literal concise description>\",\"visible_text\":\"<readable on-screen text or empty string>\"}}]}}. Rules: observations length must equal {}; preserve the provided timestamp_ms values exactly; do not speculate beyond visible frame content; if readable text is absent, use an empty string for visible_text.",
            samples.len()
        )
    }));
    for sample in samples {
        content.push(json!({
            "type": "text",
            "text": format!("Frame timestamp_ms={}", sample.timestamp_ms)
        }));
        content.push(json!({
            "type": "image_url",
            "image_url": {
                "url": format!("data:{};base64,{}", sample.mime_type, BASE64.encode(&sample.bytes))
            }
        }));
    }
    json!([{ "role": "user", "content": content }])
}

fn build_visual_summary(frames: &[MediaFrameEvidence]) -> String {
    frames
        .iter()
        .map(|frame| {
            if frame.visible_text.is_empty() {
                format!("[{}] {}", frame.timestamp_label, frame.scene_summary)
            } else {
                format!(
                    "[{}] {} Visible text: {}",
                    frame.timestamp_label, frame.scene_summary, frame.visible_text
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn transcript_excerpt_near(segments: &[TranscriptSegment], timestamp_ms: u64) -> Option<String> {
    let window_start = timestamp_ms.saturating_sub(90_000);
    let window_end = timestamp_ms.saturating_add(90_000);
    let excerpt = segments
        .iter()
        .filter(|segment| segment.start_ms >= window_start && segment.start_ms <= window_end)
        .take(4)
        .map(|segment| segment.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let compact = compact_ws(&excerpt);
    (!compact.is_empty()).then_some(truncate_chars(&compact, 400))
}

fn ffmpeg_seek_timestamp(timestamp_ms: u64) -> String {
    format!("{:.3}", timestamp_ms as f64 / 1_000.0)
}

async fn probe_vision_runtime(inference: Arc<dyn InferenceRuntime>) -> Result<bool> {
    let probe_image_url = build_vision_probe_image_data_url()?;
    let prompt = json!([
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "Return JSON only with {\"image_support\":true}. Do not add any other keys."
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": probe_image_url
                    }
                }
            ]
        }
    ]);
    let payload = serde_json::to_vec(&prompt)
        .context("ERROR_CLASS=SynthesisFailed failed to serialize vision probe prompt")?;
    let options = InferenceOptions {
        tools: Vec::new(),
        temperature: 0.0,
        json_mode: true,
        max_tokens: 60,
    };
    let raw = timeout(
        Duration::from_secs(VISION_PROBE_TIMEOUT_SECS),
        inference.execute_inference([0u8; 32], &payload, options),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal vision probe timed out after {}s",
            VISION_PROBE_TIMEOUT_SECS
        )
    })?
    .map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal vision probe failed: {}",
            err
        )
    })?;
    let value = parse_json_value(&raw)?;
    Ok(value
        .get("image_support")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn build_vision_probe_image_data_url() -> Result<String> {
    let probe = ImageBuffer::from_fn(64, 64, |x, y| {
        if (x / 8 + y / 8) % 2 == 0 {
            Rgb([240, 240, 240])
        } else {
            Rgb([32, 128, 224])
        }
    });
    let mut cursor = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(probe)
        .write_to(&mut cursor, ImageFormat::Jpeg)
        .context("ERROR_CLASS=SynthesisFailed failed to encode vision probe image")?;
    Ok(format!(
        "data:image/jpeg;base64,{}",
        BASE64.encode(cursor.into_inner())
    ))
}

fn parse_json_value(raw: &[u8]) -> Result<Value> {
    let raw_str = String::from_utf8(raw.to_vec())
        .context("ERROR_CLASS=VerificationMissing inference response was not valid utf-8")?;
    if let Ok(value) = serde_json::from_str::<Value>(&raw_str) {
        return Ok(value);
    }
    let trimmed = raw_str.trim();
    let start = trimmed.find('{').ok_or_else(|| {
        anyhow!("ERROR_CLASS=VerificationMissing inference response did not contain a json object")
    })?;
    let end = trimmed.rfind('}').ok_or_else(|| {
        anyhow!("ERROR_CLASS=VerificationMissing inference response did not contain a json object")
    })?;
    serde_json::from_str::<Value>(&trimmed[start..=end]).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse inference json response {}",
            truncate_log(trimmed, 200)
        )
    })
}

async fn transcribe_audio_with_managed_whisper(
    model: &ManagedWhisperModel,
    audio_path: &Path,
    language: &str,
) -> Result<Vec<TranscriptSegment>> {
    let audio_path = audio_path.to_path_buf();
    let model_path = model.model_path.clone();
    let language = language.to_string();
    let job =
        spawn_blocking(move || transcribe_audio_blocking(&model_path, &audio_path, &language));
    timeout(Duration::from_secs(WHISPER_TRANSCRIBE_TIMEOUT_SECS), job)
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal audio transcription timed out after {}s",
                WHISPER_TRANSCRIBE_TIMEOUT_SECS
            )
        })?
        .map_err(|err| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal audio transcription worker join failed: {}",
                err
            )
        })?
}

fn transcribe_audio_blocking(
    model_path: &Path,
    audio_path: &Path,
    language: &str,
) -> Result<Vec<TranscriptSegment>> {
    let pcm = decode_audio_to_whisper_pcm(audio_path)?;
    let context = WhisperContext::new_with_params(
        &model_path.to_string_lossy(),
        WhisperContextParameters::default(),
    )
    .map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to load whisper model {}: {}",
            model_path.display(),
            err
        )
    })?;
    let mut state = context.create_state().map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create whisper state: {}",
            err
        )
    })?;

    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 0 });
    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(2)
        .clamp(1, 6) as i32;
    params.set_n_threads(threads);
    params.set_translate(false);
    params.set_no_context(true);
    params.set_language(Some(language));
    params.set_print_special(false);
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);

    state.full(params, &pcm).map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal whisper inference failed for {}: {}",
            audio_path.display(),
            err
        )
    })?;

    let mut segments = Vec::new();
    let mut last_text = String::new();
    for segment in state.as_iter() {
        let text = compact_ws(&segment.to_string());
        if text.is_empty() || text == last_text {
            continue;
        }
        last_text = text.clone();
        let start_ms = u64::try_from(segment.start_timestamp().max(0)).unwrap_or(0) * 10;
        segments.push(TranscriptSegment { start_ms, text });
    }
    Ok(segments)
}

fn decode_audio_to_whisper_pcm(path: &Path) -> Result<Vec<f32>> {
    let file = Box::new(File::open(path).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to open audio artifact {}",
            path.display()
        )
    })?);
    let mss = MediaSourceStream::new(file, Default::default());
    let mut hint = Hint::new();
    if let Some(extension) = path.extension().and_then(|value| value.to_str()) {
        hint.with_extension(extension);
    }

    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to probe audio format {}",
                path.display()
            )
        })?;
    let mut format = probed.format;
    let track_id = selected_audio_track_id(format.as_ref())?;
    let track = format
        .tracks()
        .iter()
        .find(|track| track.id == track_id)
        .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing selected audio track disappeared"))?;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to create audio decoder for {}",
                path.display()
            )
        })?;

    let mut output = Vec::new();
    let mut resampler: Option<LinearResampler> = None;

    loop {
        let packet = match format.next_packet() {
            Ok(packet) => packet,
            Err(SymphoniaError::IoError(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(SymphoniaError::ResetRequired) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal symphonia reset required for {}",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to read audio packet {}: {}",
                    path.display(),
                    err
                ));
            }
        };
        if packet.track_id() != track_id {
            continue;
        }

        match decoder.decode(&packet) {
            Ok(audio_buf) => {
                let spec = *audio_buf.spec();
                let channel_count = spec.channels.count();
                if channel_count == 0 {
                    continue;
                }
                let mut sample_buf = SampleBuffer::<f32>::new(audio_buf.capacity() as u64, spec);
                sample_buf.copy_interleaved_ref(audio_buf);
                let resampler = resampler.get_or_insert_with(|| {
                    LinearResampler::new(spec.rate, WHISPER_TARGET_SAMPLE_RATE)
                });
                if resampler.input_rate != spec.rate {
                    return Err(anyhow!(
                        "ERROR_CLASS=ExecutionFailedTerminal variable sample rate audio is unsupported for {}",
                        path.display()
                    ));
                }
                process_interleaved_chunk(
                    sample_buf.samples(),
                    channel_count,
                    resampler,
                    &mut output,
                );
            }
            Err(SymphoniaError::DecodeError(_)) => {}
            Err(SymphoniaError::IoError(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(SymphoniaError::ResetRequired) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal symphonia decoder reset required for {}",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to decode audio {}: {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    if let Some(resampler) = resampler.as_mut() {
        resampler.finish(&mut output);
    }
    if output.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing decoded audio contained no whisper-ready PCM samples."
        ));
    }
    Ok(output)
}

fn selected_audio_track_id(format: &dyn symphonia::core::formats::FormatReader) -> Result<u32> {
    if let Some(track) = format.default_track().filter(|track| is_audio_track(track)) {
        return Ok(track.id);
    }

    format
        .tracks()
        .iter()
        .find(|track| is_audio_track(track))
        .map(|track| track.id)
        .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing no decodable audio track found"))
}

fn is_audio_track(track: &symphonia::core::formats::Track) -> bool {
    track.codec_params.channels.is_some() || track.codec_params.sample_rate.is_some()
}

fn process_interleaved_chunk(
    samples: &[f32],
    channel_count: usize,
    resampler: &mut LinearResampler,
    output: &mut Vec<f32>,
) {
    if channel_count == 0 {
        return;
    }
    let mut mono = Vec::with_capacity(samples.len() / channel_count);
    for frame in samples.chunks(channel_count) {
        let sum = frame.iter().copied().sum::<f32>();
        mono.push(sum / channel_count as f32);
    }
    resampler.push(&mono, output);
}

#[derive(Debug, Clone)]
struct LinearResampler {
    input_rate: u32,
    step: f64,
    position: f64,
    pending: Vec<f32>,
}

impl LinearResampler {
    fn new(input_rate: u32, output_rate: u32) -> Self {
        Self {
            input_rate,
            step: input_rate as f64 / output_rate as f64,
            position: 0.0,
            pending: Vec::new(),
        }
    }

    fn push(&mut self, samples: &[f32], output: &mut Vec<f32>) {
        self.pending.extend_from_slice(samples);
        while self.position + 1.0 < self.pending.len() as f64 {
            let left_index = self.position.floor() as usize;
            let right_index = left_index + 1;
            let fraction = (self.position - left_index as f64) as f32;
            let left = self.pending[left_index];
            let right = self.pending[right_index];
            output.push(left + (right - left) * fraction);
            self.position += self.step;
        }

        let keep_from = self.position.floor().max(1.0) as usize - 1;
        if keep_from > 0 {
            self.pending.drain(0..keep_from);
            self.position -= keep_from as f64;
        }
    }

    fn finish(&mut self, output: &mut Vec<f32>) {
        if output.is_empty() && !self.pending.is_empty() {
            output.push(self.pending[0]);
        }
    }
}

fn parse_webvtt_segments(raw: &str) -> Vec<TranscriptSegment> {
    let mut segments = Vec::new();
    let mut last_text = String::new();

    for block in raw.split("\n\n") {
        let mut lines = block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if lines.is_empty() {
            continue;
        }
        if lines[0] == "WEBVTT"
            || lines[0].starts_with("Kind:")
            || lines[0].starts_with("Language:")
            || lines[0].starts_with("NOTE")
            || lines[0].starts_with("STYLE")
            || lines[0].starts_with("REGION")
        {
            continue;
        }

        let timestamp_index = lines
            .iter()
            .position(|line| line.contains("-->"))
            .unwrap_or(usize::MAX);
        if timestamp_index == usize::MAX {
            continue;
        }
        let timestamp_line = lines[timestamp_index];
        let start_raw = timestamp_line.split("-->").next().unwrap_or("").trim();
        let Some(start_ms) = parse_timestamp_ms(start_raw) else {
            continue;
        };
        let text = lines
            .drain(timestamp_index + 1..)
            .map(strip_markup_and_entities)
            .map(|line| compact_ws(&line))
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() || text == last_text {
            continue;
        }
        last_text = text.clone();
        segments.push(TranscriptSegment { start_ms, text });
    }

    segments
}

fn parse_timestamp_ms(raw: &str) -> Option<u64> {
    let mut parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() == 2 {
        parts.insert(0, "0");
    }
    if parts.len() != 3 {
        return None;
    }
    let hours = parts[0].parse::<u64>().ok()?;
    let minutes = parts[1].parse::<u64>().ok()?;
    let sec_parts = parts[2].split('.').collect::<Vec<_>>();
    if sec_parts.len() != 2 {
        return None;
    }
    let seconds = sec_parts[0].parse::<u64>().ok()?;
    let millis = sec_parts[1].parse::<u64>().ok()?;
    Some(
        hours.saturating_mul(3_600_000)
            + minutes.saturating_mul(60_000)
            + seconds.saturating_mul(1_000)
            + millis.min(999),
    )
}

fn strip_markup_and_entities(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn render_timestamp(start_ms: u64) -> String {
    let total_seconds = start_ms / 1_000;
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn truncate_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_sha256sum_line_matches_asset() {
        let line = "abcdef1234567890  yt-dlp";
        assert_eq!(
            parse_sha256sum_line(line, "yt-dlp").as_deref(),
            Some("abcdef1234567890")
        );
        assert!(parse_sha256sum_line(line, "other").is_none());
    }

    #[test]
    fn parse_header_hex_sha256_accepts_quoted_value() {
        let value = header::HeaderValue::from_static(
            "\"818710568da3ca15689e31a743197b520007872ff9576237bda97bd1b469c3d7\"",
        );
        assert_eq!(
            parse_header_hex_sha256(&value).as_deref(),
            Some("818710568da3ca15689e31a743197b520007872ff9576237bda97bd1b469c3d7")
        );
    }

    #[test]
    fn select_track_from_bucket_prefers_exact_then_prefix() {
        let bucket = json!({
            "en": [],
            "en-US": [],
            "fr": [],
        });
        let map = bucket.as_object();
        assert_eq!(select_track_from_bucket(map, "en").as_deref(), Some("en"));
        assert_eq!(
            select_track_from_bucket(map, "en-GB").as_deref(),
            Some("en")
        );
    }

    #[test]
    fn select_subtitle_track_prefers_manual_before_automatic() {
        let metadata = json!({
            "subtitles": {"en": [{}]},
            "automatic_captions": {"en": [{}]}
        });
        let selection = select_subtitle_track(&metadata, "en").expect("selection");
        assert_eq!(selection.source_kind, "manual");
        assert_eq!(selection.language_key, "en");
    }

    #[test]
    fn select_audio_format_prefers_aac_container() {
        let metadata = json!({
            "formats": [
                {"format_id": "251", "ext": "webm", "acodec": "opus"},
                {"format_id": "140", "ext": "m4a", "acodec": "mp4a.40.2"},
                {"format_id": "18", "ext": "mp4", "acodec": "mp4a.40.2"}
            ]
        });
        let selection = select_audio_format(&metadata).expect("audio selection");
        assert_eq!(selection.format_id, "140");
        assert_eq!(selection.ext, "m4a");
    }

    #[test]
    fn select_video_format_prefers_mid_band_mp4_over_higher_webm() {
        let metadata = json!({
            "formats": [
                {"format_id": "248", "ext": "webm", "vcodec": "vp9", "width": 1920, "height": 1080},
                {"format_id": "22", "ext": "mp4", "vcodec": "avc1.64001F", "width": 1280, "height": 720},
                {"format_id": "18", "ext": "mp4", "vcodec": "avc1.42001E", "width": 640, "height": 360}
            ]
        });
        let selection = select_video_format(&metadata).expect("video selection");
        assert_eq!(selection.format_id, "22");
        assert_eq!(selection.ext, "mp4");
        assert_eq!(selection.height, 720);
    }

    #[test]
    fn sample_visual_frame_timestamps_spans_duration_window() {
        let timestamps = sample_visual_frame_timestamps(2_900, 6);
        assert_eq!(timestamps.len(), 6);
        assert!(timestamps[0] >= 145_000);
        assert!(timestamps[5] <= 2_755_000);
        assert!(timestamps.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn sample_sequence_indices_spans_available_positions() {
        let indices = sample_sequence_indices(7, 4);
        assert_eq!(indices, vec![0, 2, 4, 6]);
    }

    #[test]
    fn sample_chapter_thumbnails_respects_frame_limit() {
        let chapters = vec![
            YouTubeChapterThumbnail {
                title: "Intro".to_string(),
                start_ms: 0,
                thumbnail_url: "https://example.com/0.jpg".to_string(),
            },
            YouTubeChapterThumbnail {
                title: "Field".to_string(),
                start_ms: 60_000,
                thumbnail_url: "https://example.com/1.jpg".to_string(),
            },
            YouTubeChapterThumbnail {
                title: "Coils".to_string(),
                start_ms: 120_000,
                thumbnail_url: "https://example.com/2.jpg".to_string(),
            },
            YouTubeChapterThumbnail {
                title: "Wrap".to_string(),
                start_ms: 180_000,
                thumbnail_url: "https://example.com/3.jpg".to_string(),
            },
        ];
        let sampled = sample_chapter_thumbnails(&chapters, 3);
        assert_eq!(sampled.len(), 3);
        assert_eq!(sampled[0].start_ms, 0);
        assert_eq!(sampled[1].start_ms, 120_000);
        assert_eq!(sampled[2].start_ms, 180_000);
    }

    #[test]
    fn youtube_watch_provider_version_uses_client_context_version() {
        let version = youtube_watch_provider_version(&json!({
            "client": {
                "clientName": "WEB",
                "clientVersion": "2.20260310.01.00"
            }
        }));
        assert_eq!(version, "youtube-web@2.20260310.01.00");
    }

    #[test]
    fn parse_json_value_extracts_wrapped_object() {
        let value = parse_json_value(
            br#"```json
{"image_support":true}
```"#,
        )
        .expect("wrapped json should parse");
        assert_eq!(
            value.get("image_support").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn build_vision_probe_image_data_url_emits_jpeg_data_url() {
        let data_url = build_vision_probe_image_data_url().expect("probe image");
        assert!(data_url.starts_with("data:image/jpeg;base64,"));
        assert!(data_url.len() > "data:image/jpeg;base64,".len());
    }

    #[test]
    fn parse_webvtt_segments_strips_markup_entities_and_dedupes_adjacent() {
        let raw = concat!(
            "WEBVTT\n\n",
            "00:00:01.000 --> 00:00:03.000\n",
            "<c.colorE5E5E5>Hello &amp; welcome</c>\n\n",
            "00:00:03.500 --> 00:00:05.000\n",
            "<c.colorE5E5E5>Hello &amp; welcome</c>\n\n",
            "00:00:06.000 --> 00:00:07.000\n",
            "Next line\n"
        );
        let segments = parse_webvtt_segments(raw);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].start_ms, 1_000);
        assert_eq!(segments[0].text, "Hello & welcome");
        assert_eq!(segments[1].text, "Next line");
    }

    #[test]
    fn render_timestamp_formats_hours() {
        assert_eq!(render_timestamp(3_661_000), "01:01:01");
    }
}
