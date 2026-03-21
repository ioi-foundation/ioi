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
