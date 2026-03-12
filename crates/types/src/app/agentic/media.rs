use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::WebRetrievalAffordance;

/// Discovery-backed candidate provider observed during media evidence extraction.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaProviderCandidate {
    /// Stable provider identifier.
    pub provider_id: String,
    /// Optional modality associated with the provider (`transcript`, `visual`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<String>,
    /// Number of usable sources admitted for this provider.
    pub source_count: u32,
    /// Whether this provider was selected for execution.
    pub selected: bool,
    /// Whether this provider satisfied discovery admission checks.
    pub success: bool,
    /// Whether execution attempted this provider during the current run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_attempted: Option<bool>,
    /// Whether an attempted execution for this provider completed successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_satisfied: Option<bool>,
    /// Optional machine-readable reason why execution failed after discovery admitted the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_failure_reason: Option<String>,
    /// Request URL associated with this provider candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_url: Option<String>,
    /// Optional machine-readable reason why the candidate was not admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_reason: Option<String>,
    /// Structural affordances exposed by the candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affordances: Vec<WebRetrievalAffordance>,
}

/// Backward-compatible alias for transcript-specific callers.
pub type MediaTranscriptProviderCandidate = MediaProviderCandidate;

/// Typed transcript evidence extracted from a remote media URL.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaTranscriptBundle {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// UNIX timestamp (milliseconds) when the transcript was retrieved.
    pub retrieved_at_ms: u64,
    /// Tool that produced this bundle.
    pub tool: String,
    /// Backend identifier for the managed media provider.
    pub backend: String,
    /// Stable provider identifier used during runtime selection.
    pub provider_id: String,
    /// Provider version or artifact tag.
    pub provider_version: String,
    /// Original request URL.
    pub requested_url: String,
    /// Canonical provider URL for the media resource.
    pub canonical_url: String,
    /// Discovery-backed provider candidates observed before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_candidates: Vec<MediaProviderCandidate>,
    /// Media title when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Media duration in seconds when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    /// Requested transcript language.
    pub requested_language: String,
    /// Selected subtitle track language.
    pub transcript_language: String,
    /// Whether the selected track was manual or automatic.
    pub transcript_source_kind: String,
    /// Number of transcript segments after parsing.
    pub segment_count: u32,
    /// Number of UTF-8 characters in `transcript_text`.
    pub transcript_char_count: u32,
    /// Hex SHA-256 of `transcript_text`.
    pub transcript_hash: String,
    /// Cleaned transcript text.
    pub transcript_text: String,
}

/// Typed timeline cue extracted from a remote media URL.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaTimelineCue {
    /// Cue offset in milliseconds from media start.
    pub timestamp_ms: u64,
    /// Rendered human-readable timestamp for the cue.
    pub timestamp_label: String,
    /// Concise cue title grounded in the provider timeline surface.
    pub title: String,
    /// Optional provider thumbnail URL associated with the cue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
}

/// Typed timeline outline extracted from a remote media URL.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaTimelineOutlineBundle {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// UNIX timestamp (milliseconds) when the timeline was retrieved.
    pub retrieved_at_ms: u64,
    /// Tool that produced this bundle.
    pub tool: String,
    /// Backend identifier for the provider timeline pipeline.
    pub backend: String,
    /// Stable provider identifier used during runtime selection.
    pub provider_id: String,
    /// Provider version or artifact tag.
    pub provider_version: String,
    /// Original request URL.
    pub requested_url: String,
    /// Canonical provider URL for the media resource.
    pub canonical_url: String,
    /// Discovery-backed provider candidates observed before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_candidates: Vec<MediaProviderCandidate>,
    /// Media title when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Media duration in seconds when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    /// Source surface used to derive the timeline outline.
    pub timeline_source_kind: String,
    /// Number of timeline cues after parsing.
    pub cue_count: u32,
    /// Number of UTF-8 characters in `timeline_text`.
    pub timeline_char_count: u32,
    /// Hex SHA-256 of `timeline_text`.
    pub timeline_hash: String,
    /// Cleaned timeline text.
    pub timeline_text: String,
    /// Individual timeline cues.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cues: Vec<MediaTimelineCue>,
}

/// Typed observation extracted from a sampled media frame.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaFrameEvidence {
    /// Frame offset in milliseconds from media start.
    pub timestamp_ms: u64,
    /// Rendered human-readable timestamp for the frame.
    pub timestamp_label: String,
    /// Hex SHA-256 of the sampled frame bytes.
    pub frame_hash: String,
    /// Output image mime type.
    pub mime_type: String,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Concise scene summary grounded in the sampled frame.
    pub scene_summary: String,
    /// Visible text/OCR-style content observed in the sampled frame.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub visible_text: String,
    /// Optional transcript excerpt aligned near this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_excerpt: Option<String>,
}

/// Typed visual evidence extracted from a remote media URL.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaVisualEvidenceBundle {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// UNIX timestamp (milliseconds) when the visual evidence was retrieved.
    pub retrieved_at_ms: u64,
    /// Tool that produced this bundle.
    pub tool: String,
    /// Backend identifier for the managed visual provider pipeline.
    pub backend: String,
    /// Stable provider identifier used during runtime selection.
    pub provider_id: String,
    /// Provider version or artifact tag.
    pub provider_version: String,
    /// Original request URL.
    pub requested_url: String,
    /// Canonical provider URL for the media resource.
    pub canonical_url: String,
    /// Discovery-backed provider candidates observed before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_candidates: Vec<MediaProviderCandidate>,
    /// Media title when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Media duration in seconds when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    /// Number of sampled frames after verification.
    pub frame_count: u32,
    /// Number of UTF-8 characters across frame observations.
    pub visual_char_count: u32,
    /// Hex SHA-256 of the aggregate visual summary payload.
    pub visual_hash: String,
    /// Aggregate visual summary across sampled frames.
    pub visual_summary: String,
    /// Individual frame observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<MediaFrameEvidence>,
}

/// Typed multimodal evidence extracted from a remote media URL.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MediaMultimodalBundle {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// UNIX timestamp (milliseconds) when the multimodal evidence was retrieved.
    pub retrieved_at_ms: u64,
    /// Tool that produced this bundle.
    pub tool: String,
    /// Original request URL.
    pub requested_url: String,
    /// Canonical provider URL for the media resource.
    pub canonical_url: String,
    /// Media title when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Media duration in seconds when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    /// Requested transcript language for audio-backed extraction.
    pub requested_language: String,
    /// Discovery-backed provider candidates observed before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_candidates: Vec<MediaProviderCandidate>,
    /// Selected modalities for this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_modalities: Vec<String>,
    /// Selected provider ids for this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_provider_ids: Vec<String>,
    /// Transcript evidence when the transcript modality was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<MediaTranscriptBundle>,
    /// Timeline evidence when the timeline modality was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<MediaTimelineOutlineBundle>,
    /// Visual evidence when the visual modality was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual: Option<MediaVisualEvidenceBundle>,
}
