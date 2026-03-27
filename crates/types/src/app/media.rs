//! Typed first-party media workload contracts.
//!
//! These types define the absorbed receipt surface for audio, vision, image,
//! and video operations that should become first-class kernel concepts rather
//! than external product-shaped APIs.

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The specific media-class operation performed by a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum MediaOperationKind {
    /// Audio transcription or speech-to-text.
    Transcription,
    /// Text-to-speech or speech synthesis.
    SpeechSynthesis,
    /// Visual understanding over image or screenshot inputs.
    VisionRead,
    /// Image generation from prompts or structured inputs.
    ImageGeneration,
    /// Image editing or inpainting over an existing image.
    ImageEdit,
    /// Video generation.
    VideoGeneration,
    /// Voice activity detection or similar pre-processing.
    VoiceActivityDetection,
    /// Session-oriented realtime audio processing.
    RealtimeAudioSession,
}

impl MediaOperationKind {
    /// Returns a stable deterministic label for receipts and projections.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Transcription => "transcription",
            Self::SpeechSynthesis => "speech_synthesis",
            Self::VisionRead => "vision_read",
            Self::ImageGeneration => "image_generation",
            Self::ImageEdit => "image_edit",
            Self::VideoGeneration => "video_generation",
            Self::VoiceActivityDetection => "voice_activity_detection",
            Self::RealtimeAudioSession => "realtime_audio_session",
        }
    }
}

/// Typed receipt for an absorbed media workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WorkloadMediaReceipt {
    /// Tool that initiated the media workload.
    pub tool_name: String,
    /// Specific media-class operation executed.
    pub operation: MediaOperationKind,
    /// Runtime backend identifier used for execution.
    pub backend: String,
    /// Optional model identifier selected for execution.
    #[serde(default)]
    pub model_id: Option<String>,
    /// Optional source URI or artifact reference.
    #[serde(default)]
    pub source_uri: Option<String>,
    /// Number of input artifacts or inputs admitted to the run.
    pub input_artifact_count: u32,
    /// Number of output artifacts produced by the run.
    pub output_artifact_count: u32,
    /// Aggregate output byte count when known.
    #[serde(default)]
    pub output_bytes: Option<u64>,
    /// End-to-end workload duration when available.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// MIME types produced by the run.
    #[serde(default)]
    pub output_mime_types: Vec<String>,
    /// Success flag as surfaced by the runtime.
    pub success: bool,
    /// Optional machine-readable failure class.
    #[serde(default)]
    pub error_class: Option<String>,
}
