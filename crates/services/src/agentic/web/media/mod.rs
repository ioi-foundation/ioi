mod receipts;
mod selection;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use image::{
    codecs::{
        gif::{GifEncoder, Repeat},
        jpeg::JpegEncoder,
    },
    Delay, DynamicImage, Frame, GenericImageView, ImageBuffer, ImageFormat, Rgb, Rgba, RgbaImage,
};
use ioi_api::vm::inference::{
    ImageEditRequest, ImageGenerationRequest, InferenceRuntime, VideoGenerationRequest,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{
    InferenceOptions, MediaFrameEvidence, MediaMultimodalBundle, MediaProviderCandidate,
    MediaTimelineCue, MediaTimelineOutlineBundle, MediaTranscriptBundle,
    MediaTranscriptProviderCandidate, MediaVisualEvidenceBundle, WebRetrievalAffordance,
};
use reqwest::{header, redirect};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

mod api {
    use super::*;
    include!("api.rs");
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("tests.rs");
}

include!("types.rs");
include!("tooling.rs");
include!("youtube.rs");
include!("execution.rs");
include!("transcript.rs");
include!("visual.rs");

pub use api::{
    edge_media_extract_multimodal_evidence, edge_media_extract_transcript, kernel_media_edit_image,
    kernel_media_generate_image, kernel_media_generate_video, kernel_media_synthesize_speech,
    kernel_media_transcribe_audio, kernel_media_vision_read, KernelMediaImageGeneration,
    KernelMediaSpeechSynthesis, KernelMediaTranscription, KernelMediaVideoGeneration,
    KernelMediaVisionRead,
};
