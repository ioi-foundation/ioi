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

#[derive(Debug, Clone)]
pub(crate) struct LocalVideoPreview {
    pub preview_png: Vec<u8>,
    pub duration_seconds: Option<u64>,
    pub frame_count: usize,
    pub frame_summaries: Vec<String>,
}

pub(crate) async fn sample_local_video_preview(
    video_path: &Path,
    frame_limit: u32,
) -> Result<LocalVideoPreview> {
    let tool_home = ensure_media_tool_home()?;
    let ffmpeg = ensure_managed_ffmpeg_provider(&tool_home).await?;
    let duration_seconds = probe_local_video_duration_seconds(&ffmpeg.ffprobe_path, video_path)
        .await
        .ok();
    let effective_duration = duration_seconds.unwrap_or(3).max(1);
    let preview_hash = sha256_hex(video_path.to_string_lossy().as_bytes());
    let run_dir = tool_home.join("local_video_preview").join(preview_hash);
    fs::create_dir_all(&run_dir).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create local video preview dir {}",
            run_dir.display()
        )
    })?;

    let timestamps_ms = sample_visual_frame_timestamps(effective_duration, frame_limit as usize);
    let frame_samples = extract_visual_frame_samples(&ffmpeg, video_path, &timestamps_ms, &run_dir)
        .await
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to sample local video frames from {}",
                video_path.display()
            )
        })?;
    if frame_samples.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing local video preview produced no frames for {}",
            video_path.display()
        ));
    }

    let preview_png = build_local_video_contact_sheet(&frame_samples)?;
    let frame_summaries = frame_samples
        .iter()
        .map(|sample| {
            format!(
                "- {} | {}x{} | {}",
                sample.timestamp_label, sample.width, sample.height, sample.mime_type
            )
        })
        .collect::<Vec<_>>();

    Ok(LocalVideoPreview {
        preview_png,
        duration_seconds,
        frame_count: frame_samples.len(),
        frame_summaries,
    })
}

async fn probe_local_video_duration_seconds(ffprobe_path: &Path, video_path: &Path) -> Result<u64> {
    let output = Command::new(ffprobe_path)
        .arg("-v")
        .arg("error")
        .arg("-show_entries")
        .arg("format=duration")
        .arg("-of")
        .arg("default=noprint_wrappers=1:nokey=1")
        .arg(video_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .await
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to launch ffprobe for {}",
                video_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal ffprobe failed for {} status={} stderr={}",
            video_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let seconds = raw
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|value| *value > 0.0)
        .map(|value| value.ceil() as u64)
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing ffprobe returned no duration for {}",
                video_path.display()
            )
        })?;
    Ok(seconds)
}

fn build_local_video_contact_sheet(frame_samples: &[VisualFrameSample]) -> Result<Vec<u8>> {
    let decoded_frames = frame_samples
        .iter()
        .map(|sample| {
            image::load_from_memory(&sample.bytes).with_context(|| {
                format!(
                    "ERROR_CLASS=VerificationMissing failed to decode sampled frame {}",
                    sample.timestamp_label
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if decoded_frames.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing no decoded frames available for contact sheet"
        ));
    }

    let cols = decoded_frames.len().min(3).max(1) as u32;
    let rows = ((decoded_frames.len() as u32) + cols - 1) / cols;
    let tile_width = decoded_frames
        .iter()
        .map(DynamicImage::width)
        .max()
        .unwrap_or(1);
    let tile_height = decoded_frames
        .iter()
        .map(DynamicImage::height)
        .max()
        .unwrap_or(1);
    let gutter = 12u32;
    let canvas_width = cols * tile_width + (cols + 1) * gutter;
    let canvas_height = rows * tile_height + (rows + 1) * gutter;
    let mut canvas = RgbaImage::from_pixel(
        canvas_width.max(1),
        canvas_height.max(1),
        Rgba([18, 20, 24, 255]),
    );

    for (index, frame) in decoded_frames.iter().enumerate() {
        let index = index as u32;
        let col = index % cols;
        let row = index / cols;
        let x = gutter + col * (tile_width + gutter);
        let y = gutter + row * (tile_height + gutter);
        let frame_rgba = frame.to_rgba8();
        image::imageops::overlay(&mut canvas, &frame_rgba, i64::from(x), i64::from(y));
    }

    let mut cursor = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(canvas)
        .write_to(&mut cursor, ImageFormat::Png)
        .context(
            "ERROR_CLASS=ExecutionFailedTerminal failed to encode local video contact sheet",
        )?;
    Ok(cursor.into_inner())
}
