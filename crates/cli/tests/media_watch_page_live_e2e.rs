use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_services::agentic::web::edge_media_extract_multimodal_evidence;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde_json::json;
use serde_json::Value;
use tempfile::tempdir;

const YOUTUBE_VIDEO_URL: &str = "https://www.youtube.com/watch?v=9Tm2c6NJH4Y";

struct MockVisualRuntime;

#[async_trait]
impl InferenceRuntime for MockVisualRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let payload: Value = serde_json::from_slice(input_context).map_err(|err| {
            VmError::HostError(format!("mock visual runtime invalid json: {err}"))
        })?;
        let mut text_entries = Vec::new();
        collect_text_entries(&payload, &mut text_entries);
        let timestamps = text_entries
            .iter()
            .filter_map(|text| {
                text.strip_prefix("Frame timestamp_ms=")
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
            .collect::<Vec<_>>();
        if !timestamps.is_empty() {
            return serde_json::to_vec(&json!({
                "observations": timestamps.into_iter().map(|timestamp_ms| {
                    json!({
                        "timestamp_ms": timestamp_ms,
                        "scene_summary": format!("Frame {}", timestamp_ms),
                        "visible_text": ""
                    })
                }).collect::<Vec<_>>()
            }))
            .map_err(|err| VmError::HostError(format!("serialize mock response failed: {err}")));
        }

        if payload_contains_image_url(&payload) {
            return Ok(br#"{"image_support":true}"#.to_vec());
        }

        Err(VmError::HostError(
            "mock visual runtime received no frame timestamps".to_string(),
        ))
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn collect_text_entries(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                output.push(text.to_string());
            }
            for nested in map.values() {
                collect_text_entries(nested, output);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_text_entries(nested, output);
            }
        }
        _ => {}
    }
}

fn payload_contains_image_url(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("type").and_then(Value::as_str) == Some("image_url")
                || map.values().any(payload_contains_image_url)
        }
        Value::Array(values) => values.iter().any(payload_contains_image_url),
        _ => false,
    }
}

struct ToolHomeGuard {
    previous: Option<String>,
}

impl ToolHomeGuard {
    fn set(path: &Path) -> Self {
        let previous = std::env::var("IOI_MEDIA_TOOL_HOME").ok();
        std::env::set_var("IOI_MEDIA_TOOL_HOME", path);
        Self { previous }
    }
}

impl Drop for ToolHomeGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var("IOI_MEDIA_TOOL_HOME", previous);
        } else {
            std::env::remove_var("IOI_MEDIA_TOOL_HOME");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn youtube_watch_page_multimodal_live_handles_watch_page_recovery() {
    let temp_dir = tempdir().expect("tempdir");
    let _tool_home_guard = ToolHomeGuard::set(temp_dir.path());
    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockVisualRuntime);

    let bundle = edge_media_extract_multimodal_evidence(
        YOUTUBE_VIDEO_URL,
        Some("en"),
        Some(12_000),
        Some(4),
        browser,
        inference,
    )
    .await
    .expect("multimodal media extraction should succeed");

    assert!(bundle
        .selected_modalities
        .iter()
        .any(|value| value == "transcript" || value == "timeline"));
    assert!(bundle
        .selected_modalities
        .iter()
        .any(|value| value == "visual"));

    if let Some(transcript) = bundle.transcript.as_ref() {
        assert!(matches!(
            transcript.provider_id.as_str(),
            "yt_dlp.managed_subtitles" | "yt_dlp.whisper_rs_audio" | "youtube.watch_transcript"
        ));
        assert!(transcript.transcript_char_count >= 3_000);
        assert!(transcript.segment_count >= 100);
    } else {
        let timeline = bundle.timeline.as_ref().expect("timeline bundle");
        assert_eq!(timeline.provider_id, "youtube.key_moments_timeline");
        assert_eq!(timeline.timeline_source_kind, "key_moments");
        assert!(timeline.cue_count >= 5);
        assert!(timeline.timeline_char_count >= 120);
    }

    let visual = bundle.visual.expect("visual bundle");
    assert!(matches!(
        visual.provider_id.as_str(),
        "ffmpeg.managed_frames_vision" | "youtube.chapter_thumbnails_vision"
    ));
    assert!(visual.frame_count >= 4);
    assert!(visual.visual_char_count > 0);

    assert!(bundle.provider_candidates.iter().any(|candidate| {
        candidate.provider_id == "youtube.watch_transcript"
            && !candidate.success
            && !candidate.selected
            && candidate.challenge_reason.is_some()
    }));
    assert!(bundle.provider_candidates.iter().any(|candidate| {
        candidate.provider_id == "youtube.key_moments_timeline" && candidate.success
    }));
    assert!(bundle.provider_candidates.iter().any(|candidate| {
        candidate.provider_id == "youtube.chapter_thumbnails_vision" && candidate.success
    }));
}
