use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    cec_receipt_usize, cec_receipt_value, environment_bool, environment_u64, environment_value,
    has_cec_receipt, has_cec_stage, has_typed_contract_failure_evidence, observation_has_tool_name,
    truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "summarize_the_key_points_from_this_45_minute_youtube_video";
const EXPECTED_FIXTURE_MODE: &str = "media_multimodal_tool_home_fixture_v1";
const EXPECTED_URL: &str = "https://www.youtube.com/watch?v=9Tm2c6NJH4Y";
const EXPECTED_VIDEO_ID: &str = "9Tm2c6NJH4Y";
const TIMELINE_PROVIDER_ID: &str = "youtube.key_moments_timeline";
const VISUAL_PROVIDER_ID: &str = "ffmpeg.managed_frames_vision";
const CHAPTER_THUMBNAIL_VISUAL_PROVIDER_ID: &str = "youtube.chapter_thumbnails_vision";

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Summarize the key points from this 45-minute YouTube video: [https://www.youtube.com/watch?v=9Tm2c6NJH4Y]. Use direct media-content retrieval from the video itself. Prefer `media__extract_multimodal_evidence`, summarize the multimodal evidence you extract, and do not substitute webpage metadata, browser summaries, or shell execution workflows. Do not use `web__search`, `web__read`, `net__fetch`, `browser__*`, or `sys__exec*`. Return a concise key-point summary of the video.",
        success_definition: "Extract direct multimodal evidence from the target YouTube video via the dedicated media tool, using either transcript+visual or timeline+visual evidence with discovery/provider-selection/execution/verification receipts, return a non-raw summary reply, and satisfy isolated fixture + cleanup environment receipts.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 480,
        max_steps: 16,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let provider_candidates = obs
        .web
        .as_ref()
        .map(|web| web.provider_candidates.clone())
        .unwrap_or_default();
    let provider_candidate_count = provider_candidates.len();
    let selected_provider_count = provider_candidates
        .iter()
        .filter(|candidate| {
            candidate.selected
                && candidate.success
                && candidate.source_count > 0
                && candidate.execution_attempted == Some(true)
                && candidate.execution_satisfied == Some(true)
        })
        .count();
    let transcript_provider_selected = provider_candidates.iter().any(|candidate| {
        candidate.selected
            && candidate.success
            && candidate.source_count > 0
            && candidate.execution_attempted == Some(true)
            && candidate.execution_satisfied == Some(true)
            && matches!(
                candidate.provider_id.as_str(),
                "yt_dlp.managed_subtitles" | "yt_dlp.whisper_rs_audio" | "youtube.watch_transcript"
            )
    });
    let timeline_provider_selected = provider_candidates.iter().any(|candidate| {
        candidate.selected
            && candidate.success
            && candidate.source_count > 0
            && candidate.execution_attempted == Some(true)
            && candidate.execution_satisfied == Some(true)
            && candidate.provider_id == TIMELINE_PROVIDER_ID
    });
    let visual_provider_selected = provider_candidates.iter().any(|candidate| {
        candidate.selected
            && candidate.success
            && candidate.source_count > 0
            && candidate.execution_attempted == Some(true)
            && candidate.execution_satisfied == Some(true)
            && matches!(
                candidate.provider_id.as_str(),
                VISUAL_PROVIDER_ID | CHAPTER_THUMBNAIL_VISUAL_PROVIDER_ID
            )
    });

    let selected_modalities =
        cec_receipt_value(obs, "provider_selection", "selected_modalities").unwrap_or_default();
    let media_title = cec_receipt_value(obs, "verification", "media_title").unwrap_or_default();
    let duration_seconds =
        cec_receipt_usize(obs, "verification", "media_duration_seconds").unwrap_or(0);
    let transcript_char_count =
        cec_receipt_usize(obs, "verification", "media_transcript_char_count").unwrap_or(0);
    let transcript_segment_count =
        cec_receipt_usize(obs, "verification", "media_transcript_segment_count").unwrap_or(0);
    let transcript_source_kind =
        cec_receipt_value(obs, "verification", "media_transcript_source_kind").unwrap_or_default();
    let transcript_language =
        cec_receipt_value(obs, "verification", "media_transcript_language").unwrap_or_default();
    let timeline_cue_count =
        cec_receipt_usize(obs, "verification", "media_timeline_cue_count").unwrap_or(0);
    let timeline_char_count =
        cec_receipt_usize(obs, "verification", "media_timeline_char_count").unwrap_or(0);
    let timeline_source_kind =
        cec_receipt_value(obs, "verification", "media_timeline_source_kind").unwrap_or_default();
    let visual_frame_count =
        cec_receipt_usize(obs, "verification", "media_visual_frame_count").unwrap_or(0);
    let visual_char_count =
        cec_receipt_usize(obs, "verification", "media_visual_char_count").unwrap_or(0);
    let visual_hash =
        cec_receipt_value(obs, "verification", "media_visual_hash").unwrap_or_default();
    let selected_source_url =
        cec_receipt_value(obs, "verification", "selected_source_url").unwrap_or_default();
    let selected_source_total =
        cec_receipt_usize(obs, "verification", "selected_source_total").unwrap_or(0);
    let selected_source_distinct_domains =
        cec_receipt_usize(obs, "verification", "selected_source_distinct_domains").unwrap_or(0);

    let completion_gate_satisfied =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let completion_evidence_present =
        obs.completed && !obs.failed && obs.chat_reply_count > 0 && completion_gate_satisfied;
    let media_tool_path_evidence_present =
        observation_has_tool_name(obs, "media__extract_multimodal_evidence")
            && !observation_has_tool_name(obs, "web__search")
            && !observation_has_tool_name(obs, "web__read")
            && !observation_has_tool_name(obs, "net__fetch")
            && !observation_has_tool_name(obs, "browser__navigate")
            && !observation_has_tool_name(obs, "sys__exec")
            && !observation_has_tool_name(obs, "sys__exec_session");
    let cec_phase_receipts_present = has_cec_stage(obs, "discovery", Some(true))
        && has_cec_stage(obs, "provider_selection", Some(true))
        && has_cec_stage(obs, "execution", Some(true))
        && has_cec_stage(obs, "verification", Some(true))
        && has_cec_receipt(
            obs,
            "verification",
            "media_multimodal_evidence_available",
            Some(true),
        )
        && has_cec_receipt(
            obs,
            "verification",
            "media_visual_evidence_available",
            Some(true),
        )
        && completion_gate_satisfied;
    let transcript_postcondition_present = has_cec_receipt(
        obs,
        "verification",
        "media_transcript_available",
        Some(true),
    );
    let timeline_postcondition_present =
        has_cec_receipt(obs, "verification", "media_timeline_available", Some(true));
    let provider_discovery_evidence_present = provider_candidate_count >= 3
        && selected_provider_count >= 2
        && (transcript_provider_selected || timeline_provider_selected)
        && visual_provider_selected;
    let transcript_modalities_ok =
        selected_modalities.contains("transcript") && selected_modalities.contains("visual");
    let timeline_modalities_ok =
        selected_modalities.contains("timeline") && selected_modalities.contains("visual");
    let transcript_objective_receipts_present = transcript_postcondition_present
        && transcript_modalities_ok
        && duration_seconds >= 2_400
        && duration_seconds <= 4_200
        && transcript_char_count >= 3_000
        && transcript_segment_count >= 100
        && matches!(
            transcript_source_kind.trim(),
            "manual" | "automatic" | "stt" | "watch_transcript"
        )
        && transcript_language
            .trim()
            .to_ascii_lowercase()
            .starts_with("en");
    let timeline_objective_receipts_present = timeline_postcondition_present
        && timeline_modalities_ok
        && duration_seconds >= 2_400
        && duration_seconds <= 4_200
        && timeline_cue_count >= 5
        && timeline_char_count >= 120
        && timeline_source_kind
            .trim()
            .eq_ignore_ascii_case("key_moments");
    let objective_media_receipts_present = !media_title.trim().is_empty()
        && (transcript_objective_receipts_present || timeline_objective_receipts_present)
        && visual_frame_count >= 4
        && visual_char_count >= 100
        && !visual_hash.trim().is_empty()
        && (selected_source_url.contains(EXPECTED_VIDEO_ID)
            || selected_source_url.eq_ignore_ascii_case(EXPECTED_URL))
        && selected_source_total == 1
        && selected_source_distinct_domains == 1;

    let environment_receipts = collect_environment_receipts(obs);
    let fixture_mode_matches = environment_value(obs, "env_receipt::media_multimodal_fixture_mode")
        .is_some_and(|value| value == EXPECTED_FIXTURE_MODE);
    let environment_receipts_present =
        fixture_mode_matches && environment_receipts.iter().all(|receipt| receipt.satisfied);
    let cleanup_evidence_present =
        environment_bool(obs, "env_receipt::media_multimodal_cleanup_satisfied").unwrap_or(false);
    let contract_failure_marker = has_typed_contract_failure_evidence(obs);

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "completed={} failed={} chat_reply_count={} completion_gate_satisfied={}",
                obs.completed, obs.failed, obs.chat_reply_count, completion_gate_satisfied
            ),
        ),
        LocalCheck::new(
            "media_tool_path_evidence_present",
            media_tool_path_evidence_present,
            format!("action_tools={:?}", obs.action_tools),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present
                && (transcript_postcondition_present || timeline_postcondition_present),
            format!(
                "cec_receipts={} transcript_postcondition_present={} timeline_postcondition_present={}",
                obs.cec_receipts.len(),
                transcript_postcondition_present,
                timeline_postcondition_present
            ),
        ),
        LocalCheck::new(
            "provider_discovery_evidence_present",
            provider_discovery_evidence_present,
            format!(
                "provider_candidate_count={} selected_provider_count={} provider_candidates={:?}",
                provider_candidate_count, selected_provider_count, provider_candidates
            ),
        ),
        LocalCheck::new(
            "objective_media_receipts_present",
            objective_media_receipts_present,
            format!(
                "media_title={} duration_seconds={} transcript_char_count={} transcript_segment_count={} timeline_cue_count={} timeline_char_count={} visual_frame_count={} visual_char_count={} selected_modalities={} selected_source_url={}",
                truncate_chars(&media_title, 80),
                duration_seconds,
                transcript_char_count,
                transcript_segment_count,
                timeline_cue_count,
                timeline_char_count,
                visual_frame_count,
                visual_char_count,
                selected_modalities,
                truncate_chars(&selected_source_url, 120),
            ),
        ),
        LocalCheck::new(
            "environment_receipts_present",
            environment_receipts_present,
            serde_json::to_string(&environment_receipts).unwrap_or_default(),
        ),
        LocalCheck::new(
            "cleanup_evidence_present",
            cleanup_evidence_present,
            format!(
                "cleanup={} cleanup_fixture_root_exists={} cleanup_receipt_exists={}",
                environment_bool(obs, "env_receipt::media_multimodal_cleanup_satisfied")
                    .unwrap_or(false),
                environment_value(obs, "env_receipt::media_multimodal_cleanup_fixture_root_exists")
                    .unwrap_or_default(),
                environment_value(obs, "env_receipt::media_multimodal_cleanup_receipt_exists")
                    .unwrap_or_default(),
            ),
        ),
        LocalCheck::new(
            "contract_failure_marker_absent",
            !contract_failure_marker,
            format!("contract_failure_marker={}", contract_failure_marker),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn collect_environment_receipts(obs: &RunObservation) -> Vec<EnvironmentEvidenceReceipt> {
    [
        "media_multimodal_fixture_mode",
        "media_multimodal_fixture_root",
        "media_multimodal_tool_home",
        "media_multimodal_receipt_path",
        "media_multimodal_requested_url",
        "media_multimodal_canonical_url",
        "media_multimodal_selected_modalities",
        "media_multimodal_timeline_provider_id",
        "media_multimodal_timeline_cue_count",
        "media_multimodal_visual_provider_binary_path",
        "media_multimodal_visual_frame_count",
        "media_multimodal_cleanup",
    ]
    .into_iter()
    .map(|key| EnvironmentEvidenceReceipt {
        key,
        observed_value: environment_value(obs, &format!("env_receipt::{key}")).unwrap_or_default(),
        probe_source: environment_value(obs, &format!("env_receipt::{key}_probe_source"))
            .unwrap_or_default(),
        timestamp_ms: environment_u64(obs, &format!("env_receipt::{key}_timestamp_ms"))
            .unwrap_or(obs.run_timestamp_ms),
        satisfied: environment_bool(obs, &format!("env_receipt::{key}_satisfied")).unwrap_or(false),
    })
    .collect()
}
