use super::events::{
    emit_execution_contract_receipt_event, emit_execution_contract_receipt_event_with_observation,
};
use super::tool_outcome::{apply_tool_outcome_and_followups, ToolOutcomeContext};
use super::*;
use crate::agentic::desktop::connectors::{
    connector_id_for_tool_name, connector_postcondition_verifier_bindings,
};
use crate::agentic::desktop::service::step::action::command_contract::contract_requires_postcondition_with_rules;
use crate::agentic::desktop::service::step::cognition::build_browser_snapshot_pending_state_context_with_history;
use ioi_types::app::agentic::{
    MediaFrameEvidence, MediaMultimodalBundle, MediaTimelineOutlineBundle, MediaTranscriptBundle,
    MediaVisualEvidenceBundle,
};
use std::collections::HashSet;

const TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT: usize = 3_200;
const TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT: usize = 1_800;
const MEDIA_TRANSCRIPT_CONTEXT_EXCERPT_LIMIT: usize = 6;
const MEDIA_TRANSCRIPT_CONTEXT_EXCERPT_CHARS: usize = 220;
const MEDIA_VISUAL_CONTEXT_FRAME_LIMIT: usize = 6;
const MEDIA_VISUAL_CONTEXT_COMPONENT_CHARS: usize = 160;
const MEDIA_VISUAL_CONTEXT_SUMMARY_CHARS: usize = 420;

fn compact_ws_for_chat_context(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars_for_chat_context(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let compact = compact_ws_for_chat_context(text);
    if compact.chars().count() <= max_chars {
        return compact;
    }

    let kept = max_chars.saturating_sub(3);
    if kept == 0 {
        return "...".to_string();
    }

    let truncated = compact.chars().take(kept).collect::<String>();
    format!("{}...", truncated.trim_end())
}

fn split_transcript_context_units(text: &str) -> Vec<String> {
    let compact = compact_ws_for_chat_context(text);
    if compact.is_empty() {
        return Vec::new();
    }

    let mut units = Vec::new();
    let mut current = String::new();
    for ch in compact.chars() {
        current.push(ch);
        if matches!(ch, '.' | '!' | '?' | ';') {
            let candidate = current.trim();
            if !candidate.is_empty() {
                units.push(candidate.to_string());
            }
            current.clear();
        }
    }
    let trailing = current.trim();
    if !trailing.is_empty() {
        units.push(trailing.to_string());
    }

    let mut merged = Vec::new();
    let mut buffer = String::new();
    for unit in units {
        let normalized = unit.trim();
        if normalized.is_empty() {
            continue;
        }
        if buffer.is_empty() {
            buffer.push_str(normalized);
        } else if buffer.chars().count() < 90 {
            buffer.push(' ');
            buffer.push_str(normalized);
        } else {
            merged.push(buffer);
            buffer = normalized.to_string();
        }
    }
    if !buffer.trim().is_empty() {
        merged.push(buffer);
    }

    if !merged.is_empty() {
        return merged;
    }

    let words = compact.split_whitespace().collect::<Vec<_>>();
    if words.is_empty() {
        return Vec::new();
    }

    let mut fallback = Vec::new();
    for chunk in words.chunks(32) {
        let joined = chunk.join(" ");
        if !joined.trim().is_empty() {
            fallback.push(joined);
        }
    }
    fallback
}

fn evenly_sample_indices(len: usize, limit: usize) -> Vec<usize> {
    if len == 0 || limit == 0 {
        return Vec::new();
    }
    if len <= limit {
        return (0..len).collect();
    }
    if limit == 1 {
        return vec![0];
    }

    let mut indices = Vec::with_capacity(limit);
    for slot in 0..limit {
        let idx = slot.saturating_mul(len.saturating_sub(1)) / limit.saturating_sub(1);
        if indices.last().copied() != Some(idx) {
            indices.push(idx);
        }
    }
    indices
}

fn transcript_context_excerpts(text: &str) -> Vec<String> {
    let units = split_transcript_context_units(text);
    evenly_sample_indices(units.len(), MEDIA_TRANSCRIPT_CONTEXT_EXCERPT_LIMIT)
        .into_iter()
        .filter_map(|idx| units.get(idx))
        .map(|unit| truncate_chars_for_chat_context(unit, MEDIA_TRANSCRIPT_CONTEXT_EXCERPT_CHARS))
        .filter(|unit| !unit.is_empty())
        .collect()
}

fn summarize_media_transcript_bundle_for_chat(bundle: &MediaTranscriptBundle) -> String {
    let mut lines = vec![format!(
        "Tool Output (media__extract_transcript): title={} canonical_url={} duration_seconds={} provider_id={} transcript_language={} transcript_source_kind={} transcript_segment_count={} transcript_char_count={} transcript_hash={}",
        bundle.title.as_deref().unwrap_or(""),
        bundle.canonical_url,
        bundle.duration_seconds.unwrap_or_default(),
        bundle.provider_id,
        bundle.transcript_language,
        bundle.transcript_source_kind,
        bundle.segment_count,
        bundle.transcript_char_count,
        bundle.transcript_hash
    )];

    for (idx, excerpt) in transcript_context_excerpts(&bundle.transcript_text)
        .into_iter()
        .enumerate()
    {
        lines.push(format!("transcript_evidence[{}]={}", idx + 1, excerpt));
    }

    lines.join("\n")
}

fn summarize_media_frame_for_chat(frame: &MediaFrameEvidence, index: usize) -> String {
    let mut parts = vec![
        format!("timestamp={}", frame.timestamp_label),
        format!(
            "scene={}",
            truncate_chars_for_chat_context(
                frame.scene_summary.as_str(),
                MEDIA_VISUAL_CONTEXT_COMPONENT_CHARS
            )
        ),
    ];

    let visible_text = truncate_chars_for_chat_context(
        frame.visible_text.as_str(),
        MEDIA_VISUAL_CONTEXT_COMPONENT_CHARS,
    );
    if !visible_text.is_empty() {
        parts.push(format!("visible_text={}", visible_text));
    }

    if let Some(transcript_excerpt) = frame.transcript_excerpt.as_deref() {
        let excerpt = truncate_chars_for_chat_context(
            transcript_excerpt,
            MEDIA_VISUAL_CONTEXT_COMPONENT_CHARS,
        );
        if !excerpt.is_empty() {
            parts.push(format!("transcript_excerpt={}", excerpt));
        }
    }

    format!("visual_evidence[{}]={}", index + 1, parts.join(" | "))
}

fn summarize_media_visual_bundle_for_chat(bundle: &MediaVisualEvidenceBundle) -> Vec<String> {
    let mut lines = vec![format!(
        "visual_summary: provider_id={} frame_count={} visual_char_count={} visual_hash={}",
        bundle.provider_id, bundle.frame_count, bundle.visual_char_count, bundle.visual_hash
    )];

    if !bundle.frames.is_empty() {
        for (idx, frame) in bundle
            .frames
            .iter()
            .take(MEDIA_VISUAL_CONTEXT_FRAME_LIMIT)
            .enumerate()
        {
            lines.push(summarize_media_frame_for_chat(frame, idx));
        }
    } else if !bundle.visual_summary.trim().is_empty() {
        lines.push(format!(
            "visual_overview={}",
            truncate_chars_for_chat_context(
                bundle.visual_summary.as_str(),
                MEDIA_VISUAL_CONTEXT_SUMMARY_CHARS
            )
        ));
    }

    lines
}

fn summarize_media_multimodal_bundle_for_chat(bundle: &MediaMultimodalBundle) -> String {
    let selected_modalities = if bundle.selected_modalities.is_empty() {
        String::new()
    } else {
        bundle.selected_modalities.join(",")
    };
    let selected_provider_ids = if bundle.selected_provider_ids.is_empty() {
        String::new()
    } else {
        bundle.selected_provider_ids.join(",")
    };
    let provider_candidates = bundle
        .provider_candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}:{}:{}:{}",
                candidate.provider_id,
                candidate.modality.as_deref().unwrap_or(""),
                candidate.selected,
                candidate.source_count
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let mut lines = vec![format!(
        "Tool Output (media__extract_multimodal_evidence): title={} canonical_url={} duration_seconds={} selected_modalities={} selected_provider_ids={} provider_candidates={}",
        bundle.title.as_deref().unwrap_or(""),
        bundle.canonical_url,
        bundle.duration_seconds.unwrap_or_default(),
        selected_modalities,
        selected_provider_ids,
        provider_candidates
    )];

    if let Some(transcript) = bundle.transcript.as_ref() {
        lines.push(format!(
            "transcript_summary: provider_id={} transcript_language={} transcript_source_kind={} transcript_segment_count={} transcript_char_count={} transcript_hash={}",
            transcript.provider_id,
            transcript.transcript_language,
            transcript.transcript_source_kind,
            transcript.segment_count,
            transcript.transcript_char_count,
            transcript.transcript_hash
        ));
        for (idx, excerpt) in transcript_context_excerpts(&transcript.transcript_text)
            .into_iter()
            .enumerate()
        {
            lines.push(format!("transcript_evidence[{}]={}", idx + 1, excerpt));
        }
    }

    if let Some(timeline) = bundle.timeline.as_ref() {
        lines.push(summarize_media_timeline_bundle_for_chat(timeline));
    }

    if let Some(visual) = bundle.visual.as_ref() {
        lines.extend(summarize_media_visual_bundle_for_chat(visual));
    }

    lines.join("\n")
}

fn summarize_media_timeline_bundle_for_chat(bundle: &MediaTimelineOutlineBundle) -> String {
    format!(
        "timeline_summary: provider_id={} timeline_source_kind={} timeline_cue_count={} timeline_char_count={} timeline_hash={}",
        bundle.provider_id,
        bundle.timeline_source_kind,
        bundle.cue_count,
        bundle.timeline_char_count,
        bundle.timeline_hash
    )
}

fn looks_like_browser_snapshot_history_entry(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root") && trimmed.contains("id=\"") && trimmed.contains("rect=\"")
}

fn decode_browser_xml_text_for_chat(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn extract_browser_xml_attr_for_chat(fragment: &str, attr: &str) -> Option<String> {
    let marker = format!(r#"{attr}=""#);
    let start = fragment.find(&marker)? + marker.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn browser_fragment_tag_name_for_chat(fragment: &str) -> Option<&str> {
    let trimmed = fragment.trim_start();
    if trimmed.is_empty() || trimmed.starts_with("!--") || trimmed.starts_with('/') {
        return None;
    }

    let end = trimmed
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

fn browser_fragment_priority_score_for_chat(fragment: &str, tag_name: &str) -> Option<u8> {
    let mut score = 0u8;

    if fragment.contains(" dom_id=\"") {
        score = score.saturating_add(8);
    }
    if fragment.contains(" selector=\"") {
        score = score.saturating_add(2);
    }
    if matches!(
        tag_name,
        "button"
            | "link"
            | "textbox"
            | "combobox"
            | "checkbox"
            | "radio"
            | "searchbox"
            | "menuitem"
            | "option"
    ) {
        score = score.saturating_add(6);
    } else if tag_name == "listitem" {
        score = score.saturating_add(2);
    }
    if fragment.contains(" focused=\"true\"")
        || fragment.contains(" checked=\"true\"")
        || fragment.contains(" selected=\"true\"")
    {
        score = score.saturating_add(4);
    }
    if fragment.contains(" assistive_hint=\"true\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" omitted=\"true\"") {
        score = score.saturating_add(1);
    }

    (score > 0).then_some(score)
}

fn browser_fragment_priority_summary_for_chat(fragment: &str) -> Option<(String, u8, String)> {
    let id = extract_browser_xml_attr_for_chat(fragment, "id")?;
    let tag_name = browser_fragment_tag_name_for_chat(fragment)?;
    let score = browser_fragment_priority_score_for_chat(fragment, tag_name)?;

    let name = extract_browser_xml_attr_for_chat(fragment, "name")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let dom_id = extract_browser_xml_attr_for_chat(fragment, "dom_id")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let selector = extract_browser_xml_attr_for_chat(fragment, "selector")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let context = extract_browser_xml_attr_for_chat(fragment, "context")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());

    let mut summary = format!("{tag_name}#{id}");
    if let Some(name) = name {
        summary.push_str(&format!(" name={}", name));
    }
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={}", dom_id));
    }
    if let Some(selector) = selector {
        summary.push_str(&format!(" selector={}", selector));
    }
    if let Some(context) = context {
        summary.push_str(&format!(" context={}", context));
    }
    if fragment.contains(" omitted=\"true\"") {
        summary.push_str(" omitted");
    }

    Some((id, score, summary))
}

fn extract_priority_browser_targets_for_chat(snapshot: &str, max_targets: usize) -> Vec<String> {
    let mut seen_ids = HashSet::new();
    let mut targets = Vec::new();
    let mut order = 0usize;

    for fragment in snapshot.split('<') {
        let Some((id, score, summary)) = browser_fragment_priority_summary_for_chat(fragment)
        else {
            continue;
        };
        if !seen_ids.insert(id) {
            continue;
        }
        targets.push((score, order, summary));
        order += 1;
    }

    targets.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    targets
        .into_iter()
        .take(max_targets)
        .map(|(_, _, summary)| summary)
        .collect()
}

fn compact_browser_snapshot_history_entry(snapshot: &str) -> String {
    let compact = compact_ws_for_chat_context(snapshot.trim());
    if compact.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT {
        return compact;
    }

    let priority_targets = extract_priority_browser_targets_for_chat(snapshot, 6);
    if priority_targets.is_empty() {
        return truncate_chars_for_chat_context(
            snapshot,
            TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT,
        );
    }

    let suffix = format!(" IMPORTANT TARGETS: {}", priority_targets.join(" | "));
    let suffix =
        truncate_chars_for_chat_context(&suffix, TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT / 2);
    let prefix_budget = TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT
        .saturating_sub(suffix.chars().count() + 1)
        .max(TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT / 3);
    let prefix = truncate_chars_for_chat_context(snapshot, prefix_budget);

    format!("{prefix} {suffix}")
}

fn compact_tool_history_entry_for_chat(current_tool_name: &str, history_entry: &str) -> String {
    let trimmed = history_entry.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match current_tool_name {
        "media__extract_multimodal_evidence" => {
            serde_json::from_str::<MediaMultimodalBundle>(trimmed)
                .map(|bundle| summarize_media_multimodal_bundle_for_chat(&bundle))
                .unwrap_or_else(|_| {
                    truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
                })
        }
        "media__extract_transcript" => serde_json::from_str::<MediaTranscriptBundle>(trimmed)
            .map(|bundle| summarize_media_transcript_bundle_for_chat(&bundle))
            .unwrap_or_else(|_| {
                truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
            }),
        "browser__snapshot" => {
            if looks_like_browser_snapshot_history_entry(trimmed) {
                compact_browser_snapshot_history_entry(trimmed)
            } else {
                truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
            }
        }
        _ => truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT),
    }
}

fn record_browser_marker_receipt(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    mark_execution_receipt_with_value(
        &mut agent_state.tool_execution_log,
        key,
        evidence.to_string(),
    );
    verification_checks.push(receipt_marker(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

fn record_browser_marker_postcondition(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    mark_execution_postcondition(&mut agent_state.tool_execution_log, key);
    verification_checks.push(postcondition_marker(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

fn parse_find_text_found(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("result")
        .and_then(|result| result.get("found"))
        .and_then(|found| found.as_bool())
}

fn parse_selection_non_empty(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("selection")
        .and_then(|selection| selection.get("selected_text"))
        .and_then(|selected_text| selected_text.as_str())
        .map(|selected_text| !selected_text.is_empty())
}

fn parse_key_is_chord(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("key")
        .and_then(|key| key.get("is_chord"))
        .and_then(|is_chord| is_chord.as_bool())
}

fn parse_clipboard_text_length(history_entry: Option<&str>) -> Option<u64> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("clipboard")
        .and_then(|clipboard| clipboard.get("text_length"))
        .and_then(|text_length| text_length.as_u64())
}

fn parse_wait_condition_met(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("wait")
        .and_then(|wait| wait.get("met"))
        .and_then(|met| met.as_bool())
}

fn compact_browser_receipt_evidence(history_entry: Option<&str>) -> String {
    let raw = history_entry
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .unwrap_or("browser_action_success=true");

    let normalized = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| serde_jcs::to_vec(&value).ok())
        .unwrap_or_else(|| raw.as_bytes().to_vec());

    sha256(&normalized)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string())
}

fn record_browser_success_markers(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    history_entry: Option<&str>,
    trace_visual_hash: Option<[u8; 32]>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
) {
    let evidence = compact_browser_receipt_evidence(history_entry);

    match tool {
        AgentTool::BrowserHover { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_hover",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_pointer_target_acquired",
                "browser_pointer_target_acquired=true",
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_hover_applied",
                "browser_hover_applied=true",
            );
        }
        AgentTool::BrowserMoveMouse { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_pointer_move",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_position_updated",
                "browser_pointer_position_updated=true",
            );
        }
        AgentTool::BrowserMouseDown { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_mouse_down",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_pressed",
                "browser_pointer_pressed=true",
            );
        }
        AgentTool::BrowserMouseUp { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_mouse_up",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_pointer_released",
                "browser_pointer_released=true",
            );
        }
        AgentTool::BrowserSelectText { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_text_selection",
                evidence.as_str(),
            );
            if parse_selection_non_empty(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_text_selected",
                    "browser_text_selected=true",
                );
            }
        }
        AgentTool::BrowserKey { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_key_input",
                evidence.as_str(),
            );
            if parse_key_is_chord(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_key_chord_applied",
                    "browser_key_chord_applied=true",
                );
            }
        }
        AgentTool::BrowserCopySelection {} => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_clipboard_copy",
                evidence.as_str(),
            );
            if parse_clipboard_text_length(history_entry).unwrap_or(0) > 0 {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_clipboard_populated",
                    "browser_clipboard_populated=true",
                );
            }
        }
        AgentTool::BrowserPasteClipboard { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_clipboard_paste",
                evidence.as_str(),
            );
            if parse_clipboard_text_length(history_entry).unwrap_or(0) > 0 {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_clipboard_inserted",
                    "browser_clipboard_inserted=true",
                );
            }
        }
        AgentTool::BrowserUploadFile { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_upload_file",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_file_attached",
                "browser_file_attached=true",
            );
        }
        AgentTool::BrowserSelectDropdown { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_dropdown_selected",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_selection_applied",
                "browser_dropdown_selection_applied=true",
            );
        }
        AgentTool::BrowserGoBack { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_history_back",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_navigation_changed",
                "browser_navigation_changed=true",
            );
        }
        AgentTool::BrowserWait { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_wait",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_wait_completed",
                "browser_wait_completed=true",
            );
            if parse_wait_condition_met(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    None,
                    "browser_wait_condition_met",
                    "browser_wait_condition_met=true",
                );
            }
        }
        AgentTool::BrowserTabSwitch { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_switch",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_active_tab_selected",
                "browser_active_tab_selected=true",
            );
        }
        AgentTool::BrowserTabClose { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_close",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_closed",
                "browser_tab_closed=true",
            );
        }
        AgentTool::BrowserFindText { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_find_text",
                evidence.as_str(),
            );
            if parse_find_text_found(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_text_found",
                    "browser_text_found=true",
                );
            }
        }
        AgentTool::BrowserCanvasSummary { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_canvas_summary",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_canvas_observation",
                "browser_canvas_observation=true",
            );
        }
        AgentTool::BrowserScreenshot { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_screenshot",
                evidence.as_str(),
            );
            if trace_visual_hash.is_some() {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_visual_observation",
                    "browser_visual_observation=true",
                );
            }
        }
        AgentTool::BrowserDropdownOptions { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_options",
                evidence.as_str(),
            );
        }
        AgentTool::BrowserTabList {} => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_list",
                evidence.as_str(),
            );
        }
        _ => {}
    }
}

async fn verify_non_command_postconditions(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    current_tool_name: &str,
    tool_args: &serde_json::Value,
    history_entry: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), String> {
    if agent_state.resolved_intent.is_none() {
        return Ok(());
    }
    if !contract_requires_postcondition_with_rules(agent_state, rules, "mail.reply.completed") {
        return Ok(());
    }
    let connector_id = agent_state
        .resolved_intent
        .as_ref()
        .and_then(|resolved| resolved.provider_selection.as_ref())
        .and_then(|selection| selection.selected_connector_id.as_deref())
        .or_else(|| connector_id_for_tool_name(current_tool_name))
        .ok_or_else(|| {
            "ERROR_CLASS=GroundingMissing Postcondition verification requires a selected connector."
                .to_string()
        })?;
    let verifier = connector_postcondition_verifier_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=VerificationMissing No postcondition verifier is registered for connector '{}'.",
                connector_id
            )
        })?;
    let history_entry = history_entry.ok_or_else(|| {
        "ERROR_CLASS=VerificationMissing Postcondition verification requires structured tool output."
            .to_string()
    })?;
    let Some(proof) = (verifier.verify)(agent_state, current_tool_name, tool_args, history_entry)
        .await
        .map_err(|error| format!("ERROR_CLASS=PostconditionFailed {}", error))?
    else {
        return Err(
            "ERROR_CLASS=VerificationMissing Connector verifier returned no postcondition proof."
                .to_string(),
        );
    };

    for evidence in proof.evidence {
        mark_execution_postcondition(&mut agent_state.tool_execution_log, &evidence.key);
        verification_checks.push(postcondition_marker(&evidence.key));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "verification",
            &evidence.key,
            true,
            &evidence.evidence,
            Some("connector_verifier"),
            evidence.observed_value.as_deref(),
            evidence.evidence_type.as_deref(),
            None,
            evidence.provider_id,
            synthesized_payload_hash.clone(),
        );
    }

    Ok(())
}

pub(crate) async fn record_non_command_success_receipts(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    current_tool_name: &str,
    tool_args: &serde_json::Value,
    history_entry: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), String> {
    mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
    verification_checks.push(receipt_marker("execution"));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "execution",
        true,
        "execution_invocation_completed=true",
        None,
        None,
        synthesized_payload_hash.clone(),
    );

    verify_non_command_postconditions(
        service,
        agent_state,
        rules,
        current_tool_name,
        tool_args,
        history_entry,
        session_id,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash.clone(),
        verification_checks,
    )
    .await?;

    mark_execution_receipt(&mut agent_state.tool_execution_log, "verification");
    verification_checks.push(receipt_marker("verification"));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verification",
        true,
        "verification_receipt_recorded=true",
        None,
        None,
        synthesized_payload_hash,
    );

    Ok(())
}

pub(super) struct ExecutionSuccessContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub tool: &'a AgentTool,
    pub tool_args: &'a serde_json::Value,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub synthesized_payload_hash: Option<String>,
    pub command_scope: bool,
    pub req_hash_hex: &'a str,
    pub retry_intent_hash: Option<&'a str>,
    pub success: &'a mut bool,
    pub error_msg: &'a mut Option<String>,
    pub history_entry: &'a mut Option<String>,
    pub action_output: &'a mut Option<String>,
    pub trace_visual_hash: &'a mut Option<[u8; 32]>,
    pub is_lifecycle_action: &'a mut bool,
    pub current_tool_name: &'a mut String,
    pub terminal_chat_reply_output: &'a mut Option<String>,
    pub verification_checks: &'a mut Vec<String>,
    pub command_probe_completed: &'a mut bool,
    pub execution_result: (bool, Option<String>, Option<String>, Option<[u8; 32]>),
}

pub(super) async fn handle_execution_success(
    ctx: ExecutionSuccessContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ExecutionSuccessContext {
        service,
        state,
        agent_state,
        rules,
        tool,
        tool_args,
        session_id,
        block_height,
        block_timestamp_ns,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash,
        command_scope,
        req_hash_hex,
        retry_intent_hash,
        success,
        error_msg,
        history_entry,
        action_output,
        trace_visual_hash,
        is_lifecycle_action,
        current_tool_name,
        terminal_chat_reply_output,
        verification_checks,
        command_probe_completed,
        execution_result,
    } = ctx;

    let (s, entry, e, visual_hash) = execution_result;
    *success = s;
    *error_msg = e;
    *history_entry = entry.clone();
    if let Some(visual_hash) = visual_hash {
        *trace_visual_hash = Some(visual_hash);
        verification_checks.push(format!(
            "visual_observation_checksum={}",
            hex::encode(visual_hash)
        ));
    }
    if command_scope && is_command_execution_provider_tool(tool) && !*success {
        let cause = error_msg
            .clone()
            .unwrap_or_else(|| "unknown execution failure".to_string());
        if !cause.contains("ERROR_CLASS=ExecutionFailedTerminal") {
            *error_msg = Some(format!(
                "ERROR_CLASS=ExecutionFailedTerminal stage=execution cause={}",
                cause
            ));
        }
        let execution_failure = error_msg
            .clone()
            .unwrap_or_else(|| "ERROR_CLASS=ExecutionFailedTerminal".to_string());
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution",
            false,
            &execution_failure,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
    }

    // Orchestration meta-tools require access to chain state; execute them
    // on the primary path here instead of the stateless ToolExecutor.
    if *success {
        match tool {
            AgentTool::AgentDelegate { goal, budget } => {
                let tool_jcs = match serde_jcs::to_vec(tool) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        *success = false;
                        *error_msg = Some(format!(
                            "ERROR_CLASS=UnexpectedState Failed to encode delegation tool: {}",
                            err
                        ));
                        *history_entry = None;
                        Vec::new()
                    }
                };

                if *success {
                    match sha256(&tool_jcs) {
                        Ok(tool_hash) => {
                            match spawn_delegated_child_session(
                                service,
                                state,
                                agent_state,
                                tool_hash,
                                goal,
                                *budget,
                                step_index,
                                block_height,
                            )
                            .await
                            {
                                Ok(child_session_id) => {
                                    *history_entry = Some(format!(
                                        "{{\"child_session_id_hex\":\"{}\"}}",
                                        hex::encode(child_session_id)
                                    ));
                                    *error_msg = None;
                                }
                                Err(err) => {
                                    *success = false;
                                    *error_msg = Some(err.to_string());
                                    *history_entry = None;
                                }
                            }
                        }
                        Err(err) => {
                            *success = false;
                            *error_msg = Some(format!(
                                "ERROR_CLASS=UnexpectedState Delegation hash failed: {}",
                                err
                            ));
                            *history_entry = None;
                        }
                    }
                }
            }
            AgentTool::AgentAwait {
                child_session_id_hex,
            } => match child_session::await_child_session_status(state, child_session_id_hex) {
                Ok(out) => {
                    *history_entry = Some(out);
                    *error_msg = None;
                }
                Err(err) => {
                    *success = false;
                    *error_msg = Some(err);
                    *history_entry = None;
                }
            },
            _ => {}
        }
    }

    if matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    ) {
        let raw_entry = command_history::extract_command_history(history_entry);
        if raw_entry.is_some() {
            verification_checks.push("capability_execution_evidence=command_history".to_string());
        } else {
            verification_checks.push("capability_execution_evidence=tool_output".to_string());
        }
        if let Some(raw_entry_ref) = raw_entry.as_ref() {
            verification_checks.push(format!(
                "capability_execution_last_exit_code={}",
                raw_entry_ref.exit_code
            ));
        }

        if command_scope {
            mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");
            verification_checks.push(postcondition_marker("execution_artifact"));
            let artifact_evidence = raw_entry
                .as_ref()
                .map(|entry| format!("command_exit_code={}", entry.exit_code))
                .unwrap_or_else(|| {
                    format!(
                        "command_history_missing=true;tool_output_chars={}",
                        history_entry
                            .as_ref()
                            .map(|entry| entry.chars().count())
                            .unwrap_or(0)
                    )
                });
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "execution",
                "execution_artifact",
                true,
                &artifact_evidence,
                None,
                None,
                synthesized_payload_hash.clone(),
            );
        }

        if let Some(raw_entry) = raw_entry {
            let history =
                command_history::scrub_command_history_fields(&service.scrubber, raw_entry).await;
            command_history::append_to_bounded_history(
                &mut agent_state.command_history,
                history,
                MAX_COMMAND_HISTORY,
            );
        }
    }

    if command_scope && *success && matches!(tool, AgentTool::SysInstallPackage { .. }) {
        verification_checks.push("capability_execution_evidence=tool_output".to_string());
        mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");
        verification_checks.push(postcondition_marker("execution_artifact"));
        let (package, manager) = match tool {
            AgentTool::SysInstallPackage { package, manager } => {
                (package.trim(), manager.as_deref().unwrap_or("auto"))
            }
            _ => ("unknown", "auto"),
        };
        let artifact_evidence = format!(
            "install_package={};install_manager={};tool_output_chars={}",
            package,
            manager,
            history_entry
                .as_ref()
                .map(|entry| entry.chars().count())
                .unwrap_or(0)
        );
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution_artifact",
            true,
            &artifact_evidence,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
    }

    if command_scope && *success && matches!(tool, AgentTool::AutomationCreateMonitor { .. }) {
        verification_checks.push("capability_execution_evidence=tool_output".to_string());
        mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");
        verification_checks.push(postcondition_marker("execution_artifact"));
        let artifact_evidence = format!(
            "automation_monitor_install=true;tool_output_chars={}",
            history_entry
                .as_ref()
                .map(|entry| entry.chars().count())
                .unwrap_or(0)
        );
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution_artifact",
            true,
            &artifact_evidence,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
    }

    if (*success || *command_probe_completed) && !req_hash_hex.is_empty() {
        agent_state.tool_execution_log.insert(
            req_hash_hex.to_string(),
            ToolCallStatus::Executed("success".into()),
        );
        if let Some(retry_hash) = retry_intent_hash {
            mark_action_fingerprint_executed_at_step(
                &mut agent_state.tool_execution_log,
                retry_hash,
                step_index,
                "success",
            );
        }
        agent_state.pending_approval = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_request_nonce = None;
    }

    if *success {
        record_browser_success_markers(
            service,
            agent_state,
            tool,
            history_entry.as_deref(),
            *trace_visual_hash,
            verification_checks,
            session_id,
            step_index,
            resolved_intent_id,
            synthesized_payload_hash.clone(),
        );

        if is_command_execution_provider_tool(tool) {
            if command_scope && requires_timer_notification_contract(agent_state) {
                if matches!(
                    tool,
                    AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                ) {
                    if sys_exec_arms_timer_delay_backend(tool) {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                        );
                        verification_checks
                            .push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
                        let delay_seconds =
                            sys_exec_timer_delay_seconds(tool).map(|value| value.to_string());
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "execution",
                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                            true,
                            "timer_sleep_backend=armed",
                            Some("tool_payload"),
                            delay_seconds.as_deref(),
                            Some("seconds"),
                            None,
                            None,
                            synthesized_payload_hash.clone(),
                        );
                        if let Some(delay_seconds) = delay_seconds.as_deref() {
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                "timer_delay_seconds",
                                true,
                                "timer_delay_seconds_observed=true",
                                Some("tool_payload"),
                                Some(delay_seconds),
                                Some("seconds"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                        }
                    }
                    if let Some(command_preview) = sys_exec_command_preview(tool) {
                        if command_arms_deferred_notification_path(&command_preview) {
                            mark_execution_postcondition(
                                &mut agent_state.tool_execution_log,
                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                            );
                            verification_checks
                                .push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                true,
                                "timer_notification_path_armed=true",
                                Some("tool_payload"),
                                Some("deferred_notification"),
                                Some("strategy"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                            mark_execution_receipt(
                                &mut agent_state.tool_execution_log,
                                "notification_strategy",
                            );
                            verification_checks.push(receipt_marker("notification_strategy"));
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                "notification_strategy",
                                true,
                                "notification_strategy=deferred",
                                Some("tool_payload"),
                                Some("deferred"),
                                Some("strategy"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                            verification_checks
                                .push("timer_notification_path_armed=true".to_string());
                        }
                    }
                }
            }
            if command_scope {
                mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
                verification_checks.push(receipt_marker("execution"));
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "execution",
                    "execution",
                    true,
                    "execution_invocation_completed=true",
                    None,
                    None,
                    synthesized_payload_hash.clone(),
                );
            }
            verification_checks.push("capability_execution_phase=verification".to_string());
            if command_scope {
                record_verification_receipts(
                    &mut agent_state.tool_execution_log,
                    verification_checks,
                    tool,
                    if matches!(
                        tool,
                        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                    ) {
                        agent_state.command_history.back()
                    } else {
                        None
                    },
                );
                let verification_commit = execution_receipt_value(
                    &agent_state.tool_execution_log,
                    VERIFICATION_COMMIT_RECEIPT,
                )
                .map(str::to_string);
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "verification",
                    "verification",
                    true,
                    "verification_receipt_recorded=true",
                    verification_commit.clone(),
                    None,
                    synthesized_payload_hash.clone(),
                );
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "verification",
                    VERIFICATION_COMMIT_RECEIPT,
                    verification_commit
                        .as_deref()
                        .map(|value| value.starts_with("sha256:"))
                        .unwrap_or(false),
                    verification_commit
                        .as_deref()
                        .unwrap_or("verification_commit=missing"),
                    verification_commit.clone(),
                    None,
                    synthesized_payload_hash.clone(),
                );
            }
        }
        if !command_scope {
            if let Err(error) = record_non_command_success_receipts(
                service,
                agent_state,
                rules,
                current_tool_name,
                tool_args,
                history_entry.as_deref(),
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                verification_checks,
            )
            .await
            {
                *success = false;
                *error_msg = Some(error.clone());
                *history_entry = Some(error.clone());
                *action_output = Some(error);
                return Ok(());
            }
        }
        if let Some(entry) = history_entry.clone() {
            let snapshot_pending_context = if current_tool_name == "browser__snapshot" {
                service
                    .hydrate_session_history(session_id)
                    .ok()
                    .map(|history| {
                        build_browser_snapshot_pending_state_context_with_history(&entry, &history)
                    })
                    .filter(|context| !context.trim().is_empty())
            } else {
                None
            };
            let compact_entry = compact_tool_history_entry_for_chat(current_tool_name, &entry);
            if !compact_entry.trim().is_empty() {
                let content = if current_tool_name == "browser__snapshot" {
                    format!("Tool Output (browser__snapshot): {}", compact_entry)
                } else {
                    compact_entry
                };
                let tool_msg = ioi_types::app::agentic::ChatMessage {
                    role: "tool".to_string(),
                    content,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                    .await?;
            }
            if let Some(pending_context) = snapshot_pending_context {
                let sys_msg = ioi_types::app::agentic::ChatMessage {
                    role: "system".to_string(),
                    content: pending_context,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &sys_msg, block_height)
                    .await?;
            }
        }
    }

    apply_tool_outcome_and_followups(ToolOutcomeContext {
        service,
        state,
        agent_state,
        rules,
        tool,
        tool_args,
        session_id,
        block_height,
        block_timestamp_ns,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash,
        command_scope,
        success,
        error_msg,
        history_entry,
        action_output,
        is_lifecycle_action,
        current_tool_name,
        terminal_chat_reply_output,
        verification_checks,
        command_probe_completed,
    })
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        compact_tool_history_entry_for_chat, transcript_context_excerpts,
        TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT,
    };
    use serde_json::json;

    #[test]
    fn transcript_context_excerpts_evenly_sample_long_text() {
        let transcript = [
            "Maxwell introduces the electric field and the magnetic field as coupled quantities.",
            "Gauss's law relates electric flux to enclosed charge.",
            "Gauss's law for magnetism states that magnetic monopoles do not appear in the model.",
            "Faraday's law explains how changing magnetic fields induce electric fields.",
            "Ampere-Maxwell law adds displacement current to complete the system.",
            "The lecturer closes by connecting the equations to electromagnetic waves.",
        ]
        .join(" ");

        let excerpts = transcript_context_excerpts(&transcript);

        assert!(excerpts.len() >= 3);
        assert!(excerpts
            .first()
            .is_some_and(|value| value.contains("Maxwell")));
        assert!(excerpts
            .last()
            .is_some_and(|value| value.contains("electromagnetic waves")));
    }

    #[test]
    fn media_multimodal_history_is_compacted_for_chat_context() {
        let raw = json!({
            "schema_version": 1,
            "retrieved_at_ms": 1773264032396u64,
            "tool": "media__extract_multimodal_evidence",
            "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "title": "Electromagnetism - Maxwell's Laws",
            "duration_seconds": 2909u64,
            "requested_language": "en",
            "provider_candidates": [
                {
                    "provider_id": "yt_dlp.managed_subtitles",
                    "modality": "transcript",
                    "source_count": 1,
                    "selected": true,
                    "success": true,
                    "request_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                    "affordances": ["detail_document"]
                },
                {
                    "provider_id": "ffmpeg.managed_frames_vision",
                    "modality": "visual",
                    "source_count": 1,
                    "selected": true,
                    "success": true,
                    "request_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                    "affordances": ["detail_document"]
                }
            ],
            "selected_modalities": ["transcript", "visual"],
            "selected_provider_ids": ["yt_dlp.managed_subtitles", "ffmpeg.managed_frames_vision"],
            "transcript": {
                "schema_version": 1,
                "retrieved_at_ms": 1773263984722u64,
                "tool": "media__extract_transcript",
                "backend": "edge:media:yt_dlp_subtitles",
                "provider_id": "yt_dlp.managed_subtitles",
                "provider_version": "2026.03.03",
                "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "title": "Electromagnetism - Maxwell's Laws",
                "duration_seconds": 2909u64,
                "requested_language": "en",
                "transcript_language": "en",
                "transcript_source_kind": "manual",
                "segment_count": 310,
                "transcript_char_count": 21822,
                "transcript_hash": "sha256:transcript",
                "transcript_text": "Maxwell introduces the electric field. Gauss's law relates flux to charge. Faraday's law explains induction. Ampere-Maxwell law closes the system. The lecture ends by deriving electromagnetic waves."
            },
            "visual": {
                "schema_version": 1,
                "retrieved_at_ms": 1773264032396u64,
                "tool": "media__extract_visual_evidence",
                "backend": "edge:media:ffmpeg_frames_vision",
                "provider_id": "ffmpeg.managed_frames_vision",
                "provider_version": "2026.03.06",
                "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "title": "Electromagnetism - Maxwell's Laws",
                "duration_seconds": 2909u64,
                "frame_count": 2,
                "visual_char_count": 420,
                "visual_hash": "sha256:visual",
                "visual_summary": "Slides cover Maxwell's equations.",
                "frames": [
                    {
                        "timestamp_ms": 0u64,
                        "timestamp_label": "00:00",
                        "frame_hash": "frame-1",
                        "mime_type": "image/jpeg",
                        "width": 1280,
                        "height": 720,
                        "scene_summary": "Title slide introducing electromagnetism and Maxwell's laws.",
                        "visible_text": "Electromagnetism - Maxwell's Laws",
                        "transcript_excerpt": "The lecture opens by stating the four Maxwell equations."
                    },
                    {
                        "timestamp_ms": 120000u64,
                        "timestamp_label": "02:00",
                        "frame_hash": "frame-2",
                        "mime_type": "image/jpeg",
                        "width": 1280,
                        "height": 720,
                        "scene_summary": "Equation slide showing Faraday's law and Ampere-Maxwell law.",
                        "visible_text": "Faraday's law | Ampere-Maxwell law",
                        "transcript_excerpt": "These equations explain induction and displacement current."
                    }
                ]
            }
        })
        .to_string();

        let compact =
            compact_tool_history_entry_for_chat("media__extract_multimodal_evidence", &raw);

        assert!(compact.contains("selected_modalities=transcript,visual"));
        assert!(compact.contains("transcript_evidence[1]="));
        assert!(compact.contains("visual_evidence[1]="));
        assert!(!compact.contains("\"transcript_text\""));
        assert!(compact.chars().count() < TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT * 2);
    }

    #[test]
    fn compact_browser_snapshot_history_entry_preserves_late_actionable_targets() {
        let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<textbox id=\"inp_fiber\" name=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" /><combobox id=\"inp_awaiting_dispatch\" name=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_0\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_0\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_202\" name=\"T-202\" omitted=\"true\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_1\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_1\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" context=\"Unassigned / Awaiting Dispatch\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_2\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_2\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

        let compact = compact_tool_history_entry_for_chat("browser__snapshot", &snapshot);

        assert!(compact.starts_with("<root"), "{compact}");
        assert!(compact.contains("ticket-link-t-202"), "{compact}");
        assert!(compact.contains("ticket-link-t-204"), "{compact}");
        assert!(compact.contains("ticket-link-t-215"), "{compact}");
        assert!(
            compact.contains("context=Unassigned / Awaiting Dispatch"),
            "{compact}"
        );
        assert!(compact.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT + 1);
    }
}
