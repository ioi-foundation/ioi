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
const TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT: usize = 520;
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

fn browser_fragment_looks_like_instruction_context_for_chat(
    fragment: &str,
    tag_name: &str,
) -> bool {
    if !matches!(tag_name, "generic" | "group" | "presentation") {
        return false;
    }

    let dom_id = extract_browser_xml_attr_for_chat(fragment, "dom_id")
        .map(|value| decode_browser_xml_text_for_chat(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let selector = extract_browser_xml_attr_for_chat(fragment, "selector")
        .map(|value| decode_browser_xml_text_for_chat(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let name = extract_browser_xml_attr_for_chat(fragment, "name")
        .map(|value| decode_browser_xml_text_for_chat(&value).to_ascii_lowercase())
        .unwrap_or_default();

    let instruction_hint = [
        "query",
        "instruction",
        "prompt",
        "goal",
        "task",
        "directions",
    ]
    .iter()
    .any(|hint| dom_id.contains(hint) || selector.contains(hint));
    let wrapper_hint = matches!(dom_id.as_str(), "wrap" | "wrapper" | "container")
        || selector.contains("[id=\"wrap\"]")
        || selector.contains("[id=\"wrapper\"]");
    let imperative_name = ["find ", "click ", "select ", "choose ", "enter ", "type "]
        .iter()
        .any(|prefix| name.starts_with(prefix));

    instruction_hint || wrapper_hint || imperative_name
}

fn browser_fragment_priority_score_for_chat(fragment: &str, tag_name: &str) -> Option<u8> {
    if browser_fragment_looks_like_instruction_context_for_chat(fragment, tag_name) {
        return None;
    }

    let mut score = 0u8;
    let normalized_name = extract_browser_xml_attr_for_chat(fragment, "name")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let has_direct_locator = fragment.contains(" dom_id=\"")
        || fragment.contains(" selector=\"")
        || fragment.contains(" dom_clickable=\"true\"");
    let has_grounded_geometry = fragment.contains(" shape_kind=\"")
        && (fragment.contains(" center_x=\"") || fragment.contains(" line_x1=\""));

    if fragment.contains(" dom_id=\"") {
        score = score.saturating_add(8);
    }
    if fragment.contains(" selector=\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" dom_clickable=\"true\"") {
        score = score.saturating_add(6);
    }
    if fragment.contains(" shape_kind=\"") {
        score = score.saturating_add(5);
    }
    if fragment.contains(" center_x=\"") || fragment.contains(" line_x1=\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" geometry_role=\"vertex\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" line_angle_deg=\"") {
        score = score.saturating_add(1);
    }
    if has_grounded_geometry && !has_direct_locator {
        score = score.saturating_add(4);
    }
    if normalized_name
        .as_deref()
        .is_some_and(browser_name_looks_like_navigation_control_for_chat)
    {
        score = score.saturating_add(5);
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

fn browser_name_looks_like_navigation_control_for_chat(name: &str) -> bool {
    matches!(
        name.trim(),
        "<" | ">" | "<<" | ">>" | "prev" | "previous" | "previous month" | "next" | "next month"
    )
}

fn browser_context_looks_like_dense_numeric_noise_for_chat(context: &str) -> bool {
    let mut numeric_tokens = 0usize;
    let mut alphabetic_tokens = 0usize;
    let mut total_tokens = 0usize;

    for token in context.split_whitespace() {
        let normalized = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
        if normalized.is_empty() {
            continue;
        }
        total_tokens += 1;
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            numeric_tokens += 1;
        }
        if normalized.chars().any(|ch| ch.is_ascii_alphabetic()) {
            alphabetic_tokens += 1;
        }
    }

    total_tokens >= 8 && numeric_tokens >= 6 && alphabetic_tokens <= 2
}

fn summarized_browser_fragment_context_for_chat(
    name: Option<&str>,
    context: &str,
) -> Option<String> {
    let compact = compact_ws_for_chat_context(context);
    if compact.is_empty() {
        return None;
    }

    let short_numeric_name = name.is_some_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty()
            && trimmed.chars().count() <= 2
            && trimmed.chars().all(|ch| ch.is_ascii_digit())
    });
    if short_numeric_name
        && (compact.contains("<REDACTED:")
            || browser_context_looks_like_dense_numeric_noise_for_chat(&compact))
    {
        return None;
    }

    Some(truncate_chars_for_chat_context(&compact, 72))
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
    let class_name = extract_browser_xml_attr_for_chat(fragment, "class_name")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let context = extract_browser_xml_attr_for_chat(fragment, "context")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty())
        .and_then(|value| summarized_browser_fragment_context_for_chat(name.as_deref(), &value));
    let shape_kind = extract_browser_xml_attr_for_chat(fragment, "shape_kind")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let geometry_role = extract_browser_xml_attr_for_chat(fragment, "geometry_role")
        .map(|value| compact_ws_for_chat_context(&decode_browser_xml_text_for_chat(&value)))
        .filter(|value| !value.is_empty());
    let connected_lines = extract_browser_xml_attr_for_chat(fragment, "connected_lines");
    let center_x = extract_browser_xml_attr_for_chat(fragment, "center_x");
    let center_y = extract_browser_xml_attr_for_chat(fragment, "center_y");
    let radius = extract_browser_xml_attr_for_chat(fragment, "radius");
    let line_x1 = extract_browser_xml_attr_for_chat(fragment, "line_x1");
    let line_y1 = extract_browser_xml_attr_for_chat(fragment, "line_y1");
    let line_x2 = extract_browser_xml_attr_for_chat(fragment, "line_x2");
    let line_y2 = extract_browser_xml_attr_for_chat(fragment, "line_y2");
    let line_length = extract_browser_xml_attr_for_chat(fragment, "line_length");
    let line_angle_deg = extract_browser_xml_attr_for_chat(fragment, "line_angle_deg");

    let mut summary = format!("{id} tag={tag_name}");
    if let Some(name) = name {
        summary.push_str(&format!(" name={}", name));
    }
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={}", dom_id));
    }
    if let Some(selector) = selector {
        summary.push_str(&format!(" selector={}", selector));
    }
    if let Some(class_name) = class_name {
        summary.push_str(&format!(" class_name={}", class_name));
    }
    if let Some(context) = context {
        summary.push_str(&format!(" context={}", context));
    }
    if let Some(ref shape_kind) = shape_kind {
        summary.push_str(&format!(" shape_kind={shape_kind}"));
    }
    if let Some(geometry_role) = geometry_role {
        summary.push_str(&format!(" geometry_role={geometry_role}"));
    }
    if let Some(connected_lines) = connected_lines {
        summary.push_str(&format!(" connected_lines={connected_lines}"));
    }
    if shape_kind.as_deref() != Some("line") {
        if let (Some(center_x), Some(center_y)) = (center_x, center_y) {
            summary.push_str(&format!(" center={center_x},{center_y}"));
        }
    }
    if let Some(radius) = radius {
        summary.push_str(&format!(" radius={radius}"));
    }
    if let (Some(line_x1), Some(line_y1), Some(line_x2), Some(line_y2)) =
        (line_x1, line_y1, line_x2, line_y2)
    {
        summary.push_str(&format!(" line={line_x1},{line_y1}->{line_x2},{line_y2}"));
    }
    if let Some(line_length) = line_length {
        summary.push_str(&format!(" line_length={line_length}"));
    }
    if let Some(line_angle_deg) = line_angle_deg {
        summary.push_str(&format!(" line_angle={line_angle_deg}deg"));
    }
    if fragment.contains(" dom_clickable=\"true\"") {
        summary.push_str(" dom_clickable=true");
    }
    if fragment.contains(" omitted=\"true\"") {
        summary.push_str(" omitted");
    }

    Some((id, score, summary))
}

fn browser_snapshot_root_summary_for_chat(snapshot: &str) -> Option<String> {
    let trimmed = snapshot.trim();
    let start = trimmed.find("<root")?;
    let rest = &trimmed[start..];
    let end = rest.find('>')?;
    Some(compact_ws_for_chat_context(
        &decode_browser_xml_text_for_chat(&rest[..=end]),
    ))
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

    let priority_targets = extract_priority_browser_targets_for_chat(snapshot, 8);
    if priority_targets.is_empty() {
        return truncate_chars_for_chat_context(
            snapshot,
            TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT,
        );
    }

    let root_summary = browser_snapshot_root_summary_for_chat(snapshot)
        .unwrap_or_else(|| truncate_chars_for_chat_context(snapshot, 96));
    let suffix_prefix = " IMPORTANT TARGETS: ";
    let closing = " </root>";
    let suffix_budget = TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT
        .saturating_sub(
            root_summary.chars().count() + suffix_prefix.chars().count() + closing.chars().count(),
        )
        .max(64);
    let suffix = truncate_chars_for_chat_context(&priority_targets.join(" | "), suffix_budget);

    format!("{root_summary}{suffix_prefix}{suffix}{closing}")
}

fn compact_browser_click_history_entry(entry: &str) -> String {
    let compact = compact_ws_for_chat_context(entry.trim());
    if compact.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
        return compact;
    }

    let Some(verify_idx) = compact.find(" verify=") else {
        return truncate_chars_for_chat_context(
            &compact,
            TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
        );
    };
    let prefix = compact[..verify_idx].trim_end();
    let verify_raw = compact[verify_idx + " verify=".len()..].trim();
    let Ok(verify_value) = serde_json::from_str::<serde_json::Value>(verify_raw) else {
        return truncate_chars_for_chat_context(
            &compact,
            TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
        );
    };

    let mut verify_summary = serde_json::Map::new();
    for key in [
        "method",
        "center_point",
        "dispatch_elapsed_ms",
        "prompt_observation_source",
        "prompt_observation_elapsed_ms",
        "current_tree_elapsed_ms",
        "post_snapshot_elapsed_ms",
        "target_resolution_source",
        "verify_elapsed_ms",
        "settle_ms",
        "pre_url",
        "post_url",
    ] {
        if let Some(value) = verify_value.get(key) {
            verify_summary.insert(key.to_string(), value.clone());
        }
    }

    if let Some(postcondition) = verify_value
        .get("postcondition")
        .and_then(|value| value.as_object())
    {
        let mut postcondition_summary = serde_json::Map::new();
        for key in [
            "met",
            "target_disappeared",
            "editable_focus_transition",
            "tree_changed",
            "url_changed",
            "material_semantic_change",
            "semantic_change_delta",
        ] {
            if let Some(value) = postcondition.get(key) {
                postcondition_summary.insert(key.to_string(), value.clone());
            }
        }
        if !postcondition_summary.is_empty() {
            verify_summary.insert(
                "postcondition".to_string(),
                serde_json::Value::Object(postcondition_summary),
            );
        }
    }

    for (field_name, summary_keys) in [
        (
            "post_target",
            ["semantic_id", "dom_id", "selector", "tag_name"],
        ),
        (
            "focused_control",
            ["semantic_id", "dom_id", "selector", "tag_name"],
        ),
    ] {
        if let Some(target) = verify_value
            .get(field_name)
            .and_then(|value| value.as_object())
        {
            let mut target_summary = serde_json::Map::new();
            for key in summary_keys {
                if let Some(value) = target.get(key).filter(|value| !value.is_null()) {
                    target_summary.insert(key.to_string(), value.clone());
                }
            }
            if !target_summary.is_empty() {
                verify_summary.insert(
                    field_name.to_string(),
                    serde_json::Value::Object(target_summary),
                );
            }
        }
    }

    let summarized = format!(
        "{} verify={}",
        prefix,
        serde_json::Value::Object(verify_summary.clone())
    );
    if summarized.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
        return summarized;
    }

    let mut pruned_summary = verify_summary;
    let url_changed = pruned_summary
        .get("postcondition")
        .and_then(|value| value.as_object())
        .and_then(|postcondition| postcondition.get("url_changed"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if !url_changed {
        pruned_summary.remove("pre_url");
        pruned_summary.remove("post_url");
    }

    let summarized = format!(
        "{} verify={}",
        prefix,
        serde_json::Value::Object(pruned_summary.clone())
    );
    if summarized.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
        return summarized;
    }

    for key in ["center_point", "focused_control"] {
        pruned_summary.remove(key);
        let candidate = format!(
            "{} verify={}",
            prefix,
            serde_json::Value::Object(pruned_summary.clone())
        );
        if candidate.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
            return candidate;
        }
    }

    if pruned_summary
        .get("postcondition")
        .and_then(|value| value.as_object())
        .is_some()
    {
        for key in [
            "editable_focus_transition",
            "target_disappeared",
            "url_changed",
        ] {
            if let Some(postcondition) = pruned_summary
                .get_mut("postcondition")
                .and_then(|value| value.as_object_mut())
            {
                postcondition.remove(key);
            }
            let candidate = format!(
                "{} verify={}",
                prefix,
                serde_json::Value::Object(pruned_summary.clone())
            );
            if candidate.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
                return candidate;
            }
        }
    }

    if pruned_summary
        .get("post_target")
        .and_then(|value| value.as_object())
        .is_some()
    {
        for key in ["selector", "dom_id", "tag_name"] {
            if let Some(post_target) = pruned_summary
                .get_mut("post_target")
                .and_then(|value| value.as_object_mut())
            {
                post_target.remove(key);
            }
            let candidate = format!(
                "{} verify={}",
                prefix,
                serde_json::Value::Object(pruned_summary.clone())
            );
            if candidate.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT {
                return candidate;
            }
        }
    }

    truncate_chars_for_chat_context(
        &format!(
            "{} verify={}",
            prefix,
            serde_json::Value::Object(pruned_summary)
        ),
        TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
    )
}

fn compact_browser_synthetic_click_history_entry(entry: &str) -> String {
    let trimmed = entry.trim();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return truncate_chars_for_chat_context(
            trimmed,
            TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
        );
    };

    let Some(click) = value
        .get("synthetic_click")
        .and_then(|value| value.as_object())
    else {
        return truncate_chars_for_chat_context(
            trimmed,
            TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
        );
    };

    let x = click.get("x").cloned().unwrap_or(serde_json::Value::Null);
    let y = click.get("y").cloned().unwrap_or(serde_json::Value::Null);
    let summary_prefix = format!("Synthetic click at ({x}, {y})");

    let compact_target_json = |target: &serde_json::Value,
                               include_locator: bool,
                               include_center_point: bool|
     -> Option<serde_json::Value> {
        let object = target.as_object()?;
        let mut compact = serde_json::Map::new();
        for key in ["semantic_id", "tag_name"] {
            if let Some(field_value) = object.get(key) {
                compact.insert(key.to_string(), field_value.clone());
            }
        }
        if include_locator {
            for key in ["dom_id", "selector"] {
                if let Some(field_value) = object.get(key) {
                    compact.insert(key.to_string(), field_value.clone());
                }
            }
        }
        if include_center_point {
            if let Some(field_value) = object.get("center_point") {
                compact.insert("center_point".to_string(), field_value.clone());
            }
        }
        (!compact.is_empty()).then_some(serde_json::Value::Object(compact))
    };

    let postcondition_summary = value
        .get("postcondition")
        .and_then(|value| value.as_object())
        .map(|postcondition| {
            let mut postcondition_summary = serde_json::Map::new();
            for key in ["met", "tree_changed", "url_changed"] {
                if let Some(field_value) = postcondition.get(key) {
                    postcondition_summary.insert(key.to_string(), field_value.clone());
                }
            }
            postcondition_summary
        })
        .filter(|summary| !summary.is_empty());

    if let Some(postcondition_summary) = postcondition_summary {
        let build_summary = |include_pre_target: bool,
                             include_post_target: bool,
                             include_locator: bool,
                             include_center_point: bool|
         -> Option<String> {
            let mut verify_summary = serde_json::Map::new();
            verify_summary.insert(
                "postcondition".to_string(),
                serde_json::Value::Object(postcondition_summary.clone()),
            );

            if include_pre_target {
                if let Some(pre_target) = value.get("pre_target").and_then(|target| {
                    compact_target_json(target, include_locator, include_center_point)
                }) {
                    verify_summary.insert("pre_target".to_string(), pre_target);
                }
            }
            if include_post_target {
                if let Some(post_target) = value.get("post_target").and_then(|target| {
                    compact_target_json(target, include_locator, include_center_point)
                }) {
                    verify_summary.insert("post_target".to_string(), post_target);
                }
            }

            let candidate = format!(
                "{summary_prefix} verify={}",
                serde_json::Value::Object(verify_summary)
            );
            (candidate.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT)
                .then_some(candidate)
        };

        for candidate in [
            build_summary(true, true, true, true),
            build_summary(true, true, false, true),
            build_summary(true, true, false, false),
            build_summary(false, true, false, true),
            build_summary(false, true, false, false),
            build_summary(true, false, false, true),
            build_summary(true, false, false, false),
            build_summary(false, false, false, false),
        ] {
            if let Some(summary) = candidate {
                return summary;
            }
        }
    }

    truncate_chars_for_chat_context(&summary_prefix, TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT)
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
        "browser__click_element" => compact_browser_click_history_entry(trimmed),
        "browser__synthetic_click" => compact_browser_synthetic_click_history_entry(trimmed),
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

    #[test]
    fn compact_browser_snapshot_history_entry_prioritizes_clickable_controls_over_instruction_copy()
    {
        let snapshot = format!(
            concat!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "<generic id=\"grp_find_the_email_by_lonna\" name=\"Find the email by Lonna and click the trash icon.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
                "<generic id=\"grp_lonna\" name=\"Lonna\" tag_name=\"span\" class_name=\"bold\" rect=\"82,3,30,11\" />",
                "{}",
                "<generic id=\"grp_email_row\" name=\"Lonna Cras. A dictumst. Ali..\" tag_name=\"div\" class_name=\"email-thread\" dom_clickable=\"true\" rect=\"2,112,140,39\" />",
                "<generic id=\"grp_trash\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,119,12,12\" />",
                "</root>"
            ),
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

        let compact = compact_tool_history_entry_for_chat("browser__snapshot", &snapshot);

        assert!(compact.starts_with("<root"), "{compact}");
        assert!(compact.contains("grp_email_row tag=generic"), "{compact}");
        assert!(compact.contains("grp_trash tag=generic"), "{compact}");
        assert!(compact.contains("dom_clickable=true"), "{compact}");
        assert!(
            !compact.contains("grp_find_the_email_by_lonna tag=generic"),
            "{compact}"
        );
        assert!(
            !compact.contains("grp_lonna tag=generic name=Lonna"),
            "{compact}"
        );
    }

    #[test]
    fn compact_browser_snapshot_history_entry_preserves_svg_geometry_targets() {
        let snapshot = format!(
            concat!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "{}",
                "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
                "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 29,56 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"blue\" geometry_role=\"vertex\" connected_lines=\"2\" radius=\"4\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
                "<generic id=\"grp_small_black_circle\" name=\"small black circle at 69,73 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" radius=\"4\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
                "<generic id=\"grp_small_black_circle_2\" name=\"small black circle at 89,29 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" radius=\"4\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
                "<generic id=\"grp_large_line_from_2956_to_6973\" name=\"large line from 29,56 to 69,73\" tag_name=\"line\" shape_kind=\"line\" shape_size=\"large\" line_x1=\"29\" line_y1=\"56\" line_x2=\"69\" line_y2=\"73\" line_length=\"43\" line_angle_deg=\"23\" center_x=\"51\" center_y=\"116\" rect=\"31,108,40,17\" />",
                "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
                "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" tag_name=\"canvas\" rect=\"165,0,160,210\" />",
                "<generic id=\"grp_last_reward_last_10_average_ti\" name=\"Last reward: - Last 10 average: - Time left: 9 / 10sec\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" tag_name=\"div\" rect=\"165,0,160,210\" />",
                "<generic id=\"grp_minus\" name=\"-\" dom_id=\"reward-last\" selector=\"[id=&quot;reward-last&quot;]\" tag_name=\"span\" rect=\"251,10,5,16\" />",
                "<generic id=\"grp_minus_2\" name=\"-\" dom_id=\"reward-avg\" selector=\"[id=&quot;reward-avg&quot;]\" tag_name=\"span\" rect=\"278,36,5,16\" />",
                "<generic id=\"grp_9_divide_10sec\" name=\"9 / 10sec\" dom_id=\"timer-countdown\" selector=\"[id=&quot;timer-countdown&quot;]\" tag_name=\"span\" rect=\"231,62,58,16\" />",
                "<generic id=\"grp_0\" name=\"0\" dom_id=\"episode-id\" selector=\"[id=&quot;episode-id&quot;]\" tag_name=\"span\" rect=\"270,88,8,16\" />",
                "</root>"
            ),
            "<generic id=\"grp_noise\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
        );

        let compact = compact_tool_history_entry_for_chat("browser__snapshot", &snapshot);

        assert!(
            compact.contains("grp_small_blue_circle tag=generic"),
            "{compact}"
        );
        assert!(compact.contains("shape_kind=circle"), "{compact}");
        assert!(compact.contains("geometry_role=vertex"), "{compact}");
        assert!(compact.contains("connected_lines=2"), "{compact}");
        assert!(compact.contains("center=31,108"), "{compact}");
        assert!(compact.contains("radius=4"), "{compact}");
        assert!(
            compact.contains("grp_large_line_from_2956_to_6973 tag=generic"),
            "{compact}"
        );
        assert!(compact.contains("line=29,56->69,73"), "{compact}");
        assert!(compact.contains("line_length=43"), "{compact}");
        assert!(compact.contains("line_angle=23deg"), "{compact}");
        assert!(
            !compact.contains("grp_large_line_from_2956_to_6973 tag=generic name=large line from 29,56 to 69,73 center="),
            "{compact}"
        );
        assert!(compact.contains("btn_submit tag=button"), "{compact}");
    }

    #[test]
    fn compact_browser_snapshot_history_entry_surfaces_calendar_navigation_state() {
        let snapshot = format!(
            concat!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "{}",
                "<textbox id=\"inp_datepicker\" name=\"datepicker\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" class_name=\"hasDatepicker\" dom_clickable=\"true\" rect=\"29,52,128,21\" />",
                "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"27,84,95,31\" />",
                "<link id=\"lnk_prev\" name=\"Prev\" omitted=\"true\" tag_name=\"a\" rect=\"38,86,14,14\" />",
                "<generic id=\"grp_december_2016\" name=\"December 2016\" tag_name=\"div\" rect=\"54,86,48,14\" />",
                "<link id=\"lnk_1\" name=\"1\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"40,108,8,12\" />",
                "<link id=\"lnk_2\" name=\"2\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"52,108,8,12\" />",
                "<link id=\"lnk_3\" name=\"3\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"64,108,8,12\" />",
                "<link id=\"lnk_4\" name=\"4\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"76,108,8,12\" />",
                "<link id=\"lnk_5\" name=\"5\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"88,108,8,12\" />",
                "<link id=\"lnk_6\" name=\"6\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"100,108,8,12\" />",
                "</root>"
            ),
            "<generic id=\"grp_noise\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
        );

        let compact = compact_tool_history_entry_for_chat("browser__snapshot", &snapshot);

        assert!(compact.contains("lnk_prev tag=link name=Prev"), "{compact}");
        assert!(
            compact.contains("grp_december_2016 tag=generic name=December 2016"),
            "{compact}"
        );
        assert!(!compact.contains("<REDACTED:card_pan>"), "{compact}");
        assert!(!compact.contains("context=1 2 3 4 5 6"), "{compact}");
    }

    #[test]
    fn compact_browser_click_history_entry_summarizes_verbose_verify_payload() {
        let raw = concat!(
            "Clicked element 'grp_4' via geometry fallback. verify=",
            "{\"center_point\":[52.0,69.0],\"dispatch_elapsed_ms\":18234,",
            "\"dispatch_succeeded\":true,",
            "\"prompt_observation_source\":\"recent_prompt_observation_snapshot\",",
            "\"prompt_observation_elapsed_ms\":17802,",
            "\"focused_control\":null,\"method\":\"geometry_center\",",
            "\"post_target\":{\"semantic_id\":\"grp_5\",\"dom_id\":null,",
            "\"selector\":\"#area_svg > rect:nth-of-type(1)\",\"tag_name\":\"rect\",",
            "\"backend_dom_node_id\":null},",
            "\"post_snapshot_elapsed_ms\":14,",
            "\"post_url\":\"file:///tmp/ioi-miniwob-bridge/demo/miniwob/ascending-numbers.1.html\",",
            "\"postcondition\":{\"editable_focus_transition\":false,",
            "\"material_semantic_change\":true,\"met\":true,",
            "\"semantic_change_delta\":6,\"target_disappeared\":false,",
            "\"tree_changed\":true,\"url_changed\":false},",
            "\"pre_target\":{\"semantic_id\":\"grp_4\",\"selector\":\"#area_svg > rect:nth-of-type(1)\",",
            "\"tag_name\":\"rect\",\"center_point\":[52.0,69.0]},",
            "\"pre_url\":\"file:///tmp/ioi-miniwob-bridge/demo/miniwob/ascending-numbers.1.html\",",
            "\"settle_ms\":360,\"target_resolution_source\":\"prompt_observation_tree\",",
            "\"verify_elapsed_ms\":379}"
        );

        let compact = compact_tool_history_entry_for_chat("browser__click_element", raw);

        assert!(
            compact.contains("Clicked element 'grp_4' via geometry fallback."),
            "{compact}"
        );
        assert!(
            compact.contains("\"method\":\"geometry_center\""),
            "{compact}"
        );
        assert!(
            compact.contains("\"dispatch_elapsed_ms\":18234"),
            "{compact}"
        );
        assert!(
            compact
                .contains("\"prompt_observation_source\":\"recent_prompt_observation_snapshot\""),
            "{compact}"
        );
        assert!(
            compact.contains("\"target_resolution_source\":\"prompt_observation_tree\""),
            "{compact}"
        );
        assert!(compact.contains("\"semantic_change_delta\":6"), "{compact}");
        assert!(compact.contains("\"post_target\""), "{compact}");
        assert!(!compact.contains("\"pre_target\""), "{compact}");
        assert!(!compact.contains("\"dispatch_succeeded\""), "{compact}");
        assert!(compact.chars().count() <= super::TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT + 1);
    }

    #[test]
    fn compact_browser_synthetic_click_history_entry_summarizes_postcondition() {
        let raw = r##"{"synthetic_click":{"x":60,"y":107},"pre_target":{"semantic_id":"grp_vertex","selector":"#blue-circle","tag_name":"circle","center_point":[31.0,108.0],"focused":false},"post_target":{"semantic_id":"grp_blue_circle","selector":"#blue-circle","tag_name":"circle","center_point":[53.0,118.0],"focused":false},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"##;

        let compact = compact_tool_history_entry_for_chat("browser__synthetic_click", raw);

        assert!(
            compact.contains("Synthetic click at (60, 107)"),
            "{compact}"
        );
        assert!(compact.contains(r#""met":true"#), "{compact}");
        assert!(compact.contains(r#""tree_changed":true"#), "{compact}");
        assert!(compact.contains(r#""pre_target":{"#), "{compact}");
        assert!(
            compact.contains(r#""semantic_id":"grp_vertex""#),
            "{compact}"
        );
        assert!(compact.contains(r#""post_target":{"#), "{compact}");
        assert!(
            compact.contains(r#""semantic_id":"grp_blue_circle""#),
            "{compact}"
        );
    }

    #[test]
    fn compact_browser_synthetic_click_history_entry_keeps_verify_json_parseable_under_budget() {
        let raw = r##"{"synthetic_click":{"x":51.0,"y":103.0},"pre_target":{"semantic_id":"grp_large_line_from_31108_to_9181","selector":"#svg-grid > line:nth-of-type(2)","tag_name":"line","center_point":[61.0,94.5],"focused":false,"editable":false,"checked":null,"selected":null},"post_target":{"semantic_id":"grp_blue_circle","dom_id":"blue-circle","selector":"#blue-circle","tag_name":"circle","center_point":[53.5,105.5],"focused":false,"editable":false,"checked":null,"selected":null},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"##;

        let compact = compact_tool_history_entry_for_chat("browser__synthetic_click", raw);
        let verify_json = compact
            .split_once(" verify=")
            .map(|(_, verify)| verify)
            .expect("synthetic click compact summary should keep verify payload");
        let parsed = serde_json::from_str::<serde_json::Value>(verify_json)
            .expect("verify payload should remain valid JSON");

        assert!(
            compact.chars().count() <= super::TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
            "{compact}"
        );
        assert_eq!(
            parsed["postcondition"]["met"],
            serde_json::Value::Bool(true),
            "{compact}"
        );
        assert_eq!(
            parsed["post_target"]["semantic_id"],
            serde_json::Value::String("grp_blue_circle".to_string()),
            "{compact}"
        );
    }
}
