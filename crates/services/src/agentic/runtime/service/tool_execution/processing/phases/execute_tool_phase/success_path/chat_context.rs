use ioi_types::app::agentic::{
    MediaFrameEvidence, MediaMultimodalBundle, MediaTimelineOutlineBundle, MediaTranscriptBundle,
    MediaVisualEvidenceBundle,
};
use std::collections::HashSet;

pub(super) const TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT: usize = 3_200;
pub(super) const TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT: usize = 1_800;
pub(super) const TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT: usize = 520;
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

fn truncate_file_read_for_chat_context(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let markdown_context = markdown_context_for_file_read(text, 80, 6, 1_400);
    let compact = compact_ws_for_chat_context(text);
    let compact_len = compact.chars().count();
    if compact_len <= max_chars {
        if markdown_context.is_empty() || compact.contains("Markdown heading outline:") {
            return compact;
        }
        return fit_file_read_context_with_outline(&markdown_context, &compact, max_chars);
    }

    let compact = truncate_file_read_body_for_chat_context(&compact, max_chars);
    if markdown_context.is_empty() {
        return compact;
    }
    fit_file_read_context_with_outline(&markdown_context, &compact, max_chars)
}

fn truncate_file_read_body_for_chat_context(compact: &str, max_chars: usize) -> String {
    const OMITTED_MARKER: &str = " ... middle omitted ... ";
    if max_chars <= OMITTED_MARKER.chars().count() + 2 {
        return truncate_chars_for_chat_context(compact, max_chars);
    }

    let available = max_chars.saturating_sub(OMITTED_MARKER.chars().count());
    let head_len = available / 2;
    let tail_len = available.saturating_sub(head_len);
    let head = compact.chars().take(head_len).collect::<String>();
    let tail = compact
        .chars()
        .rev()
        .take(tail_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{}{}{}", head.trim_end(), OMITTED_MARKER, tail.trim_start())
}

fn markdown_heading_outline_for_file_read(text: &str, max_headings: usize) -> String {
    let headings = text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') {
                return None;
            }
            let level = trimmed.chars().take_while(|ch| *ch == '#').count();
            if level == 0
                || level > 4
                || !trimmed.chars().nth(level).is_some_and(char::is_whitespace)
            {
                return None;
            }
            Some(trimmed.to_string())
        })
        .take(max_headings)
        .collect::<Vec<_>>();

    if headings.is_empty() {
        String::new()
    } else {
        format!("Markdown heading outline:\n{}", headings.join("\n"))
    }
}

fn markdown_context_for_file_read(
    text: &str,
    max_headings: usize,
    late_section_limit: usize,
    late_section_chars: usize,
) -> String {
    let outline = markdown_heading_outline_for_file_read(text, max_headings);
    let late_sections =
        markdown_late_section_excerpts_for_file_read(text, late_section_limit, late_section_chars);

    match (outline.trim().is_empty(), late_sections.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => outline,
        (true, false) => late_sections,
        (false, false) => format!("{}\n\n{}", outline.trim(), late_sections.trim()),
    }
}

fn markdown_late_section_excerpts_for_file_read(
    text: &str,
    max_sections: usize,
    max_chars: usize,
) -> String {
    if max_sections == 0 || max_chars == 0 {
        return String::new();
    }

    let lines = text.lines().collect::<Vec<_>>();
    let heading_indices = lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') {
                return None;
            }
            let level = trimmed.chars().take_while(|ch| *ch == '#').count();
            if level == 0
                || level > 4
                || !trimmed.chars().nth(level).is_some_and(char::is_whitespace)
            {
                return None;
            }
            Some(idx)
        })
        .collect::<Vec<_>>();

    if heading_indices.is_empty() {
        return String::new();
    }

    let start_at = heading_indices.len().saturating_sub(max_sections);
    let selected_count = heading_indices.len().saturating_sub(start_at).max(1);
    let per_section_budget = (max_chars / selected_count).max(120);
    let mut rendered = String::from("Late markdown section excerpts:");
    for (slot, heading_idx) in heading_indices.iter().enumerate().skip(start_at) {
        let section_end = heading_indices
            .get(slot + 1)
            .copied()
            .unwrap_or(lines.len());
        let mut section = String::new();
        for line in &lines[*heading_idx..section_end] {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            section.push_str(trimmed);
            section.push('\n');
            if section.chars().count() >= per_section_budget {
                section = truncate_chars_for_chat_context(&section, per_section_budget);
                break;
            }
        }
        if section.trim().is_empty() {
            continue;
        }
        rendered.push('\n');
        rendered.push_str(section.trim());
        if rendered.chars().count() >= max_chars {
            return truncate_chars_for_chat_context(&rendered, max_chars);
        }
    }

    rendered.trim().to_string()
}

fn fit_file_read_context_with_outline(outline: &str, body: &str, max_chars: usize) -> String {
    let outline = outline.trim();
    if outline.is_empty() {
        return truncate_chars_for_chat_context(body, max_chars);
    }

    let separator = "\n\n";
    let outline_chars = outline.chars().count();
    let separator_chars = separator.chars().count();
    if outline_chars + separator_chars >= max_chars {
        return truncate_chars_for_chat_context(outline, max_chars);
    }

    let body_budget = max_chars
        .saturating_sub(outline_chars)
        .saturating_sub(separator_chars);
    let body = if body.chars().count() <= body_budget {
        body.trim().to_string()
    } else {
        truncate_file_read_body_for_chat_context(&compact_ws_for_chat_context(body), body_budget)
    };
    if body.trim().is_empty() {
        outline.to_string()
    } else {
        format!("{outline}{separator}{body}")
    }
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

pub(super) fn transcript_context_excerpts(text: &str) -> Vec<String> {
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
        "Tool Output (media__extract_evidence): title={} canonical_url={} duration_seconds={} selected_modalities={} selected_provider_ids={} provider_candidates={}",
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
    if normalized_name
        .as_deref()
        .is_some_and(browser_name_looks_like_calendar_header_for_chat)
    {
        score = score.saturating_add(16);
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

fn browser_name_looks_like_calendar_header_for_chat(name: &str) -> bool {
    let name = name.trim();
    let has_month = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ]
    .iter()
    .any(|month| name.contains(month));
    has_month
        && name
            .split_whitespace()
            .any(|part| part.len() == 4 && part.chars().all(|ch| ch.is_ascii_digit()))
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

pub(super) fn compact_tool_history_entry_for_chat(
    current_tool_name: &str,
    history_entry: &str,
) -> String {
    let trimmed = history_entry.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match current_tool_name {
        "media__extract_evidence" => serde_json::from_str::<MediaMultimodalBundle>(trimmed)
            .map(|bundle| summarize_media_multimodal_bundle_for_chat(&bundle))
            .unwrap_or_else(|_| {
                truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
            }),
        "media__extract_transcript" => serde_json::from_str::<MediaTranscriptBundle>(trimmed)
            .map(|bundle| summarize_media_transcript_bundle_for_chat(&bundle))
            .unwrap_or_else(|_| {
                truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
            }),
        "browser__inspect" => {
            if looks_like_browser_snapshot_history_entry(trimmed) {
                compact_browser_snapshot_history_entry(trimmed)
            } else {
                truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
            }
        }
        "browser__click" => compact_browser_click_history_entry(trimmed),
        "browser__click_at" => compact_browser_synthetic_click_history_entry(trimmed),
        "file__read" => {
            truncate_file_read_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT)
        }
        _ => truncate_chars_for_chat_context(trimmed, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT),
    }
}

pub(super) fn tool_history_message_content(current_tool_name: &str, compact_entry: &str) -> String {
    let compact_entry = compact_entry.trim();
    if compact_entry.is_empty() {
        return String::new();
    }

    let tool_name = current_tool_name.trim();
    if tool_name.is_empty() {
        return compact_entry.to_string();
    }

    let prefix = format!("Tool Output ({}):", tool_name);
    if compact_entry.starts_with(&prefix) {
        compact_entry.to_string()
    } else {
        format!("{} {}", prefix, compact_entry)
    }
}
