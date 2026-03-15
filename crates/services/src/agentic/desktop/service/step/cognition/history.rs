use crate::agentic::desktop::service::actions::safe_truncate;
use crate::agentic::desktop::types::{CommandExecution, MAX_PROMPT_HISTORY};
use ioi_types::app::agentic::ChatMessage;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};

const BROWSER_OBSERVATION_CONTEXT_MAX_CHARS: usize = 1_800;
const BROWSER_SNAPSHOT_TOOL_PREFIX: &str = "Tool Output (browser__snapshot):";
const PENDING_BROWSER_STATE_MAX_CHARS: usize = 320;
const SUCCESS_SIGNAL_MAX_CHARS: usize = 280;

fn top_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowUp"
    } else {
        "Control+Home"
    }
}

fn top_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowUp","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"Home","modifiers":["Control"]}"#
    }
}

fn bottom_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowDown"
    } else {
        "Control+End"
    }
}

fn bottom_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowDown","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"End","modifiers":["Control"]}"#
    }
}

fn compact_ws_for_prompt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn looks_like_browser_snapshot_payload(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root") && trimmed.contains("id=\"") && trimmed.contains("rect=\"")
}

fn browser_snapshot_payload(message: &ChatMessage) -> Option<&str> {
    if message.role != "tool" {
        return None;
    }

    let trimmed = message.content.trim();
    let payload = trimmed
        .strip_prefix(BROWSER_SNAPSHOT_TOOL_PREFIX)
        .unwrap_or(trimmed)
        .trim();
    looks_like_browser_snapshot_payload(payload).then_some(payload)
}

fn decode_browser_xml_text(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn extract_browser_xml_attr(fragment: &str, attr: &str) -> Option<String> {
    let marker = format!(r#"{attr}=""#);
    let start = fragment.find(&marker)? + marker.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_compact_jsonish_string_field(text: &str, key: &str) -> Option<String> {
    let marker = format!("\"{}\":\"", key);
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    let mut value = String::new();
    let mut escaped = false;

    for ch in rest.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '"' => return Some(value),
            _ => value.push(ch),
        }
    }

    None
}

fn extract_scoped_compact_jsonish_string_field(
    text: &str,
    scope_marker: &str,
    key: &str,
) -> Option<String> {
    let scope_start = text.find(scope_marker)? + scope_marker.len();
    extract_compact_jsonish_string_field(&text[scope_start..], key)
}

fn extract_compact_jsonish_number_field(text: &str, key: &str) -> Option<f64> {
    let marker = format!("\"{}\":", key);
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    let token = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-'))
        .collect::<String>();
    (!token.is_empty())
        .then(|| token.parse::<f64>().ok())
        .flatten()
}

fn format_prompt_number(value: f64) -> String {
    if value.fract() == 0.0 {
        return format!("{}", value as i64);
    }

    format!("{value}")
}

fn focused_home_should_jump_to_top_edge(compact: &str) -> Option<String> {
    let scroll_top = extract_compact_jsonish_number_field(compact, "scroll_top")?;
    if scroll_top <= 0.0 {
        return None;
    }

    let client_height = extract_compact_jsonish_number_field(compact, "client_height")?;
    (scroll_top >= client_height).then(|| format_prompt_number(scroll_top))
}

fn extract_json_object_fragment(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (start < end).then_some(&text[start..=end])
}

fn parse_json_value_from_message(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    serde_json::from_str::<Value>(trimmed)
        .ok()
        .or_else(|| {
            extract_json_object_fragment(trimmed)
                .and_then(|fragment| serde_json::from_str::<Value>(fragment).ok())
        })
        .or_else(|| {
            extract_json_object_fragment(trimmed).and_then(|fragment| {
                let unescaped = fragment.replace("\\\"", "\"");
                serde_json::from_str::<Value>(&unescaped).ok()
            })
        })
}

fn extract_assistive_browser_hints(snapshot: &str) -> Vec<String> {
    let mut hints = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.contains("assistive_hint=\"true\"") {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name") else {
            continue;
        };
        let name = compact_ws_for_prompt(&decode_browser_xml_text(&name));
        if name.is_empty() || hints.iter().any(|existing| existing == &name) {
            continue;
        }
        hints.push(name);
        if hints.len() >= 3 {
            break;
        }
    }

    hints
}

fn browser_fragment_scroll_target_summary(fragment: &str) -> Option<String> {
    if !fragment.contains(" scroll_top=\"") || !fragment.contains(" client_height=\"") {
        return None;
    }

    if !(fragment.contains(" can_scroll_up=\"true\"")
        || fragment.contains(" can_scroll_down=\"true\""))
    {
        return None;
    }

    let tag_name = browser_fragment_tag_name(fragment)?;
    let semantic_id = extract_browser_xml_attr(fragment, "id")?;
    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());

    let mut summary = format!("{semantic_id} tag={tag_name}");
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={dom_id}"));
    }

    Some(summary)
}

fn extract_scroll_target_focus_hint(snapshot: &str) -> Option<String> {
    let mut candidate = None;

    for fragment in snapshot.split('<') {
        let Some(summary) = browser_fragment_scroll_target_summary(fragment) else {
            continue;
        };

        if fragment.contains(" focused=\"true\"") {
            return None;
        }

        if candidate.replace(summary).is_some() {
            return None;
        }
    }

    let summary = candidate?;
    Some(format!(
        "Visible scroll target `{summary}` is already on the page. If the goal requires interacting with that control, use control-local actions there; for scroll-specific keys like `Home` or `End`, focus that control instead of sending page-level edge keys."
    ))
}

fn browser_fragment_tag_name(fragment: &str) -> Option<&str> {
    let trimmed = fragment.trim_start();
    if trimmed.is_empty() || trimmed.starts_with("!--") || trimmed.starts_with('/') {
        return None;
    }

    let end = trimmed
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

fn browser_fragment_looks_like_instruction_context(fragment: &str, tag_name: &str) -> bool {
    if !matches!(tag_name, "generic" | "group" | "presentation") {
        return false;
    }

    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let selector = extract_browser_xml_attr(fragment, "selector")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let name = extract_browser_xml_attr(fragment, "name")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
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

fn browser_fragment_priority_score(fragment: &str, tag_name: &str) -> Option<u8> {
    if browser_fragment_looks_like_instruction_context(fragment, tag_name) {
        return None;
    }

    let mut score = 0u8;

    if fragment.contains(" dom_id=\"") {
        score = score.saturating_add(8);
    }
    if fragment.contains(" selector=\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" dom_clickable=\"true\"") {
        score = score.saturating_add(6);
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

fn browser_fragment_priority_summary(fragment: &str) -> Option<(String, u8, String)> {
    let id = extract_browser_xml_attr(fragment, "id")?;
    let tag_name = browser_fragment_tag_name(fragment)?;
    let score = browser_fragment_priority_score(fragment, tag_name)?;

    let name = extract_browser_xml_attr(fragment, "name")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let selector = extract_browser_xml_attr(fragment, "selector")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let class_name = extract_browser_xml_attr(fragment, "class_name")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let context = extract_browser_xml_attr(fragment, "context")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());

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
    if fragment.contains(" dom_clickable=\"true\"") {
        summary.push_str(" dom_clickable=true");
    }
    if fragment.contains(" omitted=\"true\"") {
        summary.push_str(" omitted");
    }

    Some((id, score, summary))
}

fn compact_priority_target_looks_like_instruction_context(summary: &str) -> bool {
    let lower = summary.to_ascii_lowercase();
    lower.contains(" dom_id=query")
        || lower.contains(" selector=[id=\"query\"]")
        || lower.contains(" dom_id=instruction")
        || lower.contains(" dom_id=prompt")
        || lower.contains(" dom_id=goal")
        || lower.contains(" dom_id=task")
        || lower.contains(" dom_id=wrap")
        || lower.contains(" selector=[id=\"wrap\"]")
        || lower.contains(" name=find ")
        || lower.contains(" name=click ")
        || lower.contains(" name=select ")
        || lower.contains(" name=choose ")
        || lower.contains(" name=enter ")
        || lower.contains(" name=type ")
}

fn compact_priority_target_score(summary: &str) -> Option<u8> {
    if compact_priority_target_looks_like_instruction_context(summary) {
        return None;
    }

    let tag_name = priority_target_tag(summary)?;
    let mut score = 0u8;

    if summary.contains(" dom_id=") {
        score = score.saturating_add(8);
    }
    if summary.contains(" selector=") {
        score = score.saturating_add(2);
    }
    if summary.contains(" dom_clickable=true") {
        score = score.saturating_add(6);
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
    if summary.contains(" focused=true")
        || summary.contains(" checked=true")
        || summary.contains(" selected=true")
    {
        score = score.saturating_add(4);
    }
    if summary.contains(" assistive_hint=") {
        score = score.saturating_add(2);
    }
    if summary.contains(" omitted") {
        score = score.saturating_add(1);
    }

    (score > 0).then_some(score)
}

fn extract_compact_priority_browser_targets(snapshot: &str) -> Vec<(String, u8, String)> {
    let Some(start) = snapshot.find("IMPORTANT TARGETS:") else {
        return Vec::new();
    };
    let mut summary_block = &snapshot[start + "IMPORTANT TARGETS:".len()..];
    if let Some(end) = summary_block.find("</root>") {
        summary_block = &summary_block[..end];
    }

    summary_block
        .split('|')
        .filter_map(|entry| {
            let summary = compact_ws_for_prompt(&decode_browser_xml_text(entry.trim()));
            let semantic_id = priority_target_semantic_id(&summary)?.to_string();
            let score = compact_priority_target_score(&summary)?;
            Some((semantic_id, score, summary))
        })
        .collect()
}

fn extract_priority_browser_targets(snapshot: &str, max_targets: usize) -> Vec<String> {
    let mut seen_ids = HashSet::new();
    let mut targets = Vec::new();
    let mut order = 0usize;

    for fragment in snapshot.split('<') {
        let Some((id, score, summary)) = browser_fragment_priority_summary(fragment) else {
            continue;
        };
        if !seen_ids.insert(id) {
            continue;
        }
        targets.push((score, order, summary));
        order += 1;
    }

    for (id, score, summary) in extract_compact_priority_browser_targets(snapshot) {
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

fn browser_snapshot_root_summary(snapshot: &str) -> Option<String> {
    let trimmed = snapshot.trim();
    let start = trimmed.find("<root")?;
    let rest = &trimmed[start..];
    let end = rest.find('>')?;
    Some(compact_ws_for_prompt(&decode_browser_xml_text(
        &rest[..=end],
    )))
}

fn compact_browser_observation(snapshot: &str) -> String {
    let compact = compact_ws_for_prompt(snapshot.trim());
    if compact.chars().count() <= BROWSER_OBSERVATION_CONTEXT_MAX_CHARS {
        return compact;
    }

    let priority_targets = extract_priority_browser_targets(snapshot, 6);
    if priority_targets.is_empty() {
        return safe_truncate(&compact, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    }

    let root_summary =
        browser_snapshot_root_summary(snapshot).unwrap_or_else(|| safe_truncate(&compact, 96));
    let suffix_prefix = " IMPORTANT TARGETS: ";
    let closing = " </root>";
    let suffix_budget = BROWSER_OBSERVATION_CONTEXT_MAX_CHARS
        .saturating_sub(
            root_summary.chars().count() + suffix_prefix.chars().count() + closing.chars().count(),
        )
        .max(64);
    let suffix = safe_truncate(&priority_targets.join(" | "), suffix_budget);

    format!("{root_summary}{suffix_prefix}{suffix}{closing}")
}

fn snapshot_lower_text(snapshot: &str) -> String {
    compact_ws_for_prompt(&decode_browser_xml_text(snapshot)).to_ascii_lowercase()
}

fn snapshot_has_negative_selection_instruction(snapshot: &str) -> bool {
    let lower = snapshot_lower_text(snapshot);
    [
        "select nothing",
        "select none",
        "choose nothing",
        "choose none",
        "check nothing",
        "check none",
        "leave unchecked",
        "leave unselected",
        "keep unchecked",
        "keep unselected",
        "select no items",
        "select no options",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

fn snapshot_has_selectable_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("<checkbox ") || lower.contains("<radio ") || lower.contains("<option ")
}

fn snapshot_has_selected_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("checked=\"true\"") || lower.contains("selected=\"true\"")
}

fn browser_snapshot_pending_signal(snapshot: &str) -> Option<String> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && snapshot_has_selected_controls(snapshot)
    {
        return Some("The page-visible instruction requires no selections, but current browser state already shows checked or selected controls. Do not submit yet. Clear those selections so the relevant controls return to unchecked or unselected, then continue with the next required control.".to_string());
    }

    if let Some(summary) = extract_scroll_target_focus_hint(snapshot) {
        return Some(format!(
            "{} If you need control-local scrolling, focus that control with `browser__click_element` or `browser__click` before sending `Home` or `End`; otherwise continue with the next required visible control.",
            summary
        ));
    }

    None
}

fn browser_snapshot_success_signal(snapshot: &str) -> Option<&'static str> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && !snapshot_has_selected_controls(snapshot)
    {
        return Some(
            "The page-visible instruction already requires no selections, and current browser state shows no checked or selected controls. Do not click any checkbox, radio, or option. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.",
        );
    }

    None
}

fn extract_item_like_ids(text: &str) -> Vec<String> {
    let chars = text.chars().collect::<Vec<_>>();
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let mut idx = 0usize;

    while idx < chars.len() {
        if !chars[idx].is_ascii_alphabetic() {
            idx += 1;
            continue;
        }

        let start = idx;
        while idx < chars.len() && chars[idx].is_ascii_alphabetic() {
            idx += 1;
        }
        if idx >= chars.len() || chars[idx] != '-' {
            continue;
        }
        idx += 1;
        let digits_start = idx;
        while idx < chars.len() && chars[idx].is_ascii_digit() {
            idx += 1;
        }
        if digits_start == idx {
            continue;
        }

        let token = chars[start..idx]
            .iter()
            .collect::<String>()
            .to_ascii_uppercase();
        if seen.insert(token.clone()) {
            ids.push(token);
        }
    }

    ids
}

fn first_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().next()
}

fn last_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().last()
}

fn history_item_like_id_from_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    if let Some(ticket_idx) = lower.find("/tickets/") {
        let rest = &url[ticket_idx + "/tickets/".len()..];
        let candidate = rest.split('/').next().unwrap_or_default();
        if let Some(item_id) = first_item_like_id(candidate) {
            return Some(item_id);
        }
    }

    last_item_like_id(url)
}

fn extract_first_quoted_value(text: &str) -> Option<String> {
    let start = text.find('"')? + 1;
    let end = text[start..].find('"')? + start;
    let value = compact_ws_for_prompt(&text[start..end]);
    (!value.is_empty()).then_some(value)
}

fn trim_goal_target_value(text: &str) -> Option<String> {
    let compact = compact_ws_for_prompt(text);
    let value = compact.trim().trim_matches(|ch: char| {
        matches!(
            ch,
            '.' | ',' | ';' | ':' | '"' | '\'' | '`' | '(' | ')' | '[' | ']'
        )
    });
    if value.is_empty() {
        return None;
    }

    let normalized = normalized_exact_target_text(value);
    if matches!(
        normalized.as_str(),
        "nothing" | "none" | "no items" | "no options"
    ) {
        return None;
    }

    Some(value.to_string())
}

fn extract_select_submit_target(text: &str) -> Option<String> {
    const PREFIXES: &[&str] = &["select ", "choose "];
    const SUFFIXES: &[&str] = &[
        " and click submit",
        " then click submit",
        " and submit",
        " then submit",
    ];

    let lower = text.to_ascii_lowercase();
    for prefix in PREFIXES {
        let Some(start) = lower.find(prefix) else {
            continue;
        };
        let value_start = start + prefix.len();
        let original_rest = &text[value_start..];
        let lower_rest = &lower[value_start..];

        for suffix in SUFFIXES {
            let Some(end) = lower_rest.find(suffix) else {
                continue;
            };
            if let Some(value) = trim_goal_target_value(&original_rest[..end]) {
                return Some(value);
            }
        }
    }

    None
}

fn normalized_exact_target_text(text: &str) -> String {
    compact_ws_for_prompt(text)
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
                .to_ascii_lowercase()
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RankedResultRequest {
    rank: usize,
    ordinal_text: String,
}

fn parse_ordinal_token(token: &str) -> Option<usize> {
    let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
    let lower = trimmed.to_ascii_lowercase();
    let digits_len = lower.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }

    let (digits, suffix) = lower.split_at(digits_len);
    if !matches!(suffix, "st" | "nd" | "rd" | "th") {
        return None;
    }

    digits.parse::<usize>().ok().filter(|value| *value > 0)
}

fn recent_requested_result_rank(history: &[ChatMessage]) -> Option<RankedResultRequest> {
    for message in history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
    {
        let tokens = message.content.split_whitespace().collect::<Vec<_>>();
        for (idx, token) in tokens.iter().enumerate() {
            let ordinal_text = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
            let Some(rank) = parse_ordinal_token(ordinal_text) else {
                continue;
            };
            let mentions_result = tokens
                .iter()
                .skip(idx + 1)
                .take(3)
                .map(|part| {
                    part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                        .to_ascii_lowercase()
                })
                .any(|part| part.starts_with("result"));
            if !mentions_result {
                continue;
            }

            return Some(RankedResultRequest {
                rank,
                ordinal_text: ordinal_text.to_string(),
            });
        }
    }

    None
}

fn recent_requested_sort_label(history: &[ChatMessage]) -> Option<String> {
    const SORT_PATTERNS: &[&str] = &["sort to", "sort on", "sort by", "sort as"];

    for message in history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
    {
        let lower = message.content.to_ascii_lowercase();
        let mut best_match: Option<(usize, String)> = None;

        for pattern in SORT_PATTERNS {
            let mut search_start = 0usize;
            while let Some(relative_idx) = lower[search_start..].find(pattern) {
                let absolute_idx = search_start + relative_idx + pattern.len();
                if let Some(label) = extract_first_quoted_value(&message.content[absolute_idx..]) {
                    match best_match.as_ref() {
                        Some((best_idx, _)) if *best_idx >= absolute_idx => {}
                        _ => best_match = Some((absolute_idx, label)),
                    }
                }
                search_start = absolute_idx;
            }
        }

        if let Some((_, label)) = best_match {
            return Some(label);
        }
    }

    None
}

fn recent_goal_primary_target(history: &[ChatMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            extract_first_quoted_value(&message.content)
                .or_else(|| extract_select_submit_target(&message.content))
        })
}

fn recent_goal_mentions_submit(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| message.content.to_ascii_lowercase().contains("submit"))
}

fn priority_target_semantic_id(summary: &str) -> Option<&str> {
    let token = summary.split_whitespace().next()?;
    if let Some(value) = token.strip_prefix("id=") {
        return Some(value);
    }
    token
        .split_once('#')
        .map(|(_, value)| value)
        .or(Some(token))
}

fn priority_target_tag(summary: &str) -> Option<&str> {
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix("tag="))
        .or_else(|| {
            summary
                .split_whitespace()
                .next()?
                .split_once('#')
                .map(|(tag, _)| tag)
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BrowserNavigationTransition {
    semantic_id: Option<String>,
    pre_url: Option<String>,
    post_url: String,
}

fn clicked_element_semantic_id(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let rest = message.content.trim().strip_prefix("Clicked element '")?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn recent_successful_click_semantic_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success || !compact.contains("Clicked element") {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

fn recent_successful_selected_control_semantic_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success
            || !compact.contains("Clicked element")
            || !(compact.contains("\"checked\":true") || compact.contains("\"selected\":true"))
        {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

fn recent_successful_click_is_observed_in_later_snapshot(
    history: &[ChatMessage],
    semantic_id: &str,
) -> bool {
    let mut saw_later_snapshot = false;

    for message in history.iter().rev() {
        if browser_snapshot_payload(message).is_some() {
            saw_later_snapshot = true;
            continue;
        }
        if message.role != "tool" {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success || !compact.contains("Clicked element") {
            continue;
        }
        if clicked_element_semantic_id(message).as_deref() == Some(semantic_id) {
            return saw_later_snapshot;
        }
    }

    false
}

fn recent_successful_click_has_post_action_observation(
    history: &[ChatMessage],
    semantic_id: &str,
    current_snapshot: Option<&str>,
) -> bool {
    if recent_successful_click_is_observed_in_later_snapshot(history, semantic_id) {
        return true;
    }

    current_snapshot.is_some()
        && recent_successful_click_semantic_id(history).as_deref() == Some(semantic_id)
}

fn tree_change_link_reverification_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);

    let clicked_id = history[search_start..].iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success
            || !compact.contains("Clicked element")
            || !compact.contains("\"tree_changed\":true")
            || compact.contains("\"url_changed\":true")
        {
            return None;
        }

        let clicked_id = clicked_element_semantic_id(message)?;
        let link_like = clicked_id.to_ascii_lowercase().starts_with("lnk_")
            || compact.contains(r#""tag_name":"a""#);
        link_like.then_some(clicked_id)
    })?;

    Some(format!(
        "A recent click on `{clicked_id}` already changed the page state (`tree_changed=true`). Do not click `{clicked_id}` again or act on stale controls from the previous browser observation. Use `browser__snapshot` once now to ground the updated page before taking the next action."
    ))
}

fn semantic_id_is_submit_like(semantic_id: &str) -> bool {
    let lower = semantic_id.to_ascii_lowercase();
    lower.contains("submit") || lower.contains("subbtn")
}

fn snapshot_contains_semantic_id(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);
    let compact_summary = format!("#{semantic_id}");
    let compact_summary_raw = format!("{semantic_id} tag=");
    let compact_summary_attr = format!("id={semantic_id}");
    snapshot.contains(&semantic_id_attr)
        || snapshot.contains(&compact_summary)
        || snapshot.contains(&compact_summary_raw)
        || snapshot.contains(&compact_summary_attr)
}

fn recent_confirmation_queue_return(history: &[ChatMessage]) -> bool {
    history.iter().rev().take(10).any(|message| {
        let Some(transition) = browser_navigation_transition(message) else {
            return false;
        };
        let Some(pre_url) = transition.pre_url else {
            return false;
        };

        pre_url.to_ascii_lowercase().contains("/confirmation")
            && transition.post_url.to_ascii_lowercase().contains("/queue")
    })
}

fn browser_navigation_transition(message: &ChatMessage) -> Option<BrowserNavigationTransition> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_success = (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    if !has_success {
        return None;
    }

    let pre_url = extract_compact_jsonish_string_field(&compact, "pre_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"pre\":{", "url"));
    let post_url = extract_compact_jsonish_string_field(&compact, "post_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"post\":{", "url"));
    let has_url_change = compact.contains("\"url_changed\":true")
        || pre_url
            .as_ref()
            .zip(post_url.as_ref())
            .is_some_and(|(pre, post)| pre != post);
    if !has_url_change {
        return None;
    }

    Some(BrowserNavigationTransition {
        semantic_id: clicked_element_semantic_id(message),
        pre_url,
        post_url: post_url.unwrap_or_else(|| "the new page".to_string()),
    })
}

fn recent_unobserved_navigation_transition(
    history: &[ChatMessage],
) -> Option<BrowserNavigationTransition> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);
    history[search_start..]
        .iter()
        .rev()
        .find_map(browser_navigation_transition)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotLinkState {
    semantic_id: String,
    name: Option<String>,
    dom_id: Option<String>,
    selector: Option<String>,
    context: Option<String>,
    visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotTabState {
    semantic_id: String,
    name: Option<String>,
    dom_id: Option<String>,
    selector: Option<String>,
    controls_dom_id: Option<String>,
    focused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotTabPanelState {
    semantic_id: String,
    name: Option<String>,
    dom_id: Option<String>,
    selector: Option<String>,
    visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotVisibleTargetState {
    semantic_id: String,
    name: String,
    semantic_role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotAutocompleteControlState {
    semantic_id: String,
    dom_id: Option<String>,
    selector: Option<String>,
    value: Option<String>,
    has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecentAutocompleteAction {
    Typed,
    Key(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecentAutocompleteToolState {
    action: RecentAutocompleteAction,
    dom_id: Option<String>,
    selector: Option<String>,
    value: Option<String>,
    has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecentFindTextState {
    query: String,
    first_snippet: Option<String>,
}

fn snapshot_link_states(snapshot: &str) -> Vec<SnapshotLinkState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("link ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let context = extract_browser_xml_attr(fragment, "context")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let visible = !fragment.contains(r#" visible="false""#);

        states.push(SnapshotLinkState {
            semantic_id,
            name,
            dom_id,
            selector,
            context,
            visible,
        });
    }

    states
}

fn snapshot_tab_states(snapshot: &str) -> Vec<SnapshotTabState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tab ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabState {
            semantic_id,
            name,
            dom_id,
            selector,
            controls_dom_id,
            focused: fragment.contains(r#" focused="true""#),
        });
    }

    states
}

fn snapshot_tabpanel_states(snapshot: &str) -> Vec<SnapshotTabPanelState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tabpanel ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabPanelState {
            semantic_id,
            name,
            dom_id,
            selector,
            visible: !fragment.contains(r#" visible="false""#),
        });
    }

    states
}

fn visible_target_role_priority(semantic_role: &str) -> u8 {
    match semantic_role {
        "link" | "button" | "menuitem" | "option" | "tab" | "checkbox" | "radio" => 4,
        "generic" | "label" | "text" | "heading" => 3,
        "textbox" | "searchbox" | "combobox" => 2,
        _ => 1,
    }
}

fn snapshot_visible_exact_text_target(
    snapshot: &str,
    target: &str,
) -> Option<SnapshotVisibleTargetState> {
    let normalized_target = normalized_exact_target_text(target);
    if normalized_target.is_empty() {
        return None;
    }

    let mut best_match: Option<(u8, usize, SnapshotVisibleTargetState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if normalized_exact_target_text(&name) != normalized_target {
            continue;
        }

        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
        };
        let candidate_score = visible_target_role_priority(&semantic_role);
        let candidate_name_len = name.chars().count();

        match best_match.as_ref() {
            Some((best_score, best_len, best_candidate))
                if *best_score > candidate_score
                    || (*best_score == candidate_score
                        && (*best_len < candidate_name_len
                            || (*best_len == candidate_name_len
                                && best_candidate.semantic_id <= candidate.semantic_id))) => {}
            _ => best_match = Some((candidate_score, candidate_name_len, candidate)),
        }
    }

    best_match.map(|(_, _, candidate)| candidate)
}

fn snapshot_focused_text_control_states(snapshot: &str) -> Vec<SnapshotAutocompleteControlState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            value,
            has_active_candidate: false,
        });
    }

    states
}

fn snapshot_focused_autocomplete_control_state(
    snapshot: &str,
) -> Option<SnapshotAutocompleteControlState> {
    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let autocomplete = extract_browser_xml_attr(fragment, "autocomplete")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let active_descendant_dom_id =
            extract_browser_xml_attr(fragment, "active_descendant_dom_id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
        if autocomplete.is_none() && controls_dom_id.is_none() && active_descendant_dom_id.is_none()
        {
            continue;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        return Some(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            value,
            has_active_candidate: active_descendant_dom_id.is_some(),
        });
    }

    None
}

fn autocomplete_tool_state(message: &ChatMessage) -> Option<RecentAutocompleteToolState> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let (action, action_state) = if let Some(typed) = payload.get("typed") {
        (RecentAutocompleteAction::Typed, typed)
    } else {
        let key = payload
            .get("key")?
            .get("key")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())?;
        (RecentAutocompleteAction::Key(key), payload.get("key")?)
    };
    let autocomplete = action_state.get("autocomplete")?;
    if autocomplete.is_null() {
        return None;
    }

    let dom_id = action_state
        .get("dom_id")
        .and_then(Value::as_str)
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let selector = action_state
        .get("selector")
        .and_then(Value::as_str)
        .or_else(|| {
            action_state
                .get("resolved_selector")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            action_state
                .get("requested_selector")
                .and_then(Value::as_str)
        })
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let value = action_state
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| action_state.get("text").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let has_active_candidate = autocomplete
        .get("active_descendant_dom_id")
        .and_then(Value::as_str)
        .map(compact_ws_for_prompt)
        .is_some_and(|value| !value.is_empty());

    Some(RecentAutocompleteToolState {
        action,
        dom_id,
        selector,
        value,
        has_active_candidate,
    })
}

fn recent_autocomplete_tool_state(history: &[ChatMessage]) -> Option<RecentAutocompleteToolState> {
    history.iter().rev().find_map(autocomplete_tool_state)
}

fn recent_find_text_state(history: &[ChatMessage]) -> Option<RecentFindTextState> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let payload = parse_json_value_from_message(&message.content)?;
        let query = payload
            .get("query")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())?;
        let result = payload.get("result")?;
        if !result
            .get("found")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return None;
        }

        let first_snippet = result
            .get("first_snippet")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());

        Some(RecentFindTextState {
            query,
            first_snippet,
        })
    })
}

fn autocomplete_hint_signals_single_result(hint: &str) -> bool {
    let lower = hint.to_ascii_lowercase();
    lower.contains("1 result is available")
        || lower.contains("1 suggestion is available")
        || lower.contains("1 option is available")
}

fn autocomplete_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let recent_autocomplete = recent_autocomplete_tool_state(history);
    let control = snapshot_focused_autocomplete_control_state(snapshot).or_else(|| {
        let recent = recent_autocomplete.as_ref()?;
        snapshot_focused_text_control_states(snapshot)
            .into_iter()
            .find(|control| {
                recent
                    .dom_id
                    .as_deref()
                    .zip(control.dom_id.as_deref())
                    .is_some_and(|(recent, current)| recent == current)
                    || recent
                        .selector
                        .as_deref()
                        .zip(control.selector.as_deref())
                        .is_some_and(|(recent, current)| recent == current)
                    || recent
                        .value
                        .as_deref()
                        .zip(control.value.as_deref())
                        .is_some_and(|(recent, current)| recent == current)
            })
    })?;
    let hints = extract_assistive_browser_hints(snapshot);
    let hint_has_single_result = hints
        .iter()
        .any(|hint| autocomplete_hint_signals_single_result(hint));
    let value = control.value.as_deref().map(compact_ws_for_prompt);
    let hint_mentions_value = value.as_deref().is_some_and(|value| {
        hints
            .iter()
            .any(|hint| contains_ascii_case_insensitive(hint, value))
    });
    let value_clause = value
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| format!(" with `{value}` in the field"))
        .unwrap_or_default();
    let recent_navigation_highlighted = recent_autocomplete.as_ref().is_some_and(|state| {
        state.has_active_candidate
            || matches!(
                state.action,
                RecentAutocompleteAction::Key(ref key)
                    if key.eq_ignore_ascii_case("ArrowDown")
                        || key.eq_ignore_ascii_case("ArrowUp")
            )
    });
    let recent_enter_failed = recent_autocomplete.as_ref().is_some_and(|state| {
        matches!(
            state.action,
            RecentAutocompleteAction::Key(ref key) if key.eq_ignore_ascii_case("Enter")
        )
    });
    let highlighted_candidate = control.has_active_candidate || recent_navigation_highlighted;
    let guided_arrowdown_then_enter = hint_has_single_result || hint_mentions_value;

    if let Some(submit_id) = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| semantic_id_is_submit_like(semantic_id))
        .filter(|semantic_id| {
            recent_successful_click_has_post_action_observation(
                history,
                semantic_id,
                current_snapshot,
            )
        })
    {
        if highlighted_candidate {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting again.",
                control.semantic_id
            ));
        }

        if recent_enter_failed || guided_arrowdown_then_enter {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__key` `ArrowDown` now to highlight the suggestion, then `browser__key` `Enter` to commit it before submitting again.",
                control.semantic_id
            ));
        }

        return Some(format!(
            "A recent `{submit_id}` click left autocomplete unresolved on `{}`. That submit does not finish the task. Use `browser__key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__key` `Enter` to commit it before submitting again.",
            control.semantic_id
        ));
    }

    if recent_enter_failed {
        return Some(format!(
            "A recent `Enter` key left autocomplete unresolved on `{}`{value_clause}. That key did not commit the suggestion. Do not submit or finish yet. Use `browser__key` `ArrowDown` now to highlight it, then `browser__key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    if highlighted_candidate {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. Do not submit or finish yet. Use `browser__key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting.",
            control.semantic_id
        ));
    }

    if guided_arrowdown_then_enter {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. The suggestion is not committed yet. Do not submit or finish. Use `browser__key` `ArrowDown` now to highlight it, then `browser__key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    Some(format!(
        "Autocomplete is still open on `{}`. Do not submit or finish yet. Use `browser__key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__key` `Enter` to commit it.",
        control.semantic_id
    ))
}

fn is_history_like_link(link: &SnapshotLinkState) -> bool {
    link.name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("history"))
        || link
            .dom_id
            .as_deref()
            .is_some_and(|dom_id| dom_id.to_ascii_lowercase().contains("history"))
        || link
            .selector
            .as_deref()
            .is_some_and(|selector| selector.to_ascii_lowercase().contains("history"))
}

fn snapshot_link_item_id(link: &SnapshotLinkState) -> Option<String> {
    [
        Some(link.semantic_id.as_str()),
        link.name.as_deref(),
        link.dom_id.as_deref(),
        link.selector.as_deref(),
        link.context.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find_map(first_item_like_id)
}

fn recent_goal_item_ids(history: &[ChatMessage]) -> HashSet<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .flat_map(|message| extract_item_like_ids(&message.content))
        .collect()
}

fn recent_goal_item_sequence(history: &[ChatMessage]) -> Vec<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            let ids = extract_item_like_ids(&message.content);
            (!ids.is_empty()).then_some(ids)
        })
        .unwrap_or_default()
}

fn recent_successful_tab_click_ids(history: &[ChatMessage], snapshot: &str) -> Vec<String> {
    let valid_ids = snapshot_tab_states(snapshot)
        .into_iter()
        .map(|tab| tab.semantic_id)
        .collect::<HashSet<_>>();
    let mut tab_ids = Vec::new();
    let mut seen = HashSet::new();

    for message in history.iter().rev() {
        let Some(clicked_id) = clicked_element_semantic_id(message) else {
            continue;
        };
        if !valid_ids.contains(&clicked_id) || !seen.insert(clicked_id.clone()) {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success {
            continue;
        }

        tab_ids.push(clicked_id);
        if tab_ids.len() >= 3 {
            break;
        }
    }

    tab_ids
}

fn snapshot_ticket_link_for_item(snapshot: &str, item_id: &str) -> Option<SnapshotLinkState> {
    snapshot_link_states(snapshot).into_iter().find(|link| {
        !is_history_like_link(link)
            && snapshot_link_item_id(link)
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(item_id))
    })
}

fn snapshot_history_link_for_item(snapshot: &str, item_id: &str) -> Option<SnapshotLinkState> {
    snapshot_link_states(snapshot).into_iter().find(|link| {
        is_history_like_link(link)
            && snapshot_link_item_id(link)
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(item_id))
    })
}

fn snapshot_visible_item_order(snapshot: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();

    for link in snapshot_link_states(snapshot) {
        if is_history_like_link(&link) {
            continue;
        }

        let Some(item_id) = snapshot_link_item_id(&link) else {
            continue;
        };
        if seen.insert(item_id.clone()) {
            ids.push(item_id);
        }
    }

    ids
}

fn link_name_is_pagination_like(name: &str) -> bool {
    let raw = compact_ws_for_prompt(name);
    let raw_trimmed = raw.trim();
    if matches!(
        raw_trimmed,
        "<" | ">" | "<<" | ">>" | "&lt;" | "&gt;" | "&lt;&lt;" | "&gt;&gt;"
    ) {
        return true;
    }

    let normalized = normalized_exact_target_text(name);
    !normalized.is_empty()
        && (normalized.chars().all(|ch| ch.is_ascii_digit())
            || matches!(
                normalized.as_str(),
                "first" | "last" | "next" | "previous" | "prev"
            )
            || matches!(name.trim(), "<" | ">" | "<<" | ">>"))
}

fn parse_zero_based_result_rank_marker(raw: &str) -> Option<usize> {
    let normalized = raw.trim().to_ascii_lowercase();
    let suffix = normalized
        .strip_prefix("result-")
        .or_else(|| normalized.strip_prefix("result_"))?;
    suffix.parse::<usize>().ok().map(|rank| rank + 1)
}

fn snapshot_link_result_rank(link: &SnapshotLinkState) -> Option<usize> {
    link.dom_id
        .as_deref()
        .and_then(parse_zero_based_result_rank_marker)
        .or_else(|| {
            link.selector
                .as_deref()
                .and_then(parse_zero_based_result_rank_marker)
        })
        .or_else(|| {
            link.context
                .as_deref()
                .and_then(parse_zero_based_result_rank_marker)
        })
        .or_else(|| {
            link.semantic_id
                .to_ascii_lowercase()
                .contains("result")
                .then(|| semantic_id_numeric_suffix(&link.semantic_id))
                .flatten()
        })
}

fn snapshot_visible_result_links(snapshot: &str) -> Vec<SnapshotLinkState> {
    let visible_links = snapshot_link_states(snapshot)
        .into_iter()
        .filter(|link| link.visible)
        .collect::<Vec<_>>();
    let mut explicit_ranked_links = visible_links
        .iter()
        .filter_map(|link| snapshot_link_result_rank(link).map(|rank| (rank, link.clone())))
        .collect::<Vec<_>>();
    explicit_ranked_links.sort_by(|(left_rank, left_link), (right_rank, right_link)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left_link.semantic_id.cmp(&right_link.semantic_id))
    });
    explicit_ranked_links.dedup_by(|(left_rank, _), (right_rank, _)| left_rank == right_rank);
    if !explicit_ranked_links.is_empty() {
        return explicit_ranked_links
            .into_iter()
            .map(|(_, link)| link)
            .collect();
    }

    visible_links
        .into_iter()
        .filter(|link| {
            link.name
                .as_deref()
                .is_some_and(|name| !link_name_is_pagination_like(name))
        })
        .collect()
}

fn snapshot_visible_pagination_links(snapshot: &str) -> Vec<SnapshotLinkState> {
    snapshot_link_states(snapshot)
        .into_iter()
        .filter(|link| link.visible)
        .filter(|link| {
            link.name
                .as_deref()
                .is_some_and(link_name_is_pagination_like)
        })
        .collect()
}

fn snapshot_pagination_link_for_page(snapshot: &str, page: usize) -> Option<SnapshotLinkState> {
    let page_label = page.to_string();
    snapshot_visible_pagination_links(snapshot)
        .into_iter()
        .find(|link| {
            link.name
                .as_deref()
                .is_some_and(|name| normalized_exact_target_text(name) == page_label)
        })
}

fn pagination_name_is_previous_like(name: &str) -> bool {
    matches!(
        compact_ws_for_prompt(name).trim(),
        "<" | "<<" | "&lt;" | "&lt;&lt;"
    ) || matches!(
        normalized_exact_target_text(name).as_str(),
        "previous" | "prev"
    )
}

fn pagination_name_is_next_like(name: &str) -> bool {
    matches!(
        compact_ws_for_prompt(name).trim(),
        ">" | ">>" | "&gt;" | "&gt;&gt;"
    ) || matches!(normalized_exact_target_text(name).as_str(), "next")
}

fn snapshot_current_pagination_page(snapshot: &str) -> Option<usize> {
    let pagination_links = snapshot_visible_pagination_links(snapshot);
    if pagination_links.is_empty() {
        return None;
    }

    let has_previous = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .any(pagination_name_is_previous_like);
    let has_next = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .any(pagination_name_is_next_like);
    let numeric_pages = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .filter_map(|name| normalized_exact_target_text(name).parse::<usize>().ok())
        .collect::<Vec<_>>();
    if numeric_pages.is_empty() {
        return None;
    }

    if !has_previous && numeric_pages.contains(&1) {
        return Some(1);
    }

    if !has_next {
        return numeric_pages.iter().max().copied();
    }

    None
}

fn snapshot_next_pagination_link(snapshot: &str) -> Option<SnapshotLinkState> {
    snapshot_visible_pagination_links(snapshot)
        .into_iter()
        .find(|link| {
            link.name
                .as_deref()
                .is_some_and(pagination_name_is_next_like)
        })
}

fn snapshot_forward_pagination_link(snapshot: &str) -> Option<SnapshotLinkState> {
    snapshot_next_pagination_link(snapshot).or_else(|| {
        let current_page = snapshot_current_pagination_page(snapshot).unwrap_or(0);
        let mut numeric_links = snapshot_visible_pagination_links(snapshot)
            .into_iter()
            .filter_map(|link| {
                let page = link
                    .name
                    .as_deref()
                    .and_then(|name| normalized_exact_target_text(name).parse::<usize>().ok())?;
                Some((page, link))
            })
            .collect::<Vec<_>>();
        numeric_links.sort_by(|(left_page, left_link), (right_page, right_link)| {
            left_page
                .cmp(right_page)
                .then_with(|| left_link.semantic_id.cmp(&right_link.semantic_id))
        });
        numeric_links
            .into_iter()
            .find(|(page, _)| *page > current_page)
            .map(|(_, link)| link)
    })
}

fn semantic_id_numeric_suffix(semantic_id: &str) -> Option<usize> {
    let digits = semantic_id
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    (!digits.is_empty())
        .then(|| digits.parse::<usize>().ok())
        .flatten()
}

fn tool_output_click_semantic_id(message: &ChatMessage) -> Option<String> {
    clicked_element_semantic_id(message).or_else(|| {
        (message.role == "tool")
            .then(|| {
                extract_compact_jsonish_string_field(&compact_ws_for_prompt(&message.content), "id")
            })
            .flatten()
    })
}

fn recent_clicked_pagination_page_number(history: &[ChatMessage], snapshot: &str) -> Option<usize> {
    if let Some(current_page) = snapshot_current_pagination_page(snapshot) {
        return Some(current_page);
    }

    let pagination_links = snapshot_visible_pagination_links(snapshot);
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let semantic_id = tool_output_click_semantic_id(message)?;
        let mapped = pagination_links
            .iter()
            .find(|link| link.semantic_id == semantic_id)
            .and_then(|link| link.name.as_deref())
            .and_then(|name| normalized_exact_target_text(name).parse::<usize>().ok());
        let effective_transition = compact.contains("\"postcondition\":{")
            && (compact.contains("\"met\":true")
                || compact.contains("\"tree_changed\":true")
                || compact.contains("\"url_changed\":true"));
        if !effective_transition {
            return None;
        }

        mapped.or_else(|| semantic_id_numeric_suffix(&semantic_id))
    })
}

fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn instruction_like_attr_matches(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("query") || lowered.contains("instruction") || lowered.contains("prompt")
}

fn snapshot_visible_instruction_query_target(
    snapshot: &str,
    query: &str,
) -> Option<SnapshotVisibleTargetState> {
    if query.trim().is_empty() {
        return None;
    }

    let mut best_match: Option<(u8, usize, SnapshotVisibleTargetState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !contains_ascii_case_insensitive(&name, query) {
            continue;
        }

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if !instruction_like_attr_matches(&semantic_id)
            && !dom_id.as_deref().is_some_and(instruction_like_attr_matches)
            && !selector
                .as_deref()
                .is_some_and(instruction_like_attr_matches)
        {
            continue;
        }

        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
        };
        let candidate_score = visible_target_role_priority(&semantic_role);
        let candidate_name_len = name.chars().count();

        match best_match.as_ref() {
            Some((best_score, best_len, best_candidate))
                if *best_score > candidate_score
                    || (*best_score == candidate_score
                        && (*best_len < candidate_name_len
                            || (*best_len == candidate_name_len
                                && best_candidate.semantic_id <= candidate.semantic_id))) => {}
            _ => best_match = Some((candidate_score, candidate_name_len, candidate)),
        }
    }

    best_match.map(|(_, _, candidate)| candidate)
}

fn snapshot_primary_visible_heading(snapshot: &str) -> Option<SnapshotVisibleTargetState> {
    snapshot.split('<').find_map(|fragment| {
        if !fragment.trim_start().starts_with("heading ")
            || fragment.contains(r#" omitted="true""#)
            || fragment.contains(r#" visible="false""#)
        {
            return None;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;
        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;

        Some(SnapshotVisibleTargetState {
            semantic_id,
            name,
            semantic_role: "heading".to_string(),
        })
    })
}

fn recent_history_viewed_item_ids(history: &[ChatMessage]) -> Vec<String> {
    let mut item_ids = Vec::new();
    let mut seen = HashSet::new();

    for message in history.iter().rev().take(20) {
        if let Some(snapshot) = browser_snapshot_payload(message) {
            if let Some(item_id) = snapshot_history_item_id(snapshot) {
                if seen.insert(item_id.clone()) {
                    item_ids.push(item_id);
                }
            }
        }

        if let Some(transition) = browser_navigation_transition(message) {
            for url in [
                transition.pre_url.as_deref(),
                Some(transition.post_url.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                if !url.to_ascii_lowercase().contains("/history") {
                    continue;
                }
                if let Some(item_id) = history_item_like_id_from_url(url) {
                    if seen.insert(item_id.clone()) {
                        item_ids.push(item_id);
                    }
                }
            }
        }

        if item_ids.len() >= 3 {
            break;
        }
    }

    item_ids
}

fn recent_history_return_item_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        let transition = browser_navigation_transition(message)?;
        let pre_url = transition.pre_url?;
        if !pre_url.to_ascii_lowercase().contains("/history") {
            return None;
        }
        if transition
            .post_url
            .to_ascii_lowercase()
            .contains("/history")
        {
            return None;
        }
        history_item_like_id_from_url(&pre_url)
    })
}

fn history_verification_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let lowered = token.trim();
            if lowered.len() < 4 {
                return None;
            }

            let lowered = lowered.to_ascii_lowercase();
            if matches!(
                lowered.as_str(),
                "verify"
                    | "that"
                    | "this"
                    | "with"
                    | "from"
                    | "before"
                    | "after"
                    | "return"
                    | "queue"
                    | "audit"
                    | "history"
                    | "ticket"
                    | "actor"
                    | "action"
                    | "requested"
                    | "matches"
                    | "match"
                    | "there"
                    | "their"
                    | "visible"
                    | "already"
                    | "current"
            ) {
                return None;
            }

            Some(lowered)
        })
        .collect()
}

fn history_page_instruction_text(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        let is_history_status = dom_id.to_ascii_lowercase().contains("history-status")
            || selector.to_ascii_lowercase().contains("history-status");
        let mentions_verify = name
            .as_deref()
            .is_some_and(|text| text.to_ascii_lowercase().contains("verify"));
        if is_history_status || mentions_verify {
            return name;
        }
    }

    None
}

fn history_page_row_summaries(snapshot: &str) -> Vec<String> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="tr""#) || fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        rows.push(name);
    }

    rows
}

fn history_page_has_matching_verification_row(snapshot: &str) -> Option<bool> {
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }

    let instruction = history_page_instruction_text(snapshot)?;
    let instruction_tokens = history_verification_tokens(&instruction);
    if instruction_tokens.len() < 2 {
        return None;
    }

    let row_summaries = history_page_row_summaries(snapshot);
    if row_summaries.is_empty() {
        return None;
    }

    Some(row_summaries.into_iter().any(|row| {
        let row_tokens = history_verification_tokens(&row);
        instruction_tokens.intersection(&row_tokens).count() >= 2
    }))
}

fn snapshot_has_history_page_marker(snapshot: &str) -> bool {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();

        if dom_id.to_ascii_lowercase().contains("history-status")
            || selector.to_ascii_lowercase().contains("history-status")
        {
            return true;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        if !(fragment.contains(r#"tag_name="h1""#) || fragment.contains(r#"tag_name="h2""#)) {
            continue;
        }

        if name.to_ascii_lowercase().contains("history") {
            return true;
        }
    }

    false
}

fn snapshot_history_item_id(snapshot: &str) -> Option<String> {
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }

    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="h1""#) && !fragment.contains(r#"tag_name="h2""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !name.to_ascii_lowercase().contains("history") {
            continue;
        }
        if let Some(item_id) = first_item_like_id(&name) {
            return Some(item_id);
        }
    }

    first_item_like_id(snapshot)
}

fn snapshot_queue_link_id(snapshot: &str) -> Option<String> {
    snapshot_link_states(snapshot).into_iter().find_map(|link| {
        let is_queue_link = link
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("queue"))
            || link
                .dom_id
                .as_deref()
                .is_some_and(|dom_id| dom_id.to_ascii_lowercase().contains("queue-link"))
            || link.semantic_id.eq("lnk_queue");
        is_queue_link.then_some(link.semantic_id)
    })
}

fn history_page_verification_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }
    if !history_page_has_matching_verification_row(snapshot)? {
        return None;
    }

    let current_item = snapshot_history_item_id(snapshot)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next());
    let mut remaining_goal_items = recent_goal_item_ids(history);
    if let Some(current_item) = current_item.as_ref() {
        remaining_goal_items.remove(current_item);
    }

    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    if let Some(queue_link_id) = snapshot_queue_link_id(snapshot) {
        let next_item_clause = remaining_goal_items
            .iter()
            .next()
            .map(|item_id| {
                format!(
                    " then continue the remaining verification for another required item such as `{item_id}`."
                )
            })
            .unwrap_or_else(|| {
                " then continue with the next required action or finish if every required verification is complete."
                    .to_string()
            });

        return Some(format!(
            "The current history view{item_clause} already shows a row matching the page-visible verification prompt. Use `{queue_link_id}` to return to the queue,{next_item_clause} Do not call `browser__snapshot` again. Do not reopen or mutate the item just to re-read the same history view.",
        ));
    }

    let next_controls = next_visible_follow_up_controls(snapshot, &[]);
    if next_controls.is_empty() {
        return None;
    }

    Some(format!(
        "The current history view{item_clause} already shows a row matching the page-visible verification prompt. Do not call `browser__snapshot` again. Continue with another grounded control such as `{}`.",
        next_controls.join("`, `")
    ))
}

fn snapshot_confirmation_link_id(snapshot: &str) -> Option<String> {
    snapshot_link_states(snapshot).into_iter().find_map(|link| {
        let is_confirmation_link =
            link.name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("confirmation"))
                || link.dom_id.as_deref().is_some_and(|dom_id| {
                    dom_id.to_ascii_lowercase().contains("confirmation-link")
                })
                || link.semantic_id.eq("lnk_confirmation");
        is_confirmation_link.then_some(link.semantic_id)
    })
}

fn snapshot_reopen_button_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("button ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let lower_name = name.to_ascii_lowercase();
        let lower_dom_id = dom_id.to_ascii_lowercase();
        let lower_selector = selector.to_ascii_lowercase();

        if lower_name.contains("reopen")
            || lower_dom_id.contains("reopen-ticket")
            || lower_selector.contains("reopen-ticket")
            || semantic_id.to_ascii_lowercase().contains("reopen")
        {
            return Some(semantic_id);
        }
    }

    None
}

fn snapshot_confirm_update_button_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("button ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let lower_name = name.to_ascii_lowercase();
        let lower_dom_id = dom_id.to_ascii_lowercase();
        let lower_selector = selector.to_ascii_lowercase();
        let lower_semantic_id = semantic_id.to_ascii_lowercase();

        if lower_name.contains("confirm update")
            || lower_dom_id.contains("confirm-update")
            || lower_selector.contains("confirm-update")
            || lower_semantic_id.contains("confirm_update")
        {
            return Some(semantic_id);
        }
    }

    None
}

fn snapshot_edit_draft_button_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("button ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let lower_name = name.to_ascii_lowercase();
        let lower_dom_id = dom_id.to_ascii_lowercase();
        let lower_selector = selector.to_ascii_lowercase();
        let lower_semantic_id = semantic_id.to_ascii_lowercase();

        if lower_name.contains("edit draft")
            || lower_dom_id.contains("edit-update")
            || lower_selector.contains("edit-update")
            || lower_semantic_id.contains("edit_draft")
        {
            return Some(semantic_id);
        }
    }

    None
}

fn history_page_verification_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }
    if history_page_has_matching_verification_row(snapshot)? {
        return None;
    }

    let current_item = snapshot_history_item_id(snapshot)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next());
    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    let confirmation_link_id = snapshot_confirmation_link_id(snapshot);
    let reopen_button_id = snapshot_reopen_button_id(snapshot);
    let queue_link_id = snapshot_queue_link_id(snapshot);

    match (
        confirmation_link_id.as_deref(),
        reopen_button_id.as_deref(),
        queue_link_id.as_deref(),
    ) {
        (Some(confirmation_link_id), Some(reopen_button_id), Some(queue_link_id)) => Some(
            format!(
                "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details or `{reopen_button_id}` to correct them, then return through `{queue_link_id}` only after the history row matches."
            ),
        ),
        (Some(confirmation_link_id), Some(reopen_button_id), None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details or `{reopen_button_id}` to correct them before checking history again."
        )),
        (Some(confirmation_link_id), None, Some(queue_link_id)) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details, then return through `{queue_link_id}` only after the history row matches."
        )),
        (None, Some(reopen_button_id), Some(queue_link_id)) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{reopen_button_id}` to correct the saved state, then return through `{queue_link_id}` only after the history row matches."
        )),
        (Some(confirmation_link_id), None, None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details before checking history again."
        )),
        (None, Some(reopen_button_id), None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{reopen_button_id}` to correct the saved state before checking history again."
        )),
        _ => None,
    }
}

fn recent_verified_history_item_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().take(20).find_map(|message| {
        let snapshot = browser_snapshot_payload(message)?;
        if !history_page_has_matching_verification_row(snapshot).unwrap_or(false) {
            return None;
        }
        snapshot_history_item_id(snapshot)
    })
}

fn history_verification_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let returned_item = recent_history_return_item_id(history)?;
    let verified_item = recent_verified_history_item_id(history)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next())?;
    if verified_item != returned_item {
        return None;
    }

    let goal_item_ids = recent_goal_item_ids(history);
    let mut alternate_history_links = snapshot_link_states(snapshot)
        .into_iter()
        .filter(is_history_like_link)
        .filter_map(|link| {
            let item_id = snapshot_link_item_id(&link)?;
            (item_id != returned_item).then_some((link, item_id))
        })
        .collect::<Vec<_>>();
    if alternate_history_links.is_empty() {
        return None;
    }

    alternate_history_links.sort_by(|(left_link, left_item_id), (right_link, right_item_id)| {
        let left_goal_match = goal_item_ids.contains(left_item_id);
        let right_goal_match = goal_item_ids.contains(right_item_id);

        right_goal_match
            .cmp(&left_goal_match)
            .then(left_item_id.cmp(right_item_id))
            .then(left_link.semantic_id.cmp(&right_link.semantic_id))
    });

    let examples = alternate_history_links
        .into_iter()
        .take(3)
        .map(|(link, item_id)| format!("`{}` for `{}`", link.semantic_id, item_id))
        .collect::<Vec<_>>();
    if examples.is_empty() {
        return None;
    }

    Some(format!(
        "A recent browser action already returned from history for `{}` to the list view. Do not reopen `{}` right away. Continue the remaining cross-item verification on another visible history link instead, such as {}.",
        returned_item,
        returned_item,
        examples.join(" or ")
    ))
}

fn dropdown_selection_details(message: &ChatMessage) -> Option<(String, String)> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let selected = payload.get("selected")?;
    let selected_label = selected
        .get("label")
        .and_then(Value::as_str)
        .or_else(|| selected.get("value").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;
    let dropdown_id = payload
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("selector").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;

    Some((dropdown_id, selected_label))
}

fn typed_field_details(message: &ChatMessage) -> Option<(String, String)> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let typed = payload.get("typed")?;
    let text = typed
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| typed.get("text").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;
    let locator = typed
        .get("dom_id")
        .and_then(Value::as_str)
        .or_else(|| typed.get("selector").and_then(Value::as_str))
        .or_else(|| typed.get("requested_selector").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;

    Some((locator, text))
}

#[derive(Default)]
struct DispatchUpdateExpectation {
    assignee: Option<String>,
    status: Option<String>,
    note: Option<String>,
}

fn recent_dispatch_update_expectation(history: &[ChatMessage]) -> DispatchUpdateExpectation {
    let mut expectation = DispatchUpdateExpectation::default();

    for message in history.iter().rev() {
        if expectation.assignee.is_none() || expectation.status.is_none() {
            if let Some((dropdown_id, selected_label)) = dropdown_selection_details(message) {
                let dropdown_lower = dropdown_id.to_ascii_lowercase();
                if expectation.assignee.is_none()
                    && (dropdown_lower.contains("assign")
                        || dropdown_lower.contains("assignee")
                        || dropdown_lower.contains("team"))
                {
                    expectation.assignee = Some(selected_label.clone());
                }
                if expectation.status.is_none() && dropdown_lower.contains("status") {
                    expectation.status = Some(selected_label);
                }
            }
        }

        if expectation.note.is_none() {
            if let Some((locator, text)) = typed_field_details(message) {
                let locator_lower = locator.to_ascii_lowercase();
                if locator_lower.contains("note") {
                    expectation.note = Some(text);
                }
            }
        }

        if expectation.assignee.is_some()
            && expectation.status.is_some()
            && expectation.note.is_some()
        {
            break;
        }
    }

    expectation
}

fn snapshot_mentions_dropdown_locator(snapshot: &str, locator: &str) -> bool {
    let semantic_id_marker = format!(r#"id="{}""#, locator);
    let selector_marker = format!(r#"selector="{}""#, locator);
    let compact_summary_marker = format!("#{locator}");

    snapshot.contains(&semantic_id_marker)
        || snapshot.contains(&selector_marker)
        || snapshot.contains(&compact_summary_marker)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotDropdownState {
    semantic_id: String,
    name: Option<String>,
    value: Option<String>,
    dom_id: Option<String>,
    selector: Option<String>,
}

fn snapshot_dropdown_states(snapshot: &str) -> Vec<SnapshotDropdownState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("combobox ") || fragment.contains(" omitted=\"true\"")
        {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotDropdownState {
            semantic_id,
            name,
            value,
            dom_id,
            selector,
        });
    }

    states
}

fn snapshot_sort_dropdown_state(snapshot: &str) -> Option<SnapshotDropdownState> {
    snapshot_dropdown_states(snapshot)
        .into_iter()
        .find(|dropdown| {
            dropdown_descriptor_text(dropdown)
                .to_ascii_lowercase()
                .contains("sort")
        })
}

fn snapshot_apply_filters_button_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("button ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();

        let lower_name = name.to_ascii_lowercase();
        let lower_dom_id = dom_id.to_ascii_lowercase();
        let lower_selector = selector.to_ascii_lowercase();
        let lower_semantic_id = semantic_id.to_ascii_lowercase();
        if lower_name.contains("apply")
            || lower_name.contains("refresh")
            || lower_dom_id.contains("apply")
            || lower_dom_id.contains("refresh")
            || lower_selector.contains("apply")
            || lower_selector.contains("refresh")
            || lower_semantic_id.contains("apply")
            || lower_semantic_id.contains("refresh")
        {
            return Some(semantic_id);
        }
    }

    None
}

fn dropdown_descriptor_text(dropdown: &SnapshotDropdownState) -> String {
    [
        Some(dropdown.semantic_id.as_str()),
        dropdown.name.as_deref(),
        dropdown.dom_id.as_deref(),
        dropdown.selector.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

fn semantic_hint_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let lowered = token.trim_matches(|ch: char| ch.is_ascii_digit());
            if lowered.len() < 3 {
                return None;
            }

            let lowered = lowered.to_ascii_lowercase();
            if matches!(
                lowered.as_str(),
                "inp"
                    | "btn"
                    | "lnk"
                    | "grp"
                    | "dom"
                    | "id"
                    | "selector"
                    | "field"
                    | "form"
                    | "control"
                    | "dropdown"
                    | "select"
                    | "combobox"
                    | "button"
                    | "link"
                    | "queue"
                    | "ticket"
                    | "view"
                    | "list"
                    | "current"
                    | "saved"
            ) {
                return None;
            }

            Some(lowered)
        })
        .collect()
}

fn is_filter_like_dropdown(dropdown: &SnapshotDropdownState) -> bool {
    let descriptor = dropdown_descriptor_text(dropdown).to_ascii_lowercase();
    descriptor.contains("filter") || descriptor.contains("sort")
}

fn dropdown_filter_overlap_count(
    dropdown_id: &str,
    filter_dropdown: &SnapshotDropdownState,
) -> usize {
    let selection_tokens = semantic_hint_tokens(dropdown_id);
    if selection_tokens.is_empty() {
        return 0;
    }

    let filter_tokens = semantic_hint_tokens(&dropdown_descriptor_text(filter_dropdown));
    selection_tokens.intersection(&filter_tokens).count()
}

fn dropdown_filter_mismatch_pending_signal(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    let filter_dropdowns = snapshot_dropdown_states(snapshot)
        .into_iter()
        .filter(is_filter_like_dropdown)
        .collect::<Vec<_>>();
    if filter_dropdowns.is_empty() {
        return None;
    }

    for message in history.iter().rev() {
        let Some((dropdown_id, selected_label)) = dropdown_selection_details(message) else {
            continue;
        };

        let best_match = filter_dropdowns
            .iter()
            .filter_map(|filter_dropdown| {
                if filter_dropdown.semantic_id == dropdown_id {
                    return None;
                }

                let current_value = filter_dropdown.value.as_deref()?;
                if current_value.eq_ignore_ascii_case(&selected_label) {
                    return None;
                }

                let overlap = dropdown_filter_overlap_count(&dropdown_id, filter_dropdown);
                (overlap > 0).then_some((filter_dropdown, current_value, overlap))
            })
            .max_by_key(|(_, _, overlap)| *overlap);

        let Some((filter_dropdown, current_value, _)) = best_match else {
            continue;
        };

        let filter_name = filter_dropdown
            .name
            .as_deref()
            .unwrap_or(filter_dropdown.semantic_id.as_str());
        return Some(format!(
            "A recent dropdown changed `{}` to `{}`, but filter `{}` (`{}`) still shows `{}` and may hide the updated item. Do not call `browser__snapshot` again yet. Use `browser__select_dropdown` on `{}` now: first try `{}`; if unavailable, clear it to an all-items option. Then verify the updated item in the list.",
            dropdown_id,
            selected_label,
            filter_dropdown.semantic_id,
            filter_name,
            current_value,
            filter_dropdown.semantic_id,
            selected_label
        ));
    }

    None
}

fn snapshot_has_stale_queue_reverification_marker(snapshot: &str) -> bool {
    let lower = snapshot_lower_text(snapshot);
    let mentions_queue = lower.contains("queue");
    let mentions_stale = lower.contains("stale");
    let mentions_refresh = lower.contains("refresh") || lower.contains("reapply");
    let mentions_row_evidence = lower.contains("row order")
        || lower.contains("row state")
        || lower.contains("trusting any row state")
        || lower.contains("using row order as evidence");

    mentions_queue && mentions_stale && mentions_refresh && mentions_row_evidence
}

fn snapshot_has_queue_reverification_controls(snapshot: &str) -> bool {
    snapshot_sort_dropdown_state(snapshot).is_some()
        && (snapshot_apply_filters_button_id(snapshot).is_some()
            || snapshot_lower_text(snapshot).contains("queue search")
            || snapshot_lower_text(snapshot).contains("queue status filter"))
}

fn recent_goal_requires_queue_reverification(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| {
            let lower = message.content.to_ascii_lowercase();
            lower.contains("refresh the queue")
                || lower.contains("refresh the list")
                || lower.contains("queue view is stale")
                || lower.contains("row order")
                || lower.contains("row state")
        })
}

fn stale_queue_reverification_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let apply_control_id = snapshot_apply_filters_button_id(snapshot);
    let refresh_already_observed = apply_control_id.as_deref().is_some_and(|semantic_id| {
        recent_successful_click_semantic_id(history).as_deref() == Some(semantic_id)
            && (current_snapshot.is_some()
                || recent_successful_click_is_observed_in_later_snapshot(history, semantic_id))
    });
    if refresh_already_observed {
        return None;
    }

    let goal_requires_queue_reverification = recent_goal_requires_queue_reverification(history);
    let inferred_post_confirm_queue_reverification = goal_requires_queue_reverification
        && recent_confirmation_queue_return(history)
        && snapshot_has_queue_reverification_controls(snapshot);
    if !snapshot_has_stale_queue_reverification_marker(snapshot)
        && !inferred_post_confirm_queue_reverification
    {
        return None;
    }

    let sort_dropdown = snapshot_sort_dropdown_state(snapshot)?;
    let apply_control = apply_control_id
        .map(|id| format!("`{id}`"))
        .unwrap_or_else(|| "the visible refresh/apply control".to_string());
    let requested_sort = recent_requested_sort_label(history);
    let current_value = sort_dropdown
        .value
        .as_deref()
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());

    if let Some(requested_sort) = requested_sort {
        if current_value
            .as_deref()
            .is_some_and(|current| current.eq_ignore_ascii_case(&requested_sort))
        {
            return Some(format!(
                "Stale queue/list view: row order is not evidence yet. `{}` already shows `{}`, but the list still needs refresh. Do not open ticket/history links or call `browser__snapshot` again. Use {} now, then verify row order on the updated queue.",
                sort_dropdown.semantic_id, requested_sort, apply_control
            ));
        }

        if let Some(current_value) = current_value {
            return Some(format!(
                "Stale queue/list view: row order is not evidence yet. `{}` still shows `{}`. Do not open ticket/history links or call `browser__snapshot` again. Use `browser__select_dropdown` on `{}` to choose `{}`, then use {} to refresh before verifying row order.",
                sort_dropdown.semantic_id,
                current_value,
                sort_dropdown.semantic_id,
                requested_sort,
                apply_control
            ));
        }

        return Some(format!(
            "Stale queue/list view: row order is not evidence yet. Do not open ticket/history links or call `browser__snapshot` again. Use `browser__select_dropdown` on `{}` to choose `{}`, then use {} to refresh before verifying row order.",
            sort_dropdown.semantic_id, requested_sort, apply_control
        ));
    }

    Some(format!(
        "Stale queue/list view: row order is not evidence yet. Do not open ticket/history links or call `browser__snapshot` again. Reapply the visible queue controls, then use {} to refresh before verifying row order.",
        apply_control
    ))
}

fn queue_reverification_history_follow_up_pending_signal_for_snapshot(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if snapshot_has_history_page_marker(snapshot) {
        return None;
    }
    if !recent_history_viewed_item_ids(history).is_empty() {
        return None;
    }
    if !recent_confirmation_queue_return(history) {
        return None;
    }

    let sort_dropdown = snapshot_sort_dropdown_state(snapshot)?;
    let requested_sort = recent_requested_sort_label(history)?;
    let current_sort = sort_dropdown.value.as_deref()?;
    if !current_sort.eq_ignore_ascii_case(&requested_sort) {
        return None;
    }

    let apply_button_id = snapshot_apply_filters_button_id(snapshot)?;
    if recent_successful_click_semantic_id(history).as_deref() != Some(apply_button_id.as_str()) {
        return None;
    }

    let goal_items = recent_goal_item_sequence(history);
    if goal_items.len() < 2 {
        return None;
    }
    let target_item = &goal_items[0];
    let distractor_item = &goal_items[1];

    let visible_order = snapshot_visible_item_order(snapshot);
    let target_idx = visible_order
        .iter()
        .position(|item_id| item_id.eq_ignore_ascii_case(target_item))?;
    let distractor_idx = visible_order
        .iter()
        .position(|item_id| item_id.eq_ignore_ascii_case(distractor_item))?;
    if target_idx >= distractor_idx {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    if expectation.assignee.is_none() && expectation.status.is_none() {
        return None;
    }

    let target_ticket_link = snapshot_ticket_link_for_item(snapshot, target_item)?;
    let target_context = target_ticket_link.context.as_deref()?;
    if let Some(expected_assignee) = expectation.assignee.as_deref() {
        if !contains_ascii_case_insensitive(target_context, expected_assignee) {
            return None;
        }
    }
    if let Some(expected_status) = expectation.status.as_deref() {
        if !contains_ascii_case_insensitive(target_context, expected_status) {
            return None;
        }
    }

    let distractor_history_link = snapshot_history_link_for_item(snapshot, distractor_item)?;
    let mut matched_fields = Vec::new();
    if let Some(expected_assignee) = expectation.assignee.as_deref() {
        matched_fields.push(format!("assignee `{expected_assignee}`"));
    }
    if let Some(expected_status) = expectation.status.as_deref() {
        matched_fields.push(format!("status `{expected_status}`"));
    }
    let matched_clause = if matched_fields.is_empty() {
        String::new()
    } else {
        format!(" with {}", matched_fields.join(" and "))
    };

    Some(format!(
        "The refreshed queue already shows `{target_item}` ahead of `{distractor_item}` under `{requested_sort}`{matched_clause}. Do not reopen `{target_item}` or spend the next step on another `browser__snapshot`. Continue the remaining verification on `{distractor_item}` by using `{}` now.",
        distractor_history_link.semantic_id
    ))
}

fn queue_reverification_history_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    current_snapshot
        .and_then(|snapshot| {
            queue_reverification_history_follow_up_pending_signal_for_snapshot(snapshot, history)
        })
        .or_else(|| {
            history
                .iter()
                .rev()
                .find_map(browser_snapshot_payload)
                .and_then(|snapshot| {
                    queue_reverification_history_follow_up_pending_signal_for_snapshot(
                        snapshot, history,
                    )
                })
        })
}

fn dropdown_success_signal_for_message(
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    let (dropdown_id, selected_label) = dropdown_selection_details(message)?;

    if let Some(snapshot) = snapshot {
        if !snapshot_mentions_dropdown_locator(snapshot, &dropdown_id) {
            return None;
        }
    }

    let mut signal = format!(
        "A recent browser dropdown selection already succeeded: `{}` is now `{}`. Do not select the same dropdown again.",
        dropdown_id, selected_label
    );

    if let Some(snapshot) = snapshot {
        let next_controls = next_visible_follow_up_controls(snapshot, &[dropdown_id.as_str()]);
        if !next_controls.is_empty() {
            signal.push_str(&format!(
                " Continue with the next required action on another visible control such as `{}`.",
                next_controls.join("`, `")
            ));
        } else {
            signal.push_str(" Continue with the next required action on another visible control.");
        }
    } else {
        signal.push_str(" Continue with the next required action.");
    }

    Some(signal)
}

fn next_visible_follow_up_controls(snapshot: &str, excluded_ids: &[&str]) -> Vec<String> {
    let excluded = excluded_ids.iter().copied().collect::<HashSet<_>>();
    let remaining_targets = extract_priority_browser_targets(snapshot, 8)
        .into_iter()
        .filter_map(|summary| {
            let semantic_id = priority_target_semantic_id(&summary)?;
            (!excluded.contains(semantic_id)).then_some(summary)
        })
        .collect::<Vec<_>>();
    let mut next_controls = Vec::new();

    for summary in &remaining_targets {
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if !matches!(tag, "link" | "heading") {
            push_unique_control(&mut next_controls, semantic_id);
            if next_controls.len() == 3 {
                return next_controls;
            }
        }
    }

    for summary in &remaining_targets {
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if matches!(tag, "heading") || summary.contains("name=History") {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    for summary in &remaining_targets {
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if matches!(tag, "heading") {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    next_controls
}

fn push_unique_control(controls: &mut Vec<String>, semantic_id: &str) {
    if controls.iter().any(|existing| existing == semantic_id) {
        return;
    }
    controls.push(semantic_id.to_string());
}

fn snapshot_has_confirmation_page_marker(snapshot: &str) -> bool {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id_lower = dom_id.to_ascii_lowercase();
        let selector_lower = selector.to_ascii_lowercase();

        if dom_id_lower.contains("assignment-banner")
            || dom_id_lower.contains("status-summary")
            || dom_id_lower.contains("note-summary")
            || dom_id_lower.contains("save-status")
            || selector_lower.contains("assignment-banner")
            || selector_lower.contains("status-summary")
            || selector_lower.contains("note-summary")
            || selector_lower.contains("save-status")
        {
            return true;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        if name_lower.contains("assignment confirmation")
            || name_lower.contains("saved status:")
            || name_lower.contains("saved note:")
        {
            return true;
        }
    }

    false
}

fn snapshot_confirmation_summary(
    snapshot: &str,
    dom_id_needle: &str,
    name_needle: &str,
) -> Option<String> {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id_lower = dom_id.to_ascii_lowercase();
        let selector_lower = selector.to_ascii_lowercase();

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        if dom_id_lower.contains(dom_id_needle)
            || selector_lower.contains(dom_id_needle)
            || name_lower.contains(name_needle)
        {
            return Some(name);
        }
    }

    None
}

fn snapshot_confirmation_assignment_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "assignment-banner", "routed to")
}

fn snapshot_confirmation_status_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "status-summary", "saved status:")
}

fn snapshot_confirmation_note_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "note-summary", "saved note:")
}

fn snapshot_ticket_item_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="h1""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !name.to_ascii_lowercase().contains("ticket") {
            continue;
        }
        if let Some(item_id) = first_item_like_id(&name) {
            return Some(item_id);
        }
    }

    first_item_like_id(snapshot)
}

fn confirmation_summary_value(summary: &str) -> &str {
    let summary = summary.trim();
    if let Some((_, value)) = summary.rsplit_once(':') {
        return value.trim();
    }
    if let Some((_, value)) = summary.rsplit_once("routed to") {
        return value.trim().trim_end_matches('.');
    }
    summary
}

fn confirmation_summary_mismatch(
    observed_summary: Option<&str>,
    expected_value: Option<&str>,
    label: &str,
) -> Option<String> {
    let expected_value = expected_value?.trim();
    if expected_value.is_empty() {
        return None;
    }

    let expected_lower = expected_value.to_ascii_lowercase();
    match observed_summary {
        Some(summary) if summary.to_ascii_lowercase().contains(&expected_lower) => None,
        Some(summary) => Some(format!(
            "{label} shows `{}`, not `{expected_value}`",
            confirmation_summary_value(&compact_ws_for_prompt(summary))
        )),
        None => Some(format!("{label} is still missing `{expected_value}`")),
    }
}

fn confirmation_page_saved_state_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_confirmation_page_marker(snapshot) {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let assignment_summary = snapshot_confirmation_assignment_summary(snapshot);
    let status_summary = snapshot_confirmation_status_summary(snapshot);
    let note_summary = snapshot_confirmation_note_summary(snapshot);

    let mismatch = confirmation_summary_mismatch(
        assignment_summary.as_deref(),
        expectation.assignee.as_deref(),
        "the saved assignee",
    )
    .or_else(|| {
        confirmation_summary_mismatch(
            status_summary.as_deref(),
            expectation.status.as_deref(),
            "the saved status",
        )
    })
    .or_else(|| {
        confirmation_summary_mismatch(
            note_summary.as_deref(),
            expectation.note.as_deref(),
            "the saved note",
        )
    })?;

    let current_item = assignment_summary
        .as_deref()
        .and_then(first_item_like_id)
        .or_else(|| recent_goal_item_ids(history).into_iter().next());
    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    let reopen_button_id = snapshot_reopen_button_id(snapshot)?;
    Some(format!(
        "Use `{reopen_button_id}` now: the current confirmation page{item_clause} does not yet reflect the recent saved update because {mismatch}. Do not spend the next step on `browser__snapshot` or queue/history verification."
    ))
}

fn dispatch_update_resume_clause(expectation: &DispatchUpdateExpectation) -> Option<String> {
    let mut values = Vec::new();
    if let Some(value) = expectation.assignee.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.status.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.note.as_deref() {
        values.push(format!("`{value}`"));
    }
    if values.is_empty() {
        return None;
    }

    Some(match values.len() {
        1 => format!("Reapply or verify {} on this page", values[0]),
        2 => format!(
            "Reapply or verify {} and {} on this page",
            values[0], values[1]
        ),
        _ => {
            let last = values.pop().unwrap_or_default();
            format!(
                "Reapply or verify {}, and {} on this page",
                values.join(", "),
                last
            )
        }
    })
}

fn dispatch_update_review_clause(expectation: &DispatchUpdateExpectation) -> Option<String> {
    let mut values = Vec::new();
    if let Some(value) = expectation.assignee.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.status.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.note.as_deref() {
        values.push(format!("`{value}`"));
    }
    if values.is_empty() {
        return None;
    }

    Some(match values.len() {
        1 => format!("Verify the reviewed draft still shows {}", values[0]),
        2 => format!(
            "Verify the reviewed draft still shows {} and {}",
            values[0], values[1]
        ),
        _ => {
            let last = values.pop().unwrap_or_default();
            format!(
                "Verify the reviewed draft still shows {}, and {}",
                values.join(", "),
                last
            )
        }
    })
}

fn reopened_draft_resume_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_contains_semantic_id(snapshot, "btn_review_update") {
        return None;
    }
    if recent_successful_click_semantic_id(history).as_deref() != Some("btn_reopen_ticket") {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let resume_clause = dispatch_update_resume_clause(&expectation)
        .unwrap_or_else(|| "Continue correcting the current draft on this page".to_string());
    let item_clause = snapshot_ticket_item_id(snapshot)
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    Some(format!(
        "The draft{item_clause} is reopened so the saved state can be corrected. Do not return to queue/history verification yet. {resume_clause}, then use `btn_review_update`."
    ))
}

fn reviewed_draft_confirmation_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let confirm_button_id = snapshot_confirm_update_button_id(snapshot)?;
    if recent_successful_click_semantic_id(history).as_deref() != Some("btn_review_update") {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let review_clause = dispatch_update_review_clause(&expectation)
        .unwrap_or_else(|| "Verify the reviewed draft matches the intended update".to_string());
    let item_clause = snapshot_ticket_item_id(snapshot)
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();
    let edit_clause = snapshot_edit_draft_button_id(snapshot)
        .map(|edit_button_id| {
            format!(" Use `{edit_button_id}` instead only if the reviewed draft is wrong.")
        })
        .unwrap_or_default();

    Some(format!(
        "The reviewed draft{item_clause} is ready to be saved. {review_clause}, then use `{confirm_button_id}` now.{edit_clause} Do not return to queue/history verification until the draft is confirmed."
    ))
}

fn ranked_result_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let request = recent_requested_result_rank(history)?;
    let visible_results = snapshot_visible_result_links(snapshot);
    if visible_results.is_empty() {
        return None;
    }

    let instruction_token = snapshot_visible_exact_text_target(snapshot, &request.ordinal_text)
        .filter(|target| {
            matches!(
                target.semantic_role.as_str(),
                "generic" | "label" | "text" | "heading"
            )
        })?;
    let repeated_submit_clause = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| {
            semantic_id_is_submit_like(semantic_id)
                || semantic_id.to_ascii_lowercase().contains("search")
        })
        .filter(|semantic_id| {
            recent_successful_click_has_post_action_observation(
                history,
                semantic_id,
                current_snapshot,
            )
        })
        .map(|semantic_id| {
            format!(" The search results are already updated, so do not use `{semantic_id}` again.")
        })
        .unwrap_or_default();
    let results_per_page = visible_results.len();
    let explicit_visible_ranks = visible_results
        .iter()
        .filter_map(snapshot_link_result_rank)
        .collect::<Vec<_>>();
    let (page_start_rank, page_end_rank) = if explicit_visible_ranks.is_empty() {
        let current_page = recent_clicked_pagination_page_number(history, snapshot).unwrap_or(1);
        let page_start_rank = current_page.saturating_sub(1) * results_per_page + 1;
        let page_end_rank = page_start_rank + results_per_page.saturating_sub(1);
        (page_start_rank, page_end_rank)
    } else {
        (
            *explicit_visible_ranks.iter().min()?,
            *explicit_visible_ranks.iter().max()?,
        )
    };

    if request.rank < page_start_rank || request.rank > page_end_rank {
        let target_page = (request.rank + results_per_page - 1) / results_per_page;
        let page_control = snapshot_pagination_link_for_page(snapshot, target_page)
            .or_else(|| snapshot_next_pagination_link(snapshot));
        let recent_instruction_click = recent_successful_click_semantic_id(history).as_deref()
            == Some(instruction_token.semantic_id.as_str());
        let page_hint = page_control
            .as_ref()
            .map(|link| {
                format!(
                    "Use `browser__click_element` on `{}` now to reach result {}.",
                    link.semantic_id, request.rank
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "Use a visible pagination control now to reach result {}.",
                    request.rank
                )
            });
        let recovery_clause = if recent_instruction_click {
            " That recent click hit the instruction token, not a result, so do not finish."
        } else {
            ""
        };

        return Some(format!(
            "{} `{}` is the instruction token for `{}`, not a search result. Only {} actual result links are visible here (ranks {}-{}), so result {} is still off-screen. Do not click `{}`, do not use `browser__scroll`, and do not spend the next step on `browser__snapshot`.{}{}",
            page_hint,
            instruction_token.semantic_id,
            request.ordinal_text,
            results_per_page,
            page_start_rank,
            page_end_rank,
            request.rank,
            instruction_token.semantic_id,
            recovery_clause,
            repeated_submit_clause,
        ));
    }

    let target_result = visible_results
        .iter()
        .find(|link| snapshot_link_result_rank(link) == Some(request.rank))
        .or_else(|| {
            let local_index = request.rank.saturating_sub(page_start_rank);
            visible_results.get(local_index)
        })?;
    if recent_successful_click_has_post_action_observation(
        history,
        &target_result.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    let result_name = target_result
        .name
        .as_deref()
        .unwrap_or(target_result.semantic_id.as_str());
    let recent_instruction_click = recent_successful_click_semantic_id(history).as_deref()
        == Some(instruction_token.semantic_id.as_str());
    let recovery_clause = if recent_instruction_click {
        " The recent click on the instruction token did not satisfy the task, so do not finish."
    } else {
        ""
    };

    Some(format!(
        "Use `browser__click_element` on `{}` now. Result {} on this page is visible result link `{}` (`{}`). `{}` is the visible instruction token for `{}`, not the result to click. Do not use `browser__scroll`, do not spend the next step on `browser__snapshot`, and do not click `{}` or finish.{}{}",
        target_result.semantic_id,
        request.rank,
        target_result.semantic_id,
        result_name,
        instruction_token.semantic_id,
        request.ordinal_text,
        instruction_token.semantic_id,
        recovery_clause,
        repeated_submit_clause,
    ))
}

fn instruction_only_find_text_pagination_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let recent_find = recent_find_text_state(history)?;
    if recent_find
        .first_snippet
        .as_deref()
        .is_some_and(|snippet| !contains_ascii_case_insensitive(snippet, &recent_find.query))
    {
        return None;
    }
    if snapshot_visible_exact_text_target(snapshot, &recent_find.query).is_some() {
        return None;
    }

    let instruction_token =
        snapshot_visible_instruction_query_target(snapshot, &recent_find.query)?;
    let page_control = snapshot_forward_pagination_link(snapshot)?;
    let current_heading = snapshot_primary_visible_heading(snapshot)
        .filter(|heading| !contains_ascii_case_insensitive(&heading.name, &recent_find.query));

    Some(match current_heading {
        Some(heading) => format!(
            "`{}` is not on the current record `{}`. Do not click this record's links. The only valid next `browser__click_element` id here is `{}`. Use it now. Do not invent ids or repeat `browser__find_text`.",
            recent_find.query,
            heading.name,
            page_control.semantic_id,
        ),
        None => format!(
            "Recent `browser__find_text` for `{}` matched instruction token `{}`, not the current record. The only valid next `browser__click_element` id here is `{}`. Use it now. Do not invent ids, repeat `browser__find_text`, or spend the next step on `browser__snapshot`.",
            recent_find.query,
            instruction_token.semantic_id,
            page_control.semantic_id,
        ),
    })
}

fn alternate_tab_exploration_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let tabs = snapshot_tab_states(snapshot);
    if tabs.len() < 2 {
        return None;
    }

    let recent_tab_click_ids = recent_successful_tab_click_ids(history, snapshot);
    let focused_tab = tabs.iter().find(|tab| tab.focused).or_else(|| {
        recent_tab_click_ids
            .first()
            .and_then(|tab_id| tabs.iter().find(|tab| tab.semantic_id == *tab_id))
    })?;
    if !recent_tab_click_ids.contains(&focused_tab.semantic_id) {
        return None;
    }

    let target = recent_goal_primary_target(history)?;
    let panel_text = focused_tab
        .controls_dom_id
        .as_deref()
        .and_then(|controls_dom_id| {
            snapshot_tabpanel_states(snapshot)
                .into_iter()
                .find(|panel| panel.visible && panel.dom_id.as_deref() == Some(controls_dom_id))
                .and_then(|panel| panel.name)
        })?;
    if contains_ascii_case_insensitive(&panel_text, &target) {
        return None;
    }

    let mut candidate_tab_ids = tabs
        .iter()
        .filter(|tab| tab.semantic_id != focused_tab.semantic_id)
        .filter(|tab| !recent_tab_click_ids.contains(&tab.semantic_id))
        .map(|tab| tab.semantic_id.clone())
        .collect::<Vec<_>>();
    if candidate_tab_ids.is_empty() {
        candidate_tab_ids = tabs
            .iter()
            .filter(|tab| tab.semantic_id != focused_tab.semantic_id)
            .map(|tab| tab.semantic_id.clone())
            .collect();
    }
    if candidate_tab_ids.is_empty() {
        return None;
    }

    let focused_label = focused_tab
        .name
        .as_deref()
        .unwrap_or(focused_tab.semantic_id.as_str());
    let candidate_clause = candidate_tab_ids
        .iter()
        .take(3)
        .map(|tab_id| format!("`{tab_id}`"))
        .collect::<Vec<_>>()
        .join(" or ");

    Some(format!(
        "The currently expanded section `{focused_label}` does not show the target text `{target}`. Do not click `{}` again, and do not spend the next step on another `browser__snapshot`. Use another visible section tab such as {candidate_clause} now. When `{target}` becomes visible, click that target directly.",
        focused_tab.semantic_id,
    ))
}

fn visible_target_click_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_primary_target(history)?;
    let candidate = snapshot_visible_exact_text_target(snapshot, &target)?;

    if recent_successful_click_has_post_action_observation(
        history,
        &candidate.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    Some(format!(
        "The target text `{target}` is already visible as `{}`. Use `browser__click_element` on `{}` now. Do not click a surrounding container or panel, do not use `browser__find_text`, and do not spend the next step on another `browser__snapshot`.",
        candidate.semantic_id, candidate.semantic_id
    ))
}

fn browser_effect_success_signal_for_message(
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
        && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    if compact.contains("\"typed\":{") && compact.contains("\"already_satisfied\":true") {
        return Some(
            "A recent browser typing action found that the targeted field already contained the requested text. Do not type the same text into that field again. Continue with the next required control or verify the updated page state if needed.".to_string(),
        );
    }

    if has_click_postcondition_success
        && compact.contains("Clicked element")
        && (compact.contains("\"checked\":true") || compact.contains("\"selected\":true"))
    {
        return Some(
            "A recent browser interaction already selected a form control (`checked=true` or `selected=true`). Do not click the surrounding option group or form container again. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.".to_string(),
        );
    }

    if has_click_postcondition_success && compact.contains("Clicked element") {
        let clicked_id = clicked_element_semantic_id(message);
        let mut signal = "A recent browser interaction already reported observable state change (`postcondition.met=true`). Do not repeat the same interaction.".to_string();
        if let Some(snapshot) = snapshot {
            let next_controls = next_visible_follow_up_controls(
                snapshot,
                &clicked_id.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            if !next_controls.is_empty() {
                signal.push_str(&format!(
                    " Continue with another visible control such as `{}`.",
                    next_controls.join("`, `")
                ));
                signal.push_str(
                    " Do not spend the next step on another `browser__snapshot` unless those controls disappear or the page changes again.",
                );
            } else {
                signal.push_str(
                    " Verify once if needed, then finish with `agent__complete` when the goal is satisfied.",
                );
            }
        } else {
            signal.push_str(
                " Verify once if needed, then finish with `agent__complete` when the goal is satisfied.",
            );
        }
        return Some(signal);
    }

    if compact.contains("\"selected\":{")
        && (compact.contains("\"label\":") || compact.contains("\"value\":"))
    {
        return Some(
            "A recent browser dropdown selection already succeeded. Do not repeat the same selection. Use the updated browser state to continue with the next required action or finish if the goal is already satisfied.".to_string(),
        );
    }

    if compact.contains("identical action already succeeded on the previous step") {
        return Some(
            "The identical action already succeeded on the previous step. Do not repeat it. Verify the updated state or finish with the gathered evidence.".to_string(),
        );
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"Home\"") || compact.contains("\"key\":\"PageUp\""))
        && compact.contains("\"scroll_top\":0")
        && compact.contains("\"can_scroll_up\":false")
    {
        return Some(
            "A recent browser key already moved the focused scrollable control to its top edge. Do not repeat the same key. Verify once if needed, then continue with the next required action or finish if the goal is satisfied.".to_string(),
        );
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"End\"") || compact.contains("\"key\":\"PageDown\""))
        && compact.contains("\"can_scroll_down\":false")
    {
        return Some(
            "A recent browser key already moved the focused scrollable control to its bottom edge. Do not repeat the same key. Verify once if needed, then continue with the next required action or finish if the goal is satisfied.".to_string(),
        );
    }

    None
}

fn submitted_selection_turnover_success_signal(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<String> {
    if !recent_goal_mentions_submit(history) {
        return None;
    }

    let submit_id = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| semantic_id_is_submit_like(semantic_id))?;
    if !recent_successful_click_has_post_action_observation(history, &submit_id, Some(snapshot)) {
        return None;
    }

    let selected_control_id = recent_successful_selected_control_semantic_id(history)?;
    if snapshot_contains_semantic_id(snapshot, &selected_control_id) {
        return None;
    }

    let target = recent_goal_primary_target(history)?;
    if contains_ascii_case_insensitive(snapshot, &target) {
        return None;
    }

    Some(format!(
        "`{submit_id}` turned over the page: target `{target}` and `{selected_control_id}` are gone in the current browser observation. Do not use the new page's controls. Call `agent__complete` now."
    ))
}

fn recent_browser_success_signal(
    history: &[ChatMessage],
    snapshot: Option<&str>,
) -> Option<String> {
    let snapshot = snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload));

    if let Some(snapshot) = snapshot {
        if let Some(signal) = submitted_selection_turnover_success_signal(history, snapshot) {
            return Some(signal);
        }
    }

    for message in history.iter().rev() {
        if let Some(signal) = dropdown_success_signal_for_message(message, snapshot) {
            return Some(signal);
        }
        if dropdown_selection_details(message).is_some() {
            continue;
        }
        if let Some(signal) = browser_effect_success_signal_for_message(message, snapshot) {
            return Some(signal);
        }
    }

    None
}

pub(super) fn build_browser_observation_context_from_snapshot(snapshot: &str) -> String {
    let mut assistive_hints = extract_assistive_browser_hints(snapshot);
    if let Some(scroll_target_hint) = extract_scroll_target_focus_hint(snapshot) {
        assistive_hints.push(scroll_target_hint);
    }
    let compact_observation = compact_browser_observation(snapshot);
    if compact_observation.is_empty() {
        return String::new();
    }

    let assistive_context = if assistive_hints.is_empty() {
        String::new()
    } else {
        format!("ASSISTIVE BROWSER HINTS: {}\n", assistive_hints.join(" | "))
    };

    format!(
        "RECENT BROWSER OBSERVATION:\n{}{}\nUse this semantic browser evidence directly when selecting the next browser action.\n",
        assistive_context, compact_observation
    )
}

fn browser_effect_pending_signal(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if compact.contains("\"autocomplete\":{")
        && (compact.contains("\"assistive_hint\":")
            || compact.contains("\"active_descendant_dom_id\":")
            || compact.contains("\"controls_dom_id\":"))
    {
        if compact.contains("\"key\":{") {
            if compact.contains("\"key\":\"ArrowDown\"") || compact.contains("\"key\":\"ArrowUp\"")
            {
                return Some("A recent browser navigation key updated the active autocomplete candidate, but the widget is still open. If the highlighted candidate is the intended choice, press `Enter` to commit it before submitting. Otherwise continue navigating or use `browser__snapshot` to verify.".to_string());
            }
            return Some("A recent browser key press left autocomplete active, so that key did not resolve the widget. Do not submit or finish. Use `browser__key` with a different navigation key (for example `ArrowDown` or `ArrowUp`) or take `browser__snapshot` to ground the candidate before committing.".to_string());
        }

        return Some("A recent browser action surfaced active autocomplete state. This widget is not resolved yet. Do not submit or finish until you explicitly commit or dismiss the suggestion, usually by checking updated browser state or using `browser__key`.".to_string());
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"tag_name\":\"body\"") || compact.contains("\"tag_name\":\"html\""))
    {
        return Some("A recent browser key landed on the page itself, not on a specific control. Do not repeat the same key blindly. If you intended a textarea, listbox, or nested scroll region, focus that control first with `browser__click_element` or `browser__click`, then send the key again.".to_string());
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"Home\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control with `can_scroll_up=true`. Do not call `{}` again, and do not submit or finish yet. Use `PageUp` next, and stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_name(),
                top_edge_jump_name(),
            ));
        }

        if let Some(scroll_top) = focused_home_should_jump_to_top_edge(&compact) {
            return Some(format!(
                "`Home` left a focused scrollable control far from top (`scroll_top={scroll_top}`, `can_scroll_up=true`). Do not use `Home` again or spend the next step on `PageUp`. Do not submit yet. Use `{}` next. Stop only at top (`can_scroll_up=false` or `scroll_top=0`).",
                top_edge_jump_call(),
            ));
        }

        return Some(format!(
            "A recent `Home` key still left the focused scrollable control with `can_scroll_up=true`. Do not call `Home` again, and do not submit or finish yet. Use `PageUp` or `{}` next. Stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageUp\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        return Some(format!(
            "A recent `PageUp` still left the focused scrollable control with `can_scroll_up=true`. Do not submit yet. Continue upward or use `{}`. Stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"End\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control with `can_scroll_down=true`. Do not call `{}` again, and do not submit or finish yet. Use `PageDown` next, and stop only when grounded state shows `can_scroll_down=false`.",
                bottom_edge_jump_name(),
                bottom_edge_jump_name(),
            ));
        }

        return Some(format!(
            "A recent `End` key still left the focused scrollable control with `can_scroll_down=true`. Do not call `End` again, and do not submit or finish yet. Use `PageDown` or `{}` next. Stop only when grounded state shows `can_scroll_down=false`.",
            bottom_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageDown\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        return Some(format!(
            "A recent `PageDown` still left the focused scrollable control with `can_scroll_down=true`. Do not submit yet. Continue downward or use `{}`. Stop only when grounded state shows `can_scroll_down=false`.",
            bottom_edge_jump_call(),
        ));
    }

    if compact.contains("\"scroll\":{")
        && compact.contains("\"page_moved\":false")
        && compact.contains("\"target_moved\":false")
    {
        return Some("A recent browser scroll had no grounded effect on the page or the current scrollable control. Do not repeat the same blind scroll. First verify or focus the intended scroll container with `browser__snapshot`, then use a control-local action such as `browser__key` (`Home`, `End`, `PageUp`, or `PageDown`) or a better-targeted scroll.".to_string());
    }

    if compact.contains("\"focused_control\":{")
        && compact.contains("\"focused\":true")
        && (compact.contains("\"can_scroll_up\":true")
            || compact.contains("\"can_scroll_down\":true"))
        && compact.contains("Clicked element")
    {
        return Some("A recent browser click already focused a scrollable control. Do not keep clicking the surrounding wrapper or container. If the goal is control-local scrolling or text selection in that control, continue there with a control-local action such as `browser__key` or `browser__select_text`; otherwise move to the next required visible control.".to_string());
    }

    None
}

fn repeated_pagewise_scroll_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let mut repeated_page_up = 0usize;
    let mut repeated_page_down = 0usize;

    for message in history.iter().rev() {
        if message.role != "tool" {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        if compact.contains("\"key\":{")
            && compact.contains("\"focused\":true")
            && compact.contains("\"key\":\"PageUp\"")
            && compact.contains("\"can_scroll_up\":true")
        {
            repeated_page_up += 1;
            repeated_page_down = 0;
            if repeated_page_up >= 2 {
                return Some(format!(
                    "Several recent `PageUp` steps still left the focused scrollable control with `can_scroll_up=true`. If the goal is the top edge, stop spending steps on repeated `PageUp`. Use `{}` next, then verify grounded state shows `can_scroll_up=false` or `scroll_top=0` before submitting or finishing.",
                    top_edge_jump_call(),
                ));
            }
            continue;
        }

        if compact.contains("\"key\":{")
            && compact.contains("\"focused\":true")
            && compact.contains("\"key\":\"PageDown\"")
            && compact.contains("\"can_scroll_down\":true")
        {
            repeated_page_down += 1;
            repeated_page_up = 0;
            if repeated_page_down >= 2 {
                return Some(format!(
                    "Several recent `PageDown` steps still left the focused scrollable control with `can_scroll_down=true`. If the goal is the bottom edge, stop spending steps on repeated `PageDown`. Use `{}` next, then verify grounded state shows `can_scroll_down=false` before submitting or finishing.",
                    bottom_edge_jump_call(),
                ));
            }
            continue;
        }

        if repeated_page_up > 0 || repeated_page_down > 0 {
            break;
        }
    }

    None
}

fn navigation_observation_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let transition = recent_unobserved_navigation_transition(history)?;
    let action = transition
        .semantic_id
        .map(|semantic_id| format!(" on `{semantic_id}`"))
        .unwrap_or_default();

    Some(format!(
        "A recent browser action{action} changed the page URL to `{}` but there is no newer `browser__snapshot` yet. The current browser observation may still describe the previous page. Do not act on stale element ids or finish yet. Take `browser__snapshot` now, then continue from the updated page state.",
        transition.post_url
    ))
}

fn auth_form_pending_signal_from_snapshot(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    let snapshot_lower = snapshot.to_ascii_lowercase();
    let has_password_field = snapshot_lower.contains(r#"dom_id="password""#)
        || snapshot_lower.contains(r#"name="password""#);
    let has_username_field = snapshot_lower.contains(r#"dom_id="username""#)
        || snapshot_lower.contains(r#"name="username""#)
        || snapshot_lower.contains(r#"dom_id="email""#)
        || snapshot_lower.contains(r#"name="email""#);
    let has_login_action = [
        r#"dom_id="sign-in""#,
        r#"dom_id="login""#,
        r#"dom_id="log-in""#,
        r#"name="sign in""#,
        r#"name="log in""#,
        r#"name="login""#,
    ]
    .iter()
    .any(|needle| snapshot_lower.contains(needle));

    if !has_password_field || !has_login_action {
        return None;
    }

    let mut typed_username = false;
    let mut typed_password = false;
    for message in history.iter().rev().take(8) {
        if message.role != "tool" {
            continue;
        }
        let compact = compact_ws_for_prompt(&message.content);
        if !compact.contains("\"typed\":{") {
            continue;
        }
        if compact.contains("\"selector\":\"#username\"")
            || compact.contains("\"selector\":\"#email\"")
            || compact.contains("\"dom_id\":\"username\"")
            || compact.contains("\"dom_id\":\"email\"")
        {
            typed_username = true;
        }
        if compact.contains("\"selector\":\"#password\"")
            || compact.contains("\"dom_id\":\"password\"")
        {
            typed_password = true;
        }
    }

    if typed_username && !typed_password {
        return Some("A visible browser auth form still includes a password field, and recent browser state only confirms the username or email entry. Do not click `Sign in` or submit yet. Fill the remaining password credential field first, then continue with the login action.".to_string());
    }

    if typed_password && !typed_username && has_username_field {
        return Some("A visible browser auth form still includes a username or email field, and recent browser state only confirms the password entry. Do not click `Sign in` or submit yet. Fill the remaining username or email field first, then continue with the login action.".to_string());
    }

    if typed_username && typed_password {
        return Some("A visible browser auth form still remains, and recent browser state confirms both credential fields were filled. Do not keep taking snapshots or retyping the same credentials. Use the login action now (for example `browser__click_element` on the visible sign-in button), then verify that the page changes.".to_string());
    }

    None
}

fn auth_form_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let snapshot = history.iter().rev().find_map(browser_snapshot_payload)?;
    auth_form_pending_signal_from_snapshot(snapshot, history)
}

fn filter_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    dropdown_filter_mismatch_pending_signal(snapshot, history)
}

pub(super) fn build_recent_command_history_context(
    command_history: &VecDeque<CommandExecution>,
) -> String {
    if command_history.is_empty() {
        return String::new();
    }

    let mut section = String::new();
    section.push_str(
        "\n## RECENT COMMAND EXECUTION HISTORY (Redacted/Reasoning-only)\nYou have access to recent sanitized command context for continuity.\n",
    );

    for (idx, entry) in command_history
        .iter()
        .rev()
        .take(MAX_PROMPT_HISTORY)
        .enumerate()
    {
        section.push_str(&format!(
            "{}. [Step {}] {} → exit={} (stdout: {} | stderr: {})\n",
            idx + 1,
            entry.step_index,
            entry.command,
            entry.exit_code,
            safe_truncate(&entry.stdout, 60),
            safe_truncate(&entry.stderr, 60),
        ));
    }

    section.push_str(
        "Use this context to avoid repeating failed commands and to build on successful steps.\n",
    );
    section
}

fn is_browser_snapshot_no_effect_message(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with(BROWSER_SNAPSHOT_TOOL_PREFIX)
        && compact.contains("ERROR_CLASS=NoEffectAfterAction")
}

fn is_browser_observation_refresh_message(message: &ChatMessage) -> bool {
    if browser_snapshot_payload(message).is_some() {
        return true;
    }

    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_success = (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    has_success && (compact.contains("browser__") || compact.contains("Clicked element"))
}

fn is_incident_follow_up_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("System: Remedy")
        || compact.starts_with("System: Incident")
        || compact.starts_with("System: Selected recovery action")
}

fn is_browser_context_echo_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("RECENT PENDING BROWSER STATE:")
        || compact.starts_with("RECENT SUCCESS SIGNAL:")
        || compact.starts_with("RECENT BROWSER OBSERVATION:")
}

fn explicit_pending_browser_state_context_message(message: &ChatMessage) -> Option<String> {
    if message.role != "system" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if !compact.starts_with("RECENT PENDING BROWSER STATE:") {
        return None;
    }

    let content = message.content.trim();
    (!content.is_empty()).then(|| content.to_string())
}

pub(crate) fn latest_recent_pending_browser_state_context(
    history: &[ChatMessage],
) -> Option<String> {
    let idx = history
        .iter()
        .rposition(|message| explicit_pending_browser_state_context_message(message).is_some())?;
    if history[idx + 1..]
        .iter()
        .any(is_browser_observation_refresh_message)
    {
        return None;
    }

    explicit_pending_browser_state_context_message(&history[idx])
}

fn filtered_recent_session_events<'a>(
    history: &'a [ChatMessage],
    prefer_browser_semantics: bool,
) -> Vec<&'a ChatMessage> {
    if !prefer_browser_semantics {
        return history.iter().collect();
    }

    let mut suppressed = HashSet::new();

    for (idx, message) in history.iter().enumerate() {
        if !is_browser_snapshot_no_effect_message(message) {
            continue;
        }

        if !history[idx + 1..]
            .iter()
            .any(is_browser_observation_refresh_message)
        {
            continue;
        }

        suppressed.insert(idx);
        let mut follow_up_idx = idx + 1;
        while follow_up_idx < history.len()
            && is_incident_follow_up_system_message(&history[follow_up_idx])
        {
            suppressed.insert(follow_up_idx);
            follow_up_idx += 1;
        }
    }

    history
        .iter()
        .enumerate()
        .filter_map(|(idx, message)| {
            if suppressed.contains(&idx) {
                return None;
            }

            if is_browser_context_echo_system_message(message) {
                return None;
            }

            if recent_unobserved_navigation_transition(history).is_none()
                && browser_snapshot_payload(message).is_some()
            {
                return None;
            }

            Some(message)
        })
        .collect()
}

pub(super) fn build_recent_session_events_context(
    history: &[ChatMessage],
    prefer_browser_semantics: bool,
) -> String {
    filtered_recent_session_events(history, prefer_browser_semantics)
        .into_iter()
        .map(|message| format!("{}: {}", message.role, message.content))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn build_recent_browser_observation_context(history: &[ChatMessage]) -> String {
    if recent_unobserved_navigation_transition(history).is_some() {
        return String::new();
    }

    let Some(observation) = history.iter().rev().find_map(browser_snapshot_payload) else {
        return String::new();
    };

    build_browser_observation_context_from_snapshot(observation)
}

pub(crate) fn build_recent_pending_browser_state_context(history: &[ChatMessage]) -> String {
    build_recent_pending_browser_state_context_with_snapshot(history, None)
}

pub(crate) fn build_recent_pending_browser_state_context_with_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> String {
    let has_current_snapshot = current_snapshot.is_some();
    let navigation_signal = if has_current_snapshot {
        None
    } else {
        navigation_observation_pending_signal(history)
    };

    let Some(signal) = navigation_signal
        .or_else(|| auth_form_pending_signal(history))
        .or_else(|| autocomplete_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| tree_change_link_reverification_pending_signal(history))
        .or_else(|| filter_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| ranked_result_pending_signal(history, current_snapshot))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, current_snapshot))
        .or_else(|| visible_target_click_pending_signal(history, current_snapshot))
        .or_else(|| alternate_tab_exploration_pending_signal(history, current_snapshot))
        .or_else(|| stale_queue_reverification_pending_signal(history, current_snapshot))
        .or_else(|| {
            queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
        })
        .or_else(|| {
            confirmation_page_saved_state_mismatch_pending_signal(history, current_snapshot)
        })
        .or_else(|| reviewed_draft_confirmation_pending_signal(history, current_snapshot))
        .or_else(|| reopened_draft_resume_pending_signal(history, current_snapshot))
        .or_else(|| history_page_verification_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| history_page_verification_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| history_verification_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| repeated_pagewise_scroll_pending_signal(history))
        .or_else(|| history.iter().rev().find_map(browser_effect_pending_signal))
    else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, PENDING_BROWSER_STATE_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT PENDING BROWSER STATE:\n{}\n", compact_signal)
}

pub(crate) fn build_recent_pending_browser_state_context_with_current_snapshot(
    history: &[ChatMessage],
    has_current_snapshot: bool,
) -> String {
    let current_snapshot = if has_current_snapshot {
        history.iter().rev().find_map(browser_snapshot_payload)
    } else {
        None
    };
    build_recent_pending_browser_state_context_with_snapshot(history, current_snapshot)
}

pub(crate) fn build_browser_snapshot_pending_state_context(snapshot: &str) -> String {
    build_browser_snapshot_pending_state_context_with_history(snapshot, &[])
}

pub(crate) fn build_browser_snapshot_pending_state_context_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let Some(signal) = auth_form_pending_signal_from_snapshot(snapshot, history)
        .or_else(|| autocomplete_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| tree_change_link_reverification_pending_signal(history))
        .or_else(|| dropdown_filter_mismatch_pending_signal(snapshot, history))
        .or_else(|| ranked_result_pending_signal(history, Some(snapshot)))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, Some(snapshot)))
        .or_else(|| visible_target_click_pending_signal(history, Some(snapshot)))
        .or_else(|| alternate_tab_exploration_pending_signal(history, Some(snapshot)))
        .or_else(|| stale_queue_reverification_pending_signal(history, Some(snapshot)))
        .or_else(|| queue_reverification_history_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| confirmation_page_saved_state_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| reviewed_draft_confirmation_pending_signal(history, Some(snapshot)))
        .or_else(|| reopened_draft_resume_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| history_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| browser_snapshot_pending_signal(snapshot))
    else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, PENDING_BROWSER_STATE_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT PENDING BROWSER STATE:\n{}\n", compact_signal)
}

pub(super) fn build_recent_success_signal_context(history: &[ChatMessage]) -> String {
    build_recent_success_signal_context_with_snapshot(history, None)
}

pub(super) fn build_recent_success_signal_context_with_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> String {
    let has_current_snapshot = current_snapshot.is_some();
    let navigation_signal = if has_current_snapshot {
        None
    } else {
        navigation_observation_pending_signal(history)
    };

    if navigation_signal.is_some()
        || auth_form_pending_signal(history).is_some()
        || autocomplete_follow_up_pending_signal(history, current_snapshot).is_some()
        || tree_change_link_reverification_pending_signal(history).is_some()
        || filter_mismatch_pending_signal(history, current_snapshot).is_some()
        || ranked_result_pending_signal(history, current_snapshot).is_some()
        || instruction_only_find_text_pagination_pending_signal(history, current_snapshot).is_some()
        || visible_target_click_pending_signal(history, current_snapshot).is_some()
        || alternate_tab_exploration_pending_signal(history, current_snapshot).is_some()
        || stale_queue_reverification_pending_signal(history, current_snapshot).is_some()
        || queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
            .is_some()
        || confirmation_page_saved_state_mismatch_pending_signal(history, current_snapshot)
            .is_some()
        || reviewed_draft_confirmation_pending_signal(history, current_snapshot).is_some()
        || reopened_draft_resume_pending_signal(history, current_snapshot).is_some()
        || history_page_verification_follow_up_pending_signal(history, current_snapshot).is_some()
        || history_page_verification_mismatch_pending_signal(history, current_snapshot).is_some()
        || history_verification_follow_up_pending_signal(history, current_snapshot).is_some()
    {
        return String::new();
    }

    let Some(signal) = recent_browser_success_signal(history, current_snapshot) else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, SUCCESS_SIGNAL_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT SUCCESS SIGNAL:\n{}\n", compact_signal)
}

pub(super) fn build_browser_snapshot_success_signal_context(snapshot: &str) -> String {
    let Some(signal) = browser_snapshot_success_signal(snapshot) else {
        return String::new();
    };

    let compact_signal = safe_truncate(signal, SUCCESS_SIGNAL_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT SUCCESS SIGNAL:\n{}\n", compact_signal)
}

#[cfg(test)]
mod tests {
    use super::{
        build_browser_observation_context_from_snapshot,
        build_browser_snapshot_pending_state_context,
        build_browser_snapshot_pending_state_context_with_history,
        build_browser_snapshot_success_signal_context, build_recent_browser_observation_context,
        build_recent_pending_browser_state_context,
        build_recent_pending_browser_state_context_with_current_snapshot,
        build_recent_pending_browser_state_context_with_snapshot,
        build_recent_session_events_context, build_recent_success_signal_context,
        build_recent_success_signal_context_with_snapshot, extract_priority_browser_targets,
        latest_recent_pending_browser_state_context, recent_goal_primary_target,
        recent_history_return_item_id, top_edge_jump_call, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS,
    };
    use ioi_types::app::agentic::ChatMessage;

    fn chat_message(role: &str, content: &str, timestamp: u64) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: content.to_string(),
            timestamp,
            trace_hash: None,
        }
    }

    #[test]
    fn browser_observation_context_uses_latest_browser_snapshot_even_after_system_chatter() {
        let history = vec![
            chat_message("user", "Click Mark complete", 1),
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
                2,
            ),
            chat_message(
                "system",
                "System: Incident resolved after retry root.",
                3,
            ),
            chat_message(
                "system",
                "System: Selected recovery action `browser__scroll`.",
                4,
            ),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.contains("RECENT BROWSER OBSERVATION:"));
        assert!(context.contains("btn_mark_complete"));
        assert!(context.contains("Mark complete"));
    }

    #[test]
    fn browser_observation_context_prefers_semantic_snapshot_over_later_snapshot_error() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                2,
            ),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.contains("btn_mark_complete"));
        assert!(!context.contains("ERROR_CLASS=NoEffectAfterAction"));
    }

    #[test]
    fn browser_observation_context_ignores_non_browser_tool_messages() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (gui__click_element): clicked btn_ok",
                1,
            ),
            chat_message("system", "System: noop", 2),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.is_empty());
    }

    #[test]
    fn browser_observation_context_truncates_large_snapshot_payloads() {
        let long_snapshot = format!(
            "Tool Output (browser__snapshot): {}",
            format!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}</root>",
                "<button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\">alpha beta gamma</button> ".repeat(200)
            )
        );
        let history = vec![chat_message("tool", &long_snapshot, 1)];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.contains("RECENT BROWSER OBSERVATION:"));
        assert!(context.chars().count() <= BROWSER_OBSERVATION_CONTEXT_MAX_CHARS + 120);
        assert!(context.ends_with(".\n") || context.ends_with("...\n"));
    }

    #[test]
    fn browser_observation_context_from_snapshot_reuses_same_formatting() {
        let snapshot =
            r#"<root id="root_dom_fallback_tree"><button id="btn_submit" name="Submit" /></root>"#;
        let context = build_browser_observation_context_from_snapshot(snapshot);
        assert!(context.contains("RECENT BROWSER OBSERVATION:"));
        assert!(context.contains("btn_submit"));
        assert!(context.contains("Submit"));
    }

    #[test]
    fn browser_observation_context_surfaces_assistive_hints_before_truncation() {
        let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<status id=\"status_poland\" name=\"Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

        let context = build_browser_observation_context_from_snapshot(&snapshot);
        assert!(context.contains("ASSISTIVE BROWSER HINTS: Poland"));
        assert!(context.contains("RECENT BROWSER OBSERVATION:"));
    }

    #[test]
    fn recent_session_events_context_suppresses_stale_snapshot_no_effect_after_later_tree_change() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                1,
            ),
            chat_message(
                "system",
                "System: Remedy succeeded for incident 'abc'; queued root retry.",
                2,
            ),
            chat_message(
                "system",
                "System: Incident 'abc' resolved after 1 transition(s).",
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_next' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                4,
            ),
        ];

        let context = build_recent_session_events_context(&history, true);
        assert!(!context.contains("duplicate replay guard"), "{context}");
        assert!(!context.contains("queued root retry"), "{context}");
        assert!(
            !context.contains("resolved after 1 transition"),
            "{context}"
        );
        assert!(context.contains("Clicked element 'lnk_next'"), "{context}");
    }

    #[test]
    fn recent_session_events_context_keeps_snapshot_no_effect_without_later_refresh() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                1,
            ),
            chat_message(
                "system",
                "System: Remedy succeeded for incident 'abc'; queued root retry.",
                2,
            ),
        ];

        let context = build_recent_session_events_context(&history, true);
        assert!(context.contains("duplicate replay guard"), "{context}");
        assert!(context.contains("queued root retry"), "{context}");
    }

    #[test]
    fn recent_session_events_context_suppresses_browser_context_echoes_when_latest_snapshot_is_grounded(
    ) {
        let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_lauraine" name="Lauraine" rect="2,64,156,17" /></root>"#;
        let history = vec![
            chat_message(
                "tool",
                &format!("Tool Output (browser__snapshot): {snapshot}"),
                1,
            ),
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__snapshot` once now.\n",
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_443422' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                3,
            ),
        ];

        let context = build_recent_session_events_context(&history, true);
        assert!(
            !context.contains("Tool Output (browser__snapshot)"),
            "{context}"
        );
        assert!(
            !context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context.contains("Clicked element 'lnk_443422'"),
            "{context}"
        );
    }

    #[test]
    fn latest_recent_pending_browser_state_context_keeps_recent_explicit_context_without_refresh() {
        let history = vec![
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__click_element` on `lnk_443422` now.\n",
                1,
            ),
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                2,
            ),
            chat_message(
                "system",
                "System: Selected recovery action `browser__wait`.",
                3,
            ),
        ];

        let pending = latest_recent_pending_browser_state_context(&history)
            .expect("explicit pending browser state should remain available");
        assert!(
            pending.contains("RECENT PENDING BROWSER STATE:"),
            "{pending}"
        );
        assert!(pending.contains("`lnk_443422`"), "{pending}");
    }

    #[test]
    fn latest_recent_pending_browser_state_context_drops_stale_explicit_context_after_refresh() {
        let history = vec![
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__click_element` on `lnk_443422` now.\n",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_443422' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];

        assert!(
            latest_recent_pending_browser_state_context(&history).is_none(),
            "explicit pending browser state should not survive a later browser refresh"
        );
    }

    #[test]
    fn browser_observation_context_surfaces_visible_scroll_target_focus_hint() {
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
            "</root>",
        );

        let context = build_browser_observation_context_from_snapshot(snapshot);
        assert!(context.contains("ASSISTIVE BROWSER HINTS:"));
        assert!(context.contains(
            "Visible scroll target `inp_lorem tag=textbox dom_id=text-area` is already on the page."
        ));
        assert!(context.contains("If the goal requires interacting with that control"));
        assert!(context.contains("page-level edge keys"));
    }

    #[test]
    fn browser_observation_context_preserves_late_high_priority_targets_under_truncation() {
        let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

        let context = build_browser_observation_context_from_snapshot(&snapshot);
        assert!(context.contains("IMPORTANT TARGETS:"));
        assert!(context.contains("lnk_t_215 tag=link"));
        assert!(context.contains("ticket-link-t-215"));
    }

    #[test]
    fn browser_observation_context_prefers_actionable_omitted_targets_over_generic_noise() {
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_noise_0\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_noise_1\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_fiber\" name=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_awaiting_dispatch\" name=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_0\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_0\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_202\" name=\"T-202\" omitted=\"true\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_1\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_1\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_2\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_2\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" />",
            "</root>"
        );
        let long_snapshot = snapshot.replace(
            "</root>",
            &format!(
                "{}{}",
                "<generic id=\"grp_pad\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
                "</root>"
            ),
        );

        let context = build_browser_observation_context_from_snapshot(&long_snapshot);
        assert!(context.contains("ticket-link-t-202"), "{context}");
        assert!(context.contains("ticket-link-t-204"), "{context}");
        assert!(context.contains("ticket-link-t-215"), "{context}");
        assert!(
            !context.contains("grp_row_noise_0 tag=generic"),
            "{context}"
        );
    }

    #[test]
    fn browser_observation_context_preserves_omitted_target_row_context() {
        let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" context=\"Unassigned / Awaiting Dispatch\" rect=\"0,0,1,1\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

        let context = build_browser_observation_context_from_snapshot(&snapshot);
        assert!(context.contains("ticket-link-t-204"), "{context}");
        assert!(
            context.contains("context=Unassigned / Awaiting Dispatch"),
            "{context}"
        );
    }

    #[test]
    fn browser_observation_context_prioritizes_clickable_controls_over_instruction_copy() {
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

        let context = build_browser_observation_context_from_snapshot(&snapshot);

        assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
        assert!(context.contains("grp_email_row tag=generic"), "{context}");
        assert!(context.contains("grp_trash tag=generic"), "{context}");
        assert!(context.contains("dom_clickable=true"), "{context}");
        assert!(
            !context.contains("grp_find_the_email_by_lonna tag=generic"),
            "{context}"
        );
        assert!(
            !context.contains("grp_lonna tag=generic name=Lonna"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_highlights_recent_browser_effect() {
        let history = vec![chat_message(
            "tool",
            "Clicked element 'btn_mark_complete' via geometry fallback. verify={\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("Do not repeat the same interaction"));
        assert!(context.contains("agent__complete"));
    }

    #[test]
    fn success_signal_context_highlights_selected_form_control_follow_up() {
        let history = vec![chat_message(
            "tool",
            "Clicked element 'radio_tecslmn' via geometry fallback. verify={\"post_target\":{\"semantic_id\":\"radio_tecslmn\",\"checked\":true},\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("selected a form control"));
        assert!(context.contains("Do not click the surrounding option group"));
        assert!(context.contains("Submit"));
    }

    #[test]
    fn recent_goal_primary_target_falls_back_to_select_submit_instruction() {
        let history = vec![chat_message("user", "Select TeCSlMn and click Submit.", 1)];

        let target = recent_goal_primary_target(&history);
        assert_eq!(target.as_deref(), Some("TeCSlMn"));
    }

    #[test]
    fn success_signal_context_highlights_submit_turnover_after_selected_control() {
        let history = vec![
            chat_message(
                "user",
                "Select TeCSlMn and click Submit.",
                1,
            ),
            chat_message(
                "tool",
                "Clicked element 'radio_tecslmn' via geometry fallback. verify={\"post_target\":{\"semantic_id\":\"radio_tecslmn\",\"checked\":true},\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
                2,
            ),
            chat_message(
                "tool",
                "Clicked element 'btn_submit' via selector fallback '[id=\"subbtn\"]'. Browser click/focus succeeded. verify={\"postcondition_met\":true}",
                3,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_select_jtddg_and_click_submit_\" name=\"Select JtddG and click Submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<label id=\"label_hdbp\" name=\"hDbp\" tag_name=\"label\" rect=\"2,59,52,11\" />",
            "<radio id=\"radio_hdbp\" name=\"hDbp\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,171,95,31\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
        assert!(context.contains("`btn_submit`"), "{context}");
        assert!(context.contains("`TeCSlMn`"), "{context}");
        assert!(context.contains("`radio_tecslmn`"), "{context}");
        assert!(context.contains("turned over the page"), "{context}");
        assert!(context.contains("current browser observation"), "{context}");
        assert!(
            context.contains("Do not use the new page's controls"),
            "{context}"
        );
        assert!(context.contains("`agent__complete`"), "{context}");
    }

    #[test]
    fn success_signal_context_keeps_submit_follow_up_when_target_still_visible() {
        let history = vec![
            chat_message(
                "user",
                "Select TeCSlMn and click Submit.",
                1,
            ),
            chat_message(
                "tool",
                "Clicked element 'radio_tecslmn' via geometry fallback. verify={\"post_target\":{\"semantic_id\":\"radio_tecslmn\",\"checked\":true},\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
                2,
            ),
            chat_message(
                "tool",
                "Clicked element 'btn_submit' via selector fallback '[id=\"subbtn\"]'. Browser click/focus succeeded. verify={\"postcondition_met\":true}",
                3,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_select_tecslmn_and_click_submi\" name=\"Select TeCSlMn and click Submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<radio id=\"radio_tecslmn\" name=\"TeCSlMn\" checked=\"true\" focused=\"true\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,153,95,31\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
        assert!(
            !context.contains("Do not treat the newly visible controls"),
            "{context}"
        );
        assert!(!context.contains("`agent__complete`"), "{context}");
    }

    #[test]
    fn success_signal_context_uses_duplicate_success_noop_guidance() {
        let history = vec![chat_message(
            "tool",
            "Skipped immediate replay of 'browser__click_element' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state once or finish with the gathered evidence.",
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("already succeeded on the previous step"));
    }

    #[test]
    fn success_signal_context_highlights_successful_dropdown_selection() {
        let history = vec![chat_message(
            "tool",
            r#"{"id":"inp_country","selected":{"label":"Australia","value":"Australia"}}"#,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("dropdown selection already succeeded"));
        assert!(context.contains("next required action"));
    }

    #[test]
    fn success_signal_context_highlights_prefixed_dropdown_selection_output() {
        let history = vec![chat_message(
            "tool",
            r#"Tool Output (browser__select_dropdown): {"id":"inp_country","selected":{"label":"Australia","value":"Australia"}}"#,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("dropdown selection already succeeded"));
        assert!(context.contains("`inp_country`"));
        assert!(context.contains("`Australia`"));
    }

    #[test]
    fn success_signal_context_points_to_remaining_controls_after_dropdown_selection() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
                2,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("`inp_assign_team`"));
        assert!(context.contains("`Network Ops`"));
        assert!(context.contains("`inp_awaiting_dispatch`"));
        assert!(context.contains("`inp_dispatch_note`"));
        assert!(context.contains("`btn_review_update`"));
    }

    #[test]
    fn success_signal_context_uses_compacted_snapshot_targets_for_dropdown_follow_up() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_queue tag=link name=Queue dom_id=queue-link selector=[id="queue-link"] | inp_assign_team tag=combobox name=Assign team dom_id=assignee selector=[id="assignee"] | inp_awaiting_dispatch tag=combobox name=Awaiting Dispatch dom_id=status selector=[id="status"] | inp_dispatch_note tag=textbox name=Dispatch note dom_id=note selector=[id="note"] | btn_review_update tag=button name=Review update dom_id=review-update selector=[id="review-update"]</root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
                2,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("dropdown selection already succeeded"));
        assert!(context.contains("`inp_assign_team`"));
        assert!(context.contains("`inp_awaiting_dispatch`"));
        assert!(context.contains("`inp_dispatch_note`"));
        assert!(context.contains("`btn_review_update`"));
    }

    #[test]
    fn priority_target_extraction_reads_compact_summary_targets() {
        let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_queue tag=link name=Queue dom_id=queue-link selector=[id="queue-link"] | inp_assign_team tag=combobox name=Assign team dom_id=assignee selector=[id="assignee"] | inp_awaiting_dispatch tag=combobox name=Awaiting Dispatch dom_id=status selector=[id="status"] | inp_dispatch_note tag=textbox name=Dispatch note dom_id=note selector=[id="note"] | btn_review_update tag=button name=Review update dom_id=review-update selector=[id="review-update"] | heading_ticket_t_215 tag=heading name=Ticket T-215 dom_id=ticket-title selector=[id="ticket-title"]</root>"#;

        let targets = extract_priority_browser_targets(snapshot, 8);
        assert!(targets
            .iter()
            .any(|target| target.contains("lnk_queue tag=link")));
        assert!(targets
            .iter()
            .any(|target| target.contains("inp_assign_team tag=combobox")));
        assert!(targets
            .iter()
            .any(|target| target.contains("inp_awaiting_dispatch tag=combobox")));
        assert!(targets
            .iter()
            .any(|target| target.contains("inp_dispatch_note tag=textbox")));
        assert!(targets
            .iter()
            .any(|target| target.contains("btn_review_update tag=button")));
    }

    #[test]
    fn success_signal_context_prefers_more_recent_click_success_over_older_dropdown_success() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"id":"inp_awaiting_dispatch","selected":{"label":"Awaiting Dispatch","value":"Awaiting Dispatch"}}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_t_215' via selector fallback '[id=\"ticket-link-t-215\"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
                2,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("observable state change"));
        assert!(context.contains("Do not repeat the same interaction"));
        assert!(!context.contains("`inp_awaiting_dispatch`"));
    }

    #[test]
    fn success_signal_context_prefers_prefixed_dropdown_selection_over_older_click_success() {
        let history = vec![
            chat_message(
                "tool",
                r#"Clicked element 'lnk_t_215' via selector fallback '[id=\"ticket-link-t-215\"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__select_dropdown): {"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
                3,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("dropdown selection already succeeded"));
        assert!(context.contains("`inp_assign_team`"));
        assert!(context.contains("`inp_awaiting_dispatch`"));
        assert!(context.contains("`inp_dispatch_note`"));
        assert!(context.contains("`btn_review_update`"));
        assert!(!context.contains("observable state change"));
    }

    #[test]
    fn success_signal_context_suppresses_stale_dropdown_when_latest_snapshot_moved_on() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"id":"inp_awaiting_dispatch","selected":{"label":"Awaiting Dispatch","value":"Awaiting Dispatch"}}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /></root>"#,
                2,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn browser_observation_context_suppresses_stale_snapshot_after_unobserved_navigation() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn browser_observation_context_uses_newer_snapshot_after_navigation() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_confirm_update" name="Confirm update" dom_id="confirm-update" selector="[id=&quot;confirm-update&quot;]" rect="0,0,1,1" /></root>"#,
                3,
            ),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.contains("RECENT BROWSER OBSERVATION:"), "{context}");
        assert!(context.contains("btn_confirm_update"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_requires_snapshot_after_unobserved_navigation() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
        ];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("browser__snapshot"), "{context}");
        assert!(context.contains("btn_review_update"), "{context}");
        assert!(context.contains("/review"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_skips_navigation_snapshot_when_current_snapshot_exists() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
        ];

        let context =
            build_recent_pending_browser_state_context_with_current_snapshot(&history, true);
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn snapshot_pending_context_highlights_filter_mismatch_after_recent_dropdown_change() {
        let history = vec![chat_message(
            "tool",
            r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
            1,
        )];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`inp_ticket_status`"), "{context}");
        assert!(context.contains("`Escalated`"), "{context}");
        assert!(context.contains("`inp_queue_status_filter`"), "{context}");
        assert!(context.contains("`Queue status filter`"), "{context}");
        assert!(context.contains("`Awaiting Dispatch`"), "{context}");
        assert!(context.contains("browser__select_dropdown"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_with_snapshot_highlights_filter_mismatch() {
        let history = vec![chat_message(
            "tool",
            r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
            1,
        )];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("may hide the updated item"), "{context}");
        assert!(context.contains("browser__select_dropdown"), "{context}");
    }

    #[test]
    fn success_signal_context_with_snapshot_suppresses_generic_click_when_filter_hides_update() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_202\" name=\"T-202\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_stale_queue_reverification_before_history() {
        let history = vec![
            chat_message(
                "user",
                "Sign in, keep the queue sort on \"Ticket ID\", then after saving switch the queue sort to \"Recently Updated\" and refresh before trusting row order.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_queue_stale_warning\" name=\"This queue view is stale. Reapply the queue controls and refresh the list before using row order as evidence.\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Stale queue/list view"), "{context}");
        assert!(context.contains("`inp_queue_sort`"), "{context}");
        assert!(context.contains("`Ticket ID`"), "{context}");
        assert!(context.contains("`Recently Updated`"), "{context}");
        assert!(context.contains("`btn_apply_filters`"), "{context}");
        assert!(
            context.contains("Do not open ticket/history links"),
            "{context}"
        );
        assert!(
            context.contains("call `browser__snapshot` again"),
            "{context}"
        );
    }

    #[test]
    fn pending_browser_state_context_guides_queue_reverification_after_confirmation_return_with_compact_snapshot(
    ) {
        let history = vec![
            chat_message(
                "user",
                "Return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_queue_dispatch_stale\" name=\"Login / Queue Dispatch stale queue reorder Return ...\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_dispatch_stale_queue_reorder\" name=\"Dispatch stale queue reorder\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_215\" name=\"T-215\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`inp_queue_sort`"), "{context}");
        assert!(context.contains("`Ticket ID`"), "{context}");
        assert!(context.contains("`Recently Updated`"), "{context}");
        assert!(context.contains("ticket/history links"), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_stale_queue_reverification_pending() {
        let history = vec![chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            1,
        )];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_queue_stale_warning\" name=\"This queue view is stale. Reapply the queue controls and refresh the list before using row order as evidence.\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_distractor_history_after_reverified_queue_order() {
        let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_confirm_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/review","post_url":"http://127.0.0.1:40363/workflow/case/confirmation"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_queue_sort","selected":{"label":"Recently Updated","value":"Recently Updated"}}"#,
                5,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                6,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"invoice\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Pending Review\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_318\" name=\"T-318\" context=\"Invoice adjustment awaiting callback / Pending Review / Billing Review\" dom_id=\"ticket-link-t-318\" selector=\"[id=&quot;ticket-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_318\" name=\"History\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" dom_id=\"ticket-history-link-t-318\" selector=\"[id=&quot;ticket-history-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_310\" name=\"T-310\" context=\"Recurring invoice delta / Pending Review / Unassigned\" dom_id=\"ticket-link-t-310\" selector=\"[id=&quot;ticket-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_807ebf\" name=\"History\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" dom_id=\"ticket-history-link-t-310\" selector=\"[id=&quot;ticket-history-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`T-318`"), "{context}");
        assert!(context.contains("`T-310`"), "{context}");
        assert!(context.contains("Do not reopen `T-318`"), "{context}");
        assert!(context.contains("`lnk_history_807ebf`"), "{context}");
        assert!(context.contains("another `browser__snapshot`"), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_distractor_history_follow_up_pending() {
        let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_318\" name=\"T-318\" context=\"Invoice adjustment awaiting callback / Pending Review / Billing Review\" dom_id=\"ticket-link-t-318\" selector=\"[id=&quot;ticket-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_318\" name=\"History\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" dom_id=\"ticket-history-link-t-318\" selector=\"[id=&quot;ticket-history-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_310\" name=\"T-310\" context=\"Recurring invoice delta / Pending Review / Unassigned\" dom_id=\"ticket-link-t-310\" selector=\"[id=&quot;ticket-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_807ebf\" name=\"History\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" dom_id=\"ticket-history-link-t-310\" selector=\"[id=&quot;ticket-history-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_falls_back_to_recent_queue_snapshot_for_distractor_history_follow_up(
    ) {
        let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_queue_sort","selected":{"label":"Recently Updated","value":"Recently Updated"}}"#,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via selector fallback '[id="apply-filters"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
                5,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><textbox id="inp_queue_search" name="Queue search" value="invoice" dom_id="queue-search" selector="[id=&quot;queue-search&quot;]" rect="0,0,1,1" /><combobox id="inp_queue_sort" name="Queue sort" value="Recently Updated" dom_id="queue-sort" selector="[id=&quot;queue-sort&quot;]" rect="0,0,1,1" /><button id="btn_apply_filters" name="Apply filters" dom_id="apply-filters" selector="[id=&quot;apply-filters&quot;]" rect="0,0,1,1" /><link id="lnk_t_318" name="T-318" context="Invoice adjustment awaiting callback / Pending Review / Billing Review" dom_id="ticket-link-t-318" selector="[id=&quot;ticket-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_318" name="History" context="T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History" dom_id="ticket-history-link-t-318" selector="[id=&quot;ticket-history-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_t_310" name="T-310" context="Recurring invoice delta / Pending Review / Unassigned" dom_id="ticket-link-t-310" selector="[id=&quot;ticket-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_807ebf" name="History" context="T-310 Recurring invoice delta Pending Review Unassigned Billing Review History" dom_id="ticket-history-link-t-310" selector="[id=&quot;ticket-history-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /></root>"#,
                6,
            ),
        ];
        let current_snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"invoice\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_pending_browser_state_context_with_snapshot(
            &history,
            Some(current_snapshot),
        );
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Do not reopen `T-318`"), "{context}");
        assert!(context.contains("`lnk_history_807ebf`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_alternate_tab_exploration_when_target_missing() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'tab_section_1' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tablist id=\"tablist_section_1_orci_elementum_conse\" name=\"Section #1 Orci elementum consectetur egestas est ...\" dom_id=\"area\" selector=\"[id=&quot;area&quot;]\" tag_name=\"div\" rect=\"0,50,160,123\" />",
            "<tab id=\"tab_section_1\" name=\"Section #1\" focused=\"true\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tabpanel id=\"tabpanel_section_1\" name=\"Orci elementum consectetur egestas est morbi a. Pharetra lacus.\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" tag_name=\"div\" rect=\"4,73,152,58\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,133,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,152,152,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`elit`"), "{context}");
        assert!(
            context.contains("Do not click `tab_section_1` again"),
            "{context}"
        );
        assert!(context.contains("`tab_section_2`"), "{context}");
        assert!(context.contains("`tab_section_3`"), "{context}");
        assert!(context.contains("another `browser__snapshot`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_ignores_alternate_tab_exploration_when_target_visible() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,73,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. elit non, ultrices risus.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_exact_visible_target_click() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,73,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_consectetur_dot\" name=\"Consectetur.\" tag_name=\"span\" rect=\"6,112,56,11\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`grp_elit`"), "{context}");
        assert!(context.contains("browser__click_element"), "{context}");
        assert!(
            context.contains("Do not click a surrounding container"),
            "{context}"
        );
        assert!(context.contains("`browser__find_text`"), "{context}");
        assert!(context.contains("another `browser__snapshot`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_suppresses_exact_visible_target_after_target_click() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'grp_elit' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_ranked_result_pagination() {
        let history = vec![
            chat_message(
                "user",
                r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_sergio\" name=\"Sergio\" tag_name=\"span\" rect=\"115,3,31,11\" />",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_karrie\" name=\"Karrie\" dom_id=\"result-0\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_riley\" name=\"Riley\" dom_id=\"result-1\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_kanesha\" name=\"Kanesha\" dom_id=\"result-2\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,42,11\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"68,191,8,17\" />",
            "<link id=\"lnk_next\" name=\">\" selector=\"#pagination > li:nth-of-type(6) > a\" rect=\"81,191,9,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`grp_6th`"), "{context}");
        assert!(context.contains("not a search result"), "{context}");
        assert!(context.contains("Only 3 actual result links"), "{context}");
        assert!(context.contains("ranks 1-3"), "{context}");
        assert!(context.contains("`lnk_page_2`"), "{context}");
        assert!(context.contains("Do not click `grp_6th`"), "{context}");
        assert!(context.contains("`browser__scroll`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_ranked_result_link_after_page_change() {
        let history = vec![
            chat_message(
                "user",
                r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_page_2' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_result_4\" name=\"Teodora\" dom_id=\"result-3\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_result_5\" name=\"Merrie\" dom_id=\"result-4\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_result_6\" name=\"Sergio result\" dom_id=\"result-5\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,42,11\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"68,191,8,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`grp_6th`"), "{context}");
        assert!(context.contains("`lnk_result_6`"), "{context}");
        assert!(context.contains("not the result to click"), "{context}");
        assert!(context.contains("`browser__scroll`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_ranked_result_link_after_failed_page_click() {
        let history = vec![
            chat_message(
                "user",
                r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_page_2'. verify={"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_thaddeus\" name=\"Thaddeus\" dom_id=\"result-3\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,47,11\" />",
            "<link id=\"lnk_emile\" name=\"Emile\" dom_id=\"result-4\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,27,11\" />",
            "<link id=\"lnk_sergio\" name=\"Sergio\" dom_id=\"result-5\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,31,11\" />",
            "<link id=\"lnk_prev\" name=\"<\" selector=\"#pagination > li:nth-of-type(2) > a\" rect=\"44,191,9,17\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"57,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"81,191,8,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Result 6 on this page"), "{context}");
        assert!(context.contains("`lnk_sergio`"), "{context}");
        assert!(!context.contains("`lnk_page_2`"), "{context}");
        assert!(context.contains("`browser__scroll`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_ranked_result_link_after_failed_page_click_without_result_markers(
    ) {
        let history = vec![
            chat_message(
                "user",
                r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_thaddeus\" name=\"Thaddeus\" tag_name=\"a\" rect=\"4,77,47,11\" />",
            "<link id=\"lnk_emile\" name=\"Emile\" tag_name=\"a\" rect=\"4,110,27,11\" />",
            "<link id=\"lnk_sergio\" name=\"Sergio\" tag_name=\"a\" rect=\"4,143,31,11\" />",
            "<generic id=\"grp_123\" name=\"&lt;123&gt;\" dom_id=\"pagination\" selector=\"#pagination\" tag_name=\"ul\" rect=\"2,191,103,17\" />",
            "<link id=\"lnk_prev\" name=\"&lt;\" tag_name=\"a\" rect=\"44,191,9,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"57,191,8,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_3\" name=\"3\" tag_name=\"a\" rect=\"81,191,8,17\" />",
            "<link id=\"lnk_next\" name=\"&gt;\" omitted=\"true\" tag_name=\"a\" rect=\"94,191,9,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Result 6 on this page"), "{context}");
        assert!(context.contains("`lnk_sergio`"), "{context}");
        assert!(
            !context.contains("`lnk_2` (`2`) now to advance"),
            "{context}"
        );
        assert!(context.contains("`browser__scroll`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_pagination_after_instruction_only_find_text_hit() {
        let history = vec![
            chat_message(
                "user",
                "Find Deena in the contact book and click on their address.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"query":"Deena","result":{"count":1,"first_snippet":"Find Deena in the contact book and click on their address.","found":true,"scope":"document","scrolled":true}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<generic id=\"grp_address\" name=\"Address:\" tag_name=\"span\" rect=\"6,124,46,11\" />",
            "<link id=\"lnk_5735_valdez_crescent\" name=\"5735 Valdez Crescent\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<generic id=\"grp_1\" name=\"1&gt;\" dom_id=\"pagination\" selector=\"[id=&quot;pagination&quot;]\" tag_name=\"ul\" rect=\"2,183,65,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"44,183,8,17\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`Deena`"), "{context}");
        assert!(context.contains("`Karol`"), "{context}");
        assert!(
            context.contains("Do not click this record's links"),
            "{context}"
        );
        assert!(context.contains("`lnk_443422`"), "{context}");
        assert!(context.contains("`browser__find_text`"), "{context}");
        assert!(context.contains("Do not invent ids"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_suppresses_instruction_only_find_text_hint_once_target_is_visible(
    ) {
        let history = vec![
            chat_message(
                "user",
                "Find Deena in the contact book and click on their address.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"query":"Deena","result":{"count":1,"first_snippet":"Find Deena in the contact book and click on their address.","found":true,"scope":"document","scrolled":true}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_deena\" name=\"Deena\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_19_townsend_road\" name=\"19 Townsend Road\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<generic id=\"grp_2\" name=\"2&gt;\" dom_id=\"pagination\" selector=\"[id=&quot;pagination&quot;]\" tag_name=\"ul\" rect=\"2,183,65,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"44,183,8,17\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_requests_snapshot_after_successful_tree_change_link_click_without_reobservation(
    ) {
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_5735_valdez_crescent\" name=\"5735 Valdez Crescent\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );
        let history = vec![
            chat_message(
                "user",
                "Find Deena in the contact book and click on their address.",
                1,
            ),
            chat_message(
                "tool",
                &format!("Tool Output (browser__snapshot): {snapshot}"),
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_443422' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_443422","tag_name":"a","center_point":[73.5,191.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                3,
            ),
        ];

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`lnk_443422`"), "{context}");
        assert!(context.contains("`browser__snapshot`"), "{context}");
        assert!(context.contains("stale controls"), "{context}");
        assert!(
            !context.contains("Do not click this record's links"),
            "{context}"
        );
    }

    #[test]
    fn pending_browser_state_context_suppresses_tree_change_reverification_after_later_snapshot() {
        let old_snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );
        let new_snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<heading id=\"heading_deena\" name=\"Deena\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_5159_middleton_crescent_apt_5\" name=\"5159 Middleton Crescent, Apt 5\" tag_name=\"a\" rect=\"6,124,115,22\" />",
            "</root>",
        );
        let history = vec![
            chat_message(
                "user",
                "Find Deena in the contact book and click on their address.",
                1,
            ),
            chat_message(
                "tool",
                &format!("Tool Output (browser__snapshot): {old_snapshot}"),
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_443422' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_443422","tag_name":"a","center_point":[73.5,191.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                3,
            ),
            chat_message(
                "tool",
                &format!("Tool Output (browser__snapshot): {new_snapshot}"),
                4,
            ),
        ];

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(new_snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_resets_ranked_result_page_after_resubmit_returns_to_first_page(
    ) {
        let history = vec![
            chat_message(
                "user",
                r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_karrie\" name=\"Karrie\" tag_name=\"a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_riley\" name=\"Riley\" tag_name=\"a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_kanesha\" name=\"Kanesha\" tag_name=\"a\" rect=\"4,143,42,11\" />",
            "<generic id=\"grp_123\" name=\"123&gt;\" dom_id=\"pagination\" selector=\"#pagination\" tag_name=\"ul\" rect=\"2,191,90,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_3\" name=\"3\" tag_name=\"a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_next\" name=\"&gt;\" omitted=\"true\" tag_name=\"a\" rect=\"81,191,9,17\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Only 3 actual result links"), "{context}");
        assert!(context.contains("ranks 1-3"), "{context}");
        assert!(context.contains("`lnk_2`"), "{context}");
        assert!(!context.contains("`lnk_kanesha`"), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_alternate_tab_exploration_pending() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'tab_section_1' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" focused=\"true\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tabpanel id=\"tabpanel_section_1\" name=\"Orci elementum consectetur egestas est morbi a. Pharetra lacus.\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" tag_name=\"div\" rect=\"4,73,152,58\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,133,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,152,152,17\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_exact_target_click_is_pending() {
        let history = vec![
            chat_message(
                "user",
                r#"Expand the sections below, to find and click on the link "elit"."#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_after_unobserved_navigation() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn success_signal_context_points_to_visible_controls_after_navigation_click() {
        let history = vec![chat_message(
            "tool",
            r#"Clicked element 'btn_sign_in' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/login","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            1,
        )];
        let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_login_divide_queue" name="Login / Queue" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_history tag=link name=History dom_id=ticket-history-link-t-202 selector=[id="ticket-history-link-t-202"] | lnk_t_204 tag=link name=T-204 dom_id=ticket-link-t-204 selector=[id="ticket-link-t-204"] | lnk_history_4c23bd tag=link name=History dom_id=ticket-history-link-t-204 selector=[id="ticket-history-link-t-204"] | lnk_t_215 tag=link name=T-215 dom_id=ticket-link-t-215 selector=[id="ticket-link-t-215"]</root>"#;

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
        assert!(context.contains("`lnk_t_204`"), "{context}");
        assert!(context.contains("`lnk_t_215`"), "{context}");
        assert!(
            context.contains("Do not spend the next step on another `browser__snapshot`"),
            "{context}"
        );
        assert!(
            !context.contains("finish with `agent__complete` when the goal is satisfied"),
            "{context}"
        );
    }

    #[test]
    fn pending_browser_state_context_guides_alternate_history_after_returning_to_list() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_202\" name=\"History\" dom_id=\"ticket-history-link-t-202\" context=\"T-202 Fiber handoff requires vendor logs / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Do not reopen `T-215`"), "{context}");
        assert!(
            context.contains("`lnk_history_t_204` for `T-204`"),
            "{context}"
        );
    }

    #[test]
    fn pending_browser_state_context_ignores_queue_snapshots_when_guiding_alternate_history() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_history_t_202" name="History" dom_id="ticket-history-link-t-202" /><link id="lnk_history_t_204" name="History" dom_id="ticket-history-link-t-204" context="T-204 Metro fiber outage / Awaiting Dispatch / Unassigned" /><link id="lnk_history_t_215" name="History" dom_id="ticket-history-link-t-215" context="T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" tag_name="h1" rect="0,0,1,1" /><generic id="grp_verify_saved_dispatch" name="Verify that the saved dispatch event matches the requested change before you return to the queue." dom_id="history-status" rect="0,0,1,1" /></root>"#,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                5,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_202\" name=\"History\" dom_id=\"ticket-history-link-t-202\" context=\"T-202 Fiber handoff requires vendor logs / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Do not reopen `T-215`"), "{context}");
        assert!(
            context.contains("`lnk_history_t_204` for `T-204`"),
            "{context}"
        );
    }

    #[test]
    fn pending_browser_state_context_guides_alternate_history_after_confirmation_audit_return() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_confirm_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/review","post_url":"http://127.0.0.1:40363/workflow/case/confirmation"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                5,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_303\" name=\"History\" dom_id=\"ticket-history-link-t-303\" context=\"Invoice reminder needs correction / Pending Review / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Do not reopen `T-318`"), "{context}");
        assert!(
            context.contains("`lnk_history_7c01a1` for `T-310`"),
            "{context}"
        );
    }

    #[test]
    fn recent_history_return_item_id_prefers_ticket_segment_over_case_slug() {
        let history = vec![chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
            1,
        )];

        assert_eq!(
            recent_history_return_item_id(&history),
            Some("T-318".to_string())
        );
    }

    #[test]
    fn pending_browser_state_context_excludes_completed_item_after_slugged_history_return() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/confirmation","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("Do not reopen `T-318`"), "{context}");
        assert!(
            context.contains("`lnk_history_7c01a1` for `T-310`"),
            "{context}"
        );
        assert!(!context.contains("`lnk_history_1ebf96`"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_skips_generic_confirmation_history_link_after_return() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/confirmation","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_open_audit_history\" name=\"Open audit history\" dom_id=\"history-link\" selector=\"[id=&quot;history-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Billing Review.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_note_summary\" name=\"Saved note: Validate recurring invoice delta\" dom_id=\"note-summary\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_alternate_history_verification_pending()
    {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_after_confirmation_audit_return() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_history_page_verification_return_to_queue() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_215\" name=\"Audit history for ticket T-215\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_history_header\" name=\"Actor Action Assignee Status Note\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_saved_dispatch_row\" name=\"dispatch.agent Saved dispatch update Network Ops Awaiting Dispatch Escalate fiber outage to on-call\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`lnk_queue`"), "{context}");
        assert!(context.contains("`T-204`"), "{context}");
        assert!(
            context.contains("Do not call `browser__snapshot` again"),
            "{context}"
        );
        assert!(
            context.contains("Do not reopen or mutate the item"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_history_page_verification_is_pending() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_215\" name=\"Audit history for ticket T-215\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_saved_dispatch_row\" name=\"dispatch.agent Saved dispatch update Network Ops Awaiting Dispatch Escalate fiber outage to on-call\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_history_page_mismatch_recovery() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_318' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_confirmation\" name=\"Confirmation\" dom_id=\"confirmation-link\" selector=\"[id=&quot;confirmation-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_318\" name=\"Audit history for ticket T-318\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_history_header\" name=\"Actor Action Assignee Status Note\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_requested_callback_row\" name=\"dispatch.agent Requested billing callback Unassigned Pending Review Awaiting customer callback\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context
                .contains("does not yet show a row matching the page-visible verification prompt"),
            "{context}"
        );
        assert!(context.contains("`lnk_confirmation`"), "{context}");
        assert!(context.contains("`btn_reopen_ticket`"), "{context}");
        assert!(
            context.contains("Do not spend the next step on another `browser__snapshot`"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_history_page_verification_is_unmet() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_318' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_confirmation\" name=\"Confirmation\" dom_id=\"confirmation-link\" selector=\"[id=&quot;confirmation-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_318\" name=\"Audit history for ticket T-318\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_requested_callback_row\" name=\"dispatch.agent Requested billing callback Unassigned Pending Review Awaiting customer callback\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_confirmation_mismatch_recovery() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_open_audit_history\" name=\"Open audit history\" dom_id=\"history-link\" selector=\"[id=&quot;history-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Unassigned.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_note_summary\" name=\"Saved note: Validate recurring invoice delta\" dom_id=\"note-summary\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context.contains("does not yet reflect the recent saved update"),
            "{context}"
        );
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Unassigned`"), "{context}");
        assert!(context.contains("`btn_reopen_ticket`"), "{context}");
        assert!(
            context.contains("Do not spend the next step on `browser__snapshot`"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_confirmation_summary_is_stale() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Unassigned.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_reopened_draft_resume() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_reopen_ticket' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318"}"#,
                5,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"ticket-title\" selector=\"[id=&quot;ticket-title&quot;]\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_assign_team\" name=\"Assign team\" dom_id=\"assignee\" selector=\"[id=&quot;assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_ticket_status\" name=\"Ticket status\" value=\"Pending Review\" dom_id=\"status\" selector=\"[id=&quot;status&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_note\" name=\"Dispatch note\" dom_id=\"note\" selector=\"[id=&quot;note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_review_update\" name=\"Review update\" dom_id=\"review-update\" selector=\"[id=&quot;review-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context.contains("reopened so the saved state can be corrected"),
            "{context}"
        );
        assert!(
            context.contains("Do not return to queue/history verification yet"),
            "{context}"
        );
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Pending Review`"), "{context}");
        assert!(
            context.contains("`Validate recurring invoice delta`"),
            "{context}"
        );
        assert!(context.contains("`btn_review_update`"), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_reopened_draft_requires_resume() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_reopen_ticket' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"ticket-title\" selector=\"[id=&quot;ticket-title&quot;]\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_assign_team\" name=\"Assign team\" dom_id=\"assignee\" selector=\"[id=&quot;assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_ticket_status\" name=\"Ticket status\" value=\"Pending Review\" dom_id=\"status\" selector=\"[id=&quot;status&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_note\" name=\"Dispatch note\" dom_id=\"note\" selector=\"[id=&quot;note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_review_update\" name=\"Review update\" dom_id=\"review-update\" selector=\"[id=&quot;review-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_review_confirmation_before_queue_return() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_review_queued_update\" name=\"Review queued update\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"review-ticket\" selector=\"[id=&quot;review-ticket&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_assignee\" name=\"Draft assignee: Billing Review\" dom_id=\"review-assignee\" selector=\"[id=&quot;review-assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_status\" name=\"Draft status: Pending Review\" dom_id=\"review-status\" selector=\"[id=&quot;review-status&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_note\" name=\"Draft note: Validate recurring invoice delta\" dom_id=\"review-note\" selector=\"[id=&quot;review-note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_edit_draft\" name=\"Edit draft\" dom_id=\"edit-update\" selector=\"[id=&quot;edit-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_confirm_update\" name=\"Confirm update\" dom_id=\"confirm-update\" selector=\"[id=&quot;confirm-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_cancel_draft\" name=\"Cancel draft\" dom_id=\"cancel-update\" selector=\"[id=&quot;cancel-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("ready to be saved"), "{context}");
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Pending Review`"), "{context}");
        assert!(
            context.contains("`Validate recurring invoice delta`"),
            "{context}"
        );
        assert!(context.contains("`btn_confirm_update`"), "{context}");
        assert!(context.contains("`btn_edit_draft`"), "{context}");
        assert!(
            context.contains("Do not return to queue/history verification"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_review_confirmation_is_pending() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"review-ticket\" selector=\"[id=&quot;review-ticket&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_edit_draft\" name=\"Edit draft\" dom_id=\"edit-update\" selector=\"[id=&quot;edit-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_confirm_update\" name=\"Confirm update\" dom_id=\"confirm-update\" selector=\"[id=&quot;confirm-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_highlights_autocomplete_follow_up() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","controls_dom_id":"ui-id-1","active_descendant_dom_id":"ui-id-2","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("autocomplete state"));
        assert!(context.contains("Do not submit or finish"));
        assert!(context.contains("browser__key"));
    }

    #[test]
    fn pending_browser_state_context_highlights_key_follow_up() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("key did not resolve the widget"));
        assert!(context.contains("ArrowDown"));
        assert!(context.contains("browser__snapshot"));
    }

    #[test]
    fn pending_browser_state_context_highlights_navigation_key_commit() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"ArrowDown","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"Poland"}}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("active autocomplete candidate"));
        assert!(context.contains("press `Enter` to commit"));
        assert!(context.contains("browser__snapshot"));
    }

    #[test]
    fn success_signal_context_ignores_autocomplete_follow_up() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","controls_dom_id":"ui-id-1","active_descendant_dom_id":"ui-id-2","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.is_empty());
    }

    #[test]
    fn pending_browser_state_context_uses_snapshot_to_commit_single_autocomplete_result() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        )];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"10,97,95,31\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("Autocomplete is still open on `inp_tags`"));
        assert!(context.contains("`Poland`"));
        assert!(context.contains("`ArrowDown`"));
        assert!(context.contains("`Enter`"));
        assert!(context.contains("The suggestion is not committed yet"));
    }

    #[test]
    fn pending_browser_state_context_treats_submit_on_open_autocomplete_as_incomplete() {
        let history = vec![
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_submit' via geometry fallback. verify={"focused_control":{"semantic_id":"inp_tags","dom_id":"tags","focused":true},"postcondition":{"met":true,"tree_changed":true}}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"10,97,95,31\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("A recent `btn_submit` click left autocomplete unresolved"));
        assert!(context.contains("does not finish the task"));
        assert!(context.contains("`ArrowDown`"));
        assert!(context.contains("`Enter`"));

        let success = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(success.is_empty(), "{success}");
    }

    #[test]
    fn pending_browser_state_context_treats_unresolved_enter_as_navigation_then_commit() {
        let history = vec![
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
                1,
            ),
            chat_message(
                "tool",
                r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("A recent `Enter` key left autocomplete unresolved"));
        assert!(context.contains("`ArrowDown`"));
        assert!(context.contains("`Enter`"));
    }

    #[test]
    fn success_signal_context_highlights_already_satisfied_typed_field() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#queue-search","text":"fiber","value":"fiber","focused":true,"already_satisfied":true}}"##,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("already contained the requested text"));
        assert!(context.contains("Do not type the same text"));
    }

    #[test]
    fn pending_browser_state_context_highlights_no_effect_scroll() {
        let history = vec![chat_message(
            "tool",
            r##"{"scroll":{"delta_x":0,"delta_y":-1000,"anchor":"viewport_center","anchor_x":400.0,"anchor_y":300.0,"page_before":{"x":0.0,"y":0.0},"page_after":{"x":0.0,"y":0.0},"page_moved":false,"target_before":{"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","focused":false,"scroll_top":120.0,"scroll_height":510.0,"client_height":104.0,"can_scroll_up":true,"can_scroll_down":true},"target_after":{"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","focused":false,"scroll_top":120.0,"scroll_height":510.0,"client_height":104.0,"can_scroll_up":true,"can_scroll_down":true},"target_moved":false}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("no grounded effect"));
        assert!(context.contains("browser__snapshot"));
        assert!(context.contains("browser__key"));
    }

    #[test]
    fn pending_browser_state_context_highlights_incomplete_auth_form() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"Username\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"Password\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
        ];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("password credential field"));
        assert!(context.contains("Do not click `Sign in`"));
    }

    #[test]
    fn pending_browser_state_context_highlights_ready_auth_submit() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
                3,
            ),
        ];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("both credential fields were filled"));
        assert!(context.contains("Use the login action now"));
        assert!(context.contains("browser__click_element"));
    }

    #[test]
    fn snapshot_pending_context_highlights_incomplete_auth_without_history_snapshot() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
            1,
        )];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_dispatch_dot_agent\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_password\" name=\"Password\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("password credential field"));
        assert!(context.contains("Do not click `Sign in`"));
    }

    #[test]
    fn snapshot_pending_context_highlights_ready_auth_submit_without_history_snapshot() {
        let history = vec![
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_dispatch_dot_agent\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_215\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("both credential fields were filled"));
        assert!(context.contains("Use the login action now"));
        assert!(context.contains("browser__click_element"));
    }

    #[test]
    fn success_signal_context_suppresses_stale_click_guidance_while_auth_pending() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_sign_in' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                4,
            ),
        ];

        let context = build_recent_success_signal_context(&history);
        assert!(context.is_empty());
    }

    #[test]
    fn pending_browser_state_context_highlights_page_level_key_target() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":null,"dom_id":null,"tag_name":"body","value":"Scroll the textarea to the top of the text hit submit.","focused":true,"scroll_top":null,"scroll_height":null,"client_height":null,"can_scroll_up":null,"can_scroll_down":null,"autocomplete":null}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("page itself"));
        assert!(context.contains("focus that control first"));
        assert!(context.contains("browser__click_element"));
        assert!(context.contains("otherwise continue with the next required visible control"));
    }

    #[test]
    fn pending_browser_state_context_highlights_focused_scroll_control_after_click() {
        let history = vec![chat_message(
            "tool",
            r#"Clicked element 'grp_scroll_the_textarea_to_the_top' via geometry fallback. verify={"post_target":{"dom_id":"wrap","focused":false},"focused_control":{"dom_id":"text-area","selector":"[id=\"text-area\"]","tag_name":"textarea","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true},"postcondition":{"met":true,"tree_changed":true}}"#,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("already focused a scrollable control"));
        assert!(context.contains("Do not keep clicking"));
        assert!(context.contains("text selection"));
        assert!(context.contains("browser__select_text"));
    }

    #[test]
    fn pending_browser_state_context_highlights_no_effect_home_on_focused_scroll_control() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("Do not submit yet"));
        assert!(context.contains("Do not use `Home` again"));
        assert!(context.contains("scroll_top=257"));
        assert!(context.contains("spend the next step on `PageUp`"));
        assert!(context.contains("can_scroll_up=true"));
        assert!(context.contains("can_scroll_up=false"));
        assert!(context.contains("scroll_top=0"));
        assert!(context.contains(top_edge_jump_call()));
    }

    #[test]
    fn pending_browser_state_context_keeps_page_up_option_when_home_is_near_top() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":24,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        )];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("Use `PageUp` or"));
        assert!(!context.contains("Do not spend the next step on `PageUp`"));
        assert!(context.contains(top_edge_jump_call()));
    }

    #[test]
    fn pending_browser_state_context_escalates_repeated_page_up_to_control_home() {
        let history = vec![
            chat_message(
                "tool",
                r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":112,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
                1,
            ),
            chat_message(
                "tool",
                r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":24,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
                2,
            ),
        ];

        let context = build_recent_pending_browser_state_context(&history);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("Several recent `PageUp` steps"));
        assert!(context.contains(top_edge_jump_call()));
        assert!(context.contains("stop spending steps on repeated `PageUp`"));
        assert!(context.contains("scroll_top=0"));
    }

    #[test]
    fn success_signal_context_highlights_scroll_edge_key_completion() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":0,"scroll_height":510,"client_height":104,"can_scroll_up":false,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("top edge"));
        assert!(context.contains("Do not repeat the same key"));
    }

    #[test]
    fn snapshot_success_signal_highlights_already_satisfied_negative_selection_state() {
        let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><generic id="grp_query" name="Select nothing and click Submit." /><checkbox id="checkbox_r8" name="r8" /><checkbox id="checkbox_bptkv" name="BpTkv" /><button id="btn_submit" name="Submit" /></root>"#;

        let context = build_browser_snapshot_success_signal_context(snapshot);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("requires no selections"));
        assert!(context.contains("Do not click any checkbox"));
        assert!(context.contains("Submit"));
    }

    #[test]
    fn snapshot_pending_signal_highlights_negative_selection_violation() {
        let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><generic id="grp_query" name="Select nothing and click Submit." /><checkbox id="checkbox_r8" name="r8" checked="true" /><checkbox id="checkbox_bptkv" name="BpTkv" /><button id="btn_submit" name="Submit" /></root>"#;

        let context = build_browser_snapshot_pending_state_context(snapshot);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains("requires no selections"));
        assert!(context.contains("Do not submit yet"));
        assert!(context.contains("unchecked or unselected"));
    }

    #[test]
    fn snapshot_pending_signal_highlights_visible_scroll_target_before_body_key() {
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_query\" name=\"Scroll the textarea to the top of the text hit submit.\" />",
            "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
            "<button id=\"btn_submit\" name=\"Submit\" />",
            "</root>",
        );

        let context = build_browser_snapshot_pending_state_context(snapshot);
        assert!(context.contains("RECENT PENDING BROWSER STATE:"));
        assert!(context.contains(
            "Visible scroll target `inp_lorem tag=textbox dom_id=text-area` is already on the page."
        ));
        assert!(context.contains("browser__click_element"));
        assert!(context.contains("otherwise continue with the next required visible control"));
    }
}
