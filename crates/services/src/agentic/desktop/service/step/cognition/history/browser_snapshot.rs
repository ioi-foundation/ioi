use super::*;

pub(super) fn top_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowUp"
    } else {
        "Control+Home"
    }
}

pub(super) fn top_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowUp","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"Home","modifiers":["Control"]}"#
    }
}

pub(super) fn bottom_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowDown"
    } else {
        "Control+End"
    }
}

pub(super) fn bottom_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowDown","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"End","modifiers":["Control"]}"#
    }
}

pub(super) fn compact_ws_for_prompt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn looks_like_browser_snapshot_payload(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root") && trimmed.contains("id=\"") && trimmed.contains("rect=\"")
}

pub(super) fn browser_snapshot_payload(message: &ChatMessage) -> Option<&str> {
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

pub(super) fn decode_browser_xml_text(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

pub(super) fn extract_browser_xml_attr(fragment: &str, attr: &str) -> Option<String> {
    let marker = format!(r#"{attr}=""#);
    let start = fragment.find(&marker)? + marker.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub(super) fn extract_compact_jsonish_string_field(text: &str, key: &str) -> Option<String> {
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

pub(super) fn extract_scoped_compact_jsonish_string_field(
    text: &str,
    scope_marker: &str,
    key: &str,
) -> Option<String> {
    let scope_start = text.find(scope_marker)? + scope_marker.len();
    extract_compact_jsonish_string_field(&text[scope_start..], key)
}

pub(super) fn extract_compact_jsonish_number_field(text: &str, key: &str) -> Option<f64> {
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

pub(super) fn format_prompt_number(value: f64) -> String {
    if value.fract() == 0.0 {
        return format!("{}", value as i64);
    }

    format!("{value}")
}

pub(super) fn focused_home_should_jump_to_top_edge(compact: &str) -> Option<String> {
    let scroll_top = extract_compact_jsonish_number_field(compact, "scroll_top")?;
    if scroll_top <= 0.0 {
        return None;
    }

    let client_height = extract_compact_jsonish_number_field(compact, "client_height")?;
    (scroll_top >= client_height).then(|| format_prompt_number(scroll_top))
}

pub(super) fn extract_json_object_fragment(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (start < end).then_some(&text[start..=end])
}

pub(super) fn parse_json_value_from_message(text: &str) -> Option<Value> {
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

pub(super) fn extract_assistive_browser_hints(snapshot: &str) -> Vec<String> {
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

pub(super) fn browser_fragment_scroll_target_summary(fragment: &str) -> Option<String> {
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

pub(super) fn extract_scroll_target_focus_hint(snapshot: &str) -> Option<String> {
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

pub(super) fn browser_fragment_tag_name(fragment: &str) -> Option<&str> {
    let trimmed = fragment.trim_start();
    if trimmed.is_empty() || trimmed.starts_with("!--") || trimmed.starts_with('/') {
        return None;
    }

    let end = trimmed
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

pub(super) fn browser_fragment_looks_like_instruction_context(fragment: &str, tag_name: &str) -> bool {
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

pub(super) fn browser_fragment_priority_score(fragment: &str, tag_name: &str) -> Option<u8> {
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

pub(super) fn browser_fragment_priority_summary(fragment: &str) -> Option<(String, u8, String)> {
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

pub(super) fn compact_priority_target_looks_like_instruction_context(summary: &str) -> bool {
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

pub(super) fn compact_priority_target_score(summary: &str) -> Option<u8> {
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

pub(super) fn extract_compact_priority_browser_targets(snapshot: &str) -> Vec<(String, u8, String)> {
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

pub(super) fn extract_priority_browser_targets(snapshot: &str, max_targets: usize) -> Vec<String> {
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

pub(super) fn browser_snapshot_root_summary(snapshot: &str) -> Option<String> {
    let trimmed = snapshot.trim();
    let start = trimmed.find("<root")?;
    let rest = &trimmed[start..];
    let end = rest.find('>')?;
    Some(compact_ws_for_prompt(&decode_browser_xml_text(
        &rest[..=end],
    )))
}

pub(super) fn compact_browser_observation(snapshot: &str) -> String {
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

pub(super) fn snapshot_lower_text(snapshot: &str) -> String {
    compact_ws_for_prompt(&decode_browser_xml_text(snapshot)).to_ascii_lowercase()
}

pub(super) fn snapshot_has_negative_selection_instruction(snapshot: &str) -> bool {
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

pub(super) fn snapshot_has_selectable_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("<checkbox ") || lower.contains("<radio ") || lower.contains("<option ")
}

pub(super) fn snapshot_has_selected_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("checked=\"true\"") || lower.contains("selected=\"true\"")
}

pub(super) fn browser_snapshot_pending_signal(snapshot: &str) -> Option<String> {
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

pub(super) fn browser_snapshot_success_signal(snapshot: &str) -> Option<&'static str> {
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

pub(super) fn extract_item_like_ids(text: &str) -> Vec<String> {
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

pub(super) fn first_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().next()
}

pub(super) fn last_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().last()
}

pub(super) fn history_item_like_id_from_url(url: &str) -> Option<String> {
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

pub(super) fn extract_first_quoted_value(text: &str) -> Option<String> {
    let start = text.find('"')? + 1;
    let end = text[start..].find('"')? + start;
    let value = compact_ws_for_prompt(&text[start..end]);
    (!value.is_empty()).then_some(value)
}

pub(super) fn trim_goal_target_value(text: &str) -> Option<String> {
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

pub(super) fn extract_select_submit_target(text: &str) -> Option<String> {
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

pub(super) fn normalized_exact_target_text(text: &str) -> String {
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
pub(super) struct RankedResultRequest {
    pub(super) rank: usize,
    pub(super) ordinal_text: String,
}

pub(super) fn parse_ordinal_token(token: &str) -> Option<usize> {
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

pub(super) fn recent_requested_result_rank(history: &[ChatMessage]) -> Option<RankedResultRequest> {
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

pub(super) fn recent_requested_sort_label(history: &[ChatMessage]) -> Option<String> {
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

pub(super) fn recent_goal_primary_target(history: &[ChatMessage]) -> Option<String> {
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

pub(super) fn recent_goal_mentions_submit(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| message.content.to_ascii_lowercase().contains("submit"))
}

pub(super) fn priority_target_semantic_id(summary: &str) -> Option<&str> {
    let token = summary.split_whitespace().next()?;
    if let Some(value) = token.strip_prefix("id=") {
        return Some(value);
    }
    token
        .split_once('#')
        .map(|(_, value)| value)
        .or(Some(token))
}

pub(super) fn priority_target_tag(summary: &str) -> Option<&str> {
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
pub(super) struct BrowserNavigationTransition {
    pub(super) semantic_id: Option<String>,
    pub(super) pre_url: Option<String>,
    pub(super) post_url: String,
}

pub(super) fn clicked_element_semantic_id(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let rest = message.content.trim().strip_prefix("Clicked element '")?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

pub(super) fn recent_successful_click_semantic_id(history: &[ChatMessage]) -> Option<String> {
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

pub(super) fn recent_successful_selected_control_semantic_id(history: &[ChatMessage]) -> Option<String> {
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

pub(super) fn recent_successful_click_is_observed_in_later_snapshot(
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

pub(super) fn recent_successful_click_has_post_action_observation(
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

pub(super) fn tree_change_link_reverification_pending_signal(history: &[ChatMessage]) -> Option<String> {
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

pub(super) fn semantic_id_is_submit_like(semantic_id: &str) -> bool {
    let lower = semantic_id.to_ascii_lowercase();
    lower.contains("submit") || lower.contains("subbtn")
}

pub(super) fn snapshot_contains_semantic_id(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);
    let compact_summary = format!("#{semantic_id}");
    let compact_summary_raw = format!("{semantic_id} tag=");
    let compact_summary_attr = format!("id={semantic_id}");
    snapshot.contains(&semantic_id_attr)
        || snapshot.contains(&compact_summary)
        || snapshot.contains(&compact_summary_raw)
        || snapshot.contains(&compact_summary_attr)
}

pub(super) fn recent_confirmation_queue_return(history: &[ChatMessage]) -> bool {
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

pub(super) fn browser_navigation_transition(message: &ChatMessage) -> Option<BrowserNavigationTransition> {
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

pub(super) fn recent_unobserved_navigation_transition(
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
pub(super) struct SnapshotLinkState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) context: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) controls_dom_id: Option<String>,
    pub(super) focused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabPanelState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotVisibleTargetState {
    pub(super) semantic_id: String,
    pub(super) name: String,
    pub(super) semantic_role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotAutocompleteControlState {
    pub(super) semantic_id: String,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecentAutocompleteAction {
    Typed,
    Key(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentAutocompleteToolState {
    pub(super) action: RecentAutocompleteAction,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentFindTextState {
    pub(super) query: String,
    pub(super) first_snippet: Option<String>,
}

pub(super) fn snapshot_link_states(snapshot: &str) -> Vec<SnapshotLinkState> {
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

pub(super) fn snapshot_tab_states(snapshot: &str) -> Vec<SnapshotTabState> {
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

pub(super) fn snapshot_tabpanel_states(snapshot: &str) -> Vec<SnapshotTabPanelState> {
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

pub(super) fn visible_target_role_priority(semantic_role: &str) -> u8 {
    match semantic_role {
        "link" | "button" | "menuitem" | "option" | "tab" | "checkbox" | "radio" => 4,
        "generic" | "label" | "text" | "heading" => 3,
        "textbox" | "searchbox" | "combobox" => 2,
        _ => 1,
    }
}

pub(super) fn snapshot_visible_exact_text_target(
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

pub(super) fn snapshot_focused_text_control_states(snapshot: &str) -> Vec<SnapshotAutocompleteControlState> {
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

pub(super) fn snapshot_focused_autocomplete_control_state(
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

pub(super) fn autocomplete_tool_state(message: &ChatMessage) -> Option<RecentAutocompleteToolState> {
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

pub(super) fn recent_autocomplete_tool_state(history: &[ChatMessage]) -> Option<RecentAutocompleteToolState> {
    history.iter().rev().find_map(autocomplete_tool_state)
}

pub(super) fn recent_find_text_state(history: &[ChatMessage]) -> Option<RecentFindTextState> {
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

pub(super) fn autocomplete_hint_signals_single_result(hint: &str) -> bool {
    let lower = hint.to_ascii_lowercase();
    lower.contains("1 result is available")
        || lower.contains("1 suggestion is available")
        || lower.contains("1 option is available")
}

pub(super) fn autocomplete_follow_up_pending_signal(
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
