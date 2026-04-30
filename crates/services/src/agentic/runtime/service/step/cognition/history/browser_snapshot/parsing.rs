pub(super) fn recent_browser_key_selector_from_compact(compact: &str) -> Option<String> {
    extract_scoped_compact_jsonish_string_field(compact, "\"key\":{", "selector")
        .map(|selector| selector.trim().to_string())
        .filter(|selector| !selector.is_empty())
}

pub(super) fn compact_ws_for_prompt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn looks_like_browser_snapshot_payload(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root")
        && trimmed.contains("id=\"")
        && trimmed.contains("rect=\"")
        && trimmed.contains("</root>")
}

pub(super) fn extract_browser_snapshot_xml(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    if !trimmed.starts_with("<root") {
        return None;
    }

    let end = trimmed.rfind("</root>")?;
    let xml = &trimmed[..end + "</root>".len()];
    (xml.contains("id=\"") && xml.contains("rect=\"")).then_some(xml)
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
    extract_browser_snapshot_xml(payload)
}

pub(super) fn decode_browser_xml_text(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

pub(super) fn extract_browser_xml_attr(fragment: &str, attr: &str) -> Option<String> {
    let marker = format!(r#"{attr}=""#);
    let mut search_start = 0usize;

    while let Some(relative_start) = fragment[search_start..].find(&marker) {
        let start = search_start + relative_start;
        let prefix_valid = start == 0
            || fragment[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_whitespace() || ch == '<');
        if !prefix_valid {
            search_start = start + 1;
            continue;
        }

        let value_start = start + marker.len();
        let rest = &fragment[value_start..];
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }

    None
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

pub(super) fn extract_scoped_compact_jsonish_number_field(
    text: &str,
    scope_marker: &str,
    key: &str,
) -> Option<f64> {
    let scope_start = text.find(scope_marker)? + scope_marker.len();
    extract_compact_jsonish_number_field(&text[scope_start..], key)
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

pub(super) fn recent_focused_scroll_remaining_near_top(
    history: &[ChatMessage],
    selector: &str,
) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    let (scroll_top, client_height) = history.iter().rev().take(6).find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        if !compact.contains("\"key\":{")
            || !compact.contains("\"focused\":true")
            || !compact.contains("\"can_scroll_up\":true")
        {
            return None;
        }
        if recent_browser_key_selector_from_compact(&compact).as_deref() != Some(selector) {
            return None;
        }

        let scroll_top = extract_compact_jsonish_number_field(&compact, "scroll_top")?;
        let client_height = extract_compact_jsonish_number_field(&compact, "client_height")?;
        Some((scroll_top, client_height))
    })?;

    (scroll_top > 0.0 && scroll_top < client_height).then(|| format_prompt_number(scroll_top))
}

pub(super) fn recent_focused_scroll_remaining_within_final_page_up_window(
    history: &[ChatMessage],
    selector: &str,
) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    let (scroll_top, client_height) = history.iter().rev().take(6).find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        if !compact.contains("\"key\":{")
            || !compact.contains("\"focused\":true")
            || !compact.contains("\"can_scroll_up\":true")
        {
            return None;
        }
        if recent_browser_key_selector_from_compact(&compact).as_deref() != Some(selector) {
            return None;
        }

        let scroll_top = extract_compact_jsonish_number_field(&compact, "scroll_top")?;
        let client_height = extract_compact_jsonish_number_field(&compact, "client_height")?;
        Some((scroll_top, client_height))
    })?;

    ((scroll_top >= client_height) && (scroll_top < client_height * 2.0))
        .then(|| format_prompt_number(scroll_top))
}

pub(super) fn recent_top_edge_jump_left_scroll_remaining(
    history: &[ChatMessage],
    selector: &str,
) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    let scroll_top = history.iter().rev().take(6).find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        if !compact.contains("\"key\":{")
            || !compact.contains("\"focused\":true")
            || !compact.contains("\"can_scroll_up\":true")
        {
            return None;
        }
        if recent_browser_key_selector_from_compact(&compact).as_deref() != Some(selector) {
            return None;
        }

        let used_top_edge_jump = (compact.contains("\"key\":\"Home\"")
            && compact.contains("\"modifiers\":[\"Control\"]"))
            || (compact.contains("\"key\":\"ArrowUp\"")
                && compact.contains("\"modifiers\":[\"Meta\"]"));
        if !used_top_edge_jump {
            return None;
        }

        extract_compact_jsonish_number_field(&compact, "scroll_top")
    })?;

    (scroll_top > 0.0).then(|| format_prompt_number(scroll_top))
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
