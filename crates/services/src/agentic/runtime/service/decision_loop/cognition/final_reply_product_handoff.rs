use serde_json::Value;

pub(crate) fn sanitize_direct_chat_reply_output(raw_output: &str) -> String {
    let mut text = raw_output.to_string();
    loop {
        let lower = text.to_ascii_lowercase();
        let Some(start) = lower.find("<think") else {
            break;
        };
        let after_open = lower[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(start);
        let end = lower[after_open..]
            .find("</think>")
            .map(|offset| after_open + offset + "</think>".len())
            .unwrap_or_else(|| text.len());
        text.replace_range(start..end, "");
    }
    let text = text.trim().to_string();
    let unwrapped = unwrap_direct_chat_reply_json(&text).unwrap_or(text);
    collapse_repeated_final_reply_cycles(&unwrapped)
}

pub(crate) fn sanitize_product_handoff_internal_markers(raw_output: &str) -> String {
    let mut text = raw_output.to_string();

    text = remove_json_string_field(&text, "command_id");
    text = remove_json_string_field(&text, "commandId");
    text = redact_internal_runtime_tokens(&text);
    text = text.replace(
        "The tool returned an \"Invalid transaction\" error with the specific policy reason: ",
        "The policy reason was: ",
    );
    text = text.replace(
        "The tool returned an 'Invalid transaction' error with the specific policy reason: ",
        "The policy reason was: ",
    );
    text = text.replace("\"Invalid transaction\" error", "policy block");
    text = text.replace("'Invalid transaction' error", "policy block");
    text = text.replace("an policy block", "a policy block");
    text = text.replace("An policy block", "A policy block");
    text = text.replace("Invalid transaction: ", "");
    text = text.replace("Blocked by Policy:", "Blocked by policy:");
    text = redact_error_class_markers(&text);
    text = redact_internal_tool_names(&text);
    text = redact_disposable_absolute_paths(&text);
    text = text.replace(
        "The governed file tool returned the following error: Blocked by policy:",
        "The policy reason was:",
    );
    text = text.replace(
        "The governed file write returned the following error: Blocked by policy:",
        "The policy reason was:",
    );
    text = text.replace(
        "The governed file tool returned an error: Blocked by policy:",
        "The policy reason was:",
    );
    text = text.replace(
        "The governed file write returned an error: Blocked by policy:",
        "The policy reason was:",
    );

    for marker in [
        "(Tool Catalogue Fixture)",
        "Tool Catalogue Fixture",
        "TOOLCAT_BROWSER_CANARY",
        "TOOLCAT_SINGLE_TOOL",
        "TOOLCAT",
        "toolcat",
        "native-fixture",
        "fixture response",
        "fixture marker",
    ] {
        text = text.replace(marker, "");
    }

    for marker in [
        "Autopilot Agent Studio",
        "autopilot_agent_studio",
        "autopilot-agent-studio",
    ] {
        text = text.replace(marker, "the workbench");
    }

    replace_local_disposable_urls(&text)
        .lines()
        .map(|line| {
            line.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .replace(" .", ".")
                .replace(" ,", ",")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

pub(crate) fn final_reply_product_handoff_reason(
    message: &str,
    goal: &str,
) -> Option<&'static str> {
    let trimmed = message.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }

    if final_reply_contains_internal_runtime_reference(trimmed) {
        return Some("internal_runtime_reference");
    }

    if final_reply_contains_product_forbidden_marker(trimmed) {
        return Some("product_forbidden_marker");
    }

    if final_reply_goal_requests_raw_tool_output(goal) {
        return None;
    }

    if final_reply_goal_forbids_raw_coordinates(goal)
        && final_reply_contains_raw_coordinate_pair(trimmed)
    {
        return Some("raw_coordinate_pair");
    }

    if lower.contains("tool output (")
        || lower.contains("tool output:")
        || lower.contains("raw_output")
        || (lower.starts_with('{') && lower.contains("\"name\"") && lower.contains("\"arguments\""))
    {
        return Some("raw_tool_payload");
    }

    if final_reply_contains_goal_derived_command_output_token(trimmed, goal) {
        return Some("raw_command_output_token");
    }

    if lower.contains("tap version")
        && (lower.contains("# subtest")
            || lower.contains("# tests")
            || lower.contains("# pass")
            || lower.contains("duration_ms"))
    {
        return Some("raw_test_log_dump");
    }

    if (lower.contains("stdout:") || lower.contains("stderr:"))
        && (lower.contains("exited with code") || lower.starts_with("command "))
    {
        return Some("raw_command_output_dump");
    }

    None
}

fn replace_local_disposable_urls(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let http = input[index..]
            .find("http://127.0.0.1:")
            .map(|offset| (index + offset, "http://127.0.0.1:"));
        let https = input[index..]
            .find("https://127.0.0.1:")
            .map(|offset| (index + offset, "https://127.0.0.1:"));
        let Some((start, marker)) = [http, https]
            .into_iter()
            .flatten()
            .min_by_key(|(start, _)| *start)
        else {
            break;
        };
        out.push_str(&input[index..start]);
        out.push_str("the disposable browser page");
        let mut end = start + marker.len();
        while end < input.len() {
            let Some(ch) = input[end..].chars().next() else {
                break;
            };
            if ch.is_whitespace() || matches!(ch, ')' | ']' | '}' | '"' | '\'' | '<') {
                break;
            }
            end += ch.len_utf8();
        }
        index = end;
    }
    out.push_str(&input[index..]);
    out
}

fn redact_error_class_markers(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(|token| {
                    if token.to_ascii_lowercase().starts_with("error_class=") {
                        "policy block"
                    } else {
                        token
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

fn redact_internal_tool_names(input: &str) -> String {
    let mut text = input.to_string();
    for (raw, replacement) in [
        ("`file__write`", "the governed file write"),
        ("file__write", "the governed file write"),
        ("`file__read`", "the governed file read"),
        ("file__read", "the governed file read"),
        ("`shell__run`", "the governed command runner"),
        ("shell__run", "the governed command runner"),
        ("`chat__reply`", "the final reply"),
        ("chat__reply", "the final reply"),
    ] {
        text = text.replace(raw, replacement);
    }
    text
}

fn redact_disposable_absolute_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let Some((start, marker)) = disposable_path_match(input, index) else {
            break;
        };
        out.push_str(&input[index..start]);
        out.push_str("the requested workspace path");
        let mut end = start + marker.len();
        while end < input.len() {
            let Some(ch) = input[end..].chars().next() else {
                break;
            };
            if ch.is_whitespace() || matches!(ch, ')' | ']' | '}' | '"' | '\'' | '<' | '`') {
                break;
            }
            end += ch.len_utf8();
        }
        index = end;
    }
    out.push_str(&input[index..]);
    out
}

fn disposable_path_match(input: &str, index: usize) -> Option<(usize, &'static str)> {
    [
        "/tmp/autopilot-agent-studio-",
        "/tmp/autopilot-",
        "/tmp/ioi-",
        ".tmp/autopilot-",
    ]
    .into_iter()
    .filter_map(|marker| {
        input[index..]
            .find(marker)
            .map(|offset| (index + offset, marker))
    })
    .min_by_key(|(start, _)| *start)
}

fn unwrap_direct_chat_reply_json(text: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    let name = value.get("name").and_then(Value::as_str).unwrap_or("");
    if name != "chat__reply" {
        return None;
    }
    value
        .get("arguments")
        .and_then(|arguments| arguments.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(str::to_string)
}

fn collapse_repeated_final_reply_cycles(text: &str) -> String {
    let mut current = text.trim().to_string();
    for _ in 0..4 {
        let char_count = current.chars().count();
        if char_count < 500 {
            break;
        }
        let Some(cut_at) = repeated_final_reply_cycle_cut_index(&current) else {
            break;
        };
        if cut_at < 240 || cut_at >= current.len() {
            break;
        }
        current.truncate(cut_at);
        current = current.trim_end().to_string();
    }
    current
}

fn repeated_final_reply_cycle_cut_index(text: &str) -> Option<usize> {
    let exact_prefix: String = text.chars().take(180).collect();
    if exact_prefix.chars().count() >= 80 {
        let search_start = exact_prefix.len();
        if let Some(offset) = text[search_start..].find(&exact_prefix) {
            let cut_at = search_start + offset;
            if cut_at + exact_prefix.len() < text.len() {
                return Some(cut_at);
            }
        }
    }

    let anchor = repeated_final_reply_cycle_anchor(text)?;
    let search_start = anchor.len();
    let lower_text = text.to_ascii_lowercase();
    let lower_anchor = anchor.to_ascii_lowercase();
    let offset = lower_text[search_start..].find(&lower_anchor)?;
    Some(search_start + offset)
}

fn repeated_final_reply_cycle_anchor(text: &str) -> Option<String> {
    let mut anchor = String::new();
    for ch in text.chars() {
        anchor.push(ch);
        if anchor.chars().count() >= 120 {
            break;
        }
        if matches!(ch, '.' | '!' | '?') && anchor.chars().count() >= 72 {
            break;
        }
    }
    let anchor = anchor.trim();
    if anchor.chars().count() < 72 {
        return None;
    }
    Some(anchor.to_string())
}

fn final_reply_contains_goal_derived_command_output_token(message: &str, goal: &str) -> bool {
    let prefixes = goal_command_output_token_prefixes(goal);
    if prefixes.is_empty() {
        return false;
    }

    message
        .split(|ch: char| !is_command_output_token_char(ch))
        .any(|token| {
            prefixes.iter().any(|prefix| {
                token.strip_prefix(prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
                })
            })
        })
}

fn goal_command_output_token_prefixes(goal: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    for token in goal.split(|ch: char| !is_command_output_token_char(ch)) {
        let token = token.trim();
        if token.len() < 3
            || token.len() > 80
            || !(token.ends_with('-') || token.ends_with('_'))
            || !token.chars().any(|ch| ch.is_ascii_alphabetic())
        {
            continue;
        }
        if !prefixes.iter().any(|prefix| prefix == token) {
            prefixes.push(token.to_string());
        }
    }
    prefixes
}

fn is_command_output_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

fn final_reply_contains_internal_runtime_reference(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if lower.contains("\"command_id\"")
        || lower.contains("\"commandid\"")
        || lower.contains("command_id:")
        || lower.contains("commandid:")
        || lower.contains("receipt://")
        || lower.contains("trace://")
        || lower.contains("workspace_change:")
    {
        return true;
    }
    contains_internal_runtime_token(message)
}

fn contains_internal_runtime_token(input: &str) -> bool {
    let mut token = String::new();
    for ch in input.chars().chain(std::iter::once(' ')) {
        if is_runtime_token_char(ch) {
            token.push(ch);
            continue;
        }
        if internal_runtime_token(&token) {
            return true;
        }
        token.clear();
    }
    false
}

fn redact_internal_runtime_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();
    for ch in input.chars().chain(std::iter::once(' ')) {
        if is_runtime_token_char(ch) {
            token.push(ch);
            continue;
        }
        if !token.is_empty() {
            if internal_runtime_token(&token) {
                output.push_str("Tracing");
            } else {
                output.push_str(&token);
            }
            token.clear();
        }
        if ch != ' ' || input.ends_with(' ') {
            output.push(ch);
        } else {
            output.push(ch);
        }
    }
    output.trim_end().to_string()
}

fn internal_runtime_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.starts_with("shell__start:")
        || lower.starts_with("receipt://")
        || lower.starts_with("trace://")
        || lower.starts_with("workspace_change:")
        || internal_runtime_prefixed_id(&lower, "receipt_")
        || internal_runtime_prefixed_id(&lower, "trace_")
        || internal_runtime_prefixed_id(&lower, "request_")
        || internal_runtime_prefixed_id(&lower, "turn_")
        || internal_runtime_prefixed_id(&lower, "thread_")
}

fn internal_runtime_prefixed_id(token: &str, prefix: &str) -> bool {
    token.starts_with(prefix) && token.len() >= prefix.len() + 8
}

fn is_runtime_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '-' | '/')
}

fn remove_json_string_field(input: &str, field: &str) -> String {
    let needle = format!("\"{field}\"");
    let mut text = input.to_string();
    while let Some(start) = text.find(&needle) {
        let Some(colon_offset) = text[start + needle.len()..].find(':') else {
            break;
        };
        let value_start = start + needle.len() + colon_offset + 1;
        let mut cursor = value_start;
        while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= text.len() || text.as_bytes()[cursor] != b'"' {
            break;
        }
        cursor += 1;
        let mut escaped = false;
        while cursor < text.len() {
            let byte = text.as_bytes()[cursor];
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                cursor += 1;
                break;
            }
            cursor += 1;
        }
        while cursor < text.len() && text.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let mut remove_start = start;
        let mut remove_end = cursor;
        if cursor < text.len() && text.as_bytes()[cursor] == b',' {
            remove_end = cursor + 1;
        } else if start > 0 {
            let before = text[..start].trim_end();
            if before.ends_with(',') {
                remove_start = before.len() - 1;
            }
        }
        text.replace_range(remove_start..remove_end, "");
    }
    text
}

fn final_reply_goal_forbids_raw_coordinates(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    lower.contains("coordinates")
        && (lower.contains("keep raw")
            || lower.contains("keep")
            || lower.contains("out of")
            || lower.contains("do not")
            || lower.contains("don't"))
}

fn final_reply_contains_raw_coordinate_pair(message: &str) -> bool {
    for segment in message.split('(').skip(1) {
        let Some(candidate) = segment.split(')').next() else {
            continue;
        };
        let mut parts = candidate.split(',').map(str::trim);
        let first = parts.next().unwrap_or_default();
        let second = parts.next().unwrap_or_default();
        if parts.next().is_none()
            && final_reply_coordinate_number(first)
            && final_reply_coordinate_number(second)
        {
            return true;
        }
    }
    false
}

fn final_reply_coordinate_number(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 12 {
        return false;
    }
    let mut digit_count = 0usize;
    let mut dot_count = 0usize;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            digit_count += 1;
        } else if ch == '.' {
            dot_count += 1;
            if dot_count > 1 {
                return false;
            }
        } else {
            return false;
        }
    }
    digit_count > 0
}

fn final_reply_contains_product_forbidden_marker(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "toolcat",
        "toolcat_",
        "tool catalogue fixture",
        "autopilot_agent_studio",
        "autopilot-agent-studio",
        "/tmp/autopilot",
        "/tmp/ioi",
        ".tmp/autopilot",
        "native-fixture",
        "fixture response",
        "fixture marker",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn final_reply_goal_requests_raw_tool_output(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    [
        "raw stdout",
        "raw stderr",
        "raw output",
        "full stdout",
        "full stderr",
        "full output",
        "paste stdout",
        "paste stderr",
        "show stdout",
        "show stderr",
        "show the log",
        "full log",
        "verbatim output",
        "tap output",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
