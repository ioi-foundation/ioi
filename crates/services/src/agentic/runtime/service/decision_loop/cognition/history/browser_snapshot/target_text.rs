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
        " and hit submit",
        " then hit submit",
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
            let candidate = original_rest[..end]
                .trim_end()
                .strip_suffix(" as the date")
                .or_else(|| original_rest[..end].trim_end().strip_suffix(" as date"))
                .unwrap_or(&original_rest[..end]);
            if let Some(value) = trim_goal_target_value(candidate) {
                return Some(value);
            }
        }
    }

    None
}

fn extract_find_by_target(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let find_start = lower.find("find ")?;
    let search_window = &lower[find_start..];
    let by_marker = search_window.find(" by ")?;
    let value_start = find_start + by_marker + " by ".len();
    let original_rest = &text[value_start..];
    let lower_rest = &lower[value_start..];

    let mut end = original_rest.len();
    for marker in [" and ", " then ", ".", ",", ";", "\n"] {
        if let Some(idx) = lower_rest.find(marker) {
            end = end.min(idx);
        }
    }

    trim_goal_target_value(&original_rest[..end])
}

fn extract_message_source_target(text: &str) -> Option<String> {
    const MESSAGE_MARKERS: &[&str] = &["email", "e-mail", "mail", "message"];
    const SOURCE_PATTERNS: &[&str] = &[
        " that i got from ",
        " that i received from ",
        " that i have from ",
        " from ",
    ];
    const END_MARKERS: &[&str] = &[" and ", " then ", " to ", ".", ",", ";", "\n", "!", "?"];

    let lower = text.to_ascii_lowercase();

    for marker in MESSAGE_MARKERS {
        let mut search_start = 0usize;
        while let Some(relative_idx) = lower[search_start..].find(marker) {
            let message_end = search_start + relative_idx + marker.len();
            let _original_rest = &text[message_end..];
            let lower_rest = &lower[message_end..];

            for pattern in SOURCE_PATTERNS {
                let Some(pattern_idx) = lower_rest.find(pattern) else {
                    continue;
                };
                let value_start = message_end + pattern_idx + pattern.len();
                let original_value_rest = &text[value_start..];
                let lower_value_rest = &lower[value_start..];

                let mut end = original_value_rest.len();
                for marker in END_MARKERS {
                    if let Some(idx) = lower_value_rest.find(marker) {
                        end = end.min(idx);
                    }
                }

                if let Some(target) = trim_goal_target_value(&original_value_rest[..end]) {
                    return Some(target);
                }
            }

            search_start = message_end;
        }
    }

    None
}

fn extract_message_recipient_target(text: &str) -> Option<String> {
    const MESSAGE_SUFFIXES: &[&str] = &[" the email", " the e-mail", " the mail", " the message"];
    const END_MARKERS: &[&str] = &[" and ", " then ", " to ", ".", ",", ";", "\n", "!", "?"];

    let lower = text.to_ascii_lowercase();

    if let Some(send_start) = lower.find("send ") {
        let value_start = send_start + "send ".len();
        let original_rest = &text[value_start..];
        let lower_rest = &lower[value_start..];
        let mut end = original_rest.len();

        for suffix in MESSAGE_SUFFIXES {
            if let Some(idx) = lower_rest.find(suffix) {
                end = end.min(idx);
            }
        }

        if end < original_rest.len() {
            if let Some(target) = trim_goal_target_value(&original_rest[..end]) {
                return Some(target);
            }
        }
    }

    if let Some(forward_start) = lower.find("forward ") {
        let value_start = forward_start + "forward ".len();
        let lower_rest = &lower[value_start..];
        if let Some(to_idx) = lower_rest.rfind(" to ") {
            let target_start = value_start + to_idx + " to ".len();
            let original_target_rest = &text[target_start..];
            let lower_target_rest = &lower[target_start..];
            let mut end = original_target_rest.len();

            for marker in END_MARKERS {
                if let Some(idx) = lower_target_rest.find(marker) {
                    end = end.min(idx);
                }
            }

            if let Some(target) = trim_goal_target_value(&original_target_rest[..end]) {
                return Some(target);
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

fn normalized_text_contains_exact_phrase(text: &str, phrase: &str) -> bool {
    let normalized_text = normalized_exact_target_text(text);
    let normalized_phrase = normalized_exact_target_text(phrase);
    if normalized_text.is_empty() || normalized_phrase.is_empty() {
        return false;
    }

    normalized_text == normalized_phrase
        || normalized_text.starts_with(&format!("{normalized_phrase} "))
        || normalized_text.ends_with(&format!(" {normalized_phrase}"))
        || normalized_text.contains(&format!(" {normalized_phrase} "))
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
                .or_else(|| extract_message_source_target(&message.content))
                .or_else(|| extract_find_by_target(&message.content))
        })
}

pub(super) fn recent_goal_message_recipient_target(history: &[ChatMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| extract_message_recipient_target(&message.content))
}

pub(super) fn recent_goal_mentions_submit(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| message.content.to_ascii_lowercase().contains("submit"))
}

fn normalized_goal_is_submit_only_action(goal: &str) -> bool {
    let normalized_goal = normalized_exact_target_text(goal);
    let remaining_tokens = normalized_goal
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "a" | "an"
                    | "and"
                    | "button"
                    | "click"
                    | "control"
                    | "hit"
                    | "icon"
                    | "now"
                    | "on"
                    | "please"
                    | "press"
                    | "tap"
                    | "the"
                    | "then"
                    | "use"
            )
        })
        .collect::<Vec<_>>();

    !remaining_tokens.is_empty()
        && remaining_tokens
            .iter()
            .all(|token| matches!(*token, "submit"))
}

fn snapshot_goal_text_match_is_premature_submit_fallback(
    semantic_id: &str,
    normalized_name: &str,
    matching_goals: &[&str],
) -> bool {
    let submit_like_name = normalized_name
        .split_whitespace()
        .any(|token| token == "submit");
    if !(semantic_id_is_submit_like(semantic_id) || submit_like_name) {
        return false;
    }

    !matching_goals.is_empty()
        && matching_goals
            .iter()
            .all(|goal| !normalized_goal_is_submit_only_action(goal))
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

pub(super) fn priority_target_name(summary: &str) -> Option<String> {
    let marker = " name=";
    let start = summary.find(marker)? + marker.len();
    let rest = &summary[start..];
    let end = rest
        .find(" dom_id=")
        .or_else(|| rest.find(" selector="))
        .or_else(|| rest.find(" class_name="))
        .or_else(|| rest.find(" dom_clickable="))
        .or_else(|| rest.find(" focused="))
        .or_else(|| rest.find(" selected="))
        .or_else(|| rest.find(" checked="))
        .or_else(|| rest.find(" omitted"))
        .unwrap_or(rest.len());
    Some(rest[..end].trim().to_ascii_lowercase())
}
