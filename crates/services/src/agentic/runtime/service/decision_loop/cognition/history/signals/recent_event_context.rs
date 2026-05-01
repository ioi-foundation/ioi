pub(super) fn is_browser_snapshot_no_effect_message(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with(BROWSER_SNAPSHOT_TOOL_PREFIX)
        && compact.contains("ERROR_CLASS=NoEffectAfterAction")
}

pub(super) fn is_browser_observation_refresh_message(message: &ChatMessage) -> bool {
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

pub(super) fn is_incident_follow_up_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("System: Remedy")
        || compact.starts_with("System: Incident")
        || compact.starts_with("System: Selected recovery action")
}

pub(super) fn is_browser_context_echo_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("RECENT PENDING BROWSER STATE:")
        || compact.starts_with("RECENT SUCCESS SIGNAL:")
        || compact.starts_with("RECENT BROWSER OBSERVATION:")
}

pub(super) fn explicit_pending_browser_state_context_message(
    message: &ChatMessage,
) -> Option<String> {
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

pub(super) fn filtered_recent_session_events<'a>(
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

pub(crate) fn build_recent_session_events_context(
    history: &[ChatMessage],
    prefer_browser_semantics: bool,
) -> String {
    fn compact_recent_session_event_scalar(
        value: Option<&Value>,
        max_chars: usize,
    ) -> Option<String> {
        value
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())
            .map(|value| safe_truncate(&value, max_chars))
    }

    fn compact_recent_session_web_source_summaries(payload: &Value) -> Vec<String> {
        payload
            .get("sources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(2)
            .filter_map(|source| {
                let title = compact_recent_session_event_scalar(source.get("title"), 96)
                    .unwrap_or_default();
                let url =
                    compact_recent_session_event_scalar(source.get("url"), 120).unwrap_or_default();
                let snippet = compact_recent_session_event_scalar(source.get("snippet"), 140)
                    .unwrap_or_default();

                if title.is_empty() && url.is_empty() && snippet.is_empty() {
                    return None;
                }

                let mut summary = String::new();
                if !title.is_empty() {
                    summary.push_str(&title);
                }
                if !url.is_empty() {
                    if !summary.is_empty() {
                        summary.push_str(" | ");
                    }
                    summary.push_str(&url);
                }
                if !snippet.is_empty() {
                    if !summary.is_empty() {
                        summary.push_str(" | ");
                    }
                    summary.push_str(&snippet);
                }
                Some(summary)
            })
            .collect()
    }

    fn compact_recent_session_web_document_summaries(payload: &Value) -> Vec<String> {
        payload
            .get("documents")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(2)
            .filter_map(|document| {
                let title = compact_recent_session_event_scalar(document.get("title"), 96)
                    .unwrap_or_default();
                let url = compact_recent_session_event_scalar(document.get("url"), 120)
                    .unwrap_or_default();
                let excerpt =
                    compact_recent_session_event_scalar(document.get("content_text"), 220)
                        .unwrap_or_default();

                if title.is_empty() && url.is_empty() && excerpt.is_empty() {
                    return None;
                }

                let mut summary = String::new();
                if !title.is_empty() {
                    summary.push_str(&title);
                }
                if !url.is_empty() {
                    if !summary.is_empty() {
                        summary.push_str(" | ");
                    }
                    summary.push_str(&url);
                }
                if !excerpt.is_empty() {
                    if !summary.is_empty() {
                        summary.push_str(" | ");
                    }
                    summary.push_str(&excerpt);
                }
                Some(summary)
            })
            .collect()
    }

    fn compact_non_browser_tool_event_content(message: &ChatMessage) -> Option<String> {
        if message.role != "tool" {
            return None;
        }

        let payload = parse_json_value_from_message(&message.content)?;
        let tool = compact_recent_session_event_scalar(payload.get("tool"), 48)?;

        if matches!(tool.as_str(), "web__search" | "web__read") {
            let primary = compact_recent_session_event_scalar(
                payload.get("query").or_else(|| payload.get("url")),
                140,
            );
            let source_summaries = compact_recent_session_web_source_summaries(&payload);
            let document_summaries = compact_recent_session_web_document_summaries(&payload);
            let mut segments = vec![tool];

            if let Some(primary) = primary {
                segments.push(primary);
            }
            if !source_summaries.is_empty() {
                segments.push(format!("sources={}", source_summaries.join(" || ")));
            }
            if !document_summaries.is_empty() {
                segments.push(format!("docs={}", document_summaries.join(" || ")));
            }

            return Some(segments.join(" ; "));
        }

        None
    }

    fn compact_recent_session_event_content(
        message: &ChatMessage,
        prefer_browser_semantics: bool,
    ) -> String {
        if !prefer_browser_semantics {
            if message.role != "tool" {
                return message.content.clone();
            }

            if let Some(compact) = compact_non_browser_tool_event_content(message) {
                return compact;
            }

            return safe_truncate(&compact_ws_for_prompt(&message.content), 360);
        }

        if message.role != "tool" {
            return message.content.clone();
        }

        let compact = compact_ws_for_prompt(&message.content);
        if compact.is_empty() {
            return String::new();
        }

        if compact.starts_with("Synthetic click at (") {
            return safe_truncate(&compact, 320);
        }

        for marker in [" verify=", " geometry=", " snapshot="] {
            if let Some(prefix) = compact.split_once(marker).map(|(prefix, _)| prefix.trim()) {
                if !prefix.is_empty() {
                    return prefix.to_string();
                }
            }
        }

        safe_truncate(&compact, 220)
    }

    filtered_recent_session_events(history, prefer_browser_semantics)
        .into_iter()
        .map(|message| {
            format!(
                "{}: {}",
                message.role,
                compact_recent_session_event_content(message, prefer_browser_semantics)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn build_recent_browser_observation_context(history: &[ChatMessage]) -> String {
    if recent_unobserved_navigation_transition(history).is_some() {
        return String::new();
    }

    let Some(observation) = history.iter().rev().find_map(browser_snapshot_payload) else {
        return String::new();
    };

    build_browser_observation_context_from_snapshot_with_history(observation, history)
}

pub(crate) fn build_recent_pending_browser_state_context(history: &[ChatMessage]) -> String {
    build_recent_pending_browser_state_context_with_snapshot(history, None)
}
