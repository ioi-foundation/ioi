use crate::agentic::desktop::service::step::action::json::extract_balanced_json_object;
use crate::agentic::desktop::types::{CommandExecution, MAX_COMMAND_HISTORY};
use std::collections::VecDeque;

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";

pub fn command_history_exit_code(output: &str) -> Option<i64> {
    command_history_payload(output)?
        .get("exit_code")
        .and_then(|value| value.as_i64())
}

fn command_history_payload(output: &str) -> Option<serde_json::Value> {
    let payload = latest_command_history_payload(output)?;
    serde_json::from_str::<serde_json::Value>(payload).ok()
}

pub fn command_history_entry(output: &str) -> Option<CommandExecution> {
    let payload = latest_command_history_payload(output)?;
    serde_json::from_str::<CommandExecution>(payload).ok()
}

fn latest_command_history_payload(output: &str) -> Option<&str> {
    let mut latest_payload: Option<&str> = None;

    for (marker_idx, _) in output.match_indices(COMMAND_HISTORY_PREFIX) {
        let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
        if let Some(start) = suffix.find('{') {
            if let Some(json) = extract_balanced_json_object(suffix, start) {
                latest_payload = Some(json);
                continue;
            }
        }

        let fallback = suffix.lines().next().unwrap_or_default().trim();
        if !fallback.is_empty() {
            latest_payload = Some(fallback);
        }
    }

    latest_payload
}

pub fn append_command_history_entry(history: &mut VecDeque<CommandExecution>, entry: CommandExecution) {
    history.push_back(entry);
    while history.len() > MAX_COMMAND_HISTORY {
        let _ = history.pop_front();
    }
}
