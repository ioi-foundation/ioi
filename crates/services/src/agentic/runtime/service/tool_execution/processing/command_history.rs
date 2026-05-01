use crate::agentic::runtime::service::tool_execution::json::extract_balanced_json_object;
use crate::agentic::runtime::types::CommandExecution;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const COMMAND_HISTORY_SCRUBBED_PLACEHOLDER: &str = "[REDACTED_PII]";
static COMMAND_HISTORY_MARKER_MISS_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_PARSE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_SCRUB_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn extract_command_history(history_entry: &Option<String>) -> Option<CommandExecution> {
    let entry = history_entry.as_deref()?;
    let mut latest: Option<CommandExecution> = None;
    let mut saw_marker = false;
    let mut saw_parse_failure = false;

    for (marker_idx, _) in entry.match_indices(COMMAND_HISTORY_PREFIX) {
        saw_marker = true;
        let payload = &entry[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
        if payload.trim().is_empty() {
            saw_parse_failure = true;
            continue;
        }
        match parse_command_history_payload(payload) {
            Ok(parsed) => latest = Some(parsed),
            Err(_) => saw_parse_failure = true,
        }
    }

    if let Some(parsed) = latest {
        return Some(parsed);
    }

    if !saw_marker {
        let _ = COMMAND_HISTORY_MARKER_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if saw_parse_failure {
        let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    None
}

fn parse_command_history_payload(payload: &str) -> Result<CommandExecution, serde_json::Error> {
    if let Some(start) = payload.find('{') {
        if let Some(json) = extract_balanced_json_object(payload, start) {
            return serde_json::from_str::<CommandExecution>(json);
        }
    }
    serde_json::from_str::<CommandExecution>(payload.trim())
}

pub(super) async fn scrub_command_history_fields(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    mut entry: CommandExecution,
) -> CommandExecution {
    entry.command = scrub_text_field(scrubber, &entry.command).await;
    entry.stdout = scrub_text_field(scrubber, &entry.stdout).await;
    entry.stderr = scrub_text_field(scrubber, &entry.stderr).await;
    entry
}

async fn scrub_text_field(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> String {
    match scrubber.scrub(input).await {
        Ok((scrubbed, _)) => scrubbed,
        Err(_) => {
            let _ = COMMAND_HISTORY_SCRUB_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            COMMAND_HISTORY_SCRUBBED_PLACEHOLDER.to_string()
        }
    }
}

pub(super) fn append_to_bounded_history(
    history: &mut VecDeque<CommandExecution>,
    entry: CommandExecution,
    max_size: usize,
) {
    history.push_back(entry);
    while history.len() > max_size {
        let _ = history.pop_front();
    }
}

#[cfg(test)]
#[path = "command_history/tests.rs"]
mod tests;
