use crate::agentic::desktop::service::actions::safe_truncate;
use crate::agentic::desktop::types::{CommandExecution, MAX_PROMPT_HISTORY};
use ioi_types::app::agentic::ChatMessage;
use std::collections::VecDeque;

const BROWSER_OBSERVATION_CONTEXT_MAX_CHARS: usize = 1_800;
const BROWSER_SNAPSHOT_TOOL_PREFIX: &str = "Tool Output (browser__snapshot):";

fn compact_ws_for_prompt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn looks_like_browser_snapshot_payload(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root")
        && trimmed.contains("id=\"")
        && trimmed.contains("rect=\"")
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

pub(super) fn build_recent_browser_observation_context(history: &[ChatMessage]) -> String {
    let Some(observation) = history
        .iter()
        .rev()
        .find_map(browser_snapshot_payload)
    else {
        return String::new();
    };

    let compact_observation =
        safe_truncate(&compact_ws_for_prompt(observation), BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    if compact_observation.is_empty() {
        return String::new();
    }

    format!(
        "RECENT BROWSER OBSERVATION:\n{}\nUse this semantic browser evidence directly when selecting the next browser action.\n",
        compact_observation
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_recent_browser_observation_context, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS,
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
}
