use crate::agentic::runtime::types::{AgentState, CommandExecution};
use serde::{Deserialize, Serialize};

pub const RUNTIME_STOP_HOOK_SCHEMA_VERSION: &str = "ioi.runtime.stop_hook.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStopHookSnapshot {
    pub schema_version: String,
    pub session_id: String,
    pub status: String,
    pub completion_blocked: bool,
    pub replay_cursor_step: u32,
    pub latest_validation: Option<RuntimeValidationCommandSnapshot>,
    pub feedback: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeValidationCommandSnapshot {
    pub command: String,
    pub exit_code: i32,
    pub step_index: u32,
    pub timestamp_ms: u64,
    pub classified_as: Vec<String>,
    pub stdout_excerpt: Option<String>,
    pub stderr_excerpt: Option<String>,
}

pub fn stop_hook_snapshot_for_state(
    session_id: [u8; 32],
    agent_state: &AgentState,
) -> RuntimeStopHookSnapshot {
    let latest_validation = latest_validation_command(agent_state).map(validation_snapshot);
    let completion_blocked = latest_validation
        .as_ref()
        .is_some_and(|entry| entry.exit_code != 0);
    let status = if completion_blocked {
        "blocked"
    } else if latest_validation.is_some() {
        "cleared"
    } else {
        "not_applicable"
    };
    let feedback = if let Some(entry) = latest_validation
        .as_ref()
        .filter(|entry| entry.exit_code != 0)
    {
        vec![format!(
            "Latest validation command failed (exit_code={}): {}. Repair the failure, rerun validation, then finish.",
            entry.exit_code, entry.command
        )]
    } else {
        Vec::new()
    };

    RuntimeStopHookSnapshot {
        schema_version: RUNTIME_STOP_HOOK_SCHEMA_VERSION.to_string(),
        session_id: hex::encode(session_id),
        status: status.to_string(),
        completion_blocked,
        replay_cursor_step: agent_state.step_count,
        latest_validation,
        feedback,
    }
}

pub fn stop_hook_completion_blocker(agent_state: &AgentState) -> Option<String> {
    let latest = latest_validation_command(agent_state)?;
    if latest.exit_code == 0 {
        return None;
    }
    let mut feedback = format!(
        "ERROR_CLASS=StopHookBlocked Latest validation command failed (exit_code={}): {}. Do not call the terminal reply tool again until a later validation command exits 0. Continue the model -> tool -> typed result -> model loop: inspect the failure, repair the cause, and rerun validation.",
        latest.exit_code,
        latest.command.trim()
    );
    if let Some(stdout) = compact_log_excerpt(&latest.stdout) {
        feedback.push_str("\nLatest stdout excerpt:\n");
        feedback.push_str(&stdout);
    }
    if let Some(stderr) = compact_log_excerpt(&latest.stderr) {
        feedback.push_str("\nLatest stderr excerpt:\n");
        feedback.push_str(&stderr);
    }
    Some(feedback)
}

fn latest_validation_command(agent_state: &AgentState) -> Option<&CommandExecution> {
    agent_state
        .command_history
        .iter()
        .rev()
        .find(|entry| validation_command_classes(&entry.command).next().is_some())
}

fn validation_snapshot(entry: &CommandExecution) -> RuntimeValidationCommandSnapshot {
    RuntimeValidationCommandSnapshot {
        command: entry.command.clone(),
        exit_code: entry.exit_code,
        step_index: entry.step_index,
        timestamp_ms: entry.timestamp_ms,
        classified_as: validation_command_classes(&entry.command).collect(),
        stdout_excerpt: compact_log_excerpt(&entry.stdout),
        stderr_excerpt: compact_log_excerpt(&entry.stderr),
    }
}

fn validation_command_classes(command: &str) -> impl Iterator<Item = String> + '_ {
    let lower = command.to_ascii_lowercase();
    [
        (
            "test",
            [
                "cargo test",
                "npm test",
                "npm run test",
                "pnpm test",
                "pnpm run test",
                "yarn test",
                "pytest",
                "python -m pytest",
                "node --test",
                "go test",
                "deno test",
                "bun test",
                "vitest",
                "jest",
                "mocha",
                "mvn test",
                "gradle test",
            ]
            .as_slice(),
        ),
        (
            "diagnostic",
            [
                "cargo check",
                "cargo clippy",
                "npm run lint",
                "pnpm run lint",
                "yarn lint",
                "eslint",
                "tsc",
                "typescript",
                "ruff",
                "mypy",
                "clippy",
            ]
            .as_slice(),
        ),
    ]
    .into_iter()
    .filter_map(move |(class, markers)| {
        markers
            .iter()
            .any(|marker| lower.contains(marker))
            .then(|| class.to_string())
    })
}

fn compact_log_excerpt(value: &str) -> Option<String> {
    let lines = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }

    let mut excerpt: Vec<&str> = Vec::new();
    for line in lines.iter().take(6) {
        push_unique_line(&mut excerpt, line);
    }
    for line in lines.iter().filter(|line| diagnostic_log_line(line)) {
        push_unique_line(&mut excerpt, line);
    }
    let tail_start = lines.len().saturating_sub(8);
    for line in lines.iter().skip(tail_start) {
        push_unique_line(&mut excerpt, line);
    }

    let compact = excerpt.into_iter().take(28).collect::<Vec<_>>().join("\n");
    if compact.is_empty() {
        return None;
    }
    Some(truncate_chars(&compact, 1600))
}

fn push_unique_line<'a>(target: &mut Vec<&'a str>, line: &'a str) {
    if !target.iter().any(|existing| *existing == line) {
        target.push(line);
    }
}

fn diagnostic_log_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "not ok",
        "fail",
        "failed",
        "failure",
        "error",
        "assert",
        "expected",
        "actual",
        "operator",
        "panic",
        "exception",
        "diff",
        "caused by",
        "stack:",
        "location:",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::types::{AgentMode, AgentStatus, ExecutionTier, ToolCallStatus};
    use std::collections::{BTreeMap, VecDeque};

    fn test_state(command_history: VecDeque<CommandExecution>) -> AgentState {
        AgentState {
            session_id: [9u8; 32],
            goal: "fix the failing test".to_string(),
            runtime_route_frame: None,
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 7,
            max_steps: 16,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::<String, ToolCallStatus>::new(),
            execution_ledger: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history,
            active_lens: None,
        }
    }

    fn command(command: &str, exit_code: i32, step_index: u32) -> CommandExecution {
        CommandExecution {
            command: command.to_string(),
            exit_code,
            stdout: "stdout line".to_string(),
            stderr: "stderr line".to_string(),
            timestamp_ms: 1_772_304_000_000 + u64::from(step_index),
            step_index,
        }
    }

    #[test]
    fn stop_hook_blocks_latest_failing_validation_command() {
        let history = VecDeque::from(vec![
            command("grep missing README.md", 1, 1),
            command("npm test", 1, 2),
        ]);
        let state = test_state(history);

        let snapshot = stop_hook_snapshot_for_state([9u8; 32], &state);

        assert_eq!(snapshot.status, "blocked");
        assert!(snapshot.completion_blocked);
        assert_eq!(
            snapshot
                .latest_validation
                .as_ref()
                .map(|entry| entry.command.as_str()),
            Some("npm test")
        );
        assert!(stop_hook_completion_blocker(&state)
            .as_deref()
            .is_some_and(|error| {
                error.contains("ERROR_CLASS=StopHookBlocked")
                    && error.contains("Latest stdout excerpt:")
                    && error.contains("stdout line")
            }));
    }

    #[test]
    fn stop_hook_clears_after_later_successful_validation() {
        let history = VecDeque::from(vec![command("npm test", 1, 2), command("npm test", 0, 3)]);
        let state = test_state(history);

        let snapshot = stop_hook_snapshot_for_state([9u8; 32], &state);

        assert_eq!(snapshot.status, "cleared");
        assert!(!snapshot.completion_blocked);
        assert!(stop_hook_completion_blocker(&state).is_none());
    }

    #[test]
    fn stop_hook_keeps_diagnostic_assertion_lines_from_long_test_output() {
        let mut failing = command("node --test tests/*.test.mjs", 1, 2);
        failing.stdout = [
            "TAP version 13",
            "# Subtest: formats order totals as dollars",
            "not ok 1 - formats order totals as dollars",
            "---",
            "duration_ms: 0.920992",
            "type: 'test'",
            "location: '/tmp/repo/tests/format.test.mjs:5:1'",
            "failureType: 'testCodeFailure'",
            "error: |-",
            "Expected values to be strictly equal:",
            "+ actual - expected",
            "+ '$12.99.toFixed(2)'",
            "- '$12.99'",
            "code: 'ERR_ASSERTION'",
            "name: 'AssertionError'",
            "expected: '$12.99'",
            "actual: '$12.99.toFixed(2)'",
            "operator: 'strictEqual'",
            "1..1",
            "# tests 1",
            "# pass 0",
            "# fail 1",
        ]
        .join("\n");
        let state = test_state(VecDeque::from(vec![failing]));

        let blocker = stop_hook_completion_blocker(&state).expect("stop hook should block");

        assert!(blocker.contains("Latest stdout excerpt:"));
        assert!(blocker.contains("Expected values to be strictly equal"));
        assert!(blocker.contains("actual: '$12.99.toFixed(2)'"));
        assert!(blocker.contains("expected: '$12.99'"));
        assert!(blocker.contains("operator: 'strictEqual'"));
    }

    #[test]
    fn stop_hook_ignores_plain_nonzero_exploration_commands() {
        let history = VecDeque::from(vec![command("grep missing README.md", 1, 1)]);
        let state = test_state(history);

        let snapshot = stop_hook_snapshot_for_state([9u8; 32], &state);

        assert_eq!(snapshot.status, "not_applicable");
        assert!(!snapshot.completion_blocked);
        assert!(snapshot.latest_validation.is_none());
    }
}
