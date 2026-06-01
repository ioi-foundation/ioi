use crate::agentic::runtime::trajectory::{
    workspace_change_records_for_state, WorkspaceChangeRecord,
};
use crate::agentic::runtime::types::AgentState;

use super::tool_prompting::goal_suggests_command_workspace_rollback;

const MAX_WORKSPACE_CHANGE_ROWS: usize = 8;
const MAX_WORKSPACE_CHANGE_PATH_CHARS: usize = 120;

pub(crate) fn render_workspace_change_context(agent_state: &AgentState) -> String {
    render_workspace_change_context_from_records(workspace_change_records_for_state(agent_state))
}

pub(crate) fn render_workspace_change_lifecycle_instruction(agent_state: &AgentState) -> String {
    if !goal_suggests_command_workspace_rollback(&agent_state.goal) {
        return String::new();
    }

    if agent_state.last_action_type.as_deref() == Some("workspace_change__rollback") {
        return "WORKSPACE CHANGE LIFECYCLE CONTRACT:\n\
                - The rollback action has just run. The next action must verify the target file with `file__read` before replying.\n\
                - Do not repeat the rollback unless the tool result explicitly says it failed."
            .to_string();
    }

    let actionable_change_count = workspace_change_records_for_state(agent_state)
        .into_iter()
        .filter(|change| change.lifecycle == "applied" && rollback_supported(change))
        .count();
    if actionable_change_count > 0 {
        return "WORKSPACE CHANGE LIFECYCLE CONTRACT:\n\
                - The user asked to roll back a previously applied workspace change.\n\
                - The next action must be `workspace_change__rollback` using one listed daemon-owned `change_id`.\n\
                - Do not read or edit files before the rollback action succeeds.\n\
                - After rollback succeeds, read the target file and then answer cleanly."
            .to_string();
    }

    "WORKSPACE CHANGE LIFECYCLE CONTRACT:\n\
     - The user asked to roll back a workspace change, but no actionable handle is visible in prompt context.\n\
     - The next action must be `workspace_change__status` to recover daemon-owned change handles.\n\
     - Do not pass full workspace change JSON in product-visible text."
        .to_string()
}

fn render_workspace_change_context_from_records(changes: Vec<WorkspaceChangeRecord>) -> String {
    let rows = changes
        .into_iter()
        .filter_map(render_actionable_workspace_change_row)
        .take(MAX_WORKSPACE_CHANGE_ROWS)
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return String::new();
    }

    format!(
        "WORKSPACE CHANGE HANDLES:\n\
         Use these daemon-owned `change_id` values when selecting workspace lifecycle tools. \
         Prefer `change_id` over full change payloads. Do not pass full workspace change JSON, \
         hunk text, receipts, or evidence payloads in tool arguments.\n{}",
        rows.join("\n")
    )
}

fn render_actionable_workspace_change_row(change: WorkspaceChangeRecord) -> Option<String> {
    let change_id = change.change_id.trim();
    if change_id.is_empty() {
        return None;
    }

    let action = match change.lifecycle.as_str() {
        "applied" if rollback_supported(&change) => "rollback_available=true",
        "proposed" | "awaiting_approval" => "reject_available=true",
        _ => return None,
    };

    Some(format!(
        "- change_id={} lifecycle={} tool={} path={} edits={} {}",
        change_id,
        change.lifecycle,
        compact_field(&change.tool_name, MAX_WORKSPACE_CHANGE_PATH_CHARS),
        compact_field(
            change.path.as_deref().unwrap_or("unknown"),
            MAX_WORKSPACE_CHANGE_PATH_CHARS
        ),
        change.edit_count,
        action
    ))
}

fn rollback_supported(change: &WorkspaceChangeRecord) -> bool {
    matches!(change.tool_name.as_str(), "file__edit" | "file__multi_edit")
}

fn compact_field(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .take(max_chars.saturating_sub(3))
        .chain("...".chars())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(tool_name: &str, lifecycle: &str) -> WorkspaceChangeRecord {
        WorkspaceChangeRecord {
            change_id: format!("workspace_change:{tool_name}:{lifecycle}"),
            tool_name: tool_name.to_string(),
            path: Some("src/lib.rs".to_string()),
            lifecycle: lifecycle.to_string(),
            edit_count: 1,
            receipt_ref: Some("{\"receipt\":\"must-not-render\"}".to_string()),
            evidence_ref: Some("evidence::full_payload".to_string()),
            ..WorkspaceChangeRecord::default()
        }
    }

    #[test]
    fn renders_applied_edit_change_ids_for_rollback() {
        let rendered =
            render_workspace_change_context_from_records(vec![change("file__edit", "applied")]);

        assert!(rendered.contains("WORKSPACE CHANGE HANDLES"));
        assert!(rendered.contains("change_id=workspace_change:file__edit:applied"));
        assert!(rendered.contains("rollback_available=true"));
        assert!(rendered.contains("path=src/lib.rs"));
        assert!(!rendered.contains("must-not-render"));
        assert!(!rendered.contains("evidence::full_payload"));
        assert!(!rendered.contains("{\"receipt\""));
    }

    #[test]
    fn omits_applied_changes_that_cannot_be_rolled_back_by_handle() {
        let rendered = render_workspace_change_context_from_records(vec![
            change("file__write", "applied"),
            change("file__delete", "applied"),
        ]);

        assert!(rendered.trim().is_empty());
    }

    #[test]
    fn renders_pending_change_ids_for_rejection() {
        let rendered = render_workspace_change_context_from_records(vec![
            change("file__edit", "proposed"),
            change("file__multi_edit", "awaiting_approval"),
        ]);

        assert!(rendered.contains("change_id=workspace_change:file__edit:proposed"));
        assert!(rendered.contains("change_id=workspace_change:file__multi_edit:awaiting_approval"));
        assert_eq!(rendered.matches("reject_available=true").count(), 2);
    }

    #[test]
    fn omits_terminal_lifecycle_rows() {
        let rendered = render_workspace_change_context_from_records(vec![
            change("file__edit", "rejected"),
            change("file__edit", "rolled_back"),
            change("file__edit", "failed"),
        ]);

        assert!(rendered.trim().is_empty());
    }
}
