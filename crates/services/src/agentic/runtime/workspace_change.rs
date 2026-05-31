use crate::agentic::runtime::trajectory::{
    AgentTrajectoryStepRecord, WorkspaceChangeRecord, WorkspaceHunkRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const LIFECYCLE_PROPOSED: &str = "proposed";
const LIFECYCLE_AWAITING_APPROVAL: &str = "awaiting_approval";
const LIFECYCLE_APPLIED: &str = "applied";
const LIFECYCLE_REJECTED: &str = "rejected";
const LIFECYCLE_ROLLED_BACK: &str = "rolled_back";
const LIFECYCLE_FAILED: &str = "failed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkspaceChangeStatus {
    pub total: usize,
    pub proposed: usize,
    pub awaiting_approval: usize,
    pub applied: usize,
    pub rejected: usize,
    pub rolled_back: usize,
    pub failed: usize,
    pub by_lifecycle: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceChangeLifecycleError {
    pub code: String,
    pub message: String,
}

impl WorkspaceChangeLifecycleError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WorkspaceChangeLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WorkspaceChangeLifecycleError {}

pub fn workspace_change_status(record: &AgentTrajectoryStepRecord) -> WorkspaceChangeStatus {
    let mut status = WorkspaceChangeStatus {
        total: record.workspace_changes.len(),
        ..WorkspaceChangeStatus::default()
    };
    for change in &record.workspace_changes {
        *status
            .by_lifecycle
            .entry(change.lifecycle.clone())
            .or_insert(0) += 1;
        match change.lifecycle.as_str() {
            LIFECYCLE_PROPOSED => status.proposed += 1,
            LIFECYCLE_AWAITING_APPROVAL => status.awaiting_approval += 1,
            LIFECYCLE_APPLIED => status.applied += 1,
            LIFECYCLE_REJECTED => status.rejected += 1,
            LIFECYCLE_ROLLED_BACK => status.rolled_back += 1,
            LIFECYCLE_FAILED => status.failed += 1,
            _ => {}
        }
    }
    status
}

pub fn reject_workspace_change(
    change: &WorkspaceChangeRecord,
    reason: &str,
) -> Result<WorkspaceChangeRecord, WorkspaceChangeLifecycleError> {
    match change.lifecycle.as_str() {
        LIFECYCLE_PROPOSED | LIFECYCLE_AWAITING_APPROVAL => {
            let mut rejected = change.clone();
            rejected.lifecycle = LIFECYCLE_REJECTED.to_string();
            rejected.receipt_ref = Some(compact_reason_ref("workspace_change_rejected", reason));
            rejected.evidence_ref = rejected.receipt_ref.clone();
            Ok(rejected)
        }
        other => Err(WorkspaceChangeLifecycleError::new(
            "invalid_lifecycle",
            format!("workspace change in lifecycle '{other}' cannot be rejected"),
        )),
    }
}

pub fn rollback_workspace_change(
    workspace_root: impl AsRef<Path>,
    change: &WorkspaceChangeRecord,
) -> Result<WorkspaceChangeRecord, WorkspaceChangeLifecycleError> {
    if change.lifecycle != LIFECYCLE_APPLIED {
        return Err(WorkspaceChangeLifecycleError::new(
            "invalid_lifecycle",
            format!(
                "workspace change in lifecycle '{}' cannot be rolled back",
                change.lifecycle
            ),
        ));
    }
    if !matches!(change.tool_name.as_str(), "file__edit" | "file__multi_edit") {
        return Err(WorkspaceChangeLifecycleError::new(
            "unsupported_rollback_tool",
            format!(
                "workspace change tool '{}' has no exact rollback material",
                change.tool_name
            ),
        ));
    }

    let path = change.path.as_deref().ok_or_else(|| {
        WorkspaceChangeLifecycleError::new(
            "missing_path",
            "workspace change cannot be rolled back without a path",
        )
    })?;
    let target = resolve_existing_workspace_path(workspace_root.as_ref(), path)?;
    let mut content = fs::read_to_string(&target).map_err(|error| {
        WorkspaceChangeLifecycleError::new(
            "read_failed",
            format!(
                "failed to read rollback target '{}': {error}",
                target.display()
            ),
        )
    })?;

    for hunk in change.hunks.iter().rev() {
        content = reverse_hunk_once(&content, hunk)?;
    }

    fs::write(&target, content).map_err(|error| {
        WorkspaceChangeLifecycleError::new(
            "write_failed",
            format!(
                "failed to write rollback target '{}': {error}",
                target.display()
            ),
        )
    })?;

    let mut rolled_back = change.clone();
    rolled_back.lifecycle = LIFECYCLE_ROLLED_BACK.to_string();
    rolled_back.receipt_ref = Some(format!(
        "workspace_change_rolled_back:path={}",
        change.path.as_deref().unwrap_or_default()
    ));
    rolled_back.evidence_ref = rolled_back.receipt_ref.clone();
    Ok(rolled_back)
}

fn reverse_hunk_once(
    content: &str,
    hunk: &WorkspaceHunkRecord,
) -> Result<String, WorkspaceChangeLifecycleError> {
    let search_text = hunk.search_text.as_deref().ok_or_else(|| {
        WorkspaceChangeLifecycleError::new(
            "missing_rollback_material",
            format!("hunk {} has no original text", hunk.hunk_index),
        )
    })?;
    let replace_text = hunk.replace_text.as_deref().ok_or_else(|| {
        WorkspaceChangeLifecycleError::new(
            "missing_rollback_material",
            format!("hunk {} has no replacement text", hunk.hunk_index),
        )
    })?;
    replace_exactly_once(content, replace_text, search_text, hunk.hunk_index)
}

fn replace_exactly_once(
    content: &str,
    search: &str,
    replace: &str,
    hunk_index: u32,
) -> Result<String, WorkspaceChangeLifecycleError> {
    if search.is_empty() {
        return Err(WorkspaceChangeLifecycleError::new(
            "empty_rollback_search",
            format!("hunk {hunk_index} replacement text is empty"),
        ));
    }
    let mut matches = content.match_indices(search);
    let first = matches.next().map(|(index, _)| index);
    if first.is_none() {
        return Err(WorkspaceChangeLifecycleError::new(
            "rollback_search_not_found",
            format!("hunk {hunk_index} replacement text was not found"),
        ));
    }
    if matches.next().is_some() {
        return Err(WorkspaceChangeLifecycleError::new(
            "ambiguous_rollback_search",
            format!("hunk {hunk_index} replacement text occurs more than once"),
        ));
    }
    Ok(content.replacen(search, replace, 1))
}

fn resolve_existing_workspace_path(
    workspace_root: &Path,
    path: &str,
) -> Result<PathBuf, WorkspaceChangeLifecycleError> {
    let root = workspace_root.canonicalize().map_err(|error| {
        WorkspaceChangeLifecycleError::new(
            "workspace_root_unavailable",
            format!(
                "failed to canonicalize workspace root '{}': {error}",
                workspace_root.display()
            ),
        )
    })?;
    let raw_path = Path::new(path);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        root.join(raw_path)
    };
    let resolved = candidate.canonicalize().map_err(|error| {
        WorkspaceChangeLifecycleError::new(
            "target_unavailable",
            format!(
                "failed to canonicalize rollback target '{}': {error}",
                candidate.display()
            ),
        )
    })?;
    if !resolved.starts_with(&root) {
        return Err(WorkspaceChangeLifecycleError::new(
            "path_outside_workspace",
            format!("rollback target '{}' escapes workspace", resolved.display()),
        ));
    }
    Ok(resolved)
}

fn compact_reason_ref(prefix: &str, reason: &str) -> String {
    let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.is_empty() {
        return prefix.to_string();
    }
    format!(
        "{prefix}:reason={}",
        reason.chars().take(160).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::trajectory::workspace_change_record_from_tool;
    use ioi_types::app::agentic::{AgentFileEditOperation, AgentTool};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn status_groups_changes_by_lifecycle() {
        let mut record = AgentTrajectoryStepRecord::default();
        record.workspace_changes = vec![
            test_change("proposed"),
            test_change("awaiting_approval"),
            test_change("applied"),
            test_change("rejected"),
            test_change("rolled_back"),
            test_change("failed"),
        ];

        let status = workspace_change_status(&record);

        assert_eq!(status.total, 6);
        assert_eq!(status.proposed, 1);
        assert_eq!(status.awaiting_approval, 1);
        assert_eq!(status.applied, 1);
        assert_eq!(status.rejected, 1);
        assert_eq!(status.rolled_back, 1);
        assert_eq!(status.failed, 1);
        assert_eq!(status.by_lifecycle.get("applied"), Some(&1));
    }

    #[test]
    fn rejects_proposed_change() {
        let change = test_change("proposed");

        let rejected = reject_workspace_change(&change, "operator declined")
            .expect("proposed change should reject");

        assert_eq!(rejected.lifecycle, "rejected");
        assert!(rejected
            .receipt_ref
            .as_deref()
            .unwrap_or_default()
            .contains("operator declined"));
    }

    #[test]
    fn rejects_awaiting_approval_change() {
        let change = test_change("awaiting_approval");

        let rejected = reject_workspace_change(&change, "policy denied")
            .expect("awaiting approval change should reject");

        assert_eq!(rejected.lifecycle, "rejected");
        assert_eq!(rejected.evidence_ref, rejected.receipt_ref);
    }

    #[test]
    fn reject_denies_applied_change() {
        let change = test_change("applied");

        let error = reject_workspace_change(&change, "too late").expect_err("reject should deny");

        assert_eq!(error.code, "invalid_lifecycle");
    }

    #[test]
    fn rollback_applied_patch_restores_file() {
        let workspace = temp_workspace("rollback_patch");
        let file = workspace.join("src.txt");
        fs::write(&file, "alpha\nnew_call()\nomega\n").expect("write test file");
        let change = workspace_change_record_from_tool(
            &AgentTool::FsPatch {
                path: "src.txt".to_string(),
                search: "old_call()".to_string(),
                replace: "new_call()".to_string(),
            },
            "applied",
            None,
            None,
        )
        .expect("change record");

        let rolled_back =
            rollback_workspace_change(&workspace, &change).expect("rollback should pass");

        assert_eq!(rolled_back.lifecycle, "rolled_back");
        assert_eq!(
            fs::read_to_string(&file).expect("read rolled back file"),
            "alpha\nold_call()\nomega\n"
        );
        cleanup_workspace(workspace);
    }

    #[test]
    fn rollback_applied_multi_patch_restores_file() {
        let workspace = temp_workspace("rollback_multi_patch");
        let file = workspace.join("src.txt");
        fs::write(&file, "alpha\nnew_first()\nnew_second()\nomega\n").expect("write test file");
        let change = workspace_change_record_from_tool(
            &AgentTool::FsMultiPatch {
                path: "src.txt".to_string(),
                edits: vec![
                    AgentFileEditOperation {
                        search: "old_first()".to_string(),
                        replace: "new_first()".to_string(),
                    },
                    AgentFileEditOperation {
                        search: "old_second()".to_string(),
                        replace: "new_second()".to_string(),
                    },
                ],
            },
            "applied",
            None,
            None,
        )
        .expect("change record");

        let rolled_back =
            rollback_workspace_change(&workspace, &change).expect("rollback should pass");

        assert_eq!(rolled_back.lifecycle, "rolled_back");
        assert_eq!(
            fs::read_to_string(&file).expect("read rolled back file"),
            "alpha\nold_first()\nold_second()\nomega\n"
        );
        cleanup_workspace(workspace);
    }

    #[test]
    fn rollback_denies_without_exact_hunk_material() {
        let workspace = temp_workspace("rollback_no_material");
        let file = workspace.join("src.txt");
        fs::write(&file, "alpha\nnew_call()\nomega\n").expect("write test file");
        let mut change = test_change("applied");
        change.tool_name = "file__edit".to_string();
        change.path = Some("src.txt".to_string());
        change.hunks = vec![WorkspaceHunkRecord {
            hunk_index: 0,
            kind: "replace".to_string(),
            replace_text: Some("new_call()".to_string()),
            ..WorkspaceHunkRecord::default()
        }];

        let error = rollback_workspace_change(&workspace, &change)
            .expect_err("rollback should require exact original text");

        assert_eq!(error.code, "missing_rollback_material");
        cleanup_workspace(workspace);
    }

    #[test]
    fn rollback_denies_ambiguous_current_content() {
        let workspace = temp_workspace("rollback_ambiguous");
        let file = workspace.join("src.txt");
        fs::write(&file, "new_call()\nnew_call()\n").expect("write test file");
        let change = workspace_change_record_from_tool(
            &AgentTool::FsPatch {
                path: "src.txt".to_string(),
                search: "old_call()".to_string(),
                replace: "new_call()".to_string(),
            },
            "applied",
            None,
            None,
        )
        .expect("change record");

        let error = rollback_workspace_change(&workspace, &change)
            .expect_err("rollback should deny ambiguous replacement");

        assert_eq!(error.code, "ambiguous_rollback_search");
        cleanup_workspace(workspace);
    }

    #[test]
    fn rollback_denies_write_without_previous_content() {
        let workspace = temp_workspace("rollback_write");
        let file = workspace.join("src.txt");
        fs::write(&file, "created content").expect("write test file");
        let change = workspace_change_record_from_tool(
            &AgentTool::FsWrite {
                path: "src.txt".to_string(),
                content: "created content".to_string(),
                line_number: None,
            },
            "applied",
            None,
            None,
        )
        .expect("change record");

        let error = rollback_workspace_change(&workspace, &change)
            .expect_err("write rollback should deny without before-state");

        assert_eq!(error.code, "unsupported_rollback_tool");
        cleanup_workspace(workspace);
    }

    fn test_change(lifecycle: &str) -> WorkspaceChangeRecord {
        WorkspaceChangeRecord {
            change_id: format!("workspace_change:{lifecycle}"),
            tool_name: "file__edit".to_string(),
            path: Some("src/lib.rs".to_string()),
            lifecycle: lifecycle.to_string(),
            edit_count: 1,
            hunks: Vec::new(),
            ..WorkspaceChangeRecord::default()
        }
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ioi-workspace-change-{name}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp workspace");
        path
    }

    fn cleanup_workspace(path: PathBuf) {
        let _ = fs::remove_dir_all(path);
    }
}
