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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HunkProposalReviewState {
    pub change_id: String,
    pub lifecycle: String,
    pub path: Option<String>,
    pub hunk_count: usize,
    pub accept_available: bool,
    pub reject_available: bool,
    pub rollback_available: bool,
    pub stale: bool,
    pub stale_reason: Option<String>,
}

pub fn workspace_change_lifecycle_goal_requested(goal: &str) -> bool {
    let normalized = goal.to_ascii_lowercase();
    let requests_lifecycle = ["roll back", "rollback", "revert", "reject change"]
        .iter()
        .any(|needle| normalized.contains(needle));
    let mentions_workspace_change = [
        "workspace change",
        "change lifecycle",
        "change_id",
        "change id",
        "src/",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".rs",
        ".py",
        "repository",
        "repo",
        "workspace",
        "file",
        "edit",
    ]
    .iter()
    .any(|needle| normalized.contains(needle));
    requests_lifecycle && mentions_workspace_change
}

pub fn workspace_change_lifecycle_control_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.trim().to_ascii_lowercase().as_str(),
        "workspace_change__status"
            | "workspace_change__reject"
            | "workspace_change__rollback"
            | "file__read"
            | "chat__reply"
            | "agent__pause"
            | "agent__complete"
            | "agent__escalate"
    )
}

impl WorkspaceChangeLifecycleError {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
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
    workspace_change_status_from_changes(&record.workspace_changes)
}

pub fn workspace_change_status_from_changes(
    changes: &[WorkspaceChangeRecord],
) -> WorkspaceChangeStatus {
    let mut status = WorkspaceChangeStatus {
        total: changes.len(),
        ..WorkspaceChangeStatus::default()
    };
    for change in changes {
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

pub fn find_workspace_change_by_id(
    changes: &[WorkspaceChangeRecord],
    change_id: &str,
) -> Result<WorkspaceChangeRecord, WorkspaceChangeLifecycleError> {
    let change_id = change_id.trim();
    if change_id.is_empty() {
        return Err(WorkspaceChangeLifecycleError::new(
            "missing_change_id",
            "workspace change lookup requires a non-empty change_id",
        ));
    }

    let mut matches = changes
        .iter()
        .filter(|change| change.change_id == change_id)
        .cloned()
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(WorkspaceChangeLifecycleError::new(
            "change_not_found",
            format!("workspace change '{change_id}' was not found"),
        )),
        1 => Ok(matches.remove(0)),
        _ => Err(WorkspaceChangeLifecycleError::new(
            "ambiguous_change_id",
            format!("workspace change id '{change_id}' matched multiple records"),
        )),
    }
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

pub fn hunk_proposal_review_state(
    workspace_root: impl AsRef<Path>,
    change: &WorkspaceChangeRecord,
) -> HunkProposalReviewState {
    let mut state = HunkProposalReviewState {
        change_id: change.change_id.clone(),
        lifecycle: change.lifecycle.clone(),
        path: change.path.clone(),
        hunk_count: change.hunks.len(),
        reject_available: matches!(
            change.lifecycle.as_str(),
            LIFECYCLE_PROPOSED | LIFECYCLE_AWAITING_APPROVAL
        ),
        ..HunkProposalReviewState::default()
    };

    let stale_reason = workspace_change_stale_reason(workspace_root.as_ref(), change);
    state.stale = stale_reason.is_some();
    state.stale_reason = stale_reason;
    state.accept_available = state.reject_available && !state.stale;
    state.rollback_available = change.lifecycle == LIFECYCLE_APPLIED && !state.stale;
    state
}

fn workspace_change_stale_reason(
    workspace_root: &Path,
    change: &WorkspaceChangeRecord,
) -> Option<String> {
    let path = change.path.as_deref()?.trim();
    if path.is_empty() {
        return Some("missing_path".to_string());
    }

    if change.lifecycle == LIFECYCLE_REJECTED || change.lifecycle == LIFECYCLE_ROLLED_BACK {
        return None;
    }

    if matches!(
        change.lifecycle.as_str(),
        LIFECYCLE_PROPOSED | LIFECYCLE_AWAITING_APPROVAL
    ) && change
        .hunks
        .iter()
        .all(|hunk| matches!(hunk.kind.as_str(), "write" | "line_write"))
    {
        return None;
    }

    let target = match resolve_existing_workspace_path(workspace_root, path) {
        Ok(target) => target,
        Err(error) => return Some(error.code),
    };
    let content = match fs::read_to_string(&target) {
        Ok(content) => content,
        Err(_) => return Some("read_failed".to_string()),
    };

    for hunk in &change.hunks {
        let expected = match change.lifecycle.as_str() {
            LIFECYCLE_PROPOSED | LIFECYCLE_AWAITING_APPROVAL => match hunk.kind.as_str() {
                "replace" => hunk.search_text.as_deref(),
                "delete" => Some(""),
                "write" | "line_write" => return None,
                _ => hunk.search_text.as_deref(),
            },
            LIFECYCLE_APPLIED => hunk
                .replace_text
                .as_deref()
                .or(hunk.content_text.as_deref()),
            _ => return None,
        };

        if hunk.kind == "delete" {
            continue;
        }
        let Some(expected) = expected else {
            return Some(format!(
                "hunk_{}_missing_boundary_material",
                hunk.hunk_index
            ));
        };
        if expected.is_empty() {
            return Some(format!("hunk_{}_empty_boundary_material", hunk.hunk_index));
        }
        match content.match_indices(expected).take(2).count() {
            0 => return Some(format!("hunk_{}_boundary_not_found", hunk.hunk_index)),
            1 => {}
            _ => return Some(format!("hunk_{}_boundary_ambiguous", hunk.hunk_index)),
        }
    }
    None
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
    fn lifecycle_goal_detection_targets_workspace_change_controls() {
        assert!(workspace_change_lifecycle_goal_requested(
            "Roll back the formatter edit using the workspace change lifecycle handle."
        ));
        assert!(workspace_change_lifecycle_control_tool(
            "workspace_change__rollback"
        ));
        assert!(workspace_change_lifecycle_control_tool("file__read"));
        assert!(!workspace_change_lifecycle_control_tool("shell__run"));
        assert!(!workspace_change_lifecycle_goal_requested(
            "Tell me a short story about rollback netcode."
        ));
    }

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
    fn finds_workspace_change_by_exact_id() {
        let changes = vec![test_change("applied"), test_change("proposed")];

        let found = find_workspace_change_by_id(&changes, "workspace_change:proposed")
            .expect("change should resolve by exact id");

        assert_eq!(found.lifecycle, "proposed");
    }

    #[test]
    fn find_workspace_change_by_id_denies_missing_and_ambiguous_ids() {
        let changes = vec![test_change("applied"), test_change("applied")];

        let missing =
            find_workspace_change_by_id(&changes, "workspace_change:missing").expect_err("miss");
        assert_eq!(missing.code, "change_not_found");

        let ambiguous =
            find_workspace_change_by_id(&changes, "workspace_change:applied").expect_err("dup");
        assert_eq!(ambiguous.code, "ambiguous_change_id");
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
    fn hunk_review_state_tracks_accept_reject_stale_and_rollback() {
        let workspace = temp_workspace("hunk_review_state");
        let file = workspace.join("src.txt");
        fs::write(&file, "alpha\nold_call()\nomega\n").expect("write test file");
        let proposed = workspace_change_record_from_tool(
            &AgentTool::FsPatch {
                path: "src.txt".to_string(),
                search: "old_call()".to_string(),
                replace: "new_call()".to_string(),
            },
            "proposed",
            None,
            None,
        )
        .expect("proposed hunk");

        let review = hunk_proposal_review_state(&workspace, &proposed);
        assert!(review.accept_available);
        assert!(review.reject_available);
        assert!(!review.rollback_available);
        assert!(!review.stale);

        fs::write(&file, "alpha\nsomeone_else_changed_it()\nomega\n")
            .expect("mutate outside proposal");
        let stale = hunk_proposal_review_state(&workspace, &proposed);
        assert!(!stale.accept_available);
        assert!(stale.reject_available);
        assert!(stale.stale);
        assert_eq!(
            stale.stale_reason.as_deref(),
            Some("hunk_0_boundary_not_found")
        );

        fs::write(&file, "alpha\nnew_call()\nomega\n").expect("apply hunk");
        let applied = workspace_change_record_from_tool(
            &AgentTool::FsPatch {
                path: "src.txt".to_string(),
                search: "old_call()".to_string(),
                replace: "new_call()".to_string(),
            },
            "applied",
            None,
            None,
        )
        .expect("applied hunk");
        let rollback = hunk_proposal_review_state(&workspace, &applied);
        assert!(!rollback.accept_available);
        assert!(!rollback.reject_available);
        assert!(rollback.rollback_available);
        assert!(!rollback.stale);

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
