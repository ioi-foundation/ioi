use crate::kernel::state;
use crate::models::{
    AgentTask, AppState, SessionBranchRecord, SessionBranchSnapshot, SessionFileContext,
    SessionWorktreeRecord,
};
use crate::orchestrator;
use ioi_memory::MemoryRuntime;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn session_id_from_task(task: &AgentTask) -> Option<String> {
    task.session_id.clone().or_else(|| Some(task.id.clone()))
}

fn run_git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to launch git: {}", error))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_command_succeeds(root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn git_value(root: &Path, args: &[&str]) -> Option<String> {
    run_git(root, args)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn is_git_repo(root: &Path) -> bool {
    git_value(root, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true")
}

fn parse_ahead_behind(value: &str) -> (u32, u32) {
    let mut parts = value.split_whitespace();
    let ahead = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    let behind = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    (ahead, behind)
}

fn tracking_counts(root: &Path, upstream_branch: Option<&str>) -> (u32, u32) {
    let Some(upstream_branch) = upstream_branch.filter(|value| !value.trim().is_empty()) else {
        return (0, 0);
    };

    git_value(
        root,
        &["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
    )
    .map(|value| parse_ahead_behind(&value))
    .unwrap_or_else(|| {
        let spec = format!("HEAD...{}", upstream_branch);
        git_value(root, &["rev-list", "--left-right", "--count", &spec])
            .map(|value| parse_ahead_behind(&value))
            .unwrap_or((0, 0))
    })
}

fn branch_last_commit(root: &Path, branch_name: &str) -> Option<String> {
    git_value(root, &["log", "-1", "--pretty=%h %s", branch_name])
}

fn build_recent_branch_rows(
    root: &Path,
    current_branch: Option<&str>,
    current_upstream: Option<&str>,
    current_ahead: u32,
    current_behind: u32,
) -> Vec<SessionBranchRecord> {
    let Some(listing) = git_value(
        root,
        &[
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)|%(upstream:short)",
            "refs/heads",
        ],
    ) else {
        return Vec::new();
    };

    let mut rows = listing
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }

            let mut parts = trimmed.splitn(2, '|');
            let branch_name = parts.next()?.trim().to_string();
            if branch_name.is_empty() {
                return None;
            }

            let upstream_branch = parts
                .next()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let is_current = current_branch
                .map(|value| value == branch_name.as_str())
                .unwrap_or(false);
            let (ahead_count, behind_count) = if is_current {
                (current_ahead, current_behind)
            } else {
                tracking_counts(root, upstream_branch.as_deref())
            };

            Some(SessionBranchRecord {
                branch_name: branch_name.clone(),
                upstream_branch: upstream_branch.or_else(|| {
                    current_upstream
                        .map(|value| value.to_string())
                        .filter(|_| is_current)
                }),
                is_current,
                ahead_count,
                behind_count,
                last_commit: branch_last_commit(root, &branch_name),
            })
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| left.branch_name.cmp(&right.branch_name))
    });
    rows.truncate(6);
    rows
}

fn worktree_risk(
    changed_file_count: usize,
    dirty: bool,
    ahead_count: u32,
    behind_count: u32,
) -> (String, String) {
    if dirty {
        let label = if changed_file_count > 12 {
            "High change risk".to_string()
        } else {
            "Dirty checkout".to_string()
        };
        let detail = if changed_file_count > 0 {
            format!(
                "{} tracked file {} currently changed in this worktree.",
                changed_file_count,
                if changed_file_count == 1 { "is" } else { "are" }
            )
        } else {
            "Local modifications are present in this worktree.".to_string()
        };
        return (label, detail);
    }

    if behind_count > 0 {
        return (
            "Behind upstream".to_string(),
            format!(
                "This branch is {} commit{} behind its upstream and may need review before new work starts.",
                behind_count,
                if behind_count == 1 { "" } else { "s" }
            ),
        );
    }

    if ahead_count > 0 {
        return (
            "Ahead of upstream".to_string(),
            format!(
                "This branch has {} local commit{} that have not been pushed upstream yet.",
                ahead_count,
                if ahead_count == 1 { "" } else { "s" }
            ),
        );
    }

    (
        "Clean checkout".to_string(),
        "No tracked file changes are present in this worktree.".to_string(),
    )
}

fn repo_label(root: &Path) -> Option<String> {
    root.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
}

fn normalized_path_key(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string()
}

fn same_workspace_path(left: &Path, right: &Path) -> bool {
    normalized_path_key(left) == normalized_path_key(right)
}

fn slugify_worktree_component(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_dash = false;

    for character in value.trim().chars() {
        let normalized = if character.is_ascii_alphanumeric() {
            Some(character.to_ascii_lowercase())
        } else if matches!(character, '-' | '_' | '.') {
            Some(character)
        } else {
            Some('-')
        };

        let Some(normalized) = normalized else {
            continue;
        };

        if normalized == '-' {
            if previous_was_dash || slug.is_empty() {
                continue;
            }
            previous_was_dash = true;
            slug.push(normalized);
            continue;
        }

        previous_was_dash = false;
        slug.push(normalized);
    }

    let trimmed = slug.trim_matches('-').trim_matches('.').trim_matches('_');
    if trimmed.is_empty() {
        "workcell".to_string()
    } else {
        trimmed.to_string()
    }
}

fn branch_name_from_ref(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(
        trimmed
            .strip_prefix("refs/heads/")
            .unwrap_or(trimmed)
            .to_string(),
    )
}

fn worktree_parent_directory(root: &Path) -> PathBuf {
    root.parent().unwrap_or(root).join(".ioi-worktrees")
}

fn default_worktree_path(root: &Path, branch_name: &str, worktree_name: Option<&str>) -> PathBuf {
    let repo_slug = slugify_worktree_component(repo_label(root).as_deref().unwrap_or("workspace"));
    let worktree_slug = slugify_worktree_component(worktree_name.unwrap_or(branch_name).trim());
    worktree_parent_directory(root).join(format!("{repo_slug}-{worktree_slug}"))
}

fn changed_file_count(root: &Path) -> usize {
    git_value(root, &["status", "--porcelain", "--", "."])
        .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedGitWorktreeEntry {
    path: String,
    head: Option<String>,
    branch_ref: Option<String>,
    locked_reason: Option<String>,
    prunable_reason: Option<String>,
}

fn parse_git_worktree_listing(listing: &str) -> Vec<ParsedGitWorktreeEntry> {
    let mut entries = Vec::new();
    let mut current = ParsedGitWorktreeEntry::default();

    for line in listing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current.path.trim().is_empty() {
                entries.push(current);
            }
            current = ParsedGitWorktreeEntry::default();
            continue;
        }

        if let Some(path) = trimmed.strip_prefix("worktree ") {
            current.path = path.trim().to_string();
        } else if let Some(head) = trimmed.strip_prefix("HEAD ") {
            current.head = Some(head.trim().to_string());
        } else if let Some(branch_ref) = trimmed.strip_prefix("branch ") {
            current.branch_ref = Some(branch_ref.trim().to_string());
        } else if let Some(reason) = trimmed.strip_prefix("locked") {
            let normalized = reason.trim();
            current.locked_reason = if normalized.is_empty() {
                Some("Git marked this worktree as locked.".to_string())
            } else {
                Some(normalized.to_string())
            };
        } else if let Some(reason) = trimmed.strip_prefix("prunable") {
            let normalized = reason.trim();
            current.prunable_reason = if normalized.is_empty() {
                Some("Git marked this worktree as prunable.".to_string())
            } else {
                Some(normalized.to_string())
            };
        }
    }

    if !current.path.trim().is_empty() {
        entries.push(current);
    }

    entries
}

fn worktree_status(
    branch_name: Option<&str>,
    changed_file_count: usize,
    dirty: bool,
    is_current: bool,
    locked: bool,
    lock_reason: Option<&str>,
    prunable: bool,
    prune_reason: Option<&str>,
) -> (String, String) {
    let branch_label = branch_name.unwrap_or("detached HEAD");

    if is_current {
        return (
            "Current workcell".to_string(),
            format!(
                "The active session is rooted in this workcell on {}.",
                branch_label
            ),
        );
    }

    if locked {
        return (
            "Locked".to_string(),
            lock_reason
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Git marked this linked worktree as locked.".to_string()),
        );
    }

    if dirty {
        return (
            "Dirty checkout".to_string(),
            if changed_file_count > 0 {
                format!(
                    "{} tracked file {} changed in this linked worktree.",
                    changed_file_count,
                    if changed_file_count == 1 { "is" } else { "are" }
                )
            } else {
                "Local modifications are present in this linked worktree.".to_string()
            },
        );
    }

    if prunable {
        return (
            "Prunable".to_string(),
            prune_reason
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Git marked this linked worktree as prunable.".to_string()),
        );
    }

    (
        "Ready".to_string(),
        format!(
            "This linked worktree on {} is clean and can be resumed or removed safely.",
            branch_label
        ),
    )
}

fn build_worktree_rows(root: &Path) -> Vec<SessionWorktreeRecord> {
    let Some(listing) = git_value(root, &["worktree", "list", "--porcelain"]) else {
        return Vec::new();
    };

    let mut rows = parse_git_worktree_listing(&listing)
        .into_iter()
        .filter_map(|entry| {
            let worktree_path = PathBuf::from(entry.path.trim());
            if worktree_path.as_os_str().is_empty() {
                return None;
            }

            let branch_name = entry.branch_ref.as_deref().and_then(branch_name_from_ref);
            let changed_file_count = if worktree_path.exists() && is_git_repo(&worktree_path) {
                changed_file_count(&worktree_path)
            } else {
                0
            };
            let dirty = changed_file_count > 0;
            let is_current = same_workspace_path(root, &worktree_path);
            let locked = entry.locked_reason.is_some();
            let prunable = entry.prunable_reason.is_some();
            let (status_label, status_detail) = worktree_status(
                branch_name.as_deref(),
                changed_file_count,
                dirty,
                is_current,
                locked,
                entry.locked_reason.as_deref(),
                prunable,
                entry.prunable_reason.as_deref(),
            );

            Some(SessionWorktreeRecord {
                path: worktree_path.display().to_string(),
                branch_name,
                head: entry.head.map(|value| value.chars().take(12).collect()),
                last_commit: git_value(&worktree_path, &["log", "-1", "--pretty=%h %s"]),
                changed_file_count,
                dirty,
                is_current,
                locked,
                lock_reason: entry.locked_reason,
                prunable,
                prune_reason: entry.prunable_reason,
                status_label,
                status_detail,
            })
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| left.path.cmp(&right.path))
    });
    rows
}

fn empty_snapshot(
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionBranchSnapshot {
    SessionBranchSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        is_repo: false,
        repo_label: None,
        current_branch: None,
        upstream_branch: None,
        last_commit: None,
        ahead_count: 0,
        behind_count: 0,
        changed_file_count: 0,
        dirty: false,
        worktree_risk_label: "No git repository".to_string(),
        worktree_risk_detail:
            "Open a workspace rooted in a repository to inspect branch posture and local change risk."
                .to_string(),
        recent_branches: Vec::new(),
        worktrees: Vec::new(),
    }
}

fn build_session_branch_snapshot(
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionBranchSnapshot {
    let Some(root_value) = workspace_root.clone() else {
        return empty_snapshot(session_id, workspace_root);
    };
    let root = PathBuf::from(&root_value);
    if !root.exists() || !is_git_repo(&root) {
        return empty_snapshot(session_id, workspace_root);
    }

    let current_branch = git_value(&root, &["branch", "--show-current"]);
    let upstream_branch = git_value(
        &root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    );
    let last_commit = git_value(&root, &["log", "-1", "--pretty=%h %s"]);
    let changed_file_count = changed_file_count(&root);
    let dirty = changed_file_count > 0;
    let (ahead_count, behind_count) = tracking_counts(&root, upstream_branch.as_deref());
    let (worktree_risk_label, worktree_risk_detail) =
        worktree_risk(changed_file_count, dirty, ahead_count, behind_count);
    let recent_branches = build_recent_branch_rows(
        &root,
        current_branch.as_deref(),
        upstream_branch.as_deref(),
        ahead_count,
        behind_count,
    );
    let worktrees = build_worktree_rows(&root);

    SessionBranchSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        is_repo: true,
        repo_label: repo_label(&root),
        current_branch,
        upstream_branch,
        last_commit,
        ahead_count,
        behind_count,
        changed_file_count,
        dirty,
        worktree_risk_label,
        worktree_risk_detail,
        recent_branches,
        worktrees,
    }
}

fn validate_new_branch_name(root: &Path, branch_name: &str) -> Result<String, String> {
    let trimmed = branch_name.trim();
    if trimmed.is_empty() {
        return Err("A new branch name is required for isolated worktree creation.".to_string());
    }

    if !git_command_succeeds(root, &["check-ref-format", "--branch", trimmed]) {
        return Err(format!("'{}' is not a valid branch name.", trimmed));
    }

    let branch_ref = format!("refs/heads/{}", trimmed);
    if git_command_succeeds(root, &["show-ref", "--verify", "--quiet", &branch_ref]) {
        return Err(format!(
            "Branch '{}' already exists locally. Create a unique isolated branch name instead.",
            trimmed
        ));
    }

    Ok(trimmed.to_string())
}

fn validate_start_point(
    root: &Path,
    start_point: Option<&str>,
    current_branch: Option<&str>,
) -> Result<String, String> {
    let resolved = start_point
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| current_branch.map(ToOwned::to_owned))
        .unwrap_or_else(|| "HEAD".to_string());
    let commit_ref = format!("{resolved}^{{commit}}");

    if !git_command_succeeds(root, &["rev-parse", "--verify", "--quiet", &commit_ref]) {
        return Err(format!(
            "Start point '{}' does not resolve to a commit in this repository.",
            resolved
        ));
    }

    Ok(resolved)
}

fn create_linked_worktree(
    root: &Path,
    branch_name: &str,
    start_point: Option<&str>,
    worktree_name: Option<&str>,
) -> Result<PathBuf, String> {
    let validated_branch_name = validate_new_branch_name(root, branch_name)?;
    let current_branch = git_value(root, &["branch", "--show-current"]);
    let validated_start_point = validate_start_point(root, start_point, current_branch.as_deref())?;
    let target_path = default_worktree_path(root, &validated_branch_name, worktree_name);

    if target_path.exists() {
        return Err(format!(
            "The isolated worktree path '{}' already exists.",
            target_path.display()
        ));
    }

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to prepare the isolated worktree directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }

    let target_path_string = target_path.display().to_string();
    run_git(
        root,
        &[
            "worktree",
            "add",
            "-b",
            &validated_branch_name,
            &target_path_string,
            &validated_start_point,
        ],
    )?;

    Ok(target_path)
}

fn listed_worktree_entry(root: &Path, target_path: &Path) -> Option<ParsedGitWorktreeEntry> {
    let listing = git_value(root, &["worktree", "list", "--porcelain"])?;
    parse_git_worktree_listing(&listing)
        .into_iter()
        .find(|entry| same_workspace_path(Path::new(entry.path.as_str()), target_path))
}

fn resolve_listed_worktree(root: &Path, target_path: &str) -> Result<PathBuf, String> {
    let target = PathBuf::from(target_path.trim());
    let Some(entry) = listed_worktree_entry(root, &target) else {
        return Err(
            "The selected worktree is not managed by the current repository checkout.".to_string(),
        );
    };
    Ok(PathBuf::from(entry.path))
}

fn remove_linked_worktree(root: &Path, target_path: &Path) -> Result<(), String> {
    let entry = listed_worktree_entry(root, target_path)
        .ok_or_else(|| "The selected worktree is no longer tracked by git.".to_string())?;
    let target = PathBuf::from(entry.path);

    if same_workspace_path(root, &target) {
        return Err(
            "The active session worktree cannot be removed while it is in use.".to_string(),
        );
    }

    if entry.locked_reason.is_some() {
        return Err(
            "Git marked this worktree as locked, so removal is blocked until the lock is cleared."
                .to_string(),
        );
    }

    if target.exists() && is_git_repo(&target) && changed_file_count(&target) > 0 {
        return Err(
            "This worktree still has tracked file changes. Clean it first before removing it."
                .to_string(),
        );
    }

    let target_string = target.display().to_string();
    run_git(root, &["worktree", "remove", &target_string])?;
    Ok(())
}

fn apply_workspace_root_to_task(task: &mut AgentTask, next_workspace_root: &str) -> bool {
    let mut changed = false;

    if let Some(build_session) = task.build_session.as_mut() {
        if build_session.workspace_root != next_workspace_root {
            build_session.workspace_root = next_workspace_root.to_string();
            changed = true;
        }
    }

    if let Some(renderer_session) = task.renderer_session.as_mut() {
        if renderer_session.workspace_root != next_workspace_root {
            renderer_session.workspace_root = next_workspace_root.to_string();
            changed = true;
        }
    }

    if let Some(chat_session) = task.chat_session.as_mut() {
        if chat_session.workspace_root.as_deref() != Some(next_workspace_root) {
            chat_session.workspace_root = Some(next_workspace_root.to_string());
            changed = true;
        }
    }

    changed
}

fn persist_session_workspace_root(
    memory_runtime: &Arc<MemoryRuntime>,
    session_id: Option<&str>,
    current_workspace_root: Option<&str>,
    next_workspace_root: &str,
) {
    let mut context: SessionFileContext =
        orchestrator::load_session_file_context(memory_runtime, session_id, current_workspace_root);
    context.workspace_root = next_workspace_root.to_string();
    context.updated_at_ms = state::now();
    orchestrator::save_session_file_context(memory_runtime, session_id, &context);
}

fn update_current_task_workspace_root(
    state: &State<'_, Mutex<AppState>>,
    app: &AppHandle,
    session_id: Option<&str>,
    next_workspace_root: &str,
) -> Result<bool, String> {
    let mut task_clone: Option<AgentTask> = None;
    let memory_runtime = {
        let mut guard = state
            .lock()
            .map_err(|_| "Failed to lock app state.".to_string())?;
        let memory_runtime = guard.memory_runtime.clone();

        if let Some(task) = guard.current_task.as_mut() {
            let matches_requested_session = session_id
                .map(|expected| session_id_from_task(task).as_deref() == Some(expected))
                .unwrap_or(true);
            if matches_requested_session && apply_workspace_root_to_task(task, next_workspace_root)
            {
                task.sync_runtime_views();
                task_clone = Some(task.clone());
            }
        }
        memory_runtime
    };

    let Some(task) = task_clone else {
        return Ok(false);
    };

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task);
    }
    let _ = app.emit("task-updated", &task);
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
    Ok(true)
}

fn resolved_branch_snapshot_context(
    state: &State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<(Option<String>, Option<String>, Option<Arc<MemoryRuntime>>), String> {
    let (current_task, memory_runtime) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state.".to_string())?;
        (guard.current_task.clone(), guard.memory_runtime.clone())
    };

    let resolved_session_id = normalize_optional_text(session_id).or_else(|| {
        current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())))
    });
    let resolved_workspace_root = normalize_optional_text(workspace_root)
        .or_else(|| current_task.as_ref().and_then(workspace_root_from_task));

    Ok((resolved_session_id, resolved_workspace_root, memory_runtime))
}

#[tauri::command]
pub fn get_session_branch_snapshot(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionBranchSnapshot, String> {
    let (resolved_session_id, resolved_workspace_root, _) =
        resolved_branch_snapshot_context(&state, session_id, workspace_root)?;
    Ok(build_session_branch_snapshot(
        resolved_session_id,
        resolved_workspace_root,
    ))
}

#[tauri::command]
pub fn create_session_worktree(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
    workspace_root: Option<String>,
    branch_name: String,
    start_point: Option<String>,
    worktree_name: Option<String>,
) -> Result<SessionBranchSnapshot, String> {
    let (resolved_session_id, resolved_workspace_root, memory_runtime) =
        resolved_branch_snapshot_context(&state, session_id, workspace_root)?;
    let root_value = resolved_workspace_root.clone().ok_or_else(|| {
        "Open a repository-backed workspace before creating a workcell.".to_string()
    })?;
    let root = PathBuf::from(&root_value);
    if !root.exists() || !is_git_repo(&root) {
        return Err("Open a git-backed workspace before creating a workcell.".to_string());
    }

    let worktree_path = create_linked_worktree(
        &root,
        branch_name.as_str(),
        start_point.as_deref(),
        worktree_name.as_deref(),
    )?;
    let next_workspace_root = worktree_path.display().to_string();

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        persist_session_workspace_root(
            memory_runtime,
            resolved_session_id.as_deref(),
            resolved_workspace_root.as_deref(),
            &next_workspace_root,
        );
    }
    let _ = update_current_task_workspace_root(
        &state,
        &app,
        resolved_session_id.as_deref(),
        &next_workspace_root,
    )?;

    Ok(build_session_branch_snapshot(
        resolved_session_id,
        Some(next_workspace_root),
    ))
}

#[tauri::command]
pub fn switch_session_worktree(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
    workspace_root: Option<String>,
    target_workspace_root: String,
) -> Result<SessionBranchSnapshot, String> {
    let (resolved_session_id, resolved_workspace_root, memory_runtime) =
        resolved_branch_snapshot_context(&state, session_id, workspace_root)?;
    let root_value = resolved_workspace_root.clone().ok_or_else(|| {
        "Open a repository-backed workspace before switching workcells.".to_string()
    })?;
    let root = PathBuf::from(&root_value);
    if !root.exists() || !is_git_repo(&root) {
        return Err("Open a git-backed workspace before switching workcells.".to_string());
    }

    let target = resolve_listed_worktree(&root, &target_workspace_root)?;
    let next_workspace_root = target.display().to_string();

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        persist_session_workspace_root(
            memory_runtime,
            resolved_session_id.as_deref(),
            resolved_workspace_root.as_deref(),
            &next_workspace_root,
        );
    }
    let _ = update_current_task_workspace_root(
        &state,
        &app,
        resolved_session_id.as_deref(),
        &next_workspace_root,
    )?;

    Ok(build_session_branch_snapshot(
        resolved_session_id,
        Some(next_workspace_root),
    ))
}

#[tauri::command]
pub fn remove_session_worktree(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    target_workspace_root: String,
) -> Result<SessionBranchSnapshot, String> {
    let (resolved_session_id, resolved_workspace_root, _) =
        resolved_branch_snapshot_context(&state, session_id, workspace_root)?;
    let root_value = resolved_workspace_root.clone().ok_or_else(|| {
        "Open a repository-backed workspace before removing a workcell.".to_string()
    })?;
    let root = PathBuf::from(&root_value);
    if !root.exists() || !is_git_repo(&root) {
        return Err("Open a git-backed workspace before removing a workcell.".to_string());
    }

    let target = resolve_listed_worktree(&root, &target_workspace_root)?;
    remove_linked_worktree(&root, &target)?;

    Ok(build_session_branch_snapshot(
        resolved_session_id,
        resolved_workspace_root,
    ))
}

#[cfg(test)]
#[path = "branches/tests.rs"]
mod tests;
