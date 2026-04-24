use crate::kernel::lsp;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::State;

mod paths;
mod terminal;

use self::paths::{
    display_name_for_root, file_name_for_path, language_hint_for_path, modified_time_ms,
    relative_path, resolve_root_path, resolve_scoped_candidate_path, resolve_scoped_existing_path,
    safe_relative_input,
};
pub(crate) use self::terminal::WorkspaceTerminalBridge;
pub use self::terminal::{
    WorkspaceTerminalManager, WorkspaceTerminalReadResult, WorkspaceTerminalSession,
};

// Keep initial workspace snapshots shallow so shell boot and first reveal stay
// responsive. Deeper directory contents are loaded on demand via
// `workspace_list_directory`.
const TREE_BOOTSTRAP_DEPTH: usize = 0;
const TREE_MAX_CHILDREN: usize = 200;
const EDITOR_MAX_BYTES: usize = 1024 * 1024;
const SEARCH_MAX_MATCHES: usize = 600;
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build"];

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGitSummary {
    pub is_repo: bool,
    pub branch: Option<String>,
    pub dirty: bool,
    pub last_commit: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceNode {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub has_children: bool,
    pub children: Vec<WorkspaceNode>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSnapshot {
    pub root_path: String,
    pub display_name: String,
    pub git: WorkspaceGitSummary,
    pub tree: Vec<WorkspaceNode>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFileDocument {
    pub name: String,
    pub path: String,
    pub absolute_path: String,
    pub language_hint: Option<String>,
    pub content: String,
    pub size_bytes: usize,
    pub modified_at_ms: Option<u64>,
    pub is_binary: bool,
    pub is_too_large: bool,
    pub read_only: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSearchMatch {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub preview: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSearchFileResult {
    pub path: String,
    pub match_count: usize,
    pub matches: Vec<WorkspaceSearchMatch>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSearchResult {
    pub query: String,
    pub total_matches: usize,
    pub files: Vec<WorkspaceSearchFileResult>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSourceControlEntry {
    pub path: String,
    pub original_path: Option<String>,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSourceControlState {
    pub git: WorkspaceGitSummary,
    pub entries: Vec<WorkspaceSourceControlEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceCommitResult {
    pub state: WorkspaceSourceControlState,
    pub committed_file_count: usize,
    pub remaining_change_count: usize,
    pub commit_summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDiffDocument {
    pub id: String,
    pub path: String,
    pub title: String,
    pub original_label: String,
    pub modified_label: String,
    pub original_content: String,
    pub modified_content: String,
    pub language_hint: Option<String>,
    pub is_binary: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePathMutationResult {
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePathStat {
    pub kind: String,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
    pub read_only: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDeleteResult {
    pub deleted_path: String,
}

fn should_skip_dir(name: &str) -> bool {
    SKIPPED_DIRS.iter().any(|value| value == &name)
}

fn sort_paths(a: &PathBuf, b: &PathBuf) -> std::cmp::Ordering {
    match (a.is_dir(), b.is_dir()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .cmp(
                b.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default(),
            ),
    }
}

fn visible_entries(current: &PathBuf) -> std::vec::IntoIter<PathBuf> {
    let mut entries = match fs::read_dir(current) {
        Ok(read_dir) => read_dir
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .collect::<Vec<_>>(),
        Err(_) => return Vec::new().into_iter(),
    };

    entries.sort_by(sort_paths);

    entries
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(|name| !should_skip_dir(name))
                .unwrap_or(true)
        })
        .take(TREE_MAX_CHILDREN)
        .collect::<Vec<_>>()
        .into_iter()
}

fn directory_has_visible_children(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .any(|child| {
            child
                .file_name()
                .and_then(|value| value.to_str())
                .map(|name| !should_skip_dir(name))
                .unwrap_or(true)
        })
}

fn build_tree(root: &PathBuf, current: &PathBuf, depth: usize) -> Vec<WorkspaceNode> {
    visible_entries(current)
        .map(|path| {
            let is_dir = path.is_dir();
            let children = if is_dir && depth < TREE_BOOTSTRAP_DEPTH {
                build_tree(root, &path, depth + 1)
            } else {
                Vec::new()
            };
            WorkspaceNode {
                name: file_name_for_path(&path),
                path: relative_path(root, &path),
                kind: if is_dir {
                    "directory".to_string()
                } else {
                    "file".to_string()
                },
                has_children: is_dir && directory_has_visible_children(&path),
                children,
            }
        })
        .collect()
}

fn build_directory_listing(root: &PathBuf, current: &PathBuf) -> Vec<WorkspaceNode> {
    visible_entries(current)
        .map(|path| {
            let is_dir = path.is_dir();
            WorkspaceNode {
                name: file_name_for_path(&path),
                path: relative_path(root, &path),
                kind: if is_dir {
                    "directory".to_string()
                } else {
                    "file".to_string()
                },
                has_children: is_dir && directory_has_visible_children(&path),
                children: Vec::new(),
            }
        })
        .collect()
}

fn run_git(root: &PathBuf, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to launch git: {}", error))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if stderr.is_empty() {
            stdout
        } else if stdout.is_empty() {
            stderr
        } else {
            format!("{}\n{}", stderr, stdout)
        };
        return Err(message);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_git_bytes(root: &PathBuf, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to launch git: {}", error))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(output.stdout)
}

fn git_workspace_prefix(root: &PathBuf) -> String {
    run_git(root, &["rev-parse", "--show-prefix"]).unwrap_or_default()
}

fn workspace_path_from_git_path(root: &PathBuf, git_path: &str) -> Option<String> {
    let prefix = git_workspace_prefix(root);
    if prefix.is_empty() {
        return Some(git_path.to_string());
    }

    git_path
        .strip_prefix(&prefix)
        .map(|value| value.to_string())
}

fn git_path_from_workspace_path(root: &PathBuf, workspace_path: &str) -> String {
    let prefix = git_workspace_prefix(root);
    if prefix.is_empty() {
        workspace_path.to_string()
    } else {
        format!("{}{}", prefix, workspace_path)
    }
}

fn inspect_git(root: &PathBuf) -> WorkspaceGitSummary {
    let is_repo = run_git(root, &["rev-parse", "--is-inside-work-tree"])
        .map(|value| value == "true")
        .unwrap_or(false);

    if !is_repo {
        return WorkspaceGitSummary {
            is_repo: false,
            branch: None,
            dirty: false,
            last_commit: None,
        };
    }

    let branch = run_git(root, &["branch", "--show-current"])
        .ok()
        .filter(|value| !value.is_empty());
    let dirty = run_git(root, &["status", "--porcelain", "--", "."])
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    let last_commit = run_git(root, &["log", "-1", "--pretty=%h %s"])
        .ok()
        .filter(|value| !value.is_empty());

    WorkspaceGitSummary {
        is_repo,
        branch,
        dirty,
        last_commit,
    }
}

fn inspect_git_bootstrap(root: &PathBuf) -> WorkspaceGitSummary {
    let is_repo = run_git(root, &["rev-parse", "--is-inside-work-tree"])
        .map(|value| value == "true")
        .unwrap_or(false);

    if !is_repo {
        return WorkspaceGitSummary {
            is_repo: false,
            branch: None,
            dirty: false,
            last_commit: None,
        };
    }

    let branch = run_git(root, &["branch", "--show-current"])
        .ok()
        .filter(|value| !value.is_empty());

    WorkspaceGitSummary {
        is_repo,
        branch,
        dirty: false,
        last_commit: None,
    }
}

fn read_workspace_file_document(
    root: &PathBuf,
    relative_file_path: &str,
) -> Result<WorkspaceFileDocument, String> {
    let file_path = resolve_scoped_existing_path(root, relative_file_path)?;
    if file_path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an editable file.",
            file_path.display()
        ));
    }

    let bytes = fs::read(&file_path)
        .map_err(|error| format!("Failed to read '{}': {}", file_path.display(), error))?;
    let size_bytes = bytes.len();
    let is_too_large = size_bytes > EDITOR_MAX_BYTES;
    let is_binary = bytes.iter().any(|byte| *byte == 0);

    let content = if is_too_large || is_binary {
        String::new()
    } else {
        String::from_utf8(bytes).map_err(|_| {
            format!(
                "'{}' is not valid UTF-8 and cannot be edited in the workspace.",
                file_path.display()
            )
        })?
    };

    Ok(WorkspaceFileDocument {
        name: file_name_for_path(&file_path),
        path: relative_path(root, &file_path),
        absolute_path: file_path.display().to_string(),
        language_hint: language_hint_for_path(&file_path),
        content,
        size_bytes,
        modified_at_ms: modified_time_ms(&file_path),
        is_binary,
        is_too_large,
        read_only: is_binary || is_too_large,
    })
}

fn search_text(root: &PathBuf, query: &str) -> Result<WorkspaceSearchResult, String> {
    let output = Command::new("rg")
        .arg("--json")
        .arg("--line-number")
        .arg("--column")
        .arg("--smart-case")
        .arg("--glob")
        .arg("!.git")
        .arg("--glob")
        .arg("!node_modules")
        .arg("--glob")
        .arg("!target")
        .arg("--glob")
        .arg("!dist")
        .arg("--glob")
        .arg("!build")
        .arg(query)
        .arg(root)
        .output()
        .map_err(|error| format!("Failed to launch rg: {}", error))?;

    if !output.status.success() && !output.stdout.is_empty() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let mut total_matches = 0usize;
    let mut grouped: BTreeMap<String, Vec<WorkspaceSearchMatch>> = BTreeMap::new();

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if total_matches >= SEARCH_MAX_MATCHES {
            break;
        }

        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };

        if value.get("type").and_then(Value::as_str) != Some("match") {
            continue;
        }

        let Some(data) = value.get("data") else {
            continue;
        };

        let path = data
            .get("path")
            .and_then(|path| path.get("text"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| root.clone());
        let relative = relative_path(root, &path);
        let line_number = data.get("line_number").and_then(Value::as_u64).unwrap_or(1) as usize;
        let column = data
            .get("submatches")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("start"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize
            + 1;
        let preview = data
            .get("lines")
            .and_then(|lines| lines.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_end_matches('\n')
            .to_string();

        grouped
            .entry(relative.clone())
            .or_default()
            .push(WorkspaceSearchMatch {
                path: relative,
                line: line_number,
                column,
                preview,
            });
        total_matches += 1;
    }

    let files = grouped
        .into_iter()
        .map(|(path, matches)| WorkspaceSearchFileResult {
            path,
            match_count: matches.len(),
            matches,
        })
        .collect::<Vec<_>>();

    Ok(WorkspaceSearchResult {
        query: query.to_string(),
        total_matches,
        files,
    })
}

fn parse_status_entry(root: &PathBuf, line: &str) -> Option<WorkspaceSourceControlEntry> {
    if line.len() < 3 {
        return None;
    }

    let x = line.get(0..1)?.to_string();
    let y = line.get(1..2)?.to_string();
    let raw_path = line.get(3..)?.trim();
    let (original_path, path) = if raw_path.contains(" -> ") {
        let mut parts = raw_path.splitn(2, " -> ");
        let from = parts.next()?.trim_matches('"').to_string();
        let to = parts.next()?.trim_matches('"').to_string();
        (Some(from), to)
    } else {
        (None, raw_path.trim_matches('"').to_string())
    };

    let workspace_path = workspace_path_from_git_path(root, &path)?;
    let workspace_original_path = original_path
        .as_deref()
        .and_then(|value| workspace_path_from_git_path(root, value));

    Some(WorkspaceSourceControlEntry {
        path: workspace_path,
        original_path: workspace_original_path,
        x,
        y,
    })
}

fn source_control_state(root: &PathBuf) -> WorkspaceSourceControlState {
    let git = inspect_git(root);
    if !git.is_repo {
        return WorkspaceSourceControlState {
            git,
            entries: Vec::new(),
        };
    }

    let entries = run_git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            ".",
        ],
    )
    .ok()
    .map(|value| {
        value
            .lines()
            .filter_map(|line| parse_status_entry(root, line))
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    WorkspaceSourceControlState { git, entries }
}

fn staged_commit_count(root: &PathBuf) -> usize {
    run_git(root, &["diff", "--cached", "--name-only", "--"])
        .ok()
        .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0)
}

fn commit_workspace(
    root: &PathBuf,
    headline: &str,
    body: Option<&str>,
) -> Result<WorkspaceCommitResult, String> {
    let trimmed_headline = headline.trim();
    if trimmed_headline.is_empty() {
        return Err("Enter a commit headline before committing.".to_string());
    }

    let before_state = source_control_state(root);
    if !before_state.git.is_repo {
        return Err("Open a git-backed workspace before committing.".to_string());
    }

    let committed_file_count = staged_commit_count(root);
    if committed_file_count == 0 {
        return Err("Stage at least one change before committing.".to_string());
    }

    let trimmed_body = body.map(str::trim).filter(|value| !value.is_empty());
    let mut args = vec!["commit", "-m", trimmed_headline];
    if let Some(body) = trimmed_body {
        args.push("-m");
        args.push(body);
    }
    run_git(root, &args)?;

    let state = source_control_state(root);
    let commit_summary = state
        .git
        .last_commit
        .clone()
        .unwrap_or_else(|| trimmed_headline.to_string());
    let remaining_change_count = state.entries.len();

    Ok(WorkspaceCommitResult {
        state,
        committed_file_count,
        remaining_change_count,
        commit_summary,
    })
}

fn git_blob_at(root: &PathBuf, spec: &str) -> Option<Vec<u8>> {
    run_git_bytes(root, &["show", spec]).ok()
}

fn working_tree_blob(path: &PathBuf) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

fn decode_text(bytes: Option<Vec<u8>>) -> Result<(String, bool), String> {
    let Some(bytes) = bytes else {
        return Ok((String::new(), false));
    };

    if bytes.iter().any(|byte| *byte == 0) {
        return Ok((String::new(), true));
    }

    match String::from_utf8(bytes) {
        Ok(text) => Ok((text, false)),
        Err(_) => Ok((String::new(), true)),
    }
}

fn workspace_diff(
    root: &PathBuf,
    relative_file_path: &str,
    staged: bool,
) -> Result<WorkspaceDiffDocument, String> {
    let candidate = resolve_scoped_candidate_path(root, relative_file_path)?;
    let relative = relative_path(root, &candidate);
    let git_relative_file_path = git_path_from_workspace_path(root, relative_file_path);
    let language_hint = language_hint_for_path(&candidate);

    let original_spec = format!("HEAD:{}", git_relative_file_path);
    let index_spec = format!(":{}", git_relative_file_path);
    let (original_bytes, modified_bytes, original_label, modified_label) = if staged {
        (
            git_blob_at(root, &original_spec),
            git_blob_at(root, &index_spec),
            "HEAD".to_string(),
            "Index".to_string(),
        )
    } else {
        (
            git_blob_at(root, &index_spec).or_else(|| git_blob_at(root, &original_spec)),
            working_tree_blob(&candidate),
            "Index".to_string(),
            "Working tree".to_string(),
        )
    };

    let (original_content, original_binary) = decode_text(original_bytes)?;
    let (modified_content, modified_binary) = decode_text(modified_bytes)?;
    let is_binary = original_binary || modified_binary;

    Ok(WorkspaceDiffDocument {
        id: format!(
            "{}::{}",
            if staged { "staged" } else { "working" },
            relative_file_path
        ),
        path: relative,
        title: if staged {
            format!("Staged diff · {}", relative_file_path)
        } else {
            format!("Working tree diff · {}", relative_file_path)
        },
        original_label,
        modified_label,
        original_content,
        modified_content,
        language_hint,
        is_binary,
    })
}

fn restore_path(root: &PathBuf, path: &str) -> Result<(), String> {
    let git_relative_path = git_path_from_workspace_path(root, path);
    let tracked_in_head = run_git(
        root,
        &["cat-file", "-e", &format!("HEAD:{}", git_relative_path)],
    )
    .is_ok();
    let candidate = resolve_scoped_candidate_path(root, path)?;

    if tracked_in_head {
        let _ = run_git(
            root,
            &[
                "restore",
                "--staged",
                "--worktree",
                "--source=HEAD",
                "--",
                path,
            ],
        );
        return Ok(());
    }

    let _ = run_git(root, &["reset", "HEAD", "--", path]);
    if candidate.is_dir() {
        if candidate.exists() {
            fs::remove_dir_all(&candidate).map_err(|error| {
                format!("Failed to remove '{}': {}", candidate.display(), error)
            })?;
        }
    } else if candidate.exists() {
        fs::remove_file(&candidate)
            .map_err(|error| format!("Failed to remove '{}': {}", candidate.display(), error))?;
    }

    Ok(())
}

#[tauri::command]
pub fn workspace_inspect(root: String) -> Result<WorkspaceSnapshot, String> {
    let root_path = resolve_root_path(&root)?;
    let tree = build_tree(&root_path, &root_path, 0);
    let snapshot = WorkspaceSnapshot {
        root_path: root_path.display().to_string(),
        display_name: display_name_for_root(&root_path),
        git: inspect_git_bootstrap(&root_path),
        tree,
    };
    eprintln!(
        "[WorkspaceInspect] root='{}' resolved='{}' display='{}' tree_len={}",
        root,
        snapshot.root_path,
        snapshot.display_name,
        snapshot.tree.len()
    );
    Ok(snapshot)
}

#[tauri::command]
pub fn chat_workspace_inspect(root: String) -> Result<WorkspaceSnapshot, String> {
    workspace_inspect(root)
}

#[tauri::command]
pub fn workspace_list_directory(root: String, path: String) -> Result<Vec<WorkspaceNode>, String> {
    let root_path = resolve_root_path(&root)?;
    let directory = if path.is_empty() || path == "." {
        root_path.clone()
    } else {
        resolve_scoped_existing_path(&root_path, &path)?
    };

    if !directory.is_dir() {
        return Err(format!(
            "'{}' is not a directory inside the workspace boundary.",
            directory.display()
        ));
    }

    let listing = build_directory_listing(&root_path, &directory);
    eprintln!(
        "[WorkspaceList] root='{}' resolved='{}' path='{}' dir='{}' entries={}",
        root,
        root_path.display(),
        path,
        directory.display(),
        listing.len()
    );
    Ok(listing)
}

#[tauri::command]
pub fn chat_workspace_list_directory(
    root: String,
    path: String,
) -> Result<Vec<WorkspaceNode>, String> {
    workspace_list_directory(root, path)
}

#[tauri::command]
pub fn workspace_read_file(root: String, path: String) -> Result<WorkspaceFileDocument, String> {
    let root_path = resolve_root_path(&root)?;
    read_workspace_file_document(&root_path, &path)
}

#[tauri::command]
pub fn chat_workspace_read_file(
    root: String,
    path: String,
) -> Result<WorkspaceFileDocument, String> {
    workspace_read_file(root, path)
}

#[tauri::command]
pub async fn workspace_lsp_snapshot(
    root: String,
    path: String,
    content: Option<String>,
) -> Result<lsp::WorkspaceLspSnapshot, String> {
    let root_path = resolve_root_path(&root)?;
    let relative_path = safe_relative_input(&path)?;
    let rendered_path = if relative_path.as_os_str().is_empty() {
        return Err("A file path is required for workspace intelligence.".to_string());
    } else {
        relative_path.to_string_lossy().replace('\\', "/")
    };

    tokio::task::spawn_blocking(move || {
        lsp::snapshot_workspace_file(&root_path, &rendered_path, content)
    })
    .await
    .map_err(|error| format!("Workspace language service task failed: {}", error))?
}

#[tauri::command]
pub async fn chat_workspace_lsp_snapshot(
    root: String,
    path: String,
    content: Option<String>,
) -> Result<lsp::WorkspaceLspSnapshot, String> {
    workspace_lsp_snapshot(root, path, content).await
}

#[tauri::command]
pub async fn workspace_lsp_definition(
    root: String,
    path: String,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspLocation>, String> {
    let root_path = resolve_root_path(&root)?;
    let relative_path = safe_relative_input(&path)?;
    let rendered_path = if relative_path.as_os_str().is_empty() {
        return Err("A file path is required for workspace intelligence.".to_string());
    } else {
        relative_path.to_string_lossy().replace('\\', "/")
    };

    tokio::task::spawn_blocking(move || {
        lsp::definition_locations_for_workspace_file(
            &root_path,
            &rendered_path,
            line,
            column,
            content,
        )
    })
    .await
    .map_err(|error| format!("Workspace language service task failed: {}", error))?
}

#[tauri::command]
pub async fn chat_workspace_lsp_definition(
    root: String,
    path: String,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspLocation>, String> {
    workspace_lsp_definition(root, path, line, column, content).await
}

#[tauri::command]
pub async fn workspace_lsp_references(
    root: String,
    path: String,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspLocation>, String> {
    let root_path = resolve_root_path(&root)?;
    let relative_path = safe_relative_input(&path)?;
    let rendered_path = if relative_path.as_os_str().is_empty() {
        return Err("A file path is required for workspace intelligence.".to_string());
    } else {
        relative_path.to_string_lossy().replace('\\', "/")
    };

    tokio::task::spawn_blocking(move || {
        lsp::reference_locations_for_workspace_file(
            &root_path,
            &rendered_path,
            line,
            column,
            content,
        )
    })
    .await
    .map_err(|error| format!("Workspace language service task failed: {}", error))?
}

#[tauri::command]
pub async fn chat_workspace_lsp_references(
    root: String,
    path: String,
    line: u32,
    column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspLocation>, String> {
    workspace_lsp_references(root, path, line, column, content).await
}

#[tauri::command]
pub async fn workspace_lsp_code_actions(
    root: String,
    path: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspCodeAction>, String> {
    let root_path = resolve_root_path(&root)?;
    let relative_path = safe_relative_input(&path)?;
    let rendered_path = if relative_path.as_os_str().is_empty() {
        return Err("A file path is required for workspace intelligence.".to_string());
    } else {
        relative_path.to_string_lossy().replace('\\', "/")
    };

    tokio::task::spawn_blocking(move || {
        lsp::code_actions_for_workspace_file(
            &root_path,
            &rendered_path,
            line,
            column,
            end_line,
            end_column,
            content,
        )
    })
    .await
    .map_err(|error| format!("Workspace language service task failed: {}", error))?
}

#[tauri::command]
pub async fn chat_workspace_lsp_code_actions(
    root: String,
    path: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    content: Option<String>,
) -> Result<Vec<lsp::WorkspaceLspCodeAction>, String> {
    workspace_lsp_code_actions(root, path, line, column, end_line, end_column, content).await
}

#[tauri::command]
pub fn workspace_write_file(
    root: String,
    path: String,
    content: String,
) -> Result<WorkspaceFileDocument, String> {
    let root_path = resolve_root_path(&root)?;
    let file_path = resolve_scoped_candidate_path(&root_path, &path)?;

    if file_path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an editable file.",
            file_path.display()
        ));
    }

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create '{}': {}", parent.display(), error))?;
    }

    fs::write(&file_path, content.as_bytes())
        .map_err(|error| format!("Failed to save '{}': {}", file_path.display(), error))?;

    read_workspace_file_document(&root_path, &path)
}

#[tauri::command]
pub fn chat_workspace_write_file(
    root: String,
    path: String,
    content: String,
) -> Result<WorkspaceFileDocument, String> {
    workspace_write_file(root, path, content)
}

#[tauri::command]
pub fn workspace_create_file(root: String, path: String) -> Result<WorkspaceFileDocument, String> {
    let root_path = resolve_root_path(&root)?;
    let file_path = resolve_scoped_candidate_path(&root_path, &path)?;

    if file_path.exists() {
        return Err(format!("'{}' already exists.", file_path.display()));
    }

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create '{}': {}", parent.display(), error))?;
    }

    fs::write(&file_path, b"")
        .map_err(|error| format!("Failed to create '{}': {}", file_path.display(), error))?;

    read_workspace_file_document(&root_path, &path)
}

#[tauri::command]
pub fn chat_workspace_create_file(
    root: String,
    path: String,
) -> Result<WorkspaceFileDocument, String> {
    workspace_create_file(root, path)
}

#[tauri::command]
pub fn workspace_create_directory(
    root: String,
    path: String,
) -> Result<WorkspacePathMutationResult, String> {
    let root_path = resolve_root_path(&root)?;
    let directory_path = resolve_scoped_candidate_path(&root_path, &path)?;
    fs::create_dir_all(&directory_path)
        .map_err(|error| format!("Failed to create '{}': {}", directory_path.display(), error))?;

    Ok(WorkspacePathMutationResult { path })
}

#[tauri::command]
pub fn chat_workspace_create_directory(
    root: String,
    path: String,
) -> Result<WorkspacePathMutationResult, String> {
    workspace_create_directory(root, path)
}

#[tauri::command]
pub fn workspace_stat_path(root: String, path: String) -> Result<WorkspacePathStat, String> {
    let root_path = resolve_root_path(&root)?;
    let target_path = if path.is_empty() || path == "." {
        root_path.clone()
    } else {
        resolve_scoped_existing_path(&root_path, &path)?
    };
    let metadata = fs::metadata(&target_path).map_err(|error| {
        format!(
            "Failed to inspect workspace path '{}': {}",
            target_path.display(),
            error
        )
    })?;

    Ok(WorkspacePathStat {
        kind: if metadata.is_dir() {
            "directory".to_string()
        } else {
            "file".to_string()
        },
        size_bytes: metadata.len(),
        modified_at_ms: modified_time_ms(&target_path),
        read_only: metadata.permissions().readonly(),
    })
}

#[tauri::command]
pub fn chat_workspace_stat_path(root: String, path: String) -> Result<WorkspacePathStat, String> {
    workspace_stat_path(root, path)
}

#[tauri::command]
pub fn workspace_rename_path(
    root: String,
    from: String,
    to: String,
) -> Result<WorkspacePathMutationResult, String> {
    let root_path = resolve_root_path(&root)?;
    let current_path = resolve_scoped_existing_path(&root_path, &from)?;
    let target_path = resolve_scoped_candidate_path(&root_path, &to)?;

    if target_path.exists() {
        return Err(format!("'{}' already exists.", target_path.display()));
    }

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create '{}': {}", parent.display(), error))?;
    }

    fs::rename(&current_path, &target_path).map_err(|error| {
        format!(
            "Failed to rename '{}' to '{}': {}",
            current_path.display(),
            target_path.display(),
            error
        )
    })?;

    Ok(WorkspacePathMutationResult { path: to })
}

#[tauri::command]
pub fn chat_workspace_rename_path(
    root: String,
    from: String,
    to: String,
) -> Result<WorkspacePathMutationResult, String> {
    workspace_rename_path(root, from, to)
}

#[tauri::command]
pub fn workspace_delete_path(root: String, path: String) -> Result<WorkspaceDeleteResult, String> {
    if path.is_empty() || path == "." {
        return Err("Refusing to delete the workspace root.".to_string());
    }

    let root_path = resolve_root_path(&root)?;
    let target_path = resolve_scoped_existing_path(&root_path, &path)?;

    if target_path.is_dir() {
        fs::remove_dir_all(&target_path)
            .map_err(|error| format!("Failed to remove '{}': {}", target_path.display(), error))?;
    } else {
        fs::remove_file(&target_path)
            .map_err(|error| format!("Failed to remove '{}': {}", target_path.display(), error))?;
    }

    Ok(WorkspaceDeleteResult { deleted_path: path })
}

#[tauri::command]
pub fn chat_workspace_delete_path(
    root: String,
    path: String,
) -> Result<WorkspaceDeleteResult, String> {
    workspace_delete_path(root, path)
}

#[tauri::command]
pub fn workspace_search_text(root: String, query: String) -> Result<WorkspaceSearchResult, String> {
    let root_path = resolve_root_path(&root)?;
    search_text(&root_path, &query)
}

#[tauri::command]
pub fn chat_workspace_search_text(
    root: String,
    query: String,
) -> Result<WorkspaceSearchResult, String> {
    workspace_search_text(root, query)
}

#[tauri::command]
pub fn workspace_git_status(root: String) -> Result<WorkspaceSourceControlState, String> {
    let root_path = resolve_root_path(&root)?;
    Ok(source_control_state(&root_path))
}

#[tauri::command]
pub fn chat_workspace_git_status(root: String) -> Result<WorkspaceSourceControlState, String> {
    workspace_git_status(root)
}

#[tauri::command]
pub fn workspace_git_diff(
    root: String,
    path: String,
    staged: bool,
) -> Result<WorkspaceDiffDocument, String> {
    let root_path = resolve_root_path(&root)?;
    workspace_diff(&root_path, &path, staged)
}

#[tauri::command]
pub fn chat_workspace_git_diff(
    root: String,
    path: String,
    staged: bool,
) -> Result<WorkspaceDiffDocument, String> {
    workspace_git_diff(root, path, staged)
}

#[tauri::command]
pub fn workspace_git_commit(
    root: String,
    headline: String,
    body: Option<String>,
) -> Result<WorkspaceCommitResult, String> {
    let root_path = resolve_root_path(&root)?;
    commit_workspace(&root_path, &headline, body.as_deref())
}

#[tauri::command]
pub fn chat_workspace_git_commit(
    root: String,
    headline: String,
    body: Option<String>,
) -> Result<WorkspaceCommitResult, String> {
    workspace_git_commit(root, headline, body)
}

#[tauri::command]
pub fn workspace_git_stage(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    let root_path = resolve_root_path(&root)?;
    for path in paths.iter() {
        let _ = resolve_scoped_candidate_path(&root_path, path)?;
        run_git(&root_path, &["add", "--", path])?;
    }
    Ok(source_control_state(&root_path))
}

#[tauri::command]
pub fn chat_workspace_git_stage(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    workspace_git_stage(root, paths)
}

#[tauri::command]
pub fn workspace_git_unstage(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    let root_path = resolve_root_path(&root)?;
    for path in paths.iter() {
        let _ = resolve_scoped_candidate_path(&root_path, path)?;
        run_git(&root_path, &["restore", "--staged", "--", path])?;
    }
    Ok(source_control_state(&root_path))
}

#[tauri::command]
pub fn chat_workspace_git_unstage(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    workspace_git_unstage(root, paths)
}

#[tauri::command]
pub fn workspace_git_discard(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    let root_path = resolve_root_path(&root)?;
    for path in paths.iter() {
        restore_path(&root_path, path)?;
    }
    Ok(source_control_state(&root_path))
}

#[tauri::command]
pub fn chat_workspace_git_discard(
    root: String,
    paths: Vec<String>,
) -> Result<WorkspaceSourceControlState, String> {
    workspace_git_discard(root, paths)
}

#[tauri::command]
pub fn workspace_terminal_create(
    root: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalSession, String> {
    terminal::workspace_terminal_create(root, cols, rows, manager)
}

#[tauri::command]
pub fn chat_workspace_terminal_create(
    root: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalSession, String> {
    workspace_terminal_create(root, cols, rows, manager)
}

#[tauri::command]
pub fn workspace_terminal_read(
    session_id: String,
    cursor: u64,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalReadResult, String> {
    terminal::workspace_terminal_read(session_id, cursor, manager)
}

#[tauri::command]
pub fn chat_workspace_terminal_read(
    session_id: String,
    cursor: u64,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalReadResult, String> {
    workspace_terminal_read(session_id, cursor, manager)
}

#[tauri::command]
pub fn workspace_terminal_write(
    session_id: String,
    data: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    terminal::workspace_terminal_write(session_id, data, manager)
}

#[tauri::command]
pub fn chat_workspace_terminal_write(
    session_id: String,
    data: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    workspace_terminal_write(session_id, data, manager)
}

#[tauri::command]
pub fn workspace_terminal_resize(
    session_id: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    terminal::workspace_terminal_resize(session_id, cols, rows, manager)
}

#[tauri::command]
pub fn chat_workspace_terminal_resize(
    session_id: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    workspace_terminal_resize(session_id, cols, rows, manager)
}

#[tauri::command]
pub fn workspace_terminal_close(
    session_id: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    terminal::workspace_terminal_close(session_id, manager)
}

#[tauri::command]
pub fn chat_workspace_terminal_close(
    session_id: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    workspace_terminal_close(session_id, manager)
}

#[cfg(test)]
#[path = "workspace/tests.rs"]
mod tests;
