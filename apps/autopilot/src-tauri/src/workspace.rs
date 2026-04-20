use crate::kernel::lsp;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::UNIX_EPOCH;
use tauri::State;

const TREE_BOOTSTRAP_DEPTH: usize = 2;
const TREE_MAX_CHILDREN: usize = 200;
const EDITOR_MAX_BYTES: usize = 1024 * 1024;
const SEARCH_MAX_MATCHES: usize = 600;
const TERMINAL_MAX_CHUNKS: usize = 2400;
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

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalSession {
    pub session_id: String,
    pub shell: String,
    pub root_path: String,
    pub started_at_ms: u64,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalOutputChunk {
    pub sequence: u64,
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalReadResult {
    pub session_id: String,
    pub cursor: u64,
    pub chunks: Vec<WorkspaceTerminalOutputChunk>,
    pub running: bool,
    pub exit_code: Option<i32>,
}

#[derive(Default)]
pub struct WorkspaceTerminalManager {
    sessions: Mutex<HashMap<String, Arc<WorkspaceTerminalHandle>>>,
}

#[derive(Clone)]
pub(crate) struct WorkspaceTerminalBridge {
    session: Arc<WorkspaceTerminalHandle>,
}

struct WorkspaceTerminalHandle {
    session: WorkspaceTerminalSession,
    writer: Mutex<Box<dyn Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    output: Mutex<VecDeque<WorkspaceTerminalOutputChunk>>,
    next_sequence: AtomicU64,
    running: AtomicBool,
    exit_code: Mutex<Option<i32>>,
}

fn resolve_root_path(root: &str) -> Result<PathBuf, String> {
    let requested = PathBuf::from(root);
    let resolved = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|error| format!("Failed to resolve current directory: {}", error))?
            .join(requested)
    };

    if !resolved.exists() {
        return Err(format!(
            "Workspace root '{}' does not exist.",
            resolved.display()
        ));
    }

    resolved
        .canonicalize()
        .map_err(|error| format!("Failed to canonicalize '{}': {}", resolved.display(), error))
}

fn safe_relative_input(relative_path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(relative_path);
    if path.as_os_str().is_empty() || relative_path == "." {
        return Ok(PathBuf::new());
    }

    if path.is_absolute() {
        return Err("Absolute paths are not allowed in the workspace.".to_string());
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("Path traversal is not allowed in the workspace.".to_string());
    }

    Ok(path)
}

fn relative_path(root: &PathBuf, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|value| {
            let rendered = value
                .components()
                .map(|component| component.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            if rendered.is_empty() {
                ".".to_string()
            } else {
                rendered
            }
        })
        .unwrap_or_else(|| path.display().to_string())
}

fn resolve_scoped_existing_path(root: &PathBuf, relative_path: &str) -> Result<PathBuf, String> {
    let safe_relative = safe_relative_input(relative_path)?;
    let candidate = root.join(&safe_relative);
    let canonical = candidate.canonicalize().map_err(|error| {
        format!(
            "Failed to resolve workspace path '{}': {}",
            candidate.display(),
            error
        )
    })?;

    if !canonical.starts_with(root) {
        return Err("Resolved path falls outside the workspace boundary.".to_string());
    }

    Ok(canonical)
}

fn resolve_scoped_candidate_path(root: &PathBuf, relative_path: &str) -> Result<PathBuf, String> {
    let safe_relative = safe_relative_input(relative_path)?;
    let candidate = root.join(&safe_relative);
    if !candidate.starts_with(root) {
        return Err("Resolved path falls outside the workspace boundary.".to_string());
    }
    Ok(candidate)
}

fn should_skip_dir(name: &str) -> bool {
    SKIPPED_DIRS.iter().any(|value| value == &name)
}

fn file_name_for_path(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn modified_time_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|timestamp| timestamp.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn language_hint_for_path(path: &Path) -> Option<String> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("ts") => Some("typescript".to_string()),
        Some("tsx") => Some("tsx".to_string()),
        Some("js") => Some("javascript".to_string()),
        Some("jsx") => Some("jsx".to_string()),
        Some("json") => Some("json".to_string()),
        Some("md") => Some("markdown".to_string()),
        Some("rs") => Some("rust".to_string()),
        Some("css") => Some("css".to_string()),
        Some("html") | Some("htm") => Some("html".to_string()),
        Some("yaml") | Some("yml") => Some("yaml".to_string()),
        Some("sh") | Some("bash") => Some("shell".to_string()),
        Some("toml") => Some("toml".to_string()),
        Some("xml") | Some("svg") => Some("xml".to_string()),
        _ => None,
    }
}

fn display_name_for_root(root: &PathBuf) -> String {
    root.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("workspace")
        .to_string()
}

fn default_terminal_shell() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMSPEC")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "powershell.exe".to_string())
    }

    #[cfg(not(windows))]
    {
        std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/bash".to_string())
    }
}

fn push_terminal_output(session: &Arc<WorkspaceTerminalHandle>, text: String) {
    if text.is_empty() {
        return;
    }

    let sequence = session.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let mut output = session
        .output
        .lock()
        .expect("terminal output lock poisoned");
    output.push_back(WorkspaceTerminalOutputChunk { sequence, text });
    while output.len() > TERMINAL_MAX_CHUNKS {
        output.pop_front();
    }
}

fn spawn_terminal_session(
    root: &PathBuf,
    cols: u16,
    rows: u16,
) -> Result<Arc<WorkspaceTerminalHandle>, String> {
    let pty_system = native_pty_system();
    let pty_size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = pty_system
        .openpty(pty_size)
        .map_err(|error| format!("Failed to open PTY: {}", error))?;
    let shell = default_terminal_shell();
    let mut command = CommandBuilder::new(&shell);
    command.cwd(root);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env("TERM_PROGRAM", "Autopilot");

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("Failed to spawn workspace shell: {}", error))?;
    drop(pair.slave);
    let killer = child.clone_killer();
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("Failed to clone PTY reader: {}", error))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("Failed to access PTY writer: {}", error))?;

    let session = Arc::new(WorkspaceTerminalHandle {
        session: WorkspaceTerminalSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            shell,
            root_path: root.display().to_string(),
            started_at_ms: now_ms(),
            cols,
            rows,
        },
        writer: Mutex::new(writer),
        master: Mutex::new(pair.master),
        killer: Mutex::new(killer),
        output: Mutex::new(VecDeque::new()),
        next_sequence: AtomicU64::new(0),
        running: AtomicBool::new(true),
        exit_code: Mutex::new(None),
    });

    let read_session = Arc::clone(&session);
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    push_terminal_output(
                        &read_session,
                        String::from_utf8_lossy(&buffer[..count]).to_string(),
                    );
                }
                Err(error) => {
                    push_terminal_output(
                        &read_session,
                        format!("\r\n[autopilot] terminal read error: {}\r\n", error),
                    );
                    break;
                }
            }
        }
    });

    let wait_session = Arc::clone(&session);
    thread::spawn(move || match child.wait() {
        Ok(status) => {
            wait_session.running.store(false, Ordering::Relaxed);
            let code = i32::try_from(status.exit_code()).unwrap_or(1);
            let mut exit_code = wait_session
                .exit_code
                .lock()
                .expect("terminal exit lock poisoned");
            *exit_code = Some(code);
            drop(exit_code);
            push_terminal_output(
                &wait_session,
                format!("\r\n[autopilot] shell exited with code {}\r\n", code),
            );
        }
        Err(error) => {
            wait_session.running.store(false, Ordering::Relaxed);
            let mut exit_code = wait_session
                .exit_code
                .lock()
                .expect("terminal exit lock poisoned");
            *exit_code = Some(1);
            drop(exit_code);
            push_terminal_output(
                &wait_session,
                format!("\r\n[autopilot] shell wait failed: {}\r\n", error),
            );
        }
    });

    Ok(session)
}

fn terminal_read_result(
    session_id: String,
    session: &Arc<WorkspaceTerminalHandle>,
    cursor: u64,
) -> Result<WorkspaceTerminalReadResult, String> {
    let chunks = session
        .output
        .lock()
        .map_err(|_| "Failed to lock terminal output.".to_string())?
        .iter()
        .filter(|chunk| chunk.sequence > cursor)
        .cloned()
        .collect::<Vec<_>>();
    let next_cursor = chunks.last().map(|chunk| chunk.sequence).unwrap_or(cursor);
    let exit_code = *session
        .exit_code
        .lock()
        .map_err(|_| "Failed to lock terminal exit state.".to_string())?;

    Ok(WorkspaceTerminalReadResult {
        session_id,
        cursor: next_cursor,
        chunks,
        running: session.running.load(Ordering::Relaxed),
        exit_code,
    })
}

fn terminal_write_bytes(session: &Arc<WorkspaceTerminalHandle>, data: &[u8]) -> Result<(), String> {
    let mut writer = session
        .writer
        .lock()
        .map_err(|_| "Failed to lock terminal writer.".to_string())?;
    writer
        .write_all(data)
        .map_err(|error| format!("Failed to write to terminal: {}", error))?;
    writer
        .flush()
        .map_err(|error| format!("Failed to flush terminal input: {}", error))?;
    Ok(())
}

fn terminal_write_input(session: &Arc<WorkspaceTerminalHandle>, data: &str) -> Result<(), String> {
    terminal_write_bytes(session, data.as_bytes())
}

fn terminal_resize(
    session: &Arc<WorkspaceTerminalHandle>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    session
        .master
        .lock()
        .map_err(|_| "Failed to lock terminal PTY.".to_string())?
        .resize(PtySize {
            rows: rows.max(12),
            cols: cols.max(40),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("Failed to resize terminal: {}", error))?;
    Ok(())
}

fn terminal_close(session: Arc<WorkspaceTerminalHandle>) -> Result<(), String> {
    session.running.store(false, Ordering::Relaxed);
    let kill_result = session
        .killer
        .lock()
        .map_err(|_| "Failed to lock terminal killer.".to_string())?
        .kill();
    if let Err(error) = kill_result {
        push_terminal_output(
            &session,
            format!(
                "\r\n[autopilot] failed to close shell cleanly: {}\r\n",
                error
            ),
        );
    }
    Ok(())
}

impl WorkspaceTerminalBridge {
    pub(crate) fn open(root: &str, cols: u16, rows: u16) -> Result<Self, String> {
        let root_path = resolve_root_path(root)?;
        let session = spawn_terminal_session(&root_path, cols.max(40), rows.max(12))?;
        Ok(Self { session })
    }

    pub(crate) fn session(&self) -> WorkspaceTerminalSession {
        self.session.session.clone()
    }

    pub(crate) fn read(&self, cursor: u64) -> Result<WorkspaceTerminalReadResult, String> {
        terminal_read_result(
            self.session.session.session_id.clone(),
            &self.session,
            cursor,
        )
    }

    pub(crate) fn write(&self, data: &str) -> Result<(), String> {
        terminal_write_input(&self.session, data)
    }

    pub(crate) fn write_bytes(&self, data: &[u8]) -> Result<(), String> {
        terminal_write_bytes(&self.session, data)
    }

    pub(crate) fn resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        terminal_resize(&self.session, cols, rows)
    }

    pub(crate) fn close(&self) -> Result<(), String> {
        terminal_close(Arc::clone(&self.session))
    }
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
    Ok(WorkspaceSnapshot {
        root_path: root_path.display().to_string(),
        display_name: display_name_for_root(&root_path),
        git: inspect_git(&root_path),
        tree: build_tree(&root_path, &root_path, 0),
    })
}

#[tauri::command]
pub fn studio_workspace_inspect(root: String) -> Result<WorkspaceSnapshot, String> {
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

    Ok(build_directory_listing(&root_path, &directory))
}

#[tauri::command]
pub fn studio_workspace_list_directory(
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
pub fn studio_workspace_read_file(
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
pub async fn studio_workspace_lsp_snapshot(
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
pub async fn studio_workspace_lsp_definition(
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
pub async fn studio_workspace_lsp_references(
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
pub async fn studio_workspace_lsp_code_actions(
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
pub fn studio_workspace_write_file(
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
pub fn studio_workspace_create_file(
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
pub fn studio_workspace_create_directory(
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
pub fn studio_workspace_stat_path(root: String, path: String) -> Result<WorkspacePathStat, String> {
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
pub fn studio_workspace_rename_path(
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
pub fn studio_workspace_delete_path(
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
pub fn studio_workspace_search_text(
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
pub fn studio_workspace_git_status(root: String) -> Result<WorkspaceSourceControlState, String> {
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
pub fn studio_workspace_git_diff(
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
pub fn studio_workspace_git_commit(
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
pub fn studio_workspace_git_stage(
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
pub fn studio_workspace_git_unstage(
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
pub fn studio_workspace_git_discard(
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
    let bridge = WorkspaceTerminalBridge::open(&root, cols, rows)?;
    let descriptor = bridge.session();
    let mut sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    sessions.insert(descriptor.session_id.clone(), bridge.session);
    Ok(descriptor)
}

#[tauri::command]
pub fn studio_workspace_terminal_create(
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
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_read_result(session_id, &session, cursor)
}

#[tauri::command]
pub fn studio_workspace_terminal_read(
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
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_write_input(&session, &data)
}

#[tauri::command]
pub fn studio_workspace_terminal_write(
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
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_resize(&session, cols, rows)
}

#[tauri::command]
pub fn studio_workspace_terminal_resize(
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
    let session = {
        let mut sessions = manager
            .sessions
            .lock()
            .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
        sessions.remove(&session_id)
    };

    let Some(session) = session else {
        return Ok(());
    };

    terminal_close(session)
}

#[tauri::command]
pub fn studio_workspace_terminal_close(
    session_id: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    workspace_terminal_close(session_id, manager)
}

#[cfg(test)]
#[path = "workspace/tests.rs"]
mod tests;
