// apps/autopilot/src-tauri/src/project.rs

use crate::orchestrator::{GraphEdge, GraphNode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

const EXPLORER_MAX_DEPTH: usize = 2;
const EXPLORER_MAX_CHILDREN: usize = 10;
const ARTIFACT_SCAN_MAX_DEPTH: usize = 3;
const ARTIFACT_SCAN_LIMIT: usize = 12;
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build"];
const EDITOR_MAX_BYTES: usize = 512 * 1024;

// Define the file format structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectFile {
    pub version: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub global_config: Option<Value>,
    // Metadata for tracking
    pub metadata: Option<ProjectMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub name: String,
    pub created_at: u64,
    pub last_modified: u64,
    pub author: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProjectGitStatus {
    pub is_repo: bool,
    pub branch: Option<String>,
    pub dirty: bool,
    pub last_commit: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProjectExplorerNode {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub has_children: bool,
    pub children: Vec<ProjectExplorerNode>,
}

#[derive(Debug, Serialize)]
pub struct ProjectArtifactCandidate {
    pub title: String,
    pub path: String,
    pub artifact_type: String,
}

#[derive(Debug, Serialize)]
pub struct ProjectShellSnapshot {
    pub root_path: String,
    pub git: ProjectGitStatus,
    pub tree: Vec<ProjectExplorerNode>,
    pub artifacts: Vec<ProjectArtifactCandidate>,
}

#[derive(Debug, Serialize)]
pub struct ProjectFileDocument {
    pub name: String,
    pub path: String,
    pub language_hint: Option<String>,
    pub content: String,
    pub size_bytes: usize,
    pub modified_at_ms: Option<u64>,
    pub is_binary: bool,
    pub is_too_large: bool,
    pub read_only: bool,
}

fn resolve_root_path(root: &str, create_if_missing: bool) -> Result<PathBuf, String> {
    let requested = PathBuf::from(root);
    let resolved = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|error| format!("Failed to resolve current directory: {}", error))?
            .join(requested)
    };

    if create_if_missing {
        fs::create_dir_all(&resolved).map_err(|error| {
            format!(
                "Failed to create project directory '{}': {}",
                resolved.display(),
                error
            )
        })?;
    }

    if !resolved.exists() {
        return Err(format!(
            "Project root '{}' does not exist.",
            resolved.display()
        ));
    }

    resolved
        .canonicalize()
        .map_err(|error| format!("Failed to canonicalize '{}': {}", resolved.display(), error))
}

fn relative_path(root: &PathBuf, path: &PathBuf) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|value| {
            let rendered = value.display().to_string();
            if rendered.is_empty() {
                ".".to_string()
            } else {
                rendered
            }
        })
        .unwrap_or_else(|| path.display().to_string())
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
            child.file_name()
                .and_then(|value| value.to_str())
                .map(|name| !should_skip_dir(name))
                .unwrap_or(true)
        })
}

fn build_directory_listing(root: &PathBuf, current: &PathBuf) -> Vec<ProjectExplorerNode> {
    visible_entries(current)
        .take(EXPLORER_MAX_CHILDREN)
        .map(|path| {
            let is_dir = path.is_dir();
            ProjectExplorerNode {
                name: file_name_for_path(&path),
                path: relative_path(root, &path),
                kind: if is_dir { "directory" } else { "file" }.to_string(),
                has_children: is_dir && directory_has_visible_children(&path),
                children: Vec::new(),
            }
        })
        .collect()
}

fn build_tree(root: &PathBuf, current: &PathBuf, depth: usize) -> Vec<ProjectExplorerNode> {
    visible_entries(current)
        .take(EXPLORER_MAX_CHILDREN)
        .map(|path| {
            let is_dir = path.is_dir();
            let children = if is_dir && depth < EXPLORER_MAX_DEPTH {
                build_tree(root, &path, depth + 1)
            } else {
                Vec::new()
            };

            ProjectExplorerNode {
                name: file_name_for_path(&path),
                path: relative_path(root, &path),
                kind: if is_dir { "directory" } else { "file" }.to_string(),
                has_children: is_dir && directory_has_visible_children(&path),
                children,
            }
        })
        .collect()
}

fn safe_relative_input(relative_path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(relative_path);
    if path.as_os_str().is_empty() || relative_path == "." {
        return Ok(PathBuf::new());
    }
    if path.is_absolute() {
        return Err("Absolute paths are not allowed in the project shell.".to_string());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    {
        return Err("Path traversal is not allowed in the project shell.".to_string());
    }
    Ok(path)
}

fn resolve_scoped_existing_path(
    root: &PathBuf,
    relative_path: &str,
) -> Result<PathBuf, String> {
    let safe_relative = safe_relative_input(relative_path)?;
    let candidate = root.join(&safe_relative);
    let canonical = candidate.canonicalize().map_err(|error| {
        format!(
            "Failed to resolve project path '{}': {}",
            candidate.display(),
            error
        )
    })?;

    if !canonical.starts_with(root) {
        return Err("Resolved path falls outside the project boundary.".to_string());
    }

    Ok(canonical)
}

fn modified_time_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|timestamp| timestamp.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
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

fn read_project_file_document(root: &PathBuf, relative_file_path: &str) -> Result<ProjectFileDocument, String> {
    let file_path = resolve_scoped_existing_path(root, relative_file_path)?;
    if file_path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an editable file.",
            file_path.display()
        ));
    }

    let bytes = fs::read(&file_path).map_err(|error| {
        format!("Failed to read '{}': {}", file_path.display(), error)
    })?;
    let size_bytes = bytes.len();
    let is_too_large = size_bytes > EDITOR_MAX_BYTES;
    let is_binary = bytes.iter().any(|byte| *byte == 0);

    let content = if is_too_large || is_binary {
        String::new()
    } else {
        String::from_utf8(bytes).map_err(|_| {
            format!(
                "'{}' is not valid UTF-8 and cannot be edited in the embedded editor.",
                file_path.display()
            )
        })?
    };

    Ok(ProjectFileDocument {
        name: file_name_for_path(&file_path),
        path: relative_path(root, &file_path),
        language_hint: language_hint_for_path(&file_path),
        content,
        size_bytes,
        modified_at_ms: modified_time_ms(&file_path),
        is_binary,
        is_too_large,
        read_only: is_binary || is_too_large,
    })
}

fn artifact_type_for_path(path: &PathBuf) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
    {
        Some(ext) if ext == "log" => Some("log"),
        Some(ext) if ext == "diff" || ext == "patch" => Some("revision"),
        Some(ext) if ext == "html" => Some("web"),
        Some(ext) if ext == "md" => Some("report"),
        Some(ext) if ext == "json" => Some("bundle"),
        Some(ext) if ext == "txt" => Some("file"),
        _ => None,
    }
}

fn gather_artifacts(
    root: &PathBuf,
    current: &PathBuf,
    depth: usize,
    artifacts: &mut Vec<ProjectArtifactCandidate>,
) {
    if artifacts.len() >= ARTIFACT_SCAN_LIMIT {
        return;
    }

    let mut entries = match fs::read_dir(current) {
        Ok(read_dir) => read_dir
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .collect::<Vec<_>>(),
        Err(_) => return,
    };

    entries.sort_by(sort_paths);

    for path in entries {
        if artifacts.len() >= ARTIFACT_SCAN_LIMIT {
            break;
        }

        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if should_skip_dir(file_name) {
            continue;
        }

        if path.is_dir() {
            if depth < ARTIFACT_SCAN_MAX_DEPTH {
                gather_artifacts(root, &path, depth + 1, artifacts);
            }
            continue;
        }

        if let Some(artifact_type) = artifact_type_for_path(&path) {
            artifacts.push(ProjectArtifactCandidate {
                title: file_name.to_string(),
                path: relative_path(root, &path),
                artifact_type: artifact_type.to_string(),
            });
        }
    }
}

fn run_git(root: &PathBuf, args: &[&str]) -> Result<String, String> {
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

fn inspect_git(root: &PathBuf) -> ProjectGitStatus {
    let is_repo = run_git(root, &["rev-parse", "--is-inside-work-tree"])
        .map(|value| value == "true")
        .unwrap_or(false);

    if !is_repo {
        return ProjectGitStatus {
            is_repo: false,
            branch: None,
            dirty: false,
            last_commit: None,
        };
    }

    let branch = run_git(root, &["branch", "--show-current"])
        .ok()
        .filter(|value| !value.is_empty());
    let dirty = run_git(root, &["status", "--porcelain"])
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    let last_commit = run_git(root, &["log", "-1", "--pretty=%h %s"])
        .ok()
        .filter(|value| !value.is_empty());

    ProjectGitStatus {
        is_repo,
        branch,
        dirty,
        last_commit,
    }
}

fn default_gitignore() -> &'static str {
    "node_modules/\ndist/\ntarget/\n.DS_Store\n.env\nioi-data/\n.autopilot/\n"
}

fn inspect_project_root(root: &PathBuf) -> ProjectShellSnapshot {
    let tree = build_tree(root, root, 0);
    let mut artifacts = Vec::new();
    gather_artifacts(root, root, 0, &mut artifacts);

    ProjectShellSnapshot {
        root_path: root.display().to_string(),
        git: inspect_git(root),
        tree,
        artifacts,
    }
}

#[tauri::command]
pub fn save_project(path: String, project: ProjectFile) -> Result<(), String> {
    // 1. Enforce versioning
    let mut final_project = project;
    final_project.version = "1.0.0".to_string();

    // 2. Update metadata
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Some(ref mut meta) = final_project.metadata {
        meta.last_modified = now;
    } else {
        final_project.metadata = Some(ProjectMetadata {
            name: std::path::Path::new(&path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Untitled")
                .to_string(),
            created_at: now,
            last_modified: now,
            author: None,
        });
    }

    let json = serde_json::to_string_pretty(&final_project).map_err(|e| e.to_string())?;

    // 3. Ensure directory exists
    let path_buf = PathBuf::from(&path);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // 4. Atomic Write (Write to .tmp then rename)
    let temp_path = format!("{}.tmp", path);
    let mut file = fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;

    // Sync to disk to ensure data is flushed
    file.sync_all().map_err(|e| e.to_string())?;

    // Rename to overwrite target
    fs::rename(temp_path, path).map_err(|e| e.to_string())?;

    println!("[Project] Saved successfully to {}", path_buf.display());
    Ok(())
}

#[tauri::command]
pub fn load_project(path: String) -> Result<ProjectFile, String> {
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let project: ProjectFile = serde_json::from_str(&content).map_err(|e| e.to_string())?;

    // Basic validation
    if project.nodes.is_empty() && project.global_config.is_none() {
        println!("[Project] Warning: Loaded empty project from {}", path);
    } else {
        println!(
            "[Project] Loaded {} nodes from {}",
            project.nodes.len(),
            path
        );
    }

    Ok(project)
}

#[tauri::command]
pub fn project_shell_inspect(root: String) -> Result<ProjectShellSnapshot, String> {
    let root_path = resolve_root_path(&root, false)?;
    Ok(inspect_project_root(&root_path))
}

#[tauri::command]
pub fn project_initialize_repository(root: String) -> Result<ProjectShellSnapshot, String> {
    let root_path = resolve_root_path(&root, true)?;

    if !inspect_git(&root_path).is_repo {
        run_git(&root_path, &["init"])?;
    }

    let gitignore_path = root_path.join(".gitignore");
    if !gitignore_path.exists() {
        fs::write(&gitignore_path, default_gitignore()).map_err(|error| {
            format!(
                "Failed to write default .gitignore at '{}': {}",
                gitignore_path.display(),
                error
            )
        })?;
    }

    Ok(inspect_project_root(&root_path))
}

#[tauri::command]
pub fn project_shell_list_directory(
    root: String,
    directory: String,
) -> Result<Vec<ProjectExplorerNode>, String> {
    let root_path = resolve_root_path(&root, false)?;
    let directory_path = if directory.is_empty() || directory == "." {
        root_path.clone()
    } else {
        resolve_scoped_existing_path(&root_path, &directory)?
    };

    if !directory_path.is_dir() {
        return Err(format!(
            "'{}' is not a directory inside the project boundary.",
            directory_path.display()
        ));
    }

    Ok(build_directory_listing(&root_path, &directory_path))
}

#[tauri::command]
pub fn project_read_file(
    root: String,
    relative_path: String,
) -> Result<ProjectFileDocument, String> {
    let root_path = resolve_root_path(&root, false)?;
    read_project_file_document(&root_path, &relative_path)
}

#[tauri::command]
pub fn project_write_file(
    root: String,
    relative_path: String,
    content: String,
) -> Result<ProjectFileDocument, String> {
    let root_path = resolve_root_path(&root, false)?;
    let file_path = resolve_scoped_existing_path(&root_path, &relative_path)?;

    if file_path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an editable file.",
            file_path.display()
        ));
    }

    fs::write(&file_path, content.as_bytes()).map_err(|error| {
        format!("Failed to save '{}': {}", file_path.display(), error)
    })?;

    read_project_file_document(&root_path, &relative_path)
}
