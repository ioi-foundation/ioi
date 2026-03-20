// apps/autopilot/src-tauri/src/project.rs

use crate::orchestrator::{GraphEdge, GraphNode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const EXPLORER_MAX_DEPTH: usize = 2;
const EXPLORER_MAX_CHILDREN: usize = 10;
const ARTIFACT_SCAN_MAX_DEPTH: usize = 3;
const ARTIFACT_SCAN_LIMIT: usize = 12;
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build"];

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

fn build_tree(root: &PathBuf, current: &PathBuf, depth: usize) -> Vec<ProjectExplorerNode> {
    let mut entries = match fs::read_dir(current) {
        Ok(read_dir) => read_dir
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .collect::<Vec<_>>(),
        Err(_) => return Vec::new(),
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
        .take(EXPLORER_MAX_CHILDREN)
        .map(|path| {
            let is_dir = path.is_dir();
            let children = if is_dir && depth < EXPLORER_MAX_DEPTH {
                build_tree(root, &path, depth + 1)
            } else {
                Vec::new()
            };

            ProjectExplorerNode {
                name: path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                path: relative_path(root, &path),
                kind: if is_dir { "directory" } else { "file" }.to_string(),
                children,
            }
        })
        .collect()
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
