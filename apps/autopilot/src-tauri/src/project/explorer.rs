use super::paths::resolve_scoped_existing_path;
use super::types::{
    ProjectArtifactCandidate, ProjectExplorerNode, ProjectFileDocument, ProjectGitStatus,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

const EXPLORER_MAX_DEPTH: usize = 2;
const EXPLORER_MAX_CHILDREN: usize = 10;
const ARTIFACT_SCAN_MAX_DEPTH: usize = 3;
const ARTIFACT_SCAN_LIMIT: usize = 12;
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build"];
const EDITOR_MAX_BYTES: usize = 512 * 1024;

pub(super) fn resolve_root_path(root: &str, create_if_missing: bool) -> Result<PathBuf, String> {
    let requested = PathBuf::from(root);
    let resolved = if requested.is_absolute() {
        requested
    } else {
        let launch_root = std::env::var("INIT_CWD")
            .ok()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.exists());
        let base = match launch_root {
            Some(path) => path,
            None => std::env::current_dir()
                .map_err(|error| format!("Failed to resolve current directory: {}", error))?,
        };
        base.join(requested)
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

pub(super) fn relative_path(root: &PathBuf, path: &PathBuf) -> String {
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

pub(super) fn sort_paths(a: &PathBuf, b: &PathBuf) -> std::cmp::Ordering {
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
            child
                .file_name()
                .and_then(|value| value.to_str())
                .map(|name| !should_skip_dir(name))
                .unwrap_or(true)
        })
}

pub(super) fn build_directory_listing(
    root: &PathBuf,
    current: &PathBuf,
) -> Vec<ProjectExplorerNode> {
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

pub(super) fn build_tree(
    root: &PathBuf,
    current: &PathBuf,
    depth: usize,
) -> Vec<ProjectExplorerNode> {
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

pub(super) fn read_project_file_document(
    root: &PathBuf,
    relative_file_path: &str,
) -> Result<ProjectFileDocument, String> {
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
                "'{}' is not valid UTF-8 and cannot be edited in the embedded editor.",
                file_path.display()
            )
        })?
    };

    Ok(ProjectFileDocument {
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

pub(super) fn gather_artifacts(
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

pub(super) fn run_git(root: &PathBuf, args: &[&str]) -> Result<String, String> {
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

pub(super) fn inspect_git(root: &PathBuf) -> ProjectGitStatus {
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
