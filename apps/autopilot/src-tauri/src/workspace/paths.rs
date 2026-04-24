use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(super) fn resolve_root_path(root: &str) -> Result<PathBuf, String> {
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

pub(super) fn safe_relative_input(relative_path: &str) -> Result<PathBuf, String> {
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

pub(super) fn relative_path(root: &PathBuf, path: &Path) -> String {
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

pub(super) fn resolve_scoped_existing_path(
    root: &PathBuf,
    relative_path: &str,
) -> Result<PathBuf, String> {
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

pub(super) fn resolve_scoped_candidate_path(
    root: &PathBuf,
    relative_path: &str,
) -> Result<PathBuf, String> {
    let safe_relative = safe_relative_input(relative_path)?;
    let candidate = root.join(&safe_relative);
    if !candidate.starts_with(root) {
        return Err("Resolved path falls outside the workspace boundary.".to_string());
    }
    Ok(candidate)
}

pub(super) fn file_name_for_path(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub(super) fn modified_time_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|timestamp| timestamp.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn language_hint_for_path(path: &Path) -> Option<String> {
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

pub(super) fn display_name_for_root(root: &PathBuf) -> String {
    root.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("workspace")
        .to_string()
}
