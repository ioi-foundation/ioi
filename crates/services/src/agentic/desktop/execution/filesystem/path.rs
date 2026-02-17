use std::env;
use std::path::{Path, PathBuf};

fn resolve_working_directory(cwd: Option<&str>) -> Result<PathBuf, String> {
    let normalized = cwd.unwrap_or(".").trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        expand_tilde_path(normalized)?
    };

    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        env::current_dir()
            .map_err(|e| format!("Failed to resolve current directory: {}", e))?
            .join(candidate)
    };

    if !absolute.exists() {
        return Err(format!(
            "Working directory '{}' does not exist.",
            absolute.display()
        ));
    }

    if !absolute.is_dir() {
        return Err(format!(
            "Working directory '{}' is not a directory.",
            absolute.display()
        ));
    }

    Ok(absolute)
}

pub(super) fn resolve_home_directory() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }

    if let Some(user_profile) = env::var_os("USERPROFILE") {
        if !user_profile.is_empty() {
            return Ok(PathBuf::from(user_profile));
        }
    }

    if let (Some(home_drive), Some(home_path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        if !home_drive.is_empty() && !home_path.is_empty() {
            let mut combined = PathBuf::from(home_drive);
            combined.push(home_path);
            return Ok(combined);
        }
    }

    Err("Home directory is not configured (HOME/USERPROFILE).".to_string())
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        return resolve_home_directory();
    }

    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Ok(resolve_home_directory()?.join(remainder));
    }

    Ok(PathBuf::from(path))
}

pub(super) fn resolve_tool_path(path: &str, cwd: Option<&str>) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Path cannot be empty.".to_string());
    }

    let requested = expand_tilde_path(trimmed)?;
    if requested.is_absolute() {
        Ok(requested)
    } else {
        Ok(resolve_working_directory(cwd)?.join(requested))
    }
}

#[allow(dead_code)]
pub(super) fn _is_safe_child_path(parent: &Path, child: &Path) -> bool {
    child.starts_with(parent)
}
