use std::env;
use std::path::PathBuf;

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

pub(super) fn resolve_working_directory(cwd: &str) -> Result<PathBuf, String> {
    let normalized = cwd.trim();
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

pub(super) fn resolve_target_directory(
    current_cwd: &str,
    requested_path: &str,
) -> Result<PathBuf, String> {
    let trimmed = requested_path.trim();
    if trimmed.is_empty() {
        return Err("Target path cannot be empty.".to_string());
    }

    let requested = expand_tilde_path(trimmed)?;
    let candidate = if requested.is_absolute() {
        requested
    } else {
        resolve_working_directory(current_cwd)?.join(requested)
    };

    let canonical = std::fs::canonicalize(&candidate).map_err(|e| {
        format!(
            "Failed to resolve directory '{}': {}",
            candidate.display(),
            e
        )
    })?;

    if !canonical.is_dir() {
        return Err(format!("'{}' is not a directory.", canonical.display()));
    }

    Ok(canonical)
}
