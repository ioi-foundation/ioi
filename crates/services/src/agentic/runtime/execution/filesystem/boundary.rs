use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(super) fn canonicalize_existing_or_intended(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }

    let mut suffix: Vec<OsString> = Vec::new();
    let mut ancestor = path.to_path_buf();
    while !ancestor.exists() {
        let Some(name) = ancestor.file_name() else {
            return path.canonicalize();
        };
        suffix.push(name.to_os_string());
        let Some(parent) = ancestor.parent() else {
            return path.canonicalize();
        };
        ancestor = parent.to_path_buf();
    }

    let mut canonical = ancestor.canonicalize()?;
    for component in suffix.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

pub(super) fn ensure_within_workspace_path(
    path: &Path,
    cwd: Option<&str>,
    operation: &str,
) -> Result<(), String> {
    let Some(cwd) = cwd else {
        return Ok(());
    };
    let workspace_root = Path::new(cwd).canonicalize().map_err(|error| {
        format!(
            "Failed to inspect workspace boundary before {}: {}",
            operation, error
        )
    })?;
    let canonical_path = canonicalize_existing_or_intended(path).map_err(|error| {
        format!(
            "Failed to inspect {} before {}: {}",
            path.display(),
            operation,
            error
        )
    })?;
    if !canonical_path.starts_with(&workspace_root) {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to {} {}: path is outside the workspace boundary.",
            operation,
            path.display()
        ));
    }
    Ok(())
}
