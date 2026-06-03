use super::*;

pub(super) fn patch_apply_failure_message(path: &Path, error: &str) -> String {
    let normalized = error.trim();
    let deterministic_search_miss = normalized.contains("search block not found in file")
        || normalized.contains("search block is ambiguous");
    let no_effect_patch = normalized.contains("replacement must differ from search block");
    let malformed_patch_payload = normalized.contains("search block must");

    if no_effect_patch {
        return format!(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for {}: {}. Submit a changed `replace` block that implements the user's requested behavior; do not retry identical search and replace arguments.",
            path.display(),
            normalized
        );
    }

    if deterministic_search_miss {
        return format!(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for {}: {}. Use the exact latest `file__read` block for `search`, or preserve a uniquely matching whitespace-collapsed block and submit a changed `replace` block.",
            path.display(),
            normalized
        );
    }

    if malformed_patch_payload {
        return format!(
            "ERROR_CLASS=UnexpectedState Patch failed for {}: {}",
            path.display(),
            normalized
        );
    }

    format!("Patch failed for {}: {}", path.display(), normalized)
}

pub(super) fn ensure_safe_regular_file_read(path: &Path, operation: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "Failed to inspect {} before {}: {}",
            path.display(),
            operation,
            error
        )
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to {} {}: symlink paths must be resolved by an explicit, governed workflow.",
            operation,
            path.display()
        ));
    }
    if !file_type.is_file() {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to {} {}: only regular files are allowed; directories, devices, sockets, FIFOs, and other special files are blocked.",
            operation,
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn ensure_read_within_workspace(
    path: &Path,
    cwd: Option<&str>,
    operation: &str,
) -> Result<(), String> {
    ensure_within_workspace_path(path, cwd, operation)
}

pub(super) fn ensure_write_within_workspace(
    path: &Path,
    cwd: Option<&str>,
    operation: &str,
) -> Result<(), String> {
    ensure_within_workspace_path(path, cwd, operation)
}

pub(super) fn ensure_safe_regular_file_write_target(
    path: &Path,
    operation: &str,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "ERROR_CLASS=PolicyBlocked Refusing to {} {}: symlink write targets are blocked.",
                    operation,
                    path.display()
                ));
            }
            if !file_type.is_file() {
                return Err(format!(
                    "ERROR_CLASS=PolicyBlocked Refusing to {} {}: existing target is not a regular file.",
                    operation,
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Failed to inspect {} before {}: {}",
            path.display(),
            operation,
            error
        )),
    }
}
