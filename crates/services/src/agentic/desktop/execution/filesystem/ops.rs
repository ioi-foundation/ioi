use std::fs;
use std::path::Path;
use walkdir::WalkDir;

fn is_cross_device_rename_error(err: &std::io::Error) -> bool {
    // Unix EXDEV=18, Windows ERROR_NOT_SAME_DEVICE=17.
    matches!(err.raw_os_error(), Some(18) | Some(17))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

fn path_entry_kind(path: &Path) -> Result<Option<FsEntryKind>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Ok(Some(FsEntryKind::Symlink));
            }
            if metadata.is_file() {
                return Ok(Some(FsEntryKind::File));
            }
            if metadata.is_dir() {
                return Ok(Some(FsEntryKind::Directory));
            }
            Ok(Some(FsEntryKind::Other))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Failed to inspect path '{}': {}",
            path.display(),
            e
        )),
    }
}

pub(super) fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!("Source '{}' is not a directory.", source.display()));
    }

    fs::create_dir_all(destination).map_err(|e| {
        format!(
            "Failed to create destination directory '{}': {}",
            destination.display(),
            e
        )
    })?;

    let walker = WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    for entry in walker {
        let entry = entry.map_err(|e| format!("Directory traversal failed: {}", e))?;
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(source)
            .map_err(|e| format!("Failed to normalize copied path: {}", e))?;
        if relative.as_os_str().is_empty() {
            continue;
        }

        let dest_path = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&dest_path).map_err(|e| {
                format!(
                    "Failed to create destination directory '{}': {}",
                    dest_path.display(),
                    e
                )
            })?;
            continue;
        }

        if entry.file_type().is_file() {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed to create destination parent '{}': {}",
                        parent.display(),
                        e
                    )
                })?;
            }
            fs::copy(entry_path, &dest_path).map_err(|e| {
                format!(
                    "Failed to copy '{}' to '{}': {}",
                    entry_path.display(),
                    dest_path.display(),
                    e
                )
            })?;
            continue;
        }

        return Err(format!(
            "Unsupported filesystem entry '{}' (symlinks and special files are not supported).",
            entry_path.display()
        ));
    }

    Ok(())
}

pub(super) fn remove_existing_destination(
    destination: &Path,
    overwrite: bool,
) -> Result<(), String> {
    let Some(destination_kind) = path_entry_kind(destination)? else {
        return Ok(());
    };

    if !overwrite {
        return Err(format!(
            "Destination '{}' already exists. Set overwrite=true to replace it.",
            destination.display()
        ));
    }

    let remove_result = match destination_kind {
        FsEntryKind::Directory => fs::remove_dir_all(destination),
        FsEntryKind::File | FsEntryKind::Symlink => fs::remove_file(destination),
        FsEntryKind::Other => {
            return Err(format!(
                "Cannot overwrite special filesystem entry '{}'.",
                destination.display()
            ))
        }
    };
    remove_result.map_err(|e| {
        format!(
            "Failed to remove existing destination '{}': {}",
            destination.display(),
            e
        )
    })?;

    Ok(())
}

pub(super) fn move_path_deterministic(
    source: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), String> {
    let source_kind = match path_entry_kind(source)? {
        Some(kind) => kind,
        None => {
            return Err(format!(
                "Source path '{}' does not exist.",
                source.display()
            ))
        }
    };

    if source == destination {
        return Ok(());
    }

    if source_kind == FsEntryKind::Directory && destination.starts_with(source) {
        return Err(format!(
            "Destination '{}' cannot be inside source directory '{}'.",
            destination.display(),
            source.display()
        ));
    }

    remove_existing_destination(destination, overwrite)?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create destination parent '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    match fs::rename(source, destination) {
        Ok(_) => Ok(()),
        Err(rename_err) => {
            if !is_cross_device_rename_error(&rename_err) {
                return Err(format!(
                    "Failed to move '{}' to '{}': {}",
                    source.display(),
                    destination.display(),
                    rename_err
                ));
            }

            match source_kind {
                FsEntryKind::File => {
                    fs::copy(source, destination).map_err(|e| {
                        format!(
                            "Cross-device fallback failed while copying '{}' to '{}': {}",
                            source.display(),
                            destination.display(),
                            e
                        )
                    })?;
                    fs::remove_file(source).map_err(|e| {
                        format!(
                            "Cross-device fallback failed while removing source '{}': {}",
                            source.display(),
                            e
                        )
                    })?;
                    Ok(())
                }
                FsEntryKind::Directory => {
                    copy_dir_recursive(source, destination)?;
                    fs::remove_dir_all(source).map_err(|e| {
                        format!(
                            "Cross-device fallback failed while removing source directory '{}': {}",
                            source.display(),
                            e
                        )
                    })?;
                    Ok(())
                }
                FsEntryKind::Symlink => Err(format!(
                    "Cross-device fallback does not support symlink source '{}'.",
                    source.display()
                )),
                FsEntryKind::Other => Err(format!(
                    "Cross-device fallback does not support special filesystem entry '{}'.",
                    source.display()
                )),
            }
        }
    }
}

pub(super) fn copy_path_deterministic(
    source: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), String> {
    let source_kind = match path_entry_kind(source)? {
        Some(kind) => kind,
        None => {
            return Err(format!(
                "Source path '{}' does not exist.",
                source.display()
            ))
        }
    };

    if source == destination {
        return Err("Source and destination are the same path.".to_string());
    }

    if source_kind == FsEntryKind::Directory && destination.starts_with(source) {
        return Err(format!(
            "Destination '{}' cannot be inside source directory '{}'.",
            destination.display(),
            source.display()
        ));
    }

    remove_existing_destination(destination, overwrite)?;

    match source_kind {
        FsEntryKind::File => {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed to create destination parent '{}': {}",
                        parent.display(),
                        e
                    )
                })?;
            }

            fs::copy(source, destination).map_err(|e| {
                format!(
                    "Failed to copy '{}' to '{}': {}",
                    source.display(),
                    destination.display(),
                    e
                )
            })?;
            Ok(())
        }
        FsEntryKind::Directory => copy_dir_recursive(source, destination),
        FsEntryKind::Symlink => Err(format!(
            "Copy does not support symlink source '{}'.",
            source.display()
        )),
        FsEntryKind::Other => Err(format!(
            "Copy does not support special filesystem entry '{}'.",
            source.display()
        )),
    }
}

pub(super) fn delete_path_deterministic(
    path: &Path,
    recursive: bool,
    ignore_missing: bool,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound && ignore_missing {
                return Ok(());
            }
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(format!("Path '{}' does not exist.", path.display()));
            }
            return Err(format!(
                "Failed to inspect path '{}': {}",
                path.display(),
                e
            ));
        }
    };

    if metadata.file_type().is_symlink() || metadata.is_file() {
        return fs::remove_file(path)
            .map_err(|e| format!("Failed to delete file/symlink '{}': {}", path.display(), e));
    }

    if metadata.is_dir() {
        if !recursive {
            return Err(format!(
                "Path '{}' is a directory. Set recursive=true to delete directories.",
                path.display()
            ));
        }
        return fs::remove_dir_all(path)
            .map_err(|e| format!("Failed to delete directory '{}': {}", path.display(), e));
    }

    Err(format!(
        "Delete does not support special filesystem entry '{}'.",
        path.display()
    ))
}

pub(super) fn create_directory_deterministic(path: &Path, recursive: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                return Ok(());
            }
            return Err(format!(
                "Path '{}' already exists and is not a directory.",
                path.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "Failed to inspect path '{}': {}",
                path.display(),
                e
            ));
        }
    }

    let create_result = if recursive {
        fs::create_dir_all(path)
    } else {
        fs::create_dir(path)
    };

    create_result.map_err(|e| format!("Failed to create directory '{}': {}", path.display(), e))?;
    Ok(())
}
