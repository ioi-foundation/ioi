use super::{
    apply_patch, copy_path_deterministic, create_directory_deterministic,
    create_zip_from_directory_deterministic, delete_path_deterministic, edit_line_content,
    list_directory_entries, move_path_deterministic, resolve_tool_path, search_files,
    stat_path_deterministic, AgentTool, ToolExecutionResult, ToolExecutor,
};
use crate::agentic::desktop::execution::workload;
use ioi_types::app::{WorkloadActivityKind, WorkloadFsWriteReceipt, WorkloadReceipt};
use std::fs;
use std::path::Path;

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn patch_apply_failure_message(path: &Path, error: &str) -> String {
    let normalized = error.trim();
    let deterministic_search_miss = normalized.contains("search block not found in file")
        || normalized.contains("search block is ambiguous");
    let malformed_patch_payload = normalized.contains("search block must");

    if deterministic_search_miss {
        return format!(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for {}: {}. Use the exact latest `filesystem__read_file` block for `search`, or prefer `filesystem__edit_line` / `filesystem__write_file` for one-line fixes.",
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

async fn emit_fs_write_receipt(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    operation: &str,
    target_path: &str,
    destination_path: Option<&str>,
    bytes_written: Option<u64>,
    success: bool,
    error: Option<&str>,
) {
    let Some(tx) = exec.event_sender.as_ref() else {
        return;
    };

    let target_path =
        workload::scrub_workload_text_field_for_receipt(exec, target_path.trim()).await;
    let destination_path = match destination_path {
        Some(path) => {
            Some(workload::scrub_workload_text_field_for_receipt(exec, path.trim()).await)
        }
        None => None,
    };
    let receipt_preview = if let Some(destination) = destination_path.as_ref() {
        format!("{} {} -> {}", tool_name, target_path, destination)
    } else {
        format!("{} {}", tool_name, target_path)
    };
    let workload_id =
        workload::compute_workload_id(session_id, step_index, tool_name, &receipt_preview);

    workload::emit_workload_activity(
        tx,
        session_id,
        step_index,
        workload_id.clone(),
        WorkloadActivityKind::Lifecycle {
            phase: "started".to_string(),
            exit_code: None,
        },
    );
    workload::emit_workload_activity(
        tx,
        session_id,
        step_index,
        workload_id.clone(),
        WorkloadActivityKind::Lifecycle {
            phase: if success {
                "completed".to_string()
            } else {
                "failed".to_string()
            },
            exit_code: None,
        },
    );
    workload::emit_workload_receipt(
        tx,
        session_id,
        step_index,
        workload_id,
        WorkloadReceipt::FsWrite(WorkloadFsWriteReceipt {
            tool_name: tool_name.to_string(),
            operation: operation.to_string(),
            target_path,
            destination_path,
            bytes_written,
            success,
            error_class: workload::extract_error_class(error),
        }),
    );
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    let cwd = exec.working_directory.as_deref();

    match tool {
        AgentTool::FsRead { path } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to read {}: {}", path, e))
                }
            };

            match fs::read_to_string(&resolved_path) {
                Ok(content) => ToolExecutionResult::success(content),
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to read {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
        }
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result =
                        ToolExecutionResult::failure(format!("Failed to write {}: {}", path, e));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__write_file",
                        "write_file",
                        path.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            if let Some(line_number) = line_number {
                let existing = match fs::read_to_string(&resolved_path) {
                    Ok(content) => content,
                    Err(e) => {
                        let result = ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                        let target = path_to_string(&resolved_path);
                        emit_fs_write_receipt(
                            exec,
                            session_id,
                            step_index,
                            "filesystem__write_file",
                            "edit_line",
                            target.as_str(),
                            None,
                            None,
                            false,
                            result.error.as_deref(),
                        )
                        .await;
                        return result;
                    }
                };

                let updated = match edit_line_content(&existing, line_number, &content) {
                    Ok(updated) => updated,
                    Err(e) => {
                        let result = ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                        let target = path_to_string(&resolved_path);
                        emit_fs_write_receipt(
                            exec,
                            session_id,
                            step_index,
                            "filesystem__write_file",
                            "edit_line",
                            target.as_str(),
                            None,
                            None,
                            false,
                            result.error.as_deref(),
                        )
                        .await;
                        return result;
                    }
                };

                let bytes_written = updated.as_bytes().len() as u64;
                let result = match fs::write(&resolved_path, updated) {
                    Ok(_) => ToolExecutionResult::success(format!(
                        "Edited line {} in {}",
                        line_number,
                        resolved_path.display()
                    )),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Failed to edit line {} in {}: {}",
                        line_number,
                        resolved_path.display(),
                        e
                    )),
                };
                let target = path_to_string(&resolved_path);
                emit_fs_write_receipt(
                    exec,
                    session_id,
                    step_index,
                    "filesystem__write_file",
                    "edit_line",
                    target.as_str(),
                    None,
                    result.success.then_some(bytes_written),
                    result.success,
                    result.error.as_deref(),
                )
                .await;
                return result;
            }

            if let Some(parent) = resolved_path.parent() {
                if !parent.exists() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let bytes_written = content.as_bytes().len() as u64;
            let result = match fs::write(&resolved_path, content) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Wrote to {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write {}: {}",
                    resolved_path.display(),
                    e
                )),
            };
            let target = path_to_string(&resolved_path);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__write_file",
                "write_file",
                target.as_str(),
                None,
                result.success.then_some(bytes_written),
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result =
                        ToolExecutionResult::failure(format!("Patch failed for {}: {}", path, e));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__patch",
                        "patch",
                        path.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let existing = match fs::read_to_string(&resolved_path) {
                Ok(content) => content,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Failed to read {}: {}",
                        resolved_path.display(),
                        e
                    ));
                    let target = path_to_string(&resolved_path);
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__patch",
                        "patch",
                        target.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let updated = match apply_patch(&existing, &search, &replace) {
                Ok(updated) => updated,
                Err(e) => {
                    let result = ToolExecutionResult::failure(patch_apply_failure_message(
                        &resolved_path,
                        &e,
                    ));
                    let target = path_to_string(&resolved_path);
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__patch",
                        "patch",
                        target.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let bytes_written = updated.as_bytes().len() as u64;
            let result = match fs::write(&resolved_path, updated) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Patched {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write patch to {}: {}",
                    resolved_path.display(),
                    e
                )),
            };
            let target = path_to_string(&resolved_path);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__patch",
                "patch",
                target.as_str(),
                None,
                result.success.then_some(bytes_written),
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsList { path } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to list {}: {}", path, e))
                }
            };

            match list_directory_entries(&resolved_path) {
                Ok(entries) => {
                    let rendered = entries
                        .into_iter()
                        .map(|(name, kind)| format!("[{}] {}", kind, name))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ToolExecutionResult::success(rendered)
                }
                Err(e) => ToolExecutionResult::failure(e),
            }
        }
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => return ToolExecutionResult::failure(format!("Search failed: {}", e)),
            };

            let task = tokio::task::spawn_blocking(move || {
                search_files(&resolved_path, &regex, file_pattern.as_deref())
            })
            .await;

            match task {
                Ok(Ok(output)) => ToolExecutionResult::success(output),
                Ok(Err(e)) => ToolExecutionResult::failure(format!("Search failed: {}", e)),
                Err(e) => ToolExecutionResult::failure(format!("Search task panicked: {}", e)),
            }
        }
        AgentTool::FsStat { path } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => return ToolExecutionResult::failure(format!("Stat failed: {}", e)),
            };

            match stat_path_deterministic(&resolved_path) {
                Ok(payload) => ToolExecutionResult::success(payload),
                Err(e) => ToolExecutionResult::failure(format!("Stat failed: {}", e)),
            }
        }
        AgentTool::FsCreateDirectory { path, recursive } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Create directory failed for '{}': {}",
                        path, e
                    ));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__create_directory",
                        "create_directory",
                        path.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let result = match create_directory_deterministic(&resolved_path, recursive) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Created directory {}",
                    resolved_path.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Create directory failed: {}", e)),
            };
            let target = path_to_string(&resolved_path);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__create_directory",
                "create_directory",
                target.as_str(),
                None,
                None,
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsCreateZip {
            source_path,
            destination_zip_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Create zip failed for '{}': {}",
                        source_path, e
                    ));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__create_zip",
                        "create_zip",
                        source_path.as_str(),
                        Some(destination_zip_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };
            let destination = match resolve_tool_path(&destination_zip_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Create zip failed for '{}': {}",
                        destination_zip_path, e
                    ));
                    let source_text = path_to_string(&source);
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__create_zip",
                        "create_zip",
                        source_text.as_str(),
                        Some(destination_zip_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let result =
                match create_zip_from_directory_deterministic(&source, &destination, overwrite) {
                    Ok(entries) => ToolExecutionResult::success(format!(
                        "Created zip {} from {} entries={} members={:?}",
                        destination.display(),
                        source.display(),
                        entries.len(),
                        entries
                    )),
                    Err(e) => ToolExecutionResult::failure(format!("Create zip failed: {}", e)),
                };
            let source_text = path_to_string(&source);
            let destination_text = path_to_string(&destination);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__create_zip",
                "create_zip",
                source_text.as_str(),
                Some(destination_text.as_str()),
                None,
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        source_path, e
                    ));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__move_path",
                        "move",
                        source_path.as_str(),
                        Some(destination_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        destination_path, e
                    ));
                    let source_text = path_to_string(&source);
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__move_path",
                        "move",
                        source_text.as_str(),
                        Some(destination_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let result = match move_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Moved {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Move failed: {}", e)),
            };
            let source_text = path_to_string(&source);
            let destination_text = path_to_string(&destination);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__move_path",
                "move",
                source_text.as_str(),
                Some(destination_text.as_str()),
                None,
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        source_path, e
                    ));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__copy_path",
                        "copy",
                        source_path.as_str(),
                        Some(destination_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        destination_path, e
                    ));
                    let source_text = path_to_string(&source);
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__copy_path",
                        "copy",
                        source_text.as_str(),
                        Some(destination_path.as_str()),
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };

            let result = match copy_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Copied {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Copy failed: {}", e)),
            };
            let source_text = path_to_string(&source);
            let destination_text = path_to_string(&destination);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__copy_path",
                "copy",
                source_text.as_str(),
                Some(destination_text.as_str()),
                None,
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!("Delete failed: {}", e));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "filesystem__delete_path",
                        "delete",
                        path.as_str(),
                        None,
                        None,
                        false,
                        result.error.as_deref(),
                    )
                    .await;
                    return result;
                }
            };
            let existed_before = fs::symlink_metadata(&resolved_path).is_ok();

            let result = match delete_path_deterministic(&resolved_path, recursive, ignore_missing)
            {
                Ok(_) => {
                    if ignore_missing && !existed_before {
                        ToolExecutionResult::success(format!(
                            "Delete no-op (path already missing): {}",
                            resolved_path.display()
                        ))
                    } else {
                        ToolExecutionResult::success(format!("Deleted {}", resolved_path.display()))
                    }
                }
                Err(e) => ToolExecutionResult::failure(format!("Delete failed: {}", e)),
            };
            let target = path_to_string(&resolved_path);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "filesystem__delete_path",
                "delete",
                target.as_str(),
                None,
                None,
                result.success,
                result.error.as_deref(),
            )
            .await;
            result
        }
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}

#[cfg(test)]
mod tests {
    use super::patch_apply_failure_message;
    use std::path::Path;

    #[test]
    fn patch_search_miss_maps_to_no_effect_after_action() {
        let message = patch_apply_failure_message(
            Path::new("/tmp/example.py"),
            "search block not found in file",
        );
        assert!(message.starts_with("ERROR_CLASS=NoEffectAfterAction"));
        assert!(message.contains("filesystem__edit_line"));
        assert!(message.contains("filesystem__write_file"));
    }

    #[test]
    fn malformed_patch_payload_maps_to_unexpected_state() {
        let message = patch_apply_failure_message(
            Path::new("/tmp/example.py"),
            "search block must be non-empty",
        );
        assert!(message.starts_with("ERROR_CLASS=UnexpectedState"));
    }
}
