use super::{
    apply_patch, copy_path_deterministic, create_directory_deterministic,
    delete_path_deterministic, edit_line_content, list_directory_entries, move_path_deterministic,
    resolve_tool_path, search_files, AgentTool, ToolExecutionResult, ToolExecutor,
};
use std::fs;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
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
                    return ToolExecutionResult::failure(format!("Failed to write {}: {}", path, e))
                }
            };

            if let Some(line_number) = line_number {
                let existing = match fs::read_to_string(&resolved_path) {
                    Ok(content) => content,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                    }
                };

                let updated = match edit_line_content(&existing, line_number, &content) {
                    Ok(updated) => updated,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                    }
                };

                return match fs::write(&resolved_path, updated) {
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
            }

            if let Some(parent) = resolved_path.parent() {
                if !parent.exists() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            match fs::write(&resolved_path, content) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Wrote to {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
        }
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Patch failed for {}: {}",
                        path, e
                    ))
                }
            };

            let existing = match fs::read_to_string(&resolved_path) {
                Ok(content) => content,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Failed to read {}: {}",
                        resolved_path.display(),
                        e
                    ));
                }
            };

            let updated = match apply_patch(&existing, &search, &replace) {
                Ok(updated) => updated,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Patch failed for {}: {}",
                        resolved_path.display(),
                        e
                    ));
                }
            };

            match fs::write(&resolved_path, updated) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Patched {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write patch to {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
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
        AgentTool::FsCreateDirectory { path, recursive } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Create directory failed for '{}': {}",
                        path, e
                    ))
                }
            };

            match create_directory_deterministic(&resolved_path, recursive) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Created directory {}",
                    resolved_path.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Create directory failed: {}", e)),
            }
        }
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        source_path, e
                    ))
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        destination_path, e
                    ))
                }
            };

            match move_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Moved {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Move failed: {}", e)),
            }
        }
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        source_path, e
                    ))
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        destination_path, e
                    ))
                }
            };

            match copy_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Copied {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Copy failed: {}", e)),
            }
        }
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => return ToolExecutionResult::failure(format!("Delete failed: {}", e)),
            };
            let existed_before = fs::symlink_metadata(&resolved_path).is_ok();

            match delete_path_deterministic(&resolved_path, recursive, ignore_missing) {
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
            }
        }
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}
