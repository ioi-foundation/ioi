use super::{
    apply_patch, copy_path_deterministic, create_directory_deterministic,
    create_zip_from_directory_deterministic, delete_path_deterministic, edit_line_content,
    list_directory_entries, move_path_deterministic, resolve_tool_path, search_files,
    stat_path_deterministic, AgentTool, ToolExecutionResult, ToolExecutor,
};
use crate::agentic::runtime::execution::workload;
use crate::agentic::web::sample_local_video_preview;
use image::ImageFormat;
use ioi_api::chat::extract_searchable_pdf_text;
use ioi_types::app::{WorkloadActivityKind, WorkloadFsWriteReceipt, WorkloadReceipt};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

const FILE_VIEW_MAX_LINES: usize = 800;
const FILE_VIEW_DEFAULT_LINES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalViewKind {
    Text,
    Image,
    Pdf,
    Video,
    Binary,
}

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
            "ERROR_CLASS=NoEffectAfterAction Patch failed for {}: {}. Use the exact latest `file__read` block for `search`, or prefer `file__replace_line` / `file__write` for one-line fixes.",
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

fn classify_local_view(path: &Path, bytes: &[u8]) -> LocalViewKind {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    if bytes.starts_with(b"%PDF-") || extension.as_deref() == Some("pdf") {
        return LocalViewKind::Pdf;
    }

    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || bytes.starts_with(b"GIF8")
        || bytes.starts_with(b"RIFF")
            && bytes
                .get(8..12)
                .map(|value| value == b"WEBP")
                .unwrap_or(false)
        || matches!(
            extension.as_deref(),
            Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp")
        )
    {
        return LocalViewKind::Image;
    }

    if matches!(
        extension.as_deref(),
        Some("mp4" | "webm" | "mov" | "mkv" | "avi" | "m4v")
    ) {
        return LocalViewKind::Video;
    }

    if std::str::from_utf8(bytes).is_ok() {
        return LocalViewKind::Text;
    }

    LocalViewKind::Binary
}

fn render_text_window(
    path: &Path,
    content: &str,
    start_line: Option<u32>,
    line_count: Option<u32>,
    kind_label: &str,
) -> String {
    let requested_start = start_line.unwrap_or(1).max(1) as usize;
    let requested_count = line_count
        .map(|value| value.max(1) as usize)
        .unwrap_or(FILE_VIEW_DEFAULT_LINES)
        .min(FILE_VIEW_MAX_LINES);
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    let start_index = requested_start.saturating_sub(1).min(total_lines);
    let end_index = start_index.saturating_add(requested_count).min(total_lines);
    let mut rendered = lines[start_index..end_index]
        .iter()
        .enumerate()
        .map(|(offset, line)| format!("{:>4} | {}", start_index + offset + 1, line))
        .collect::<Vec<_>>()
        .join("\n");
    if !rendered.is_empty() {
        rendered.push('\n');
    }
    let truncated = end_index < total_lines;
    format!(
        "FILE_VIEW kind={} path={} lines={}..{} of {}\n{}{}",
        kind_label,
        path.display(),
        if total_lines == 0 { 0 } else { start_index + 1 },
        end_index,
        total_lines,
        rendered,
        if truncated {
            format!(
                "[truncated] Use file__view with start_line={} to continue.",
                end_index + 1
            )
        } else {
            String::new()
        }
    )
}

fn normalize_image_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
    {
        return Ok(bytes.to_vec());
    }

    let image = image::load_from_memory(bytes)
        .map_err(|error| format!("Failed to decode image payload: {}", error))?;
    let mut cursor = Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, ImageFormat::Png)
        .map_err(|error| format!("Failed to encode image preview: {}", error))?;
    Ok(cursor.into_inner())
}

async fn capture_pdf_preview(exec: &ToolExecutor, path: &Path) -> Result<Vec<u8>, String> {
    let file_url = Url::from_file_path(path)
        .map_err(|_| format!("Failed to build file:// URL for {}", path.display()))?;
    exec.browser
        .navigate(file_url.as_str())
        .await
        .map_err(|error| format!("Failed to open PDF preview in browser: {}", error))?;
    sleep(Duration::from_millis(450)).await;
    exec.browser
        .capture_tab_screenshot(false)
        .await
        .map_err(|error| format!("Failed to capture PDF preview screenshot: {}", error))
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
        AgentTool::FsView {
            path,
            start_line,
            line_count,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to view {}: {}", path, e))
                }
            };

            let bytes = match fs::read(&resolved_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Failed to view {}: {}",
                        resolved_path.display(),
                        e
                    ))
                }
            };

            match classify_local_view(&resolved_path, &bytes) {
                LocalViewKind::Text => match String::from_utf8(bytes) {
                    Ok(content) => ToolExecutionResult::success(render_text_window(
                        &resolved_path,
                        &content,
                        start_line,
                        line_count,
                        "text",
                    )),
                    Err(error) => ToolExecutionResult::failure(format!(
                        "Failed to decode text from {}: {}",
                        resolved_path.display(),
                        error
                    )),
                },
                LocalViewKind::Image => match normalize_image_bytes(&bytes) {
                    Ok(image_bytes) => ToolExecutionResult::success_with_visual_observation(
                        format!(
                            "FILE_VIEW kind=image path={} bytes={}",
                            resolved_path.display(),
                            image_bytes.len()
                        ),
                        image_bytes,
                    ),
                    Err(error) => ToolExecutionResult::failure(format!(
                        "Failed to prepare image preview for {}: {}",
                        resolved_path.display(),
                        error
                    )),
                },
                LocalViewKind::Pdf => {
                    let searchable_text = extract_searchable_pdf_text(&bytes);
                    let history_entry = if searchable_text.trim().is_empty() {
                        format!(
                            "FILE_VIEW kind=pdf path={} text_preview=[empty]",
                            resolved_path.display()
                        )
                    } else {
                        render_text_window(
                            &resolved_path,
                            &searchable_text,
                            start_line,
                            line_count,
                            "pdf",
                        )
                    };

                    match capture_pdf_preview(exec, &resolved_path).await {
                        Ok(preview_png) => ToolExecutionResult::success_with_visual_observation(
                            history_entry,
                            preview_png,
                        ),
                        Err(_) => ToolExecutionResult::success(history_entry),
                    }
                }
                LocalViewKind::Video => match sample_local_video_preview(&resolved_path, 6).await {
                    Ok(preview) => ToolExecutionResult::success_with_visual_observation(
                        format!(
                            "FILE_VIEW kind=video path={} duration_seconds={} sampled_frames={}\n{}",
                            resolved_path.display(),
                            preview
                                .duration_seconds
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            preview.frame_count,
                            preview.frame_summaries.join("\n")
                        ),
                        preview.preview_png,
                    ),
                    Err(error) => ToolExecutionResult::failure(format!(
                        "Failed to prepare video preview for {}: {}",
                        resolved_path.display(),
                        error
                    )),
                },
                LocalViewKind::Binary => {
                    let metadata = fs::metadata(&resolved_path).ok();
                    ToolExecutionResult::success(format!(
                        "FILE_VIEW kind=binary path={} bytes={}",
                        resolved_path.display(),
                        metadata.map(|value| value.len()).unwrap_or(bytes.len() as u64)
                    ))
                }
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
                        "file__write",
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
                            "file__write",
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
                            "file__write",
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
                    "file__write",
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
                "file__write",
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
                        "file__edit",
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
                        "file__edit",
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
                        "file__edit",
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
                "file__edit",
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
        AgentTool::FsMultiPatch { path, edits } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "Multi-edit failed for {}: {}",
                        path, e
                    ));
                    emit_fs_write_receipt(
                        exec,
                        session_id,
                        step_index,
                        "file__multi_edit",
                        "multi_patch",
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

            if edits.is_empty() {
                let result = ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=UnexpectedState Multi-edit failed for {}: edits must not be empty.",
                    resolved_path.display()
                ));
                let target = path_to_string(&resolved_path);
                emit_fs_write_receipt(
                    exec,
                    session_id,
                    step_index,
                    "file__multi_edit",
                    "multi_patch",
                    target.as_str(),
                    None,
                    None,
                    false,
                    result.error.as_deref(),
                )
                .await;
                return result;
            }

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
                        "file__multi_edit",
                        "multi_patch",
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

            let mut updated = existing.clone();
            for (index, edit) in edits.iter().enumerate() {
                updated = match apply_patch(&updated, &edit.search, &edit.replace) {
                    Ok(next) => next,
                    Err(error) => {
                        let result = ToolExecutionResult::failure(format!(
                            "{} [edit {} of {}]",
                            patch_apply_failure_message(&resolved_path, &error),
                            index + 1,
                            edits.len()
                        ));
                        let target = path_to_string(&resolved_path);
                        emit_fs_write_receipt(
                            exec,
                            session_id,
                            step_index,
                            "file__multi_edit",
                            "multi_patch",
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
            }

            if updated == existing {
                let result = ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=NoEffectAfterAction Multi-edit for {} made no effective change.",
                    resolved_path.display()
                ));
                let target = path_to_string(&resolved_path);
                emit_fs_write_receipt(
                    exec,
                    session_id,
                    step_index,
                    "file__multi_edit",
                    "multi_patch",
                    target.as_str(),
                    None,
                    None,
                    false,
                    result.error.as_deref(),
                )
                .await;
                return result;
            }

            let bytes_written = updated.as_bytes().len() as u64;
            let result = match fs::write(&resolved_path, updated) {
                Ok(_) => ToolExecutionResult::success(
                    serde_json::json!({
                        "path": resolved_path.display().to_string(),
                        "applied_edit_count": edits.len(),
                    })
                    .to_string(),
                ),
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write multi-edit to {}: {}",
                    resolved_path.display(),
                    e
                )),
            };
            let target = path_to_string(&resolved_path);
            emit_fs_write_receipt(
                exec,
                session_id,
                step_index,
                "file__multi_edit",
                "multi_patch",
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
                        "file__create_dir",
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
                "file__create_dir",
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
                        "file__zip",
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
                        "file__zip",
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
                "file__zip",
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
                        "file__move",
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
                        "file__move",
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
                "file__move",
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
                        "file__copy",
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
                        "file__copy",
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
                "file__copy",
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
                        "file__delete",
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
                "file__delete",
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
mod tests;
