use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::{
    bind_task_session, is_hard_terminal_task, snippet, thread_id_from_session,
};
use crate::kernel::state::update_task_state;
use crate::models::{AppState, ChatMessage, EventStatus, EventType};
use ioi_ipc::public::workload_receipt::Receipt as WorkloadReceiptKind;
use ioi_ipc::public::WorkloadReceipt;
use serde_json::json;
use std::sync::Mutex;
use tauri::Manager;

#[derive(Debug)]
struct WorkloadReceiptSummary {
    kind: &'static str,
    tool_name: String,
    success: bool,
    summary: String,
    digest: serde_json::Value,
    details: serde_json::Value,
}

fn summarize_workload_receipt(receipt: &WorkloadReceipt) -> Option<WorkloadReceiptSummary> {
    match receipt.receipt.as_ref()? {
        WorkloadReceiptKind::Exec(exec) => {
            let exit_code = if exec.has_exit_code {
                Some(exec.exit_code)
            } else {
                None
            };
            let error_class = if exec.has_error_class {
                Some(exec.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "exec",
                tool_name: exec.tool_name.clone(),
                success: exec.success,
                summary: format!(
                    "WorkloadReceipt(Exec) tool={} success={} exit_code={} command_preview={}",
                    exec.tool_name,
                    exec.success,
                    exit_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    snippet(&exec.command_preview)
                ),
                digest: json!({
                    "kind": "exec",
                    "tool_name": exec.tool_name,
                    "success": exec.success,
                    "exit_code": exit_code,
                    "error_class": error_class,
                    "command_preview": snippet(&exec.command_preview),
                }),
                details: json!({
                    "command": exec.command,
                    "args": exec.args,
                    "cwd": exec.cwd,
                    "detach": exec.detach,
                    "timeout_ms": exec.timeout_ms,
                }),
            })
        }
        WorkloadReceiptKind::FsWrite(fs) => {
            let destination_path = if fs.has_destination_path {
                Some(fs.destination_path.clone())
            } else {
                None
            };
            let bytes_written = if fs.has_bytes_written {
                Some(fs.bytes_written)
            } else {
                None
            };
            let error_class = if fs.has_error_class {
                Some(fs.error_class.clone())
            } else {
                None
            };
            let destination_note = destination_path
                .as_deref()
                .map(|path| format!(" -> {}", snippet(path)))
                .unwrap_or_default();
            Some(WorkloadReceiptSummary {
                kind: "fs_write",
                tool_name: fs.tool_name.clone(),
                success: fs.success,
                summary: format!(
                    "WorkloadReceipt(FsWrite) tool={} op={} target={}{} success={} bytes_written={} error_class={}",
                    fs.tool_name,
                    fs.operation,
                    snippet(&fs.target_path),
                    destination_note,
                    fs.success,
                    bytes_written
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    error_class.as_deref().unwrap_or("none")
                ),
                digest: json!({
                    "kind": "fs_write",
                    "tool_name": fs.tool_name,
                    "operation": fs.operation,
                    "success": fs.success,
                    "bytes_written": bytes_written,
                    "error_class": error_class,
                }),
                details: json!({
                    "target_path": fs.target_path,
                    "destination_path": destination_path,
                }),
            })
        }
        WorkloadReceiptKind::NetFetch(net) => {
            let status_code = if net.has_status_code {
                Some(net.status_code)
            } else {
                None
            };
            let final_url = if net.has_final_url {
                Some(net.final_url.clone())
            } else {
                None
            };
            let error_class = if net.has_error_class {
                Some(net.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "net_fetch",
                tool_name: net.tool_name.clone(),
                success: net.success,
                summary: format!(
                    "WorkloadReceipt(NetFetch) tool={} success={} status_code={} url={}",
                    net.tool_name,
                    net.success,
                    status_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    snippet(&net.requested_url)
                ),
                digest: json!({
                    "kind": "net_fetch",
                    "tool_name": net.tool_name,
                    "method": net.method,
                    "success": net.success,
                    "status_code": status_code,
                    "truncated": net.truncated,
                    "error_class": error_class,
                }),
                details: json!({
                    "requested_url": net.requested_url,
                    "final_url": final_url,
                    "content_type": if net.has_content_type { Some(net.content_type.clone()) } else { None::<String> },
                    "max_chars": net.max_chars,
                    "max_bytes": net.max_bytes,
                    "bytes_read": net.bytes_read,
                    "timeout_ms": net.timeout_ms,
                }),
            })
        }
        WorkloadReceiptKind::WebRetrieve(web) => {
            let query = if web.has_query {
                Some(web.query.clone())
            } else {
                None
            };
            let url = if web.has_url {
                Some(web.url.clone())
            } else {
                None
            };
            let error_class = if web.has_error_class {
                Some(web.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "web_retrieve",
                tool_name: web.tool_name.clone(),
                success: web.success,
                summary: format!(
                    "WorkloadReceipt(WebRetrieve) tool={} backend={} success={} sources={} docs={}",
                    web.tool_name, web.backend, web.success, web.sources_count, web.documents_count
                ),
                digest: json!({
                    "kind": "web_retrieve",
                    "tool_name": web.tool_name,
                    "backend": web.backend,
                    "success": web.success,
                    "sources_count": web.sources_count,
                    "documents_count": web.documents_count,
                    "error_class": error_class,
                }),
                details: json!({
                    "query": query,
                    "url": url,
                    "limit": if web.has_limit { Some(web.limit) } else { None::<u32> },
                    "max_chars": if web.has_max_chars { Some(web.max_chars) } else { None::<u32> },
                }),
            })
        }
        WorkloadReceiptKind::ScsRetrieve(scs) => {
            let proof_ref = if scs.has_proof_ref {
                Some(scs.proof_ref.clone())
            } else {
                None
            };
            let proof_hash = if scs.has_proof_hash {
                Some(scs.proof_hash.clone())
            } else {
                None
            };
            let certificate_mode = if scs.has_certificate_mode {
                Some(scs.certificate_mode.clone())
            } else {
                None
            };
            let error_class = if scs.has_error_class {
                Some(scs.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "scs_retrieve",
                tool_name: scs.tool_name.clone(),
                success: scs.success,
                summary: format!(
                    "WorkloadReceipt(ScsRetrieve) tool={} backend={} success={} k={} ef={} candidates={}/{} truncated={}",
                    scs.tool_name,
                    scs.backend,
                    scs.success,
                    scs.k,
                    scs.ef_search,
                    scs.candidate_count_reranked,
                    scs.candidate_count_total,
                    scs.candidate_truncated
                ),
                digest: json!({
                    "kind": "scs_retrieve",
                    "tool_name": scs.tool_name,
                    "backend": scs.backend,
                    "query_hash": scs.query_hash,
                    "index_root": scs.index_root,
                    "k": scs.k,
                    "ef_search": scs.ef_search,
                    "candidate_limit": scs.candidate_limit,
                    "candidate_count_total": scs.candidate_count_total,
                    "candidate_count_reranked": scs.candidate_count_reranked,
                    "candidate_truncated": scs.candidate_truncated,
                    "distance_metric": scs.distance_metric,
                    "embedding_normalized": scs.embedding_normalized,
                    "success": scs.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "proof_ref": proof_ref,
                    "proof_hash": proof_hash,
                    "certificate_mode": certificate_mode,
                }),
            })
        }
        WorkloadReceiptKind::Adapter(adapter) => {
            let response_hash = if adapter.has_response_hash {
                Some(adapter.response_hash.clone())
            } else {
                None
            };
            let error_class = if adapter.has_error_class {
                Some(adapter.error_class.clone())
            } else {
                None
            };
            let replay_classification = if adapter.has_replay_classification {
                Some(adapter.replay_classification.clone())
            } else {
                None
            };
            let artifact_pointers = adapter
                .artifact_pointers
                .iter()
                .map(|pointer| {
                    json!({
                        "uri": pointer.uri,
                        "media_type": if pointer.has_media_type {
                            Some(pointer.media_type.clone())
                        } else {
                            None::<String>
                        },
                        "sha256": if pointer.has_sha256 {
                            Some(pointer.sha256.clone())
                        } else {
                            None::<String>
                        },
                        "label": if pointer.has_label {
                            Some(pointer.label.clone())
                        } else {
                            None::<String>
                        },
                    })
                })
                .collect::<Vec<_>>();
            Some(WorkloadReceiptSummary {
                kind: "adapter",
                tool_name: adapter.tool_name.clone(),
                success: adapter.success,
                summary: format!(
                    "WorkloadReceipt(Adapter) adapter={} tool={} kind={} success={} artifacts={} redactions={}",
                    adapter.adapter_id,
                    adapter.tool_name,
                    adapter.adapter_kind,
                    adapter.success,
                    adapter.artifact_pointers.len(),
                    adapter.redaction_count
                ),
                digest: json!({
                    "kind": "adapter",
                    "adapter_id": adapter.adapter_id,
                    "tool_name": adapter.tool_name,
                    "adapter_kind": adapter.adapter_kind,
                    "invocation_id": adapter.invocation_id,
                    "idempotency_key": adapter.idempotency_key,
                    "action_target": adapter.action_target,
                    "request_hash": adapter.request_hash,
                    "response_hash": response_hash,
                    "success": adapter.success,
                    "error_class": error_class,
                    "replay_classification": replay_classification,
                    "artifact_count": adapter.artifact_pointers.len(),
                    "redaction_count": adapter.redaction_count,
                    "redaction_version": adapter.redaction_version,
                }),
                details: json!({
                    "artifact_pointers": artifact_pointers,
                    "redacted_fields": adapter.redacted_fields,
                }),
            })
        }
    }
}

pub(super) async fn handle_workload_receipt(app: &tauri::AppHandle, receipt: WorkloadReceipt) {
    let Some(summary) = summarize_workload_receipt(&receipt) else {
        return;
    };

    let suppress_terminal_receipt = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(is_hard_terminal_task)
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if suppress_terminal_receipt {
        return;
    }

    let receipt_dedup_key = format!(
        "workload_receipt:{}:{}:{}:{}:{}",
        receipt.step_index,
        receipt.workload_id,
        summary.kind,
        summary.tool_name,
        receipt.timestamp_ms
    );
    let already_processed = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(|task| task.processed_steps.contains(&receipt_dedup_key))
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if already_processed {
        return;
    }

    let mut accepted_for_processing = false;
    update_task_state(app, |task| {
        if task.processed_steps.contains(&receipt_dedup_key) {
            return;
        }
        task.processed_steps.insert(receipt_dedup_key.clone());
        accepted_for_processing = true;

        bind_task_session(task, &receipt.session_id);
        task.current_step = format!("Workload receipt: {} ({})", summary.tool_name, summary.kind);

        if task
            .history
            .last()
            .map(|m| m.text == summary.summary)
            .unwrap_or(false)
        {
            return;
        }
        task.history.push(ChatMessage {
            role: "system".to_string(),
            text: summary.summary.clone(),
            timestamp: crate::kernel::state::now(),
        });
    });
    if !accepted_for_processing {
        return;
    }

    let thread_id = thread_id_from_session(app, &receipt.session_id);
    let status = if summary.success {
        EventStatus::Success
    } else {
        EventStatus::Failure
    };
    let receipt_ref = Some(format!(
        "{}:{}:{}:{}",
        thread_id, receipt.step_index, receipt.workload_id, summary.kind
    ));
    let event = build_event(
        &thread_id,
        receipt.step_index,
        EventType::Receipt,
        format!("Workload receipt: {} ({})", summary.tool_name, summary.kind),
        summary.digest,
        json!({
            "summary": summary.summary,
            "workload_id": receipt.workload_id,
            "timestamp_ms": receipt.timestamp_ms,
            "payload": summary.details,
        }),
        status,
        Vec::new(),
        receipt_ref,
        Vec::new(),
        None,
    );
    register_event(app, event);
}
