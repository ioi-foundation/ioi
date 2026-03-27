use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::support::{
    bind_task_session, is_hard_terminal_task, snippet, thread_id_from_session,
};
use crate::kernel::state::update_task_state;
use crate::models::{AppState, ChatMessage, EventStatus, EventType};
use crate::orchestrator;
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
        WorkloadReceiptKind::MemoryRetrieve(scs) => {
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
                kind: "memory_retrieve",
                tool_name: scs.tool_name.clone(),
                success: scs.success,
                summary: format!(
                    "WorkloadReceipt(MemoryRetrieve) tool={} backend={} success={} k={} ef={} candidates={}/{} truncated={}",
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
                    "kind": "memory_retrieve",
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
        WorkloadReceiptKind::Inference(inference) => {
            let model_family = if inference.has_model_family {
                Some(inference.model_family.clone())
            } else {
                None
            };
            let prompt_token_count = if inference.has_prompt_token_count {
                Some(inference.prompt_token_count)
            } else {
                None
            };
            let completion_token_count = if inference.has_completion_token_count {
                Some(inference.completion_token_count)
            } else {
                None
            };
            let total_token_count = if inference.has_total_token_count {
                Some(inference.total_token_count)
            } else {
                None
            };
            let vector_dimensions = if inference.has_vector_dimensions {
                Some(inference.vector_dimensions)
            } else {
                None
            };
            let candidate_count_total = if inference.has_candidate_count_total {
                Some(inference.candidate_count_total)
            } else {
                None
            };
            let candidate_count_scored = if inference.has_candidate_count_scored {
                Some(inference.candidate_count_scored)
            } else {
                None
            };
            let latency_ms = if inference.has_latency_ms {
                Some(inference.latency_ms)
            } else {
                None
            };
            let error_class = if inference.has_error_class {
                Some(inference.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "inference",
                tool_name: inference.tool_name.clone(),
                success: inference.success,
                summary: format!(
                    "WorkloadReceipt(Inference) tool={} op={} model={} success={} results={}",
                    inference.tool_name,
                    inference.operation,
                    inference.model_id,
                    inference.success,
                    inference.result_item_count
                ),
                digest: json!({
                    "kind": "inference",
                    "tool_name": inference.tool_name,
                    "operation": inference.operation,
                    "backend": inference.backend,
                    "model_id": inference.model_id,
                    "model_family": model_family,
                    "result_item_count": inference.result_item_count,
                    "streaming": inference.streaming,
                    "success": inference.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "prompt_token_count": prompt_token_count,
                    "completion_token_count": completion_token_count,
                    "total_token_count": total_token_count,
                    "vector_dimensions": vector_dimensions,
                    "candidate_count_total": candidate_count_total,
                    "candidate_count_scored": candidate_count_scored,
                    "latency_ms": latency_ms,
                }),
            })
        }
        WorkloadReceiptKind::Media(media) => {
            let model_id = if media.has_model_id {
                Some(media.model_id.clone())
            } else {
                None
            };
            let source_uri = if media.has_source_uri {
                Some(media.source_uri.clone())
            } else {
                None
            };
            let output_bytes = if media.has_output_bytes {
                Some(media.output_bytes)
            } else {
                None
            };
            let duration_ms = if media.has_duration_ms {
                Some(media.duration_ms)
            } else {
                None
            };
            let error_class = if media.has_error_class {
                Some(media.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "media",
                tool_name: media.tool_name.clone(),
                success: media.success,
                summary: format!(
                    "WorkloadReceipt(Media) tool={} op={} backend={} success={} outputs={}",
                    media.tool_name,
                    media.operation,
                    media.backend,
                    media.success,
                    media.output_artifact_count
                ),
                digest: json!({
                    "kind": "media",
                    "tool_name": media.tool_name,
                    "operation": media.operation,
                    "backend": media.backend,
                    "model_id": model_id,
                    "input_artifact_count": media.input_artifact_count,
                    "output_artifact_count": media.output_artifact_count,
                    "success": media.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "source_uri": source_uri,
                    "output_bytes": output_bytes,
                    "duration_ms": duration_ms,
                    "output_mime_types": media.output_mime_types,
                }),
            })
        }
        WorkloadReceiptKind::ModelLifecycle(model) => {
            let backend_id = if model.has_backend_id {
                Some(model.backend_id.clone())
            } else {
                None
            };
            let source_uri = if model.has_source_uri {
                Some(model.source_uri.clone())
            } else {
                None
            };
            let job_id = if model.has_job_id {
                Some(model.job_id.clone())
            } else {
                None
            };
            let bytes_transferred = if model.has_bytes_transferred {
                Some(model.bytes_transferred)
            } else {
                None
            };
            let hardware_profile = if model.has_hardware_profile {
                Some(model.hardware_profile.clone())
            } else {
                None
            };
            let error_class = if model.has_error_class {
                Some(model.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "model_lifecycle",
                tool_name: model.tool_name.clone(),
                success: model.success,
                summary: format!(
                    "WorkloadReceipt(ModelLifecycle) tool={} op={} subject_kind={} subject_id={} success={}",
                    model.tool_name,
                    model.operation,
                    model.subject_kind,
                    snippet(&model.subject_id),
                    model.success
                ),
                digest: json!({
                    "kind": "model_lifecycle",
                    "tool_name": model.tool_name,
                    "operation": model.operation,
                    "subject_kind": model.subject_kind,
                    "subject_id": model.subject_id,
                    "success": model.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "backend_id": backend_id,
                    "source_uri": source_uri,
                    "job_id": job_id,
                    "bytes_transferred": bytes_transferred,
                    "hardware_profile": hardware_profile,
                }),
            })
        }
        WorkloadReceiptKind::Worker(worker) => {
            let playbook_id = if worker.has_playbook_id {
                Some(worker.playbook_id.clone())
            } else {
                None
            };
            let template_id = if worker.has_template_id {
                Some(worker.template_id.clone())
            } else {
                None
            };
            let workflow_id = if worker.has_workflow_id {
                Some(worker.workflow_id.clone())
            } else {
                None
            };
            let verification_hint = if worker.has_verification_hint {
                Some(worker.verification_hint.clone())
            } else {
                None
            };
            let error_class = if worker.has_error_class {
                Some(worker.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "worker",
                tool_name: worker.tool_name.clone(),
                success: worker.success,
                summary: format!(
                    "WorkloadReceipt(Worker) tool={} phase={} role={} playbook={} success={} child={}",
                    worker.tool_name,
                    worker.phase,
                    worker.role,
                    playbook_id.as_deref().unwrap_or("n/a"),
                    worker.success,
                    snippet(&worker.child_session_id)
                ),
                digest: json!({
                    "kind": "worker",
                    "tool_name": worker.tool_name,
                    "phase": worker.phase,
                    "role": worker.role,
                    "playbook_id": playbook_id,
                    "template_id": template_id,
                    "workflow_id": workflow_id,
                    "merge_mode": worker.merge_mode,
                    "status": worker.status,
                    "success": worker.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "child_session_id": worker.child_session_id,
                    "parent_session_id": worker.parent_session_id,
                    "playbook_id": playbook_id,
                    "workflow_id": workflow_id,
                    "summary": worker.summary,
                    "verification_hint": verification_hint,
                }),
            })
        }
        WorkloadReceiptKind::ParentPlaybook(playbook) => {
            let step_id = if playbook.has_step_id {
                Some(playbook.step_id.clone())
            } else {
                None
            };
            let step_label = if playbook.has_step_label {
                Some(playbook.step_label.clone())
            } else {
                None
            };
            let child_session_id = if playbook.has_child_session_id {
                Some(playbook.child_session_id.clone())
            } else {
                None
            };
            let template_id = if playbook.has_template_id {
                Some(playbook.template_id.clone())
            } else {
                None
            };
            let workflow_id = if playbook.has_workflow_id {
                Some(playbook.workflow_id.clone())
            } else {
                None
            };
            let error_class = if playbook.has_error_class {
                Some(playbook.error_class.clone())
            } else {
                None
            };
            Some(WorkloadReceiptSummary {
                kind: "parent_playbook",
                tool_name: playbook.tool_name.clone(),
                success: playbook.success,
                summary: format!(
                    "WorkloadReceipt(ParentPlaybook) tool={} phase={} playbook={} status={} success={}",
                    playbook.tool_name,
                    playbook.phase,
                    playbook.playbook_id,
                    playbook.status,
                    playbook.success
                ),
                digest: json!({
                    "kind": "parent_playbook",
                    "tool_name": playbook.tool_name,
                    "phase": playbook.phase,
                    "playbook_id": playbook.playbook_id,
                    "playbook_label": playbook.playbook_label,
                    "status": playbook.status,
                    "success": playbook.success,
                    "error_class": error_class,
                }),
                details: json!({
                    "parent_session_id": playbook.parent_session_id,
                    "step_id": step_id,
                    "step_label": step_label,
                    "child_session_id": child_session_id,
                    "template_id": template_id,
                    "workflow_id": workflow_id,
                    "summary": playbook.summary,
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

    if let Some(WorkloadReceiptKind::ModelLifecycle(model)) = receipt.receipt.as_ref() {
        let memory_runtime = {
            let state_handle = app.state::<Mutex<AppState>>();
            let runtime = match state_handle.lock() {
                Ok(guard) => guard.memory_runtime.clone(),
                Err(_) => None,
            };
            runtime
        };
        if let Some(memory_runtime) = memory_runtime {
            let control_plane = orchestrator::load_local_engine_control_plane(&memory_runtime);
            crate::kernel::local_engine::ingest_model_lifecycle_receipt(
                &memory_runtime,
                control_plane.as_ref(),
                crate::kernel::local_engine::ModelLifecycleReceiptUpdate {
                    session_id: receipt.session_id.clone(),
                    workload_id: receipt.workload_id.clone(),
                    timestamp_ms: receipt.timestamp_ms,
                    tool_name: model.tool_name.clone(),
                    operation: model.operation.clone(),
                    subject_kind: model.subject_kind.clone(),
                    subject_id: model.subject_id.clone(),
                    success: model.success,
                    backend_id: if model.has_backend_id {
                        Some(model.backend_id.clone())
                    } else {
                        None
                    },
                    source_uri: if model.has_source_uri {
                        Some(model.source_uri.clone())
                    } else {
                        None
                    },
                    job_id: if model.has_job_id {
                        Some(model.job_id.clone())
                    } else {
                        None
                    },
                    bytes_transferred: if model.has_bytes_transferred {
                        Some(model.bytes_transferred)
                    } else {
                        None
                    },
                    hardware_profile: if model.has_hardware_profile {
                        Some(model.hardware_profile.clone())
                    } else {
                        None
                    },
                    error_class: if model.has_error_class {
                        Some(model.error_class.clone())
                    } else {
                        None
                    },
                },
            );
            crate::kernel::local_engine::emit_local_engine_update(app, "model_lifecycle_receipt");
        }
    }

    if matches!(
        receipt.receipt.as_ref(),
        Some(WorkloadReceiptKind::ParentPlaybook(_))
    ) {
        crate::kernel::local_engine::emit_local_engine_update(app, "parent_playbook_receipt");
    }

    if let Some(WorkloadReceiptKind::Worker(worker)) = receipt.receipt.as_ref() {
        update_task_state(app, |task| {
            if let Some(agent) = task
                .swarm_tree
                .iter_mut()
                .find(|agent| agent.id == worker.child_session_id)
            {
                agent.status = if worker.success {
                    if worker.phase == "merged" {
                        "merged".to_string()
                    } else {
                        "completed".to_string()
                    }
                } else {
                    "failed".to_string()
                };
                agent.current_thought = Some(worker.summary.clone());
                agent.artifacts_produced = agent.artifacts_produced.saturating_add(1);
            }
        });
    }

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
