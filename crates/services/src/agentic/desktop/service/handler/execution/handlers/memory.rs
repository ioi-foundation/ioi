use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::desktop::execution::workload;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::RecordedMessage;
use ioi_scs::FrameType;
use ioi_types::app::{WorkloadActivityKind, WorkloadReceipt, WorkloadScsRetrieveReceipt};
use ioi_types::codec;
use serde_json::json;

pub(crate) async fn handle_memory_search_tool(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    query: &str,
) -> ActionExecutionOutcome {
    if service.scs.is_none() {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__search requires an SCS-backed memory store."
                    .to_string(),
            ),
        );
    }

    let trimmed = query.trim();
    if trimmed.is_empty() {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=TargetNotFound memory__search requires a non-empty query.".to_string(),
            ),
        );
    }

    let query_preview = {
        let mut preview: String = trimmed.chars().take(160).collect();
        if trimmed.chars().count() > 160 {
            preview.push_str("...");
        }
        preview
    };
    let workload_id = workload::compute_workload_id(
        session_id,
        step_index,
        "memory__search",
        format!("memory__search {}", query_preview).as_str(),
    );

    if let Some(tx) = service.event_sender.as_ref() {
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
    }

    let retrieval = service
        .retrieve_context_hybrid_with_receipt(trimmed, None)
        .await;
    let out = retrieval.output;
    let out = if out.trim().is_empty() {
        "No matching memories found.".to_string()
    } else {
        out
    };

    let receipt = retrieval.receipt.unwrap_or(WorkloadScsRetrieveReceipt {
        tool_name: "memory__search".to_string(),
        backend: "scs:mhnsw".to_string(),
        query_hash: String::new(),
        index_root: String::new(),
        k: 5,
        ef_search: 64,
        candidate_limit: 32,
        candidate_count_total: 0,
        candidate_count_reranked: 0,
        candidate_truncated: false,
        distance_metric: "cosine_distance".to_string(),
        embedding_normalized: true,
        proof_ref: None,
        proof_hash: None,
        certificate_mode: Some("single_level_lb".to_string()),
        success: false,
        error_class: Some("UnexpectedState".to_string()),
    });

    if let Some(tx) = service.event_sender.as_ref() {
        workload::emit_workload_activity(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Lifecycle {
                phase: if receipt.success {
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
            WorkloadReceipt::ScsRetrieve(receipt.clone()),
        );
    }

    if receipt.success {
        no_visual(true, Some(out), None)
    } else {
        no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=UnexpectedState memory__search retrieval verification failed."
                    .to_string(),
            ),
        )
    }
}

pub(crate) async fn handle_memory_inspect_tool(
    service: &DesktopAgentService,
    frame_id: u64,
) -> ActionExecutionOutcome {
    let scs_mutex = match service.scs.as_ref() {
        Some(m) => m,
        None => {
            return no_visual(
                false,
                None,
                Some(
                    "ERROR_CLASS=ToolUnavailable memory__inspect requires an SCS-backed memory store."
                        .to_string(),
                ),
            );
        }
    };

    let frame_type = {
        let store = match scs_mutex.lock() {
            Ok(store) => store,
            Err(_) => {
                return no_visual(
                    false,
                    None,
                    Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                );
            }
        };

        match store.toc.frames.get(frame_id as usize) {
            Some(frame) => frame.frame_type,
            None => {
                return no_visual(
                    false,
                    None,
                    Some(format!(
                        "ERROR_CLASS=TargetNotFound Frame {} not found in memory store.",
                        frame_id
                    )),
                );
            }
        }
    };

    match frame_type {
        FrameType::Observation => match service.inspect_frame(frame_id).await {
            Ok(desc) => no_visual(true, Some(desc), None),
            Err(e) => no_visual(
                false,
                None,
                Some(format!(
                    "ERROR_CLASS=UnexpectedState memory__inspect failed: {}",
                    e
                )),
            ),
        },
        FrameType::Thought | FrameType::Action => {
            let payload = {
                let store = match scs_mutex.lock() {
                    Ok(store) => store,
                    Err(_) => {
                        return no_visual(
                            false,
                            None,
                            Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                        );
                    }
                };

                match store.read_frame_payload(frame_id) {
                    Ok(payload) => payload,
                    Err(e) => {
                        return no_visual(
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=UnexpectedState Failed to read frame payload: {}",
                                e
                            )),
                        );
                    }
                }
            };

            match codec::from_bytes_canonical::<RecordedMessage>(&payload) {
                Ok(recorded) => {
                    let content = if recorded.scrubbed_for_model.is_empty() {
                        recorded.scrubbed_for_scs
                    } else {
                        recorded.scrubbed_for_model
                    };
                    let out = json!({
                        "frame_id": frame_id,
                        "frame_type": format!("{:?}", frame_type),
                        "role": recorded.role,
                        "timestamp_ms": recorded.timestamp_ms,
                        "content": content,
                    })
                    .to_string();
                    no_visual(true, Some(out), None)
                }
                Err(_) => no_visual(
                    true,
                    Some(format!(
                        "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Non-Recorded Payload>\"}}",
                        frame_id, frame_type
                    )),
                    None,
                ),
            }
        }
        _ => no_visual(
            true,
            Some(format!(
                "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Unsupported Frame Type>\"}}",
                frame_id, frame_type
            )),
            None,
        ),
    }
}
