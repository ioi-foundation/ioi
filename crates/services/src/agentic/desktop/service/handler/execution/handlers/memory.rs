use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::desktop::execution::workload;
use crate::agentic::desktop::service::memory::{
    append_core_memory_from_tool, archival_record_id_from_inspect_id,
    clear_core_memory_from_tool, replace_core_memory_from_tool,
};
use crate::agentic::desktop::service::DesktopAgentService;
use ioi_types::app::{WorkloadActivityKind, WorkloadMemoryRetrieveReceipt, WorkloadReceipt};
use serde_json::json;

pub(crate) async fn handle_memory_search_tool(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    query: &str,
) -> ActionExecutionOutcome {
    if service.memory_runtime.is_none() {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__search requires a configured memory runtime."
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

    let receipt = retrieval.receipt.unwrap_or(WorkloadMemoryRetrieveReceipt {
        tool_name: "memory__search".to_string(),
        backend: "ioi-memory:hybrid-archival".to_string(),
        query_hash: String::new(),
        index_root: String::new(),
        k: 5,
        ef_search: 64,
        candidate_limit: 32,
        candidate_count_total: 0,
        candidate_count_reranked: 0,
        candidate_truncated: false,
        distance_metric: "hybrid_lexical_semantic".to_string(),
        embedding_normalized: false,
        proof_ref: None,
        proof_hash: None,
        certificate_mode: Some("none".to_string()),
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
            WorkloadReceipt::MemoryRetrieve(receipt.clone()),
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
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__inspect requires a configured memory runtime."
                    .to_string(),
            ),
        );
    };

    let Some(record_id) = archival_record_id_from_inspect_id(frame_id) else {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=TargetNotFound memory__inspect only supports archival IDs returned by memory__search."
                    .to_string(),
            ),
        );
    };

    match memory_runtime.load_archival_record(record_id) {
        Ok(Some(record)) => {
            let metadata = serde_json::from_str::<serde_json::Value>(&record.metadata_json)
                .unwrap_or_else(|_| json!({}));
            let out = json!({
                "frame_id": frame_id,
                "frame_type": "ArchivalMemory",
                "scope": record.scope,
                "kind": record.kind,
                "session_id": metadata.get("session_id").and_then(serde_json::Value::as_str),
                "role": metadata.get("role").and_then(serde_json::Value::as_str),
                "timestamp_ms": metadata
                    .get("timestamp_ms")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(record.created_at_ms),
                "content": record.content,
            })
            .to_string();
            no_visual(true, Some(out), None)
        }
        Ok(None) => no_visual(
            false,
            None,
            Some(format!(
                "ERROR_CLASS=TargetNotFound Memory record {} not found.",
                frame_id
            )),
        ),
        Err(error) => no_visual(
            false,
            None,
            Some(format!(
                "ERROR_CLASS=UnexpectedState memory__inspect failed: {}",
                error
            )),
        ),
    }
}

pub(crate) async fn handle_memory_replace_core_tool(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    section: &str,
    content: &str,
) -> ActionExecutionOutcome {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__replace_core requires a configured memory runtime."
                    .to_string(),
            ),
        );
    };

    match replace_core_memory_from_tool(memory_runtime, session_id, section.trim(), content.trim()) {
        Ok(()) => no_visual(
            true,
            Some(format!("Updated core memory section '{}'.", section.trim())),
            None,
        ),
        Err(error) => no_visual(
            false,
            None,
            Some(format!("ERROR_CLASS=PolicyDenied memory__replace_core failed: {}", error)),
        ),
    }
}

pub(crate) async fn handle_memory_append_core_tool(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    section: &str,
    content: &str,
) -> ActionExecutionOutcome {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__append_core requires a configured memory runtime."
                    .to_string(),
            ),
        );
    };

    match append_core_memory_from_tool(memory_runtime, session_id, section.trim(), content.trim()) {
        Ok(()) => no_visual(
            true,
            Some(format!("Appended to core memory section '{}'.", section.trim())),
            None,
        ),
        Err(error) => no_visual(
            false,
            None,
            Some(format!("ERROR_CLASS=PolicyDenied memory__append_core failed: {}", error)),
        ),
    }
}

pub(crate) async fn handle_memory_clear_core_tool(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    section: &str,
) -> ActionExecutionOutcome {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__clear_core requires a configured memory runtime."
                    .to_string(),
            ),
        );
    };

    match clear_core_memory_from_tool(memory_runtime, session_id, section.trim()) {
        Ok(()) => no_visual(
            true,
            Some(format!("Cleared core memory section '{}'.", section.trim())),
            None,
        ),
        Err(error) => no_visual(
            false,
            None,
            Some(format!("ERROR_CLASS=PolicyDenied memory__clear_core failed: {}", error)),
        ),
    }
}
