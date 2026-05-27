use ioi_types::app::{KernelEvent, RoutingReceiptEvent, WorkloadReceipt, WorkloadReceiptEvent};
use serde_json::{json, Value};

const EVENT_SCHEMA_VERSION: &str = "ioi.runtime.event.v1";
const KERNEL_EVENT_PAYLOAD_SCHEMA_VERSION: &str = "ioi.runtime.kernel-event.v1";
const BRIDGE_EVENT_TEXT_PREVIEW_BYTES: usize = 4096;

pub struct RuntimeBridgeEventContext<'a> {
    pub thread_id: &'a str,
    pub turn_id: &'a str,
    pub workspace_root: Option<&'a str>,
    pub created_at: &'a str,
    pub ordinal: usize,
}

pub fn kernel_event_to_tti_event(
    event: &KernelEvent,
    context: &RuntimeBridgeEventContext<'_>,
) -> Option<Value> {
    let kernel_payload = compact_json_value(serde_json::to_value(event).ok()?);
    match event {
        KernelEvent::AgentStep(trace) => Some(runtime_kernel_event(
            context,
            "KernelEvent::AgentStep",
            "turn.step",
            "running",
            "runtime",
            "runtime_step",
            "runtime.runtime-step",
            format!("step:{}", trace.step_index),
            json!({
                "event_kind": "KernelEvent::AgentStep",
                "session_id": hex::encode(trace.session_id),
                "step_index": trace.step_index,
                "success": trace.success,
                "error": trace.error,
                "raw_output": compact_text(&trace.raw_output),
                "cost_incurred": trace.cost_incurred,
                "fitness_score": trace.fitness_score,
                "timestamp": trace.timestamp,
                "kernel_event": kernel_payload,
            }),
        )),
        KernelEvent::AgentThought { session_id, token } => Some(runtime_kernel_event(
            context,
            "KernelEvent::AgentThought",
            "reasoning.delta",
            "running",
            "assistant",
            "reasoning_delta",
            "runtime.reasoning",
            format!("thought:{}", context.ordinal),
            json!({
                "event_kind": "KernelEvent::AgentThought",
                "session_id": hex::encode(session_id),
                "delta": token,
                "token": token,
                "kernel_event": kernel_payload,
            }),
        )),
        KernelEvent::FirewallInterception {
            verdict,
            target,
            request_hash,
            session_id,
        } => {
            let verdict_normalized = verdict.trim().to_ascii_uppercase();
            let requires_approval = verdict_normalized.contains("REQUIRE_APPROVAL")
                || verdict_normalized.contains("APPROVAL")
                || verdict_normalized.contains("REVIEW");
            let (event_kind, component_kind, workflow_node_id) = if requires_approval {
                (
                    "approval.required",
                    "approval_required",
                    "runtime.approval-gate",
                )
            } else {
                ("policy.blocked", "policy_blocked", "runtime.policy-gate")
            };
            Some(runtime_kernel_event(
                context,
                "KernelEvent::FirewallInterception",
                event_kind,
                "blocked",
                "policy",
                component_kind,
                workflow_node_id,
                format!("firewall:{}", hex::encode(request_hash)),
                json!({
                    "event_kind": "KernelEvent::FirewallInterception",
                    "verdict": verdict,
                    "target": target,
                    "request_hash": hex::encode(request_hash),
                    "session_id": session_id.map(hex::encode),
                    "kernel_event": kernel_payload,
                }),
            ))
        }
        KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name,
            output,
            error_class,
            agent_status,
        } => {
            let failed = error_class.is_some();
            Some(runtime_kernel_event(
                context,
                "KernelEvent::AgentActionResult",
                if failed {
                    "tool.failed"
                } else {
                    "tool.completed"
                },
                if failed { "failed" } else { "completed" },
                "tool",
                "tool_result",
                "runtime.tool-result",
                format!("tool:{step_index}:{tool_name}:{}", context.ordinal),
                json!({
                    "event_kind": "KernelEvent::AgentActionResult",
                    "session_id": hex::encode(session_id),
                    "step_index": step_index,
                    "tool_name": tool_name,
                    "output": compact_text(output),
                    "error_class": error_class,
                    "agent_status": agent_status,
                    "kernel_event": kernel_payload,
                }),
            ))
        }
        KernelEvent::WorkloadReceipt(receipt) => Some(workload_receipt_to_tti_event(
            receipt,
            context,
            kernel_payload,
        )),
        KernelEvent::RoutingReceipt(receipt) => Some(routing_receipt_to_tti_event(
            receipt,
            context,
            kernel_payload,
        )),
        _ => None,
    }
}

fn compact_text(text: &str) -> String {
    if text.len() <= BRIDGE_EVENT_TEXT_PREVIEW_BYTES {
        return text.to_string();
    }
    let mut end = BRIDGE_EVENT_TEXT_PREVIEW_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}...[truncated {} bytes]",
        &text[..end],
        text.len().saturating_sub(end)
    )
}

fn compact_json_value(value: Value) -> Value {
    match value {
        Value::String(text) if text.len() > BRIDGE_EVENT_TEXT_PREVIEW_BYTES => json!({
            "preview": compact_text(&text),
            "truncated": true,
            "original_bytes": text.len(),
        }),
        Value::Array(items) => Value::Array(items.into_iter().map(compact_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, compact_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn workload_receipt_to_tti_event(
    receipt: &WorkloadReceiptEvent,
    context: &RuntimeBridgeEventContext<'_>,
    kernel_payload: Value,
) -> Value {
    let summary = workload_receipt_summary(&receipt.receipt);
    runtime_kernel_event(
        context,
        "KernelEvent::WorkloadReceipt",
        "receipt.emitted",
        if summary.success {
            "completed"
        } else {
            "failed"
        },
        "runtime",
        "receipt",
        "runtime.receipt",
        format!("workload:{}:{}", receipt.step_index, receipt.workload_id),
        json!({
            "event_kind": "KernelEvent::WorkloadReceipt",
            "session_id": hex::encode(receipt.session_id),
            "step_index": receipt.step_index,
            "workload_id": receipt.workload_id,
            "timestamp_ms": receipt.timestamp_ms,
            "receipt_kind": summary.receipt_kind,
            "tool_name": summary.tool_name,
            "success": summary.success,
            "error_class": summary.error_class,
            "receipt": receipt.receipt,
            "kernel_event": kernel_payload,
        }),
    )
}

fn routing_receipt_to_tti_event(
    receipt: &RoutingReceiptEvent,
    context: &RuntimeBridgeEventContext<'_>,
    kernel_payload: Value,
) -> Value {
    let route_family = receipt
        .route_decision
        .route_family
        .trim()
        .to_ascii_lowercase();
    let is_model_route = route_family.contains("model")
        || route_family.contains("inference")
        || receipt.tool_name.contains("model");
    runtime_kernel_event(
        context,
        "KernelEvent::RoutingReceipt",
        if is_model_route {
            "model.route_decision"
        } else {
            "tool.route_decision"
        },
        "completed",
        "runtime",
        if is_model_route {
            "model_router"
        } else {
            "tool_router"
        },
        if is_model_route {
            "runtime.model-router"
        } else {
            "runtime.tool-router"
        },
        format!("routing:{}:{}", receipt.step_index, receipt.intent_hash),
        json!({
            "event_kind": "KernelEvent::RoutingReceipt",
            "session_id": hex::encode(receipt.session_id),
            "step_index": receipt.step_index,
            "intent_hash": receipt.intent_hash,
            "policy_decision": receipt.policy_decision,
            "tool_name": receipt.tool_name,
            "tool_version": receipt.tool_version,
            "gate_state": receipt.gate_state,
            "failure_class_name": receipt.failure_class_name,
            "route_decision": receipt.route_decision,
            "kernel_event": kernel_payload,
        }),
    )
}

fn runtime_kernel_event(
    context: &RuntimeBridgeEventContext<'_>,
    source_event_kind: &str,
    event_kind: &str,
    status: &str,
    actor: &str,
    component_kind: &str,
    workflow_node_id: &str,
    event_key: String,
    payload: Value,
) -> Value {
    json!({
        "event_stream_id": format!("{}:events", context.thread_id),
        "thread_id": context.thread_id,
        "turn_id": context.turn_id,
        "item_id": format!("{}:item:kernel:{}:{}", context.turn_id, context.ordinal, event_kind),
        "idempotency_key": format!(
            "runtime-agent-service:{}:{}:{}",
            context.turn_id,
            source_event_kind,
            event_key,
        ),
        "source": "runtime_service",
        "source_event_kind": source_event_kind,
        "event_kind": event_kind,
        "status": status,
        "actor": actor,
        "created_at": context.created_at,
        "workspace_root": context.workspace_root,
        "component_kind": component_kind,
        "workflow_node_id": workflow_node_id,
        "payload_schema_version": KERNEL_EVENT_PAYLOAD_SCHEMA_VERSION,
        "payload": payload,
        "schema_version": EVENT_SCHEMA_VERSION,
        "fixture_profile": Value::Null,
    })
}

struct WorkloadReceiptSummary<'a> {
    receipt_kind: &'static str,
    tool_name: &'a str,
    success: bool,
    error_class: Option<&'a str>,
}

fn workload_receipt_summary(receipt: &WorkloadReceipt) -> WorkloadReceiptSummary<'_> {
    match receipt {
        WorkloadReceipt::Exec(item) => WorkloadReceiptSummary {
            receipt_kind: "exec",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::FsWrite(item) => WorkloadReceiptSummary {
            receipt_kind: "fs_write",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::NetFetch(item) => WorkloadReceiptSummary {
            receipt_kind: "net_fetch",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::WebRetrieve(item) => WorkloadReceiptSummary {
            receipt_kind: "web_retrieve",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::MemoryRetrieve(item) => WorkloadReceiptSummary {
            receipt_kind: "memory_retrieve",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Inference(item) => WorkloadReceiptSummary {
            receipt_kind: "inference",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Media(item) => WorkloadReceiptSummary {
            receipt_kind: "media",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::ModelLifecycle(item) => WorkloadReceiptSummary {
            receipt_kind: "model_lifecycle",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Worker(item) => WorkloadReceiptSummary {
            receipt_kind: "worker",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::ParentPlaybook(item) => WorkloadReceiptSummary {
            receipt_kind: "parent_playbook",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
        WorkloadReceipt::Adapter(item) => WorkloadReceiptSummary {
            receipt_kind: "adapter",
            tool_name: &item.tool_name,
            success: item.success,
            error_class: item.error_class.as_deref(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{KernelEvent, WorkloadExecReceipt};

    fn context<'a>() -> RuntimeBridgeEventContext<'a> {
        RuntimeBridgeEventContext {
            thread_id: "thread_kernel_mapper",
            turn_id: "turn_kernel_mapper",
            workspace_root: Some("/tmp/ioi"),
            created_at: "2026-05-12T00:00:00Z",
            ordinal: 7,
        }
    }

    #[test]
    fn maps_agent_thought_to_reasoning_delta() {
        let session_id = [1u8; 32];
        let event = KernelEvent::AgentThought {
            session_id,
            token: "thinking".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(mapped["source_event_kind"], "KernelEvent::AgentThought");
        assert_eq!(mapped["event_kind"], "reasoning.delta");
        assert_eq!(mapped["component_kind"], "reasoning_delta");
        assert_eq!(mapped["workflow_node_id"], "runtime.reasoning");
        assert_eq!(mapped["payload"]["session_id"], hex::encode(session_id));
        assert_eq!(mapped["payload"]["delta"], "thinking");
        assert_eq!(mapped["fixture_profile"], Value::Null);
    }

    #[test]
    fn maps_action_result_status_from_error_class() {
        let event = KernelEvent::AgentActionResult {
            session_id: [2u8; 32],
            step_index: 3,
            tool_name: "shell__run".to_string(),
            output: "permission denied".to_string(),
            error_class: Some("permission_or_approval_required".to_string()),
            agent_status: "Paused".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(
            mapped["source_event_kind"],
            "KernelEvent::AgentActionResult"
        );
        assert_eq!(mapped["event_kind"], "tool.failed");
        assert_eq!(mapped["status"], "failed");
        assert_eq!(mapped["component_kind"], "tool_result");
        assert_eq!(mapped["payload"]["tool_name"], "shell__run");
        assert_eq!(
            mapped["payload"]["error_class"],
            "permission_or_approval_required"
        );
    }

    #[test]
    fn compacts_large_tool_output_in_bridge_events() {
        let large_output = "x".repeat(BRIDGE_EVENT_TEXT_PREVIEW_BYTES * 3);
        let event = KernelEvent::AgentActionResult {
            session_id: [9u8; 32],
            step_index: 1,
            tool_name: "file__read".to_string(),
            output: large_output,
            error_class: None,
            agent_status: "Running".to_string(),
        };
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        let output = mapped["payload"]["output"].as_str().expect("string output");
        assert!(output.len() < BRIDGE_EVENT_TEXT_PREVIEW_BYTES + 128);
        assert!(output.contains("[truncated"));
        assert_eq!(
            mapped["payload"]["kernel_event"]["AgentActionResult"]["output"]["truncated"],
            true
        );
    }

    #[test]
    fn maps_firewall_interception_to_approval_or_policy() {
        let approval = KernelEvent::FirewallInterception {
            verdict: "REQUIRE_APPROVAL".to_string(),
            target: "net::fetch".to_string(),
            request_hash: [3u8; 32],
            session_id: Some([4u8; 32]),
        };
        let mapped = kernel_event_to_tti_event(&approval, &context()).expect("mapped event");
        assert_eq!(mapped["event_kind"], "approval.required");
        assert_eq!(mapped["component_kind"], "approval_required");
        assert_eq!(mapped["workflow_node_id"], "runtime.approval-gate");

        let blocked = KernelEvent::FirewallInterception {
            verdict: "BLOCK".to_string(),
            target: "fs::delete".to_string(),
            request_hash: [5u8; 32],
            session_id: None,
        };
        let mapped = kernel_event_to_tti_event(&blocked, &context()).expect("mapped event");
        assert_eq!(mapped["event_kind"], "policy.blocked");
        assert_eq!(mapped["component_kind"], "policy_blocked");
        assert_eq!(mapped["workflow_node_id"], "runtime.policy-gate");
    }

    #[test]
    fn maps_workload_receipt_to_receipt_event() {
        let event = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [6u8; 32],
            step_index: 9,
            workload_id: "workload-1".to_string(),
            timestamp_ms: 1_765_000_000_000,
            receipt: WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "shell__run".to_string(),
                command: "printf".to_string(),
                args: vec!["ok".to_string()],
                cwd: "/tmp/ioi".to_string(),
                detach: false,
                timeout_ms: 1000,
                success: true,
                exit_code: Some(0),
                error_class: None,
                command_preview: "printf ok".to_string(),
            }),
        });
        let mapped = kernel_event_to_tti_event(&event, &context()).expect("mapped event");
        assert_eq!(mapped["source_event_kind"], "KernelEvent::WorkloadReceipt");
        assert_eq!(mapped["event_kind"], "receipt.emitted");
        assert_eq!(mapped["component_kind"], "receipt");
        assert_eq!(mapped["workflow_node_id"], "runtime.receipt");
        assert_eq!(mapped["payload"]["receipt_kind"], "exec");
        assert_eq!(mapped["payload"]["tool_name"], "shell__run");
        assert_eq!(mapped["payload"]["success"], true);
    }
}
