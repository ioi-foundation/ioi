use ioi_services::agentic::runtime::kernel::policy::{
    CompactionPolicyCore, CompactionPolicyRequest, ContextBudgetPolicyCore,
    ContextBudgetPolicyRequest, ContextCompactionPlanCore, ContextCompactionPlanRequest,
    ContextCompactionStateUpdateCore, ContextCompactionStateUpdateRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct ContextBudgetPolicyBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ContextBudgetPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct CompactionPolicyBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: CompactionPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ContextCompactionPlanBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ContextCompactionPlanRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ContextCompactionStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ContextCompactionStateUpdateRequest,
}

pub(super) fn evaluate_context_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    evaluate_context_budget_policy_bridge(
        request,
        "rust_context_budget_policy_command",
        "context_budget_policy_invalid",
    )
}

pub(super) fn evaluate_coding_tool_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    evaluate_context_budget_policy_bridge(
        request,
        "rust_coding_tool_budget_policy_command",
        "coding_tool_budget_policy_invalid",
    )
}

fn evaluate_context_budget_policy_bridge(
    request: ContextBudgetPolicyBridgeRequest,
    source: &'static str,
    error_code: &'static str,
) -> Result<Value, BridgeError> {
    let record = ContextBudgetPolicyCore
        .evaluate(&request.request)
        .map_err(|error| BridgeError::new(error_code, format!("{error:?}")))?;
    Ok(json!({
        "source": source,
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "mode": record.mode.clone(),
        "usage_telemetry": record.usage_telemetry.clone(),
        "usage_summary": record.usage_summary.clone(),
        "policy_decision_id": record.policy_decision_id.clone(),
        "policy_decision": record.policy_decision.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "warnings": record.warnings.clone(),
        "violations": record.violations.clone(),
        "would_block": record.would_block,
        "runtime_event_kind": record.runtime_event_kind.clone(),
        "runtime_event_status": record.runtime_event_status.clone(),
        "runtime_event_item_id": record.runtime_event_item_id.clone(),
        "runtime_event_idempotency_key": record.runtime_event_idempotency_key.clone(),
        "summary": record.summary.clone(),
    }))
}

pub(super) fn evaluate_compaction_policy(
    request: CompactionPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = CompactionPolicyCore
        .evaluate(&request.request)
        .map_err(|error| BridgeError::new("compaction_policy_invalid", format!("{error:?}")))?;
    Ok(json!({
        "source": "rust_compaction_policy_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "action": record.action.clone(),
        "selected_action": record.selected_action.clone(),
        "budget_status": record.budget_status.clone(),
        "policy_decision_id": record.policy_decision_id.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "approval_id": record.approval_id.clone(),
        "approval_required": record.approval_required,
        "approval_granted": record.approval_granted,
        "approval_satisfied": record.approval_satisfied,
        "execute_compaction": record.execute_compaction,
        "compaction_requested": record.compaction_requested,
        "compact_reason": record.compact_reason.clone(),
        "compact_scope": record.compact_scope.clone(),
        "runtime_event_kind": record.runtime_event_kind.clone(),
        "runtime_event_status": record.runtime_event_status.clone(),
        "runtime_event_item_id": record.runtime_event_item_id.clone(),
        "runtime_event_idempotency_key": record.runtime_event_idempotency_key.clone(),
        "compact_idempotency_key": record.compact_idempotency_key.clone(),
        "compact_workflow_node_id": record.compact_workflow_node_id.clone(),
        "continuation_allowed": record.continuation_allowed,
        "summary": record.summary.clone(),
    }))
}

pub(super) fn plan_context_compaction(
    request: ContextCompactionPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ContextCompactionPlanCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("context_compaction_plan_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_context_compaction_plan_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "event_source": record.source.clone(),
        "actor": record.actor.clone(),
        "item_id": record.item_id.clone(),
        "idempotency_key": record.idempotency_key.clone(),
        "compact_hash": record.compact_hash.clone(),
        "source_event_kind": record.source_event_kind.clone(),
        "event_kind": record.event_kind.clone(),
        "component_kind": record.component_kind.clone(),
        "payload_schema_version": record.payload_schema_version.clone(),
        "payload": record.payload.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "rollback_refs": record.rollback_refs.clone(),
        "redaction_profile": record.redaction_profile.clone(),
        "reason": record.reason.clone(),
        "scope": record.scope.clone(),
        "requested_by": record.requested_by.clone(),
        "previous_latest_seq": record.previous_latest_seq,
    }))
}

pub(super) fn plan_context_compaction_state_update(
    request: ContextCompactionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ContextCompactionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "context_compaction_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_context_compaction_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "target_kind": record.target_kind.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "context_compaction": record.context_compaction.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}
