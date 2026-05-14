// apps/autopilot/src-tauri/src/project/workflow_run_policy_lane.rs

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_execution_results_lane::{
    workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_node_metadata_lane::{workflow_node_by_id, workflow_node_type};
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_value_helpers::{
    workflow_string_array_any, workflow_value_bool_any, workflow_value_string_any,
};
use super::*;
use std::collections::BTreeSet;

const WORKFLOW_CODING_TOOL_BUDGET_PREFLIGHT_SCHEMA_VERSION: &str =
    "ioi.workflow.coding-tool-budget-preflight.v1";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_EVENT_KIND: &str =
    "WorkflowRunCodingToolBudgetPreflightBlocked";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON: &str =
    "coding_tool_budget_preflight_blocked";
const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION: &str =
    "ioi.workflow.coding-tool-budget-recovery.v1";
const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION: &str =
    "ioi.workflow.coding-tool-budget-recovery-policy.v1";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_APPROVAL_EVENT_KIND: &str =
    "WorkflowRunCodingToolBudgetRecoveryApproval";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_RETRY_EVENT_KIND: &str =
    "WorkflowRunCodingToolBudgetApprovedRetry";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID: &str =
    "runtime.coding-tool-budget-recovery";
const WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_APPROVAL_NODE_ID: &str =
    "runtime.approval.coding-tool-budget-preflight";

pub(super) fn workflow_coding_tool_budget_preflight_blocked_from_options(
    options: Option<&Value>,
) -> Option<Value> {
    let preflight = options
        .and_then(|value| {
            value
                .get("codingToolBudgetPreflight")
                .or_else(|| value.get("coding_tool_budget_preflight"))
        })?
        .clone();
    (workflow_value_string_any(&preflight, &["status"]).as_deref() == Some("blocked"))
        .then_some(preflight)
}

pub(super) fn workflow_coding_tool_budget_preflight_targets_node(
    preflight: &Value,
    node_id: &str,
) -> bool {
    let target_node_ids =
        workflow_string_array_any(preflight, &["targetNodeIds", "target_node_ids"]);
    target_node_ids.is_empty() || target_node_ids.iter().any(|id| id == node_id)
}

pub(super) fn workflow_coding_tool_budget_recovery_from_options(
    options: Option<&Value>,
) -> Option<Value> {
    options
        .and_then(|value| {
            value
                .get("codingToolBudgetRecovery")
                .or_else(|| value.get("coding_tool_budget_recovery"))
        })
        .filter(|value| workflow_coding_tool_budget_recovery_action(value).is_some())
        .cloned()
}

pub(super) fn workflow_coding_tool_budget_recovery_is_approved_retry(
    recovery: Option<&Value>,
) -> bool {
    recovery
        .and_then(workflow_coding_tool_budget_recovery_action)
        .as_deref()
        == Some("retry_approved")
}

pub(super) fn workflow_coding_tool_budget_recovery_is_control_action(recovery: &Value) -> bool {
    matches!(
        workflow_coding_tool_budget_recovery_action(recovery).as_deref(),
        Some("request_approval" | "approve_override" | "reject_override")
    )
}

pub(super) fn workflow_coding_tool_budget_preflight_blocked_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    mut thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    preflight: Value,
    target_node_id: Option<&str>,
) -> Result<WorkflowRunResult, String> {
    let started_at_ms = now_ms();
    let finished_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run-policy");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    state.step_index = state.step_index.max(1);

    let mut target_node_ids =
        workflow_string_array_any(&preflight, &["targetNodeIds", "target_node_ids"]);
    if let Some(node_id) = target_node_id {
        target_node_ids = vec![node_id.to_string()];
    }
    let target_node_ids = target_node_ids
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    state.blocked_node_ids = target_node_ids.clone();
    state
        .values
        .insert("codingToolBudgetPreflight".to_string(), preflight.clone());

    let tool_names = workflow_string_array_any(&preflight, &["toolNames", "tool_names"]);
    let tool_call_ids = workflow_string_array_any(&preflight, &["toolCallIds", "tool_call_ids"]);
    let budget_statuses =
        workflow_string_array_any(&preflight, &["budgetStatuses", "budget_statuses"]);
    let context_budget_statuses = workflow_string_array_any(
        &preflight,
        &["contextBudgetStatuses", "context_budget_statuses"],
    );
    let mut receipt_refs = workflow_string_array_any(&preflight, &["receiptRefs", "receipt_refs"]);
    receipt_refs.push(format!(
        "receipt_workflow_run_coding_tool_budget_preflight_{}",
        run_id
    ));
    receipt_refs.sort();
    receipt_refs.dedup();
    let mut policy_decision_refs =
        workflow_string_array_any(&preflight, &["policyDecisionRefs", "policy_decision_refs"]);
    policy_decision_refs.push(format!(
        "policy_workflow_run_coding_tool_budget_preflight_blocked_{}",
        run_id
    ));
    policy_decision_refs.sort();
    policy_decision_refs.dedup();

    let issue_code = workflow_value_string_any(&preflight, &["issueCode", "issue_code"])
        .unwrap_or_else(|| "prior_coding_tool_budget_evidence".to_string());
    let issue_message = workflow_value_string_any(&preflight, &["issueMessage", "issue_message"])
        .unwrap_or_else(|| {
            "Workflow run blocked by coding-tool budget preflight evidence.".to_string()
        });
    let tool_name = tool_names.first().cloned();
    let tool_call_id = tool_call_ids.first().cloned();
    let budget_status = budget_statuses
        .first()
        .cloned()
        .unwrap_or_else(|| "exceeded".to_string());
    let context_budget_status = context_budget_statuses
        .first()
        .cloned()
        .unwrap_or_else(|| "blocked".to_string());
    let budget_mode = "block";
    let total_tokens = workflow_preflight_value_any(&preflight, &["totalTokens", "total_tokens"]);
    let cost_estimate_usd =
        workflow_preflight_value_any(&preflight, &["costEstimateUsd", "cost_estimate_usd"]);
    let context_pressure =
        workflow_preflight_value_any(&preflight, &["contextPressure", "context_pressure"]);
    let context_pressure_status = workflow_value_string_any(
        &preflight,
        &["contextPressureStatus", "context_pressure_status"],
    );
    let mutation_blocked =
        workflow_value_bool_any(&preflight, &["mutationBlocked", "mutation_blocked"])
            .unwrap_or(true);
    let recovery_policy =
        workflow_coding_tool_budget_recovery_policy_from_value(&preflight, &target_node_ids)
            .unwrap_or_else(|| {
                workflow_coding_tool_budget_recovery_default_policy(&target_node_ids)
            });
    let runtime_event_id = unique_runtime_id("runtime-event");
    let cursor = format!("workflow_run_policy:{}:1", run_id);
    let runtime_workflow_node_id = target_node_id
        .map(str::to_string)
        .or_else(|| target_node_ids.first().cloned())
        .unwrap_or_else(|| "runtime.coding-tool-budget-preflight".to_string());
    let policy_payload = json!({
        "schemaVersion": WORKFLOW_CODING_TOOL_BUDGET_PREFLIGHT_SCHEMA_VERSION,
        "eventKind": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_EVENT_KIND,
        "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        "sourceKind": "tui_coding_tool_rows",
        "status": "blocked",
        "summary": issue_message.clone(),
        "issueCode": issue_code.clone(),
        "issueMessage": issue_message.clone(),
        "targetNodeIds": target_node_ids.clone(),
        "evidenceWorkflowNodeIds": workflow_string_array_any(&preflight, &["evidenceWorkflowNodeIds", "evidence_workflow_node_ids"]),
        "eventIds": workflow_string_array_any(&preflight, &["eventIds", "event_ids"]),
        "toolNames": tool_names.clone(),
        "toolCallIds": tool_call_ids.clone(),
        "toolName": tool_name.clone(),
        "toolCallId": tool_call_id.clone(),
        "budgetStatuses": budget_statuses.clone(),
        "contextBudgetStatuses": context_budget_statuses.clone(),
        "budgetStatus": budget_status.clone(),
        "contextBudgetStatus": context_budget_status.clone(),
        "budgetMode": budget_mode,
        "totalTokens": total_tokens.clone(),
        "costEstimateUsd": cost_estimate_usd.clone(),
        "contextPressure": context_pressure.clone(),
        "contextPressureStatus": context_pressure_status.clone(),
        "mutationBlocked": mutation_blocked,
        "receiptRefs": receipt_refs.clone(),
        "policyDecisionRefs": policy_decision_refs.clone(),
        "recoveryPolicy": recovery_policy.clone(),
        "recovery_policy": recovery_policy.clone(),
        "resultSummary": {
            "status": "blocked",
            "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON
        },
        "result": {
            "status": "blocked",
            "budgetStatus": budget_status.clone(),
            "contextBudgetStatus": context_budget_status.clone(),
            "mutationBlocked": mutation_blocked
        },
        "contextBudget": {
            "status": context_budget_status.clone(),
            "mode": budget_mode,
            "policyDecisionId": policy_decision_refs.first().cloned(),
            "receiptRefs": receipt_refs.clone(),
            "policyDecisionRefs": policy_decision_refs.clone(),
            "checks": [{
                "id": "workflow_run_launch",
                "severity": "violation",
                "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON
            }],
            "violations": [{
                "id": "workflow_run_launch",
                "severity": "violation",
                "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON
            }],
            "usageSummary": {
                "totalTokens": total_tokens.clone(),
                "costEstimateUsd": cost_estimate_usd.clone(),
                "contextPressure": context_pressure.clone(),
                "contextPressureStatus": context_pressure_status.clone()
            }
        },
        "budgetUsageTelemetry": {
            "totalTokens": total_tokens.clone(),
            "costEstimateUsd": cost_estimate_usd.clone(),
            "contextPressure": context_pressure.clone(),
            "contextPressureStatus": context_pressure_status.clone()
        },
        "preflight": preflight.clone()
    });

    let mut events = Vec::new();
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_started",
        None,
        Some("running"),
        Some("Workflow run started.".to_string()),
        None,
    );
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "policy_blocked",
        target_node_id,
        Some("blocked"),
        Some(issue_message.clone()),
        Some(vec![WorkflowStateUpdate {
            node_id: runtime_workflow_node_id.clone(),
            key: "codingToolBudgetPreflight".to_string(),
            value: policy_payload.clone(),
            reducer: "replace".to_string(),
        }]),
    );

    let mut checkpoints = Vec::new();
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        target_node_id,
        "blocked",
        issue_message.clone(),
        &mut checkpoints,
    )?;
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some("blocked"),
        Some("Workflow run blocked by coding-tool budget preflight.".to_string()),
        None,
    );

    let mut node_runs = Vec::new();
    for node_id in &state.blocked_node_ids {
        let Some(node) = workflow_node_by_id(workflow, node_id) else {
            continue;
        };
        node_runs.push(WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: workflow_node_type(node),
            status: "blocked".to_string(),
            started_at_ms,
            finished_at_ms: Some(finished_at_ms),
            attempt: 1,
            input: Some(policy_payload.clone()),
            output: None,
            error: Some(issue_message.clone()),
            checkpoint_id: Some(checkpoint_id.clone()),
            lifecycle: workflow_node_lifecycle_steps("blocked"),
            harness_attempt: None,
        });
    }

    let runtime_thread_events = vec![json!({
        "id": runtime_event_id.clone(),
        "cursor": cursor.clone(),
        "seq": 1,
        "threadId": thread_id.clone(),
        "turnId": Value::Null,
        "type": "policy_blocked",
        "eventKind": "policy.blocked",
        "sourceEventKind": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_EVENT_KIND,
        "status": "blocked",
        "componentKind": "coding_tool",
        "workflowNodeId": runtime_workflow_node_id.clone(),
        "workflowGraphId": workflow.metadata.id.clone(),
        "toolName": tool_name.clone(),
        "toolCallId": tool_call_id.clone(),
        "payloadSchemaVersion": WORKFLOW_CODING_TOOL_BUDGET_PREFLIGHT_SCHEMA_VERSION,
        "receiptRefs": receipt_refs.clone(),
        "artifactRefs": [],
        "policyDecisionRefs": policy_decision_refs.clone(),
        "rollbackRefs": [],
        "payload": policy_payload.clone()
    })];
    let tui_control_state = Some(json!({
        "schemaVersion": "ioi.workflow.runtime-tui-control-state.v1",
        "sourceSchemaVersion": WORKFLOW_CODING_TOOL_BUDGET_PREFLIGHT_SCHEMA_VERSION,
        "surface": "workflow_run",
        "threadId": thread.id.clone(),
        "workflowGraphId": workflow.metadata.id.clone(),
        "currentTurnId": Value::Null,
        "lastCursor": cursor.clone(),
        "lastEventId": runtime_event_id.clone(),
        "codingToolRows": [{
            "id": format!("workflow-run-coding-tool-budget-preflight-{}", run_id),
            "status": "blocked",
            "label": "Coding tool budget: run launch",
            "command": "run",
            "rawInput": "/workflow run",
            "message": issue_message.clone(),
            "workflowNodeId": runtime_workflow_node_id.clone(),
            "workflowGraphId": workflow.metadata.id.clone(),
            "eventId": runtime_event_id.clone(),
            "cursor": cursor.clone(),
            "sequence": 1,
            "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
            "budgetStatus": budget_status.clone(),
            "contextBudgetStatus": context_budget_status.clone(),
            "mutationBlocked": mutation_blocked,
            "toolName": tool_name.clone(),
            "toolCallId": tool_call_id.clone(),
            "totalTokens": total_tokens.clone(),
            "costEstimateUsd": cost_estimate_usd.clone(),
            "contextPressure": context_pressure.clone(),
            "contextPressureStatus": context_pressure_status.clone(),
            "receiptRefs": receipt_refs.clone(),
            "policyDecisionRefs": policy_decision_refs.clone(),
            "recoveryPolicy": recovery_policy.clone(),
            "recovery_policy": recovery_policy.clone(),
            "contextBudget": {
                "status": context_budget_status.clone(),
                "mode": budget_mode,
                "policyDecisionId": policy_decision_refs.first().cloned(),
                "checks": [{
                    "id": "workflow_run_launch",
                    "severity": "violation",
                    "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON
                }],
                "violations": [{
                    "id": "workflow_run_launch",
                    "severity": "violation",
                    "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON
                }],
                "usageSummary": {
                    "totalTokens": total_tokens.clone(),
                    "costEstimateUsd": cost_estimate_usd.clone(),
                    "contextPressure": context_pressure.clone(),
                    "contextPressureStatus": context_pressure_status.clone()
                }
            }
        }],
        "commandHistory": [{
            "id": format!("workflow-run-policy-command-{}", run_id),
            "command": "run",
            "rawInput": "/workflow run",
            "status": "blocked",
            "sequence": 1,
            "message": "Workflow run blocked by coding-tool budget preflight."
        }]
    }));

    thread.status = "blocked".to_string();
    thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &thread)?;

    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id),
        status: "blocked".to_string(),
        started_at_ms,
        finished_at_ms: Some(finished_at_ms),
        node_count: workflow.nodes.len(),
        test_count: Some(test_count),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: "Workflow run blocked by coding-tool budget preflight.".to_string(),
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };

    workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary,
            thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            runtime_thread_events,
            tui_control_state,
            harness_attempts: Vec::new(),
            harness_shadow_comparisons: Vec::new(),
            harness_gated_cluster_runs: Vec::new(),
            completion_requirements: Vec::new(),
            interrupt: None,
        },
    )
}

pub(super) fn workflow_coding_tool_budget_recovery_control_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    mut thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    recovery: Value,
    target_node_id: Option<&str>,
) -> Result<WorkflowRunResult, String> {
    let action = workflow_coding_tool_budget_recovery_action(&recovery)
        .ok_or_else(|| "Coding-tool budget recovery action is required.".to_string())?;
    if !workflow_coding_tool_budget_recovery_is_control_action(&recovery) {
        return Err(format!(
            "Coding-tool budget recovery action '{}' is not a control action.",
            action
        ));
    }
    let started_at_ms = now_ms();
    let finished_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run-policy");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    state.step_index = state.step_index.max(1);
    state
        .values
        .insert("codingToolBudgetRecovery".to_string(), recovery.clone());

    let mut target_node_ids =
        workflow_string_array_any(&recovery, &["targetNodeIds", "target_node_ids"]);
    if let Some(node_id) = target_node_id {
        target_node_ids = vec![node_id.to_string()];
    }
    let mut target_node_ids = target_node_ids
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut runtime_thread_events = workflow_coding_tool_budget_recovery_prior_events(&recovery);
    let recovery_policy = workflow_coding_tool_budget_recovery_policy_from_recovery(
        &recovery,
        &runtime_thread_events,
        &target_node_ids,
    );
    let policy_target_node_ids =
        workflow_string_array_any(&recovery_policy, &["targetNodeIds", "target_node_ids"]);
    if target_node_ids.is_empty() && !policy_target_node_ids.is_empty() {
        target_node_ids = policy_target_node_ids;
    }
    state.blocked_node_ids = target_node_ids.clone();
    let next_seq = workflow_coding_tool_budget_recovery_next_seq(&runtime_thread_events);
    let event_id = unique_runtime_id("runtime-event");
    let cursor = format!("workflow_run_recovery:{}:{}", run_id, next_seq);
    let source_event_id = workflow_value_string_any(
        &recovery,
        &[
            "sourceEventId",
            "source_event_id",
            "blockedEventId",
            "blocked_event_id",
        ],
    )
    .or_else(|| {
        runtime_thread_events
            .iter()
            .find(|event| {
                event
                    .get("payload")
                    .and_then(|payload| {
                        workflow_value_string_any(
                            payload,
                            &["reason", "blockReason", "block_reason"],
                        )
                    })
                    .as_deref()
                    == Some(WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON)
            })
            .and_then(|event| event.get("id").and_then(Value::as_str).map(str::to_string))
    });
    let approval_id = workflow_coding_tool_budget_recovery_approval_id(
        &recovery,
        &run_id,
        source_event_id.as_deref(),
    );
    let workflow_node_id =
        workflow_value_string_any(&recovery, &["workflowNodeId", "workflow_node_id"])
            .unwrap_or_else(|| {
                WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_APPROVAL_NODE_ID.to_string()
            });
    let approved = action == "approve_override";
    let rejected = action == "reject_override";
    if approved
        && !workflow_value_bool_any(&recovery_policy, &["allowOverride", "allow_override"])
            .unwrap_or(true)
    {
        return Err(
            "Coding-tool budget recovery override is disabled by workflow-authored policy."
                .to_string(),
        );
    }
    let (event_type, event_kind, source_event_kind, status, decision) = if approved {
        (
            "approval_decision",
            "approval.approved",
            "OperatorApproval.Approve",
            "approved",
            Some("approve"),
        )
    } else if rejected {
        (
            "approval_decision",
            "approval.rejected",
            "OperatorApproval.Reject",
            "rejected",
            Some("reject"),
        )
    } else {
        (
            "approval_required",
            "approval.required",
            "OperatorApproval.Request",
            "waiting_for_approval",
            None,
        )
    };
    let mut receipt_refs = workflow_string_array_any(&recovery, &["receiptRefs", "receipt_refs"]);
    receipt_refs.extend(workflow_coding_tool_budget_recovery_event_refs(
        &runtime_thread_events,
        "receiptRefs",
    ));
    receipt_refs.push(format!(
        "receipt_workflow_run_coding_tool_budget_recovery_{}_{}",
        action, run_id
    ));
    receipt_refs.sort();
    receipt_refs.dedup();
    let mut policy_decision_refs =
        workflow_string_array_any(&recovery, &["policyDecisionRefs", "policy_decision_refs"]);
    policy_decision_refs.extend(workflow_coding_tool_budget_recovery_event_refs(
        &runtime_thread_events,
        "policyDecisionRefs",
    ));
    policy_decision_refs.push(format!(
        "policy_workflow_run_coding_tool_budget_recovery_{}_{}",
        action, run_id
    ));
    policy_decision_refs.sort();
    policy_decision_refs.dedup();

    let summary = if approved {
        "Coding-tool budget recovery override approved; retry is now available."
    } else if rejected {
        "Coding-tool budget recovery override rejected; run remains blocked."
    } else {
        "Coding-tool budget recovery approval requested; run remains blocked."
    };
    let manifest = json!({
        "schemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
        "schema_version": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
        "action": "workflow_run.coding_budget_recovery",
        "recoveryAction": action,
        "recovery_action": action,
        "approvalId": approval_id.clone(),
        "approval_id": approval_id.clone(),
        "sourceEventId": source_event_id.clone(),
        "source_event_id": source_event_id.clone(),
        "targetNodeIds": target_node_ids.clone(),
        "target_node_ids": target_node_ids.clone(),
        "preflightReason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        "preflight_reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        "receiptRefs": receipt_refs.clone(),
        "receipt_refs": receipt_refs.clone(),
        "policyDecisionRefs": policy_decision_refs.clone(),
        "policy_decision_refs": policy_decision_refs.clone(),
        "recoveryPolicy": recovery_policy.clone(),
        "recovery_policy": recovery_policy.clone(),
        "overridePolicy": "operator_approval_required",
        "override_policy": "operator_approval_required"
    });
    runtime_thread_events.push(json!({
        "id": event_id.clone(),
        "cursor": cursor.clone(),
        "seq": next_seq,
        "threadId": thread_id.clone(),
        "turnId": Value::Null,
        "type": event_type,
        "eventKind": event_kind,
        "sourceEventKind": source_event_kind,
        "status": status,
        "componentKind": "approval_gate",
        "workflowNodeId": workflow_node_id.clone(),
        "workflowGraphId": workflow.metadata.id.clone(),
        "approvalId": approval_id.clone(),
        "payloadSchemaVersion": if decision.is_some() { "ioi.runtime.approval-decision.v1" } else { "ioi.runtime.approval-request.v1" },
        "receiptRefs": receipt_refs.clone(),
        "artifactRefs": [],
        "policyDecisionRefs": policy_decision_refs.clone(),
        "rollbackRefs": [],
        "payload": {
            "schemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
            "eventKind": source_event_kind,
            "sourceEventKind": WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_APPROVAL_EVENT_KIND,
            "action": "workflow_run.coding_budget_recovery",
            "recoveryAction": action,
            "recovery_action": action,
            "status": status,
            "decision": decision,
            "approvalId": approval_id.clone(),
            "approval_id": approval_id.clone(),
            "approval_required": true,
            "approvalRequired": true,
            "approval_satisfied": approved,
            "approvalSatisfied": approved,
            "approval_request_event_id": workflow_value_string_any(&recovery, &["approvalRequestEventId", "approval_request_event_id"]).or_else(|| source_event_id.clone()),
            "approvalRequestEventId": workflow_value_string_any(&recovery, &["approvalRequestEventId", "approval_request_event_id"]).or_else(|| source_event_id.clone()),
            "sourceEventId": source_event_id.clone(),
            "source_event_id": source_event_id.clone(),
            "summary": summary,
            "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
            "approval_manifest": manifest.clone(),
            "approvalManifest": manifest.clone(),
            "targetNodeIds": target_node_ids.clone(),
            "target_node_ids": target_node_ids.clone(),
            "recoveryPolicy": recovery_policy.clone(),
            "recovery_policy": recovery_policy.clone(),
            "receiptRefs": receipt_refs.clone(),
            "receipt_refs": receipt_refs.clone(),
            "policyDecisionRefs": policy_decision_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone()
        }
    }));

    let mut events = Vec::new();
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_started",
        None,
        Some("running"),
        Some("Workflow run started.".to_string()),
        None,
    );
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        if decision.is_some() {
            "approval_decision"
        } else {
            "approval_required"
        },
        target_node_id,
        Some(status),
        Some(summary.to_string()),
        Some(vec![WorkflowStateUpdate {
            node_id: workflow_node_id.clone(),
            key: "codingToolBudgetRecovery".to_string(),
            value: manifest.clone(),
            reducer: "replace".to_string(),
        }]),
    );
    let mut checkpoints = Vec::new();
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        target_node_id,
        "blocked",
        summary.to_string(),
        &mut checkpoints,
    )?;
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some("blocked"),
        Some(summary.to_string()),
        None,
    );

    let mut node_runs = Vec::new();
    for node_id in &state.blocked_node_ids {
        let Some(node) = workflow_node_by_id(workflow, node_id) else {
            continue;
        };
        node_runs.push(WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: workflow_node_type(node),
            status: "blocked".to_string(),
            started_at_ms,
            finished_at_ms: Some(finished_at_ms),
            attempt: 1,
            input: Some(manifest.clone()),
            output: None,
            error: Some(summary.to_string()),
            checkpoint_id: Some(checkpoint_id.clone()),
            lifecycle: workflow_node_lifecycle_steps("blocked"),
            harness_attempt: None,
        });
    }

    thread.status = "blocked".to_string();
    thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &thread)?;
    let summary_record = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id.clone()),
        status: "blocked".to_string(),
        started_at_ms,
        finished_at_ms: Some(finished_at_ms),
        node_count: workflow.nodes.len(),
        test_count: Some(test_count),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: summary.to_string(),
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };

    workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary: summary_record,
            thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            runtime_thread_events,
            tui_control_state: Some(workflow_coding_tool_budget_recovery_tui_state(
                &thread_id,
                workflow,
                &run_id,
                &cursor,
                &event_id,
                &workflow_node_id,
                &approval_id,
                &action,
                status,
                source_event_id.as_deref(),
                &target_node_ids,
                &receipt_refs,
                &policy_decision_refs,
            )),
            harness_attempts: Vec::new(),
            harness_shadow_comparisons: Vec::new(),
            harness_gated_cluster_runs: Vec::new(),
            completion_requirements: Vec::new(),
            interrupt: None,
        },
    )
}

pub(super) fn workflow_attach_coding_tool_budget_recovery_retry(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    mut result: WorkflowRunResult,
    recovery: Value,
    target_node_id: Option<&str>,
) -> Result<WorkflowRunResult, String> {
    if !workflow_coding_tool_budget_recovery_is_approved_retry(Some(&recovery)) {
        return Ok(result);
    }
    let mut runtime_thread_events = workflow_coding_tool_budget_recovery_prior_events(&recovery);
    let next_seq = workflow_coding_tool_budget_recovery_next_seq(&runtime_thread_events);
    let event_id = unique_runtime_id("runtime-event");
    let cursor = format!("workflow_run_recovery:{}:{}", result.summary.id, next_seq);
    let approval_id = workflow_coding_tool_budget_recovery_approval_id(
        &recovery,
        &result.summary.id,
        workflow_value_string_any(&recovery, &["sourceEventId", "source_event_id"]).as_deref(),
    );
    let approval_decision_event_id = workflow_value_string_any(
        &recovery,
        &["approvalDecisionEventId", "approval_decision_event_id"],
    );
    let mut target_node_ids = target_node_id
        .map(|node_id| vec![node_id.to_string()])
        .unwrap_or_else(|| {
            workflow_string_array_any(&recovery, &["targetNodeIds", "target_node_ids"])
        });
    let recovery_policy = workflow_coding_tool_budget_recovery_policy_from_recovery(
        &recovery,
        &runtime_thread_events,
        &target_node_ids,
    );
    let policy_target_node_ids =
        workflow_string_array_any(&recovery_policy, &["targetNodeIds", "target_node_ids"]);
    if target_node_ids.is_empty() && !policy_target_node_ids.is_empty() {
        target_node_ids = policy_target_node_ids;
    }
    let retry_limit =
        workflow_value_u64_any(&recovery_policy, &["retryLimit", "retry_limit"]).unwrap_or(1);
    let prior_retry_count =
        workflow_coding_tool_budget_recovery_retry_count(&runtime_thread_events);
    if prior_retry_count >= retry_limit {
        return Err(format!(
            "Coding-tool budget recovery retry limit exhausted: {} of {} retries already recorded.",
            prior_retry_count, retry_limit
        ));
    }
    let receipt_refs = unique_workflow_strings([
        workflow_string_array_any(&recovery, &["receiptRefs", "receipt_refs"]),
        workflow_coding_tool_budget_recovery_event_refs(&runtime_thread_events, "receiptRefs"),
        vec![format!(
            "receipt_workflow_run_coding_tool_budget_recovery_retry_{}",
            result.summary.id
        )],
    ]);
    let policy_decision_refs = unique_workflow_strings([
        workflow_string_array_any(&recovery, &["policyDecisionRefs", "policy_decision_refs"]),
        workflow_coding_tool_budget_recovery_event_refs(
            &runtime_thread_events,
            "policyDecisionRefs",
        ),
        vec![format!(
            "policy_workflow_run_coding_tool_budget_recovery_retry_{}",
            result.summary.id
        )],
    ]);
    let workflow_node_id =
        workflow_value_string_any(&recovery, &["workflowNodeId", "workflow_node_id"])
            .or_else(|| target_node_ids.first().cloned())
            .unwrap_or_else(|| {
                WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID.to_string()
            });
    runtime_thread_events.push(json!({
        "id": event_id.clone(),
        "cursor": cursor.clone(),
        "seq": next_seq,
        "threadId": result.thread.id.clone(),
        "turnId": Value::Null,
        "type": "tool_completed",
        "eventKind": "workflow.run.retry_completed",
        "sourceEventKind": WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_RETRY_EVENT_KIND,
        "status": "completed",
        "componentKind": "coding_tool",
        "workflowNodeId": workflow_node_id.clone(),
        "workflowGraphId": workflow.metadata.id.clone(),
        "approvalId": approval_id.clone(),
        "payloadSchemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
        "receiptRefs": receipt_refs.clone(),
        "artifactRefs": [],
        "policyDecisionRefs": policy_decision_refs.clone(),
        "rollbackRefs": [],
        "payload": {
            "schemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
            "eventKind": WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_RETRY_EVENT_KIND,
            "action": "retry_approved",
            "status": "completed",
            "approvalId": approval_id.clone(),
            "approval_id": approval_id.clone(),
            "approvalSatisfied": true,
            "approval_satisfied": true,
            "approvalDecisionEventId": approval_decision_event_id.clone(),
            "approval_decision_event_id": approval_decision_event_id.clone(),
            "targetNodeIds": target_node_ids.clone(),
            "target_node_ids": target_node_ids.clone(),
            "recoveryPolicy": recovery_policy.clone(),
            "recovery_policy": recovery_policy.clone(),
            "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
            "summary": "Workflow run retried after coding-tool budget recovery approval."
        }
    }));
    let raw_input = workflow_coding_tool_budget_recovery_tui_raw_input(
        "retry_approved",
        &result.summary.id,
        &approval_id,
    );
    result.runtime_thread_events = runtime_thread_events;
    result.tui_control_state = Some(json!({
        "schemaVersion": "ioi.workflow.runtime-tui-control-state.v1",
        "sourceSchemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
        "surface": "workflow_run",
        "threadId": result.thread.id.clone(),
        "workflowGraphId": workflow.metadata.id.clone(),
        "currentTurnId": Value::Null,
        "lastCursor": cursor,
        "lastEventId": event_id,
        "approvalDecisions": [{
            "id": format!("workflow-run-coding-tool-budget-retry-{}", result.summary.id),
            "approvalId": approval_id,
            "decision": "retry_approved",
            "status": "completed",
            "message": "Workflow run retried after coding-tool budget recovery approval.",
            "command": "run",
            "rawInput": raw_input,
            "workflowNodeId": workflow_node_id,
            "eventId": event_id,
            "receiptRefs": receipt_refs,
            "policyDecisionRefs": policy_decision_refs,
            "recoveryPolicy": recovery_policy,
            "sequence": next_seq
        }],
        "commandHistory": [{
            "id": format!("workflow-run-coding-tool-budget-retry-command-{}", result.summary.id),
            "command": "run",
            "rawInput": raw_input,
            "status": "completed",
            "sequence": next_seq,
            "message": "Workflow run retried after coding-tool budget recovery approval."
        }]
    }));
    save_workflow_run_result(workflow_path, &result)?;
    Ok(result)
}

fn workflow_preflight_value_any(value: &Value, keys: &[&str]) -> Value {
    keys.iter()
        .find_map(|key| value.get(*key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn workflow_coding_tool_budget_recovery_default_policy(target_node_ids: &[String]) -> Value {
    workflow_coding_tool_budget_recovery_normalize_policy(
        &json!({
            "source": "daemon_default",
            "approvalScope": "target_nodes",
            "operatorRole": "operator",
            "retryLimit": 1,
            "ttlMs": 900000,
            "requiresApproval": true,
            "allowOverride": true,
            "targetNodeIds": target_node_ids
        }),
        target_node_ids,
    )
}

fn workflow_coding_tool_budget_recovery_policy_from_recovery(
    recovery: &Value,
    runtime_thread_events: &[Value],
    fallback_target_node_ids: &[String],
) -> Value {
    workflow_coding_tool_budget_recovery_policy_from_value(recovery, fallback_target_node_ids)
        .or_else(|| {
            runtime_thread_events.iter().rev().find_map(|event| {
                event.get("payload").and_then(|payload| {
                    workflow_coding_tool_budget_recovery_policy_from_value(
                        payload,
                        fallback_target_node_ids,
                    )
                })
            })
        })
        .unwrap_or_else(|| {
            workflow_coding_tool_budget_recovery_default_policy(fallback_target_node_ids)
        })
}

fn workflow_coding_tool_budget_recovery_policy_from_value(
    value: &Value,
    fallback_target_node_ids: &[String],
) -> Option<Value> {
    let policy = if workflow_value_string_any(value, &["schemaVersion", "schema_version"])
        .as_deref()
        == Some(WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION)
    {
        Some(value)
    } else {
        value
            .get("recoveryPolicy")
            .or_else(|| value.get("recovery_policy"))
            .or_else(|| value.get("codingToolBudgetRecoveryPolicy"))
            .or_else(|| value.get("coding_tool_budget_recovery_policy"))
            .or_else(|| {
                value.get("preflight").and_then(|preflight| {
                    preflight
                        .get("recoveryPolicy")
                        .or_else(|| preflight.get("recovery_policy"))
                })
            })
            .or_else(|| {
                value
                    .get("approvalManifest")
                    .or_else(|| value.get("approval_manifest"))
                    .and_then(|manifest| {
                        manifest
                            .get("recoveryPolicy")
                            .or_else(|| manifest.get("recovery_policy"))
                    })
            })
    }?;
    Some(workflow_coding_tool_budget_recovery_normalize_policy(
        policy,
        fallback_target_node_ids,
    ))
}

fn workflow_coding_tool_budget_recovery_normalize_policy(
    policy: &Value,
    fallback_target_node_ids: &[String],
) -> Value {
    let target_node_ids = {
        let configured = workflow_string_array_any(policy, &["targetNodeIds", "target_node_ids"]);
        if configured.is_empty() {
            fallback_target_node_ids.to_vec()
        } else {
            configured
        }
    };
    let source_node_ids = workflow_string_array_any(policy, &["sourceNodeIds", "source_node_ids"]);
    let approval_scope = workflow_value_string_any(policy, &["approvalScope", "approval_scope"])
        .unwrap_or_else(|| "target_nodes".to_string());
    let operator_role = workflow_value_string_any(policy, &["operatorRole", "operator_role"])
        .unwrap_or_else(|| "operator".to_string());
    let retry_limit = workflow_value_u64_any(policy, &["retryLimit", "retry_limit"]).unwrap_or(1);
    let ttl_ms = workflow_value_u64_any(policy, &["ttlMs", "ttl_ms"]).unwrap_or(900000);
    let requires_approval =
        workflow_value_bool_any(policy, &["requiresApproval", "requires_approval"]).unwrap_or(true);
    let allow_override =
        workflow_value_bool_any(policy, &["allowOverride", "allow_override"]).unwrap_or(true);
    let source = workflow_value_string_any(policy, &["source"])
        .unwrap_or_else(|| "react_flow_coding_tool_pack".to_string());
    json!({
        "schemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
        "schema_version": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
        "source": source,
        "approvalScope": approval_scope,
        "approval_scope": approval_scope,
        "operatorRole": operator_role,
        "operator_role": operator_role,
        "retryLimit": retry_limit,
        "retry_limit": retry_limit,
        "ttlMs": ttl_ms,
        "ttl_ms": ttl_ms,
        "requiresApproval": requires_approval,
        "requires_approval": requires_approval,
        "allowOverride": allow_override,
        "allow_override": allow_override,
        "targetNodeIds": target_node_ids.clone(),
        "target_node_ids": target_node_ids,
        "sourceNodeIds": source_node_ids.clone(),
        "source_node_ids": source_node_ids
    })
}

fn workflow_value_u64_any(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|candidate| {
            candidate.as_u64().or_else(|| {
                candidate
                    .as_str()
                    .and_then(|text| text.trim().parse::<u64>().ok())
            })
        })
    })
}

fn workflow_coding_tool_budget_recovery_retry_count(events: &[Value]) -> u64 {
    events
        .iter()
        .filter(|event| {
            event.get("sourceEventKind").and_then(Value::as_str)
                == Some(WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_RETRY_EVENT_KIND)
                || event.get("eventKind").and_then(Value::as_str)
                    == Some("workflow.run.retry_completed")
        })
        .count() as u64
}

fn workflow_coding_tool_budget_recovery_action(recovery: &Value) -> Option<String> {
    workflow_value_string_any(recovery, &["action", "recoveryAction", "recovery_action"])
        .map(|value| value.replace('-', "_"))
        .filter(|value| {
            matches!(
                value.as_str(),
                "request_approval" | "approve_override" | "reject_override" | "retry_approved"
            )
        })
}

fn workflow_coding_tool_budget_recovery_prior_events(recovery: &Value) -> Vec<Value> {
    let mut events = recovery
        .get("recoveryEvents")
        .or_else(|| recovery.get("recovery_events"))
        .or_else(|| recovery.get("runtimeThreadEvents"))
        .or_else(|| recovery.get("runtime_thread_events"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.is_object())
                .cloned()
                .collect()
        })
        .unwrap_or_else(Vec::new);
    events.sort_by_key(|event| event.get("seq").and_then(Value::as_u64).unwrap_or(0));
    let mut seen = BTreeSet::new();
    events
        .into_iter()
        .filter(|event| {
            let id = event
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            !id.is_empty() && seen.insert(id)
        })
        .collect()
}

fn workflow_coding_tool_budget_recovery_next_seq(events: &[Value]) -> u64 {
    events
        .iter()
        .filter_map(|event| event.get("seq").and_then(Value::as_u64))
        .max()
        .unwrap_or(0)
        + 1
}

fn workflow_coding_tool_budget_recovery_event_refs(events: &[Value], key: &str) -> Vec<String> {
    events
        .iter()
        .flat_map(|event| {
            event
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn workflow_coding_tool_budget_recovery_approval_id(
    recovery: &Value,
    run_id: &str,
    source_event_id: Option<&str>,
) -> String {
    workflow_value_string_any(recovery, &["approvalId", "approval_id"]).unwrap_or_else(|| {
        format!(
            "approval_workflow_run_coding_tool_budget_{}_{}",
            run_id,
            source_event_id.unwrap_or("source")
        )
    })
}

fn workflow_coding_tool_budget_recovery_tui_raw_input(
    action: &str,
    run_id: &str,
    approval_id: &str,
) -> String {
    match action {
        "request_approval" => format!("/run recovery request {run_id} {approval_id}"),
        "approve_override" => format!("/run recovery approve {run_id} {approval_id}"),
        "reject_override" => format!("/run recovery reject {run_id} {approval_id}"),
        "retry_approved" => format!("/run recovery retry-approved {run_id} {approval_id}"),
        other => format!("/run recovery {other} {run_id} {approval_id}"),
    }
}

fn workflow_coding_tool_budget_recovery_tui_state(
    thread_id: &str,
    workflow: &WorkflowProject,
    run_id: &str,
    cursor: &str,
    event_id: &str,
    workflow_node_id: &str,
    approval_id: &str,
    action: &str,
    status: &str,
    source_event_id: Option<&str>,
    target_node_ids: &[String],
    receipt_refs: &[String],
    policy_decision_refs: &[String],
) -> Value {
    let raw_input = workflow_coding_tool_budget_recovery_tui_raw_input(action, run_id, approval_id);
    let approval_rows = if action == "request_approval" {
        json!([{
            "id": format!("workflow-run-coding-tool-budget-approval-{}", approval_id),
            "approvalId": approval_id,
            "status": status,
            "message": "Coding-tool budget recovery requires operator approval.",
            "workflowNodeId": workflow_node_id,
            "eventId": event_id,
            "receiptRefs": receipt_refs,
            "policyDecisionRefs": policy_decision_refs,
            "sequence": 1
        }])
    } else {
        json!([])
    };
    let approval_decisions = if action != "request_approval" {
        json!([{
            "id": format!("workflow-run-coding-tool-budget-decision-{}", approval_id),
            "approvalId": approval_id,
            "decision": if action == "reject_override" { "reject" } else { "approve" },
            "status": status,
            "message": "Coding-tool budget recovery decision recorded.",
            "workflowNodeId": workflow_node_id,
            "eventId": event_id,
            "receiptRefs": receipt_refs,
            "policyDecisionRefs": policy_decision_refs,
            "sequence": 1
        }])
    } else {
        json!([])
    };
    json!({
        "schemaVersion": "ioi.workflow.runtime-tui-control-state.v1",
        "sourceSchemaVersion": WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
        "surface": "workflow_run",
        "threadId": thread_id,
        "workflowGraphId": workflow.metadata.id,
        "currentTurnId": Value::Null,
        "lastCursor": cursor,
        "lastEventId": event_id,
        "codingToolRows": [{
            "id": format!("workflow-run-coding-tool-budget-recovery-{}", approval_id),
            "status": "blocked",
            "label": "Coding tool budget: recovery",
            "command": "run",
            "rawInput": raw_input,
            "message": "Coding-tool budget launch block is pending recovery.",
            "workflowNodeId": target_node_ids.first().cloned().unwrap_or_else(|| WORKFLOW_RUN_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID.to_string()),
            "workflowGraphId": workflow.metadata.id,
            "eventId": source_event_id.unwrap_or(event_id),
            "cursor": cursor,
            "sequence": 1,
            "reason": WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
            "budgetStatus": "exceeded",
            "contextBudgetStatus": "blocked",
            "mutationBlocked": true,
            "receiptRefs": receipt_refs,
            "policyDecisionRefs": policy_decision_refs
        }],
        "approvalRows": approval_rows,
        "approvalDecisions": approval_decisions,
        "commandHistory": [{
            "id": format!("workflow-run-coding-tool-budget-recovery-command-{}", approval_id),
            "command": "run",
            "rawInput": raw_input,
            "status": status,
            "sequence": 1,
            "message": "Coding-tool budget recovery control recorded."
        }]
    })
}

fn unique_workflow_strings<const N: usize>(groups: [Vec<String>; N]) -> Vec<String> {
    groups
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
