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

fn workflow_preflight_value_any(value: &Value, keys: &[&str]) -> Value {
    keys.iter()
        .find_map(|key| value.get(*key))
        .cloned()
        .unwrap_or(Value::Null)
}
