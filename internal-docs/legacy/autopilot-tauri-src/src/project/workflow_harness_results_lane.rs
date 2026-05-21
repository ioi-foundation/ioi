// apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs

use super::workflow_value_helpers::workflow_hash_value;
use super::*;
use ioi_types::app::{
    compare_harness_live_shadow_attempts, default_harness_gated_cluster_run_for_shadow_run,
    default_harness_shadow_run_for_attempts, harness_gated_cluster_run_camel_value,
    harness_node_attempt_record_from_camel_value, harness_shadow_comparison_camel_value,
    HarnessExecutionMode, HarnessNodeAttemptRecord, HarnessPromotionClusterId,
    HarnessShadowComparison, DEFAULT_AGENT_HARNESS_ACTIVATION_ID, DEFAULT_AGENT_HARNESS_HASH,
    DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
};

fn workflow_harness_result_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_harness_result_node_id(node: &Value) -> Option<String> {
    workflow_harness_result_value_string(node, "id")
}

fn workflow_harness_result_node_by_id<'a>(
    workflow: &'a WorkflowProject,
    node_id: &str,
) -> Option<&'a Value> {
    workflow
        .nodes
        .iter()
        .find(|node| workflow_harness_result_node_id(node).as_deref() == Some(node_id))
}

fn workflow_is_harness(workflow: &WorkflowProject) -> bool {
    workflow
        .metadata
        .harness
        .as_ref()
        .and_then(|harness| harness.get("schemaVersion"))
        .and_then(Value::as_str)
        .map(|schema| schema == "workflow.harness.v1")
        .unwrap_or(false)
        || workflow
            .nodes
            .iter()
            .any(|node| node.get("runtimeBinding").is_some())
}

fn workflow_harness_metadata_string(
    workflow: &WorkflowProject,
    key: &str,
    fallback: &str,
) -> String {
    workflow
        .metadata
        .harness
        .as_ref()
        .and_then(|harness| harness.get(key))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .worker_harness_binding
                .as_ref()
                .and_then(|binding| binding.get(key))
                .and_then(Value::as_str)
        })
        .unwrap_or(fallback)
        .to_string()
}

fn workflow_harness_activation_id(workflow: &WorkflowProject) -> String {
    workflow
        .metadata
        .worker_harness_binding
        .as_ref()
        .and_then(|binding| binding.get("harnessActivationId"))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .harness
                .as_ref()
                .and_then(|harness| harness.get("activationId"))
                .and_then(Value::as_str)
        })
        .unwrap_or(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        .to_string()
}

fn workflow_harness_execution_mode(workflow: &WorkflowProject, node: &Value) -> String {
    node.get("runtimeBinding")
        .and_then(|binding| binding.get("executionMode"))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .worker_harness_binding
                .as_ref()
                .and_then(|binding| binding.get("executionMode"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            workflow
                .metadata
                .harness
                .as_ref()
                .and_then(|harness| harness.get("executionMode"))
                .and_then(Value::as_str)
        })
        .unwrap_or("projection")
        .to_string()
}

fn workflow_harness_attempt_status(node_run: &WorkflowNodeRun, execution_mode: &str) -> String {
    match node_run.status.as_str() {
        "error" => "failed".to_string(),
        "blocked" | "interrupted" => "blocked".to_string(),
        _ => execution_mode.to_string(),
    }
}

fn workflow_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn workflow_harness_attempt_for_node_run(
    workflow: &WorkflowProject,
    run_id: &str,
    node_run: &WorkflowNodeRun,
) -> Option<Value> {
    let node = workflow_harness_result_node_by_id(workflow, &node_run.node_id)?;
    let binding = node.get("runtimeBinding")?;
    let component_id = binding
        .get("componentId")
        .and_then(Value::as_str)
        .unwrap_or("ioi.agent-harness.unknown.v1");
    let component_kind = binding
        .get("componentKind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let execution_mode = workflow_harness_execution_mode(workflow, node);
    let readiness = binding
        .get("readiness")
        .and_then(Value::as_str)
        .unwrap_or("projection_only");
    let evidence_refs = workflow_string_array(binding.get("evidenceEventKinds"))
        .into_iter()
        .map(|event| format!("event-kind:{}", event))
        .chain(
            workflow_string_array(binding.get("receiptKinds"))
                .into_iter()
                .map(|receipt| format!("receipt-kind:{}", receipt)),
        )
        .collect::<Vec<_>>();
    let receipt_ids = workflow_string_array(binding.get("receiptKinds"))
        .into_iter()
        .map(|receipt| format!("{}:{}", node_run.node_id, receipt))
        .collect::<Vec<_>>();
    let replay = binding.get("replayEnvelope").cloned().unwrap_or_else(|| {
        let deterministic = binding
            .get("replay")
            .and_then(|replay| replay.get("deterministicEnvelope"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        json!({
            "deterministicEnvelope": deterministic,
            "capturesInput": true,
            "capturesOutput": true,
            "capturesPolicyDecision": false,
            "determinism": if deterministic { "deterministic" } else { "nondeterministic" },
            "redactionPolicy": "runtime_redacted"
        })
    });
    let captures_policy_decision = replay
        .get("capturesPolicyDecision")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = workflow_harness_attempt_status(node_run, &execution_mode);
    let input_hash = node_run.input.as_ref().map(workflow_hash_value);
    let output_hash = node_run.output.as_ref().map(workflow_hash_value);
    let error_class = node_run.error.clone();
    let duration_ms = node_run
        .finished_at_ms
        .map(|finished| finished.saturating_sub(node_run.started_at_ms));

    Some(json!({
        "attemptId": format!("{}:{}:attempt:{}", run_id, node_run.node_id, node_run.attempt),
        "harnessWorkflowId": workflow_harness_metadata_string(
            workflow,
            "harnessWorkflowId",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        ),
        "harnessActivationId": workflow_harness_activation_id(workflow),
        "harnessHash": workflow_harness_metadata_string(
            workflow,
            "harnessHash",
            DEFAULT_AGENT_HARNESS_HASH,
        ),
        "workflowNodeId": node_run.node_id.clone(),
        "componentId": component_id,
        "componentKind": component_kind,
        "executionMode": execution_mode,
        "readiness": readiness,
        "attemptIndex": node_run.attempt,
        "status": status,
        "inputHash": input_hash,
        "outputHash": output_hash,
        "errorClass": error_class,
        "policyDecision": captures_policy_decision.then(|| {
            if node_run.error.is_some() { "blocked" } else { "allowed" }
        }),
        "startedAtMs": node_run.started_at_ms,
        "durationMs": duration_ms,
        "receiptIds": receipt_ids,
        "evidenceRefs": evidence_refs,
        "replay": replay,
    }))
}

fn workflow_harness_attempt_records_from_values(
    attempts: &[Value],
) -> Vec<HarnessNodeAttemptRecord> {
    attempts
        .iter()
        .filter_map(harness_node_attempt_record_from_camel_value)
        .collect()
}

fn workflow_harness_shadow_comparison_records_for_attempt_records(
    attempts: &[HarnessNodeAttemptRecord],
) -> Vec<HarnessShadowComparison> {
    let mut comparisons = Vec::new();
    let mut live_by_component = std::collections::BTreeMap::new();
    let mut shadow_by_component = std::collections::BTreeMap::new();
    for attempt in attempts {
        match attempt.execution_mode {
            HarnessExecutionMode::Live | HarnessExecutionMode::Gated => {
                live_by_component.insert(attempt.component_id.clone(), attempt);
            }
            HarnessExecutionMode::Shadow => {
                shadow_by_component.insert(attempt.component_id.clone(), attempt);
            }
            _ => {}
        }
    }
    for (component_id, live) in live_by_component {
        let Some(shadow) = shadow_by_component.get(&component_id) else {
            continue;
        };
        comparisons.push(compare_harness_live_shadow_attempts(live, shadow));
    }
    comparisons
}

fn workflow_harness_gated_cluster_runs_for_attempt_records(
    run_id: &str,
    attempts: Vec<HarnessNodeAttemptRecord>,
    comparisons: Vec<HarnessShadowComparison>,
) -> Vec<Value> {
    let shadow_run = default_harness_shadow_run_for_attempts(
        run_id.to_string(),
        None,
        None,
        attempts,
        comparisons,
        vec![format!("workflow-run:{run_id}")],
    );
    [
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ]
    .into_iter()
    .map(|cluster_id| {
        harness_gated_cluster_run_camel_value(&default_harness_gated_cluster_run_for_shadow_run(
            cluster_id,
            &shadow_run,
        ))
    })
    .collect()
}

pub(super) fn workflow_attach_harness_run_artifacts(
    workflow: &WorkflowProject,
    run_id: &str,
    node_runs: &mut [WorkflowNodeRun],
) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    if !workflow_is_harness(workflow) {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let mut attempts = Vec::new();
    for node_run in node_runs {
        if let Some(attempt) = workflow_harness_attempt_for_node_run(workflow, run_id, node_run) {
            node_run.harness_attempt = Some(attempt.clone());
            attempts.push(attempt);
        }
    }
    let attempt_records = workflow_harness_attempt_records_from_values(&attempts);
    let comparison_records =
        workflow_harness_shadow_comparison_records_for_attempt_records(&attempt_records);
    let comparisons = comparison_records
        .iter()
        .map(harness_shadow_comparison_camel_value)
        .collect();
    let gated_cluster_runs = workflow_harness_gated_cluster_runs_for_attempt_records(
        run_id,
        attempt_records,
        comparison_records,
    );
    (attempts, comparisons, gated_cluster_runs)
}
