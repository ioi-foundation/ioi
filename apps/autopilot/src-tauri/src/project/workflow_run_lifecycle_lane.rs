// apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs

use super::runtime::{workflow_node_by_id, workflow_node_name, workflow_node_type};
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_execution_results_lane::{
    workflow_completion_requirements, workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_node_execution_lane::execute_workflow_node;
use super::*;

pub(super) fn workflow_push_event(
    events: &mut Vec<WorkflowStreamEvent>,
    run_id: &str,
    thread_id: &str,
    kind: &str,
    node_id: Option<&str>,
    status: Option<&str>,
    message: Option<String>,
    state_delta: Option<Vec<WorkflowStateUpdate>>,
) {
    let sequence = events.len();
    events.push(WorkflowStreamEvent {
        id: unique_runtime_id("event"),
        run_id: run_id.to_string(),
        thread_id: thread_id.to_string(),
        sequence,
        kind: kind.to_string(),
        created_at_ms: now_ms(),
        node_id: node_id.map(str::to_string),
        status: status.map(str::to_string),
        message,
        state_delta,
    });
}

pub(super) fn new_workflow_thread(workflow_path: &Path, input: Option<Value>) -> WorkflowThread {
    let created_at_ms = now_ms();
    WorkflowThread {
        id: unique_runtime_id("workflow-thread"),
        workflow_path: workflow_path.display().to_string(),
        status: "queued".to_string(),
        created_at_ms,
        latest_checkpoint_id: None,
        input,
    }
}

pub(super) fn initial_workflow_state(
    thread: &WorkflowThread,
    run_id: &str,
) -> WorkflowStateSnapshot {
    let mut values = std::collections::BTreeMap::new();
    if let Some(input) = thread.input.clone() {
        values.insert("input".to_string(), input);
    }
    WorkflowStateSnapshot {
        thread_id: thread.id.clone(),
        checkpoint_id: "start".to_string(),
        run_id: run_id.to_string(),
        step_index: 0,
        values,
        node_outputs: std::collections::BTreeMap::new(),
        completed_node_ids: Vec::new(),
        blocked_node_ids: Vec::new(),
        interrupted_node_ids: Vec::new(),
        active_node_ids: Vec::new(),
        branch_decisions: std::collections::BTreeMap::new(),
        pending_writes: Vec::new(),
    }
}

pub(super) fn workflow_single_node_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node_id: &str,
    input: Option<Value>,
    dry_run: bool,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    let node = workflow_node_by_id(workflow, node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id(if dry_run {
        "workflow-dry-run"
    } else {
        "workflow-node-run"
    });
    let thread = new_workflow_thread(workflow_path, input.clone());
    save_workflow_thread(workflow_path, &thread)?;
    let mut state = initial_workflow_state(&thread, &run_id);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let execution_input = input.unwrap_or_else(|| json!({"dryRun": dry_run}));
    let mut node_run = WorkflowNodeRun {
        node_id: node_id.to_string(),
        node_type: workflow_node_type(node),
        status: "running".to_string(),
        started_at_ms,
        finished_at_ms: None,
        attempt: 1,
        input: Some(execution_input.clone()),
        output: None,
        error: None,
        checkpoint_id: None,
        lifecycle: Vec::new(),
        harness_attempt: None,
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "node_started",
        Some(node_id),
        Some("running"),
        Some(format!("{} started.", workflow_node_name(node))),
        None,
    );
    let execution = execute_workflow_node(
        workflow_path,
        Some(workflow),
        node,
        execution_input,
        1,
        None,
        skill_resolver,
    );
    let status = match execution {
        Ok(output) => {
            state
                .node_outputs
                .insert(node_id.to_string(), output.clone());
            state.values.insert(node_id.to_string(), output.clone());
            state.completed_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "passed",
                format!("{} completed.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "success".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.output = Some(output.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("success");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_succeeded",
                Some(node_id),
                Some("success"),
                Some(format!("{} completed.", workflow_node_name(node))),
                Some(vec![WorkflowStateUpdate {
                    node_id: node_id.to_string(),
                    key: node_id.to_string(),
                    value: output,
                    reducer: "replace".to_string(),
                }]),
            );
            "passed".to_string()
        }
        Err(error) => {
            state.blocked_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "blocked",
                format!("{} blocked.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "blocked".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.error = Some(error.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("blocked");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_blocked",
                Some(node_id),
                Some("blocked"),
                Some(error),
                None,
            );
            "blocked".to_string()
        }
    };
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread.id.clone()),
        status: status.clone(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: 1,
        test_count: None,
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if dry_run {
            format!("Function dry run {}.", status)
        } else {
            format!("Node run {}.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "run_completed",
        None,
        Some(&status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status;
    final_thread.latest_checkpoint_id = checkpoints.last().map(|checkpoint| checkpoint.id.clone());
    save_workflow_thread(workflow_path, &final_thread)?;
    let mut node_runs = vec![node_run];
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, &run_id, &mut node_runs);
    let completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    let result = workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            completion_requirements,
            interrupt: None,
        },
    )?;
    append_workflow_evidence(
        workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: if dry_run { "test_run" } else { "run" }.to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}
