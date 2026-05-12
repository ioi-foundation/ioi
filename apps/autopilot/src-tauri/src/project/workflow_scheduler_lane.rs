// apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs

use super::workflow_approval_interrupt_lane::workflow_runtime_approval_preview;
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_execution_results_lane::{
    workflow_completion_has_missing, workflow_completion_requirements,
    workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::workflow_next_ready_nodes;
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_node_metadata_lane::{workflow_node_by_id, workflow_node_type};
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_interrupt_lane::workflow_scheduler_interrupted_result;
use super::workflow_scheduler_node_execution_lane::{
    workflow_scheduler_execute_node, WorkflowSchedulerNodeExecutionFlow,
};
use super::workflow_scheduler_validation_lane::workflow_scheduler_validation_blocked_result;
use super::workflow_state_lane::workflow_predecessor_output;
use super::*;

pub(super) fn execute_workflow_project(
    workflow_path: &Path,
    bundle: WorkflowWorkbenchBundle,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    resume_gate: Option<(String, Value)>,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    let validation = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let mut node_runs = Vec::new();
    let mut completed = state
        .completed_node_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut active_queue = if state.active_node_ids.is_empty() {
        workflow_next_ready_nodes(&bundle.workflow, &completed, &[], &state.branch_decisions)
    } else {
        state.active_node_ids.clone()
    };

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

    if validation.status != "passed" {
        return workflow_scheduler_validation_blocked_result(
            workflow_path,
            &bundle.workflow,
            bundle.tests.len(),
            thread,
            state,
            validation,
            started_at_ms,
            &run_id,
            &thread_id,
            node_runs,
            checkpoints,
            events,
        );
    }

    let max_steps = bundle.workflow.nodes.len().saturating_mul(4).max(1);
    let mut steps = 0usize;
    while let Some(node_id) = active_queue.first().cloned() {
        active_queue.remove(0);
        if completed.contains(&node_id) {
            continue;
        }
        steps += 1;
        if steps > max_steps {
            state.blocked_node_ids.push(node_id.clone());
            break;
        }
        let Some(node) = workflow_node_by_id(&bundle.workflow, &node_id) else {
            state.blocked_node_ids.push(node_id.clone());
            continue;
        };
        let node_type = workflow_node_type(node);
        let action_kind = ActionKind::from_node_type(&node_type);
        let input = workflow_predecessor_output(&node_id, &bundle.workflow, &state);
        let resume_matches_node =
            resume_gate.as_ref().map(|(id, _)| id.as_str()) == Some(node_id.as_str());
        let runtime_approval_preview =
            workflow_runtime_approval_preview(node, &action_kind, &input);
        if (action_kind.is_interrupt() || runtime_approval_preview.is_some())
            && !resume_matches_node
        {
            return workflow_scheduler_interrupted_result(
                workflow_path,
                &bundle.workflow,
                bundle.tests.len(),
                thread.clone(),
                state,
                node,
                node_id,
                node_type,
                &action_kind,
                input,
                active_queue.clone(),
                runtime_approval_preview,
                started_at_ms,
                &run_id,
                &thread_id,
                node_runs,
                checkpoints,
                events,
            );
        }

        let execution_flow = workflow_scheduler_execute_node(
            workflow_path,
            &bundle.workflow,
            node,
            node_id,
            node_type,
            &action_kind,
            input,
            resume_gate.as_ref(),
            skill_resolver,
            &run_id,
            &thread_id,
            &mut state,
            &mut completed,
            &mut active_queue,
            &mut node_runs,
            &mut checkpoints,
            &mut events,
        )?;
        if execution_flow == WorkflowSchedulerNodeExecutionFlow::Stop {
            break;
        }
    }

    let mut status = if !state.blocked_node_ids.is_empty() {
        "failed"
    } else if !state.interrupted_node_ids.is_empty() {
        "interrupted"
    } else {
        "passed"
    };
    let mut completion_requirements =
        workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    if status == "passed" && workflow_completion_has_missing(&completion_requirements) {
        status = "failed";
        state
            .blocked_node_ids
            .extend(completion_requirements.iter().filter_map(|requirement| {
                (requirement.status != "satisfied")
                    .then(|| requirement.node_id.clone())
                    .flatten()
            }));
        state.blocked_node_ids.sort();
        state.blocked_node_ids.dedup();
        completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    }
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        None,
        status,
        format!("Workflow run {}.", status),
        &mut checkpoints,
    )?;
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id.clone()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: bundle.workflow.nodes.len(),
        test_count: Some(bundle.tests.len()),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if status == "passed" {
            "Workflow completed with durable checkpoints.".to_string()
        } else {
            format!("Workflow {} with structured blockers.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some(status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status.to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
    let result = workflow_finalize_run_result(
        workflow_path,
        &bundle.workflow,
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
    Ok(result)
}
