// apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs

use super::workflow_approval_interrupt_lane::{
    workflow_runtime_approval_preview, workflow_runtime_interrupt,
    workflow_runtime_interrupt_notice,
};
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_execution_results_lane::{
    workflow_completion_has_missing, workflow_completion_requirements,
    workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::{
    workflow_next_ready_nodes, workflow_node_lifecycle_steps,
};
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_node_metadata_lane::{
    workflow_node_by_id, workflow_node_logic, workflow_node_name, workflow_node_type,
};
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_validation_lane::workflow_scheduler_validation_blocked_result;
use super::workflow_state_lane::{workflow_predecessor_output, workflow_selected_output};
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
            let interrupt = workflow_runtime_interrupt(
                &run_id,
                &thread_id,
                node,
                &action_kind,
                runtime_approval_preview,
            );
            let interrupt_id = interrupt.id.clone();
            state.interrupted_node_ids.push(node_id.clone());
            state.active_node_ids = active_queue.clone();
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread_id,
                Some(&node_id),
                "interrupted",
                format!("Run paused at '{}'.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_interrupted",
                Some(&node_id),
                Some("interrupted"),
                Some(workflow_runtime_interrupt_notice(&action_kind)),
                None,
            );
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "interrupted".to_string(),
                started_at_ms: now_ms(),
                finished_at_ms: Some(now_ms()),
                attempt: 1,
                input: Some(input.clone()),
                output: None,
                error: None,
                checkpoint_id: Some(checkpoint_id.clone()),
                lifecycle: workflow_node_lifecycle_steps("interrupted"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "run_completed",
                None,
                Some("interrupted"),
                Some("Run paused for human input.".to_string()),
                None,
            );
            fs::create_dir_all(workflow_interrupts_dir(workflow_path))
                .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
            write_json_pretty(&workflow_interrupt_path(workflow_path, &run_id), &interrupt)?;
            let summary = WorkflowRunSummary {
                id: run_id.clone(),
                thread_id: Some(thread_id.clone()),
                status: "interrupted".to_string(),
                started_at_ms,
                finished_at_ms: Some(now_ms()),
                node_count: bundle.workflow.nodes.len(),
                test_count: Some(bundle.tests.len()),
                checkpoint_count: Some(checkpoints.len()),
                interrupt_id: Some(interrupt_id.clone()),
                summary: format!("Run paused at '{}'.", workflow_node_name(node)),
                evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
            };
            let mut final_thread = thread.clone();
            final_thread.status = "interrupted".to_string();
            final_thread.latest_checkpoint_id = Some(checkpoint_id);
            save_workflow_thread(workflow_path, &final_thread)?;
            let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
                workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
            let completion_requirements =
                workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
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
                    interrupt: Some(interrupt),
                },
            )?;
            return Ok(result);
        }

        let mut node_run = WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            status: "running".to_string(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
            attempt: 1,
            input: Some(input.clone()),
            output: None,
            error: None,
            checkpoint_id: None,
            lifecycle: Vec::new(),
            harness_attempt: None,
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "node_started",
            Some(&node_id),
            Some("running"),
            Some(format!("{} started.", workflow_node_name(node))),
            None,
        );
        let max_attempts = workflow_max_attempts(node);
        let mut execution_result = Err("Node did not execute.".to_string());
        for attempt in 1..=max_attempts {
            node_run.attempt = attempt;
            let resume_value = resume_gate
                .as_ref()
                .and_then(|(resume_node_id, value)| (resume_node_id == &node_id).then_some(value));
            execution_result = execute_workflow_node(
                workflow_path,
                Some(&bundle.workflow),
                node,
                input.clone(),
                attempt,
                resume_value,
                skill_resolver,
            );
            if execution_result.is_ok() || attempt == max_attempts {
                break;
            }
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "error".to_string(),
                started_at_ms: node_run.started_at_ms,
                finished_at_ms: Some(now_ms()),
                attempt,
                input: Some(input.clone()),
                output: None,
                error: execution_result.as_ref().err().cloned(),
                checkpoint_id: None,
                lifecycle: workflow_node_lifecycle_steps("error"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_failed",
                Some(&node_id),
                Some("retrying"),
                Some(format!(
                    "Retrying '{}' after attempt {}.",
                    workflow_node_name(node),
                    attempt
                )),
                None,
            );
        }

        match execution_result {
            Ok(output) => {
                let selected_output = workflow_selected_output(node, &output);
                if action_kind == ActionKind::Decision {
                    state
                        .branch_decisions
                        .insert(node_id.clone(), selected_output.clone());
                }
                completed.insert(node_id.clone());
                state.completed_node_ids = completed.iter().cloned().collect();
                state.interrupted_node_ids.retain(|id| id != &node_id);
                state.node_outputs.insert(node_id.clone(), output.clone());
                let update = if action_kind == ActionKind::State {
                    let key = output
                        .get("stateKey")
                        .and_then(Value::as_str)
                        .unwrap_or(&node_id)
                        .to_string();
                    let reducer = output
                        .get("reducer")
                        .and_then(Value::as_str)
                        .unwrap_or("replace")
                        .to_string();
                    let value = output
                        .get("value")
                        .cloned()
                        .unwrap_or_else(|| output.clone());
                    match reducer.as_str() {
                        "merge" => {
                            let mut merged = state
                                .values
                                .get(&key)
                                .cloned()
                                .or_else(|| workflow_node_logic(node).get("initialValue").cloned())
                                .unwrap_or_else(|| json!({}));
                            if let (Some(current), Some(next)) =
                                (merged.as_object_mut(), value.as_object())
                            {
                                for (item_key, item_value) in next {
                                    current.insert(item_key.clone(), item_value.clone());
                                }
                                state.values.insert(key.clone(), merged.clone());
                            } else {
                                state.values.insert(key.clone(), value.clone());
                            }
                        }
                        "append" => {
                            let mut list = state
                                .values
                                .get(&key)
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            list.push(value.clone());
                            state.values.insert(key.clone(), Value::Array(list));
                        }
                        _ => {
                            state.values.insert(key.clone(), value.clone());
                        }
                    }
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key,
                        value,
                        reducer,
                    }
                } else {
                    state.values.insert(node_id.clone(), output.clone());
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key: node_id.clone(),
                        value: output.clone(),
                        reducer: "replace".to_string(),
                    }
                };
                state.pending_writes.clear();
                state.step_index += 1;
                active_queue.extend(workflow_next_ready_nodes(
                    &bundle.workflow,
                    &completed,
                    &active_queue,
                    &state.branch_decisions,
                ));
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "running",
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
                    &thread_id,
                    "node_succeeded",
                    Some(&node_id),
                    Some("success"),
                    Some(format!("{} completed.", workflow_node_name(node))),
                    Some(vec![update]),
                );
                if output.get("toolKind").and_then(Value::as_str) == Some("workflow_tool") {
                    let child_run_id = output
                        .get("childRunId")
                        .and_then(Value::as_str)
                        .unwrap_or("child run");
                    let child_status = output
                        .get("childRunStatus")
                        .and_then(Value::as_str)
                        .unwrap_or("completed");
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "child_run_completed",
                        Some(&node_id),
                        Some(child_status),
                        Some(format!(
                            "{} completed child workflow run {}.",
                            workflow_node_name(node),
                            child_run_id
                        )),
                        None,
                    );
                }
                if action_kind == ActionKind::Output {
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "output_created",
                        Some(&node_id),
                        Some("success"),
                        Some(format!(
                            "{} produced an output bundle.",
                            workflow_node_name(node)
                        )),
                        None,
                    );
                    if output
                        .get("outputBundle")
                        .and_then(|bundle| bundle.get("materializedAssets"))
                        .and_then(Value::as_array)
                        .map(|assets| !assets.is_empty())
                        .unwrap_or(false)
                    {
                        workflow_push_event(
                            &mut events,
                            &run_id,
                            &thread_id,
                            "asset_materialized",
                            Some(&node_id),
                            Some("success"),
                            Some(format!(
                                "{} recorded a materialized asset.",
                                workflow_node_name(node)
                            )),
                            None,
                        );
                    }
                }
                node_runs.push(node_run);
            }
            Err(error) => {
                state.blocked_node_ids.push(node_id.clone());
                state.step_index += 1;
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "failed",
                    format!("{} failed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "error".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.error = Some(error.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("error");
                node_runs.push(node_run);
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_failed",
                    Some(&node_id),
                    Some("error"),
                    Some(error),
                    None,
                );
                break;
            }
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
