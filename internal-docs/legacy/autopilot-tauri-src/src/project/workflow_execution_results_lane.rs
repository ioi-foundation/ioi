// apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs

use crate::runtime_projection::{completion_requirement_kinds, ActionKind};

use super::workflow_coding_route_lane::{
    workflow_coding_route_evidence_from_run, workflow_coding_route_run_summary,
    workflow_route_verification_evidence,
};
use super::*;

pub(super) struct WorkflowRunResultParts {
    pub summary: WorkflowRunSummary,
    pub thread: WorkflowThread,
    pub final_state: WorkflowStateSnapshot,
    pub node_runs: Vec<WorkflowNodeRun>,
    pub checkpoints: Vec<WorkflowCheckpoint>,
    pub events: Vec<WorkflowStreamEvent>,
    pub runtime_thread_events: Vec<Value>,
    pub tui_control_state: Option<Value>,
    pub harness_attempts: Vec<Value>,
    pub harness_shadow_comparisons: Vec<Value>,
    pub harness_gated_cluster_runs: Vec<Value>,
    pub completion_requirements: Vec<WorkflowCompletionRequirement>,
    pub interrupt: Option<WorkflowInterrupt>,
}

fn workflow_execution_result_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_execution_result_node_id(node: &Value) -> Option<String> {
    workflow_execution_result_value_string(node, "id")
}

fn workflow_execution_result_node_type(node: &Value) -> String {
    workflow_execution_result_value_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

fn workflow_execution_result_edge_from(edge: &Value) -> Option<String> {
    workflow_execution_result_value_string(edge, "from")
}

fn workflow_execution_result_edge_to(edge: &Value) -> Option<String> {
    workflow_execution_result_value_string(edge, "to")
}

fn workflow_execution_result_edge_from_port(edge: &Value) -> String {
    workflow_execution_result_value_string(edge, "fromPort").unwrap_or_else(|| "output".to_string())
}

fn workflow_execution_result_edge_is_selected(
    edge: &Value,
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> bool {
    let Some(source_id) = workflow_execution_result_edge_from(edge) else {
        return false;
    };
    let Some(branch) = branch_decisions.get(&source_id) else {
        return true;
    };
    let from_port = workflow_execution_result_edge_from_port(edge);
    from_port == *branch || (from_port == "output" && branch == "output")
}

pub(super) fn workflow_verification_evidence_from_node_runs(
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowVerificationEvidence> {
    node_runs
        .iter()
        .map(|run| WorkflowVerificationEvidence {
            node_id: run.node_id.clone(),
            evidence_type: if run.node_type == "skill_context" {
                "skill_context".to_string()
            } else if run.node_type == "workflow_package_export" {
                "workflow_package_export".to_string()
            } else if run.node_type == "workflow_package_import" {
                "workflow_package_import".to_string()
            } else if matches!(
                run.node_type.as_str(),
                "repository_context"
                    | "branch_policy"
                    | "github_context"
                    | "issue_context"
                    | "pr_attempt"
                    | "review_gate"
                    | "github_pr_create"
            ) {
                run.node_type.clone()
            } else {
                "execution".to_string()
            },
            status: if run.status == "success" {
                "passed".to_string()
            } else {
                run.status.clone()
            },
            summary: run.error.clone().unwrap_or_else(|| {
                if run.node_type == "skill_context" {
                    let hashes = run
                        .output
                        .as_ref()
                        .and_then(|output| output.get("selectedSkills"))
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| {
                                    item.get("skillHash")
                                        .or_else(|| item.get("hash"))
                                        .and_then(Value::as_str)
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    format!("skill_context {} selected [{}]", run.status, hashes)
                } else {
                    format!("{} execution {}", run.node_type, run.status)
                }
            }),
            created_at_ms: run.finished_at_ms.unwrap_or(run.started_at_ms),
        })
        .collect()
}

pub(super) fn workflow_completion_requirements(
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowCompletionRequirement> {
    let mut requirements = Vec::new();
    let run_by_node = node_runs
        .iter()
        .filter(|run| run.status == "success")
        .map(|run| (run.node_id.as_str(), run))
        .collect::<std::collections::BTreeMap<_, _>>();
    for node in &workflow.nodes {
        let Some(node_id) = workflow_execution_result_node_id(node) else {
            continue;
        };
        let action_kind = ActionKind::from_node_type(&workflow_execution_result_node_type(node));
        if action_kind.is_entry() {
            continue;
        }
        let incoming = workflow
            .edges
            .iter()
            .filter(|edge| {
                workflow_execution_result_edge_to(edge).as_deref() == Some(node_id.as_str())
            })
            .collect::<Vec<_>>();
        let selected = incoming.is_empty()
            || incoming.iter().any(|edge| {
                workflow_execution_result_edge_is_selected(edge, &state.branch_decisions)
            });
        if !selected {
            continue;
        }
        let executed = run_by_node.contains_key(node_id.as_str())
            || state.completed_node_ids.iter().any(|id| id == &node_id);
        for requirement_kind in completion_requirement_kinds(&action_kind) {
            match requirement_kind {
                "execution" => requirements.push(WorkflowCompletionRequirement {
                    id: format!("execution-{}", node_id),
                    node_id: Some(node_id.clone()),
                    requirement_type: "execution".to_string(),
                    status: if executed { "satisfied" } else { "missing" }.to_string(),
                    summary: if executed {
                        "Node produced typed execution evidence.".to_string()
                    } else {
                        "Node is missing typed execution evidence.".to_string()
                    },
                }),
                "verification" => {
                    let verified = state.node_outputs.contains_key(&node_id);
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("verification-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "verification".to_string(),
                        status: if verified { "satisfied" } else { "missing" }.to_string(),
                        summary: if verified {
                            "Node output has verification material.".to_string()
                        } else {
                            "Node output is missing verification material.".to_string()
                        },
                    });
                }
                "output_created" => {
                    let output_created = state
                        .node_outputs
                        .get(&node_id)
                        .and_then(|output| output.get("outputBundle"))
                        .is_some();
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("output-created-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "output_created".to_string(),
                        status: if output_created {
                            "satisfied"
                        } else {
                            "missing"
                        }
                        .to_string(),
                        summary: if output_created {
                            "Output bundle was produced.".to_string()
                        } else {
                            "Output bundle is missing.".to_string()
                        },
                    });
                }
                _ => {}
            }
        }
    }
    requirements
}

pub(super) fn workflow_completion_has_missing(
    requirements: &[WorkflowCompletionRequirement],
) -> bool {
    requirements
        .iter()
        .any(|requirement| requirement.status != "satisfied")
}

pub(super) fn workflow_run_result_from_parts(
    workflow: &WorkflowProject,
    parts: WorkflowRunResultParts,
) -> WorkflowRunResult {
    let route_evidence = workflow_coding_route_evidence_from_run(workflow, &parts.node_runs);
    let route_run_summary = workflow_coding_route_run_summary(&route_evidence);
    let mut verification_evidence = workflow_verification_evidence_from_node_runs(&parts.node_runs);
    verification_evidence.extend(workflow_route_verification_evidence(&route_evidence));
    WorkflowRunResult {
        summary: parts.summary,
        thread: parts.thread,
        final_state: parts.final_state,
        node_runs: parts.node_runs,
        checkpoints: parts.checkpoints,
        events: parts.events,
        runtime_thread_events: parts.runtime_thread_events,
        tui_control_state: parts.tui_control_state,
        harness_attempts: parts.harness_attempts,
        harness_shadow_comparisons: parts.harness_shadow_comparisons,
        harness_gated_cluster_runs: parts.harness_gated_cluster_runs,
        verification_evidence,
        completion_requirements: parts.completion_requirements,
        route_evidence,
        route_run_summary,
        interrupt: parts.interrupt,
    }
}

pub(super) fn workflow_finalize_run_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    parts: WorkflowRunResultParts,
) -> Result<WorkflowRunResult, String> {
    let result = workflow_run_result_from_parts(workflow, parts);
    save_workflow_run_result(workflow_path, &result)?;
    Ok(result)
}
