use crate::models::{
    BuildArtifactSession, StudioArtifactLifecycleState, StudioArtifactManifest,
    StudioArtifactMaterializationCommandIntent, StudioArtifactMaterializationContract,
    StudioArtifactMaterializationVerificationStep, StudioArtifactPipelineStep,
    StudioArtifactSession, StudioOutcomeArtifactRequest, StudioOutcomeKind, StudioRendererKind,
};
use ioi_api::studio::{
    ExecutionStage, StudioArtifactJudgeClassification, StudioArtifactTasteMemory,
    StudioArtifactWorkItemStatus, StudioArtifactWorkerRole,
};
use ioi_types::app::StudioExecutionStrategy;

use super::{
    artifact_class_id_for_request, persistence_mode_id, presentation_surface_id, renderer_kind_id,
};

pub(super) fn verification_step(
    id: &str,
    label: &str,
    status: &str,
) -> StudioArtifactMaterializationVerificationStep {
    StudioArtifactMaterializationVerificationStep {
        id: id.to_string(),
        label: label.to_string(),
        kind: id.to_string(),
        status: status.to_string(),
    }
}

fn pipeline_step(
    id: &str,
    stage: ExecutionStage,
    label: &str,
    status: &str,
    summary: impl Into<String>,
    outputs: Vec<String>,
    verification_gate: Option<&str>,
) -> StudioArtifactPipelineStep {
    StudioArtifactPipelineStep {
        id: id.to_string(),
        stage,
        label: label.to_string(),
        status: status.to_string(),
        summary: summary.into(),
        outputs,
        verification_gate: verification_gate.map(|value| value.to_string()),
    }
}

fn execution_stage_for_pipeline_phase(phase_id: &str) -> ExecutionStage {
    match phase_id {
        "intake" | "requirements" | "specification" | "planner" => ExecutionStage::Plan,
        "routing" => ExecutionStage::Dispatch,
        "swarm_execution" => ExecutionStage::Work,
        "materialization" | "execution" | "repair" => ExecutionStage::Mutate,
        "merge" => ExecutionStage::Merge,
        "verification" => ExecutionStage::Verify,
        "presentation" | "reply" => ExecutionStage::Finalize,
        _ => ExecutionStage::Work,
    }
}

fn format_status_label(value: &str) -> String {
    value
        .split('_')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => format!(
                    "{}{}",
                    first.to_ascii_uppercase(),
                    chars.as_str().to_ascii_lowercase()
                ),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn pipeline_execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn worker_role_id(role: StudioArtifactWorkerRole) -> &'static str {
    match role {
        StudioArtifactWorkerRole::Planner => "planner",
        StudioArtifactWorkerRole::Coordinator => "coordinator",
        StudioArtifactWorkerRole::Responder => "responder",
        StudioArtifactWorkerRole::Skeleton => "skeleton",
        StudioArtifactWorkerRole::SectionContent => "section_content",
        StudioArtifactWorkerRole::StyleSystem => "style_system",
        StudioArtifactWorkerRole::Interaction => "interaction",
        StudioArtifactWorkerRole::Integrator => "integrator",
        StudioArtifactWorkerRole::Judge => "judge",
        StudioArtifactWorkerRole::Repair => "repair",
    }
}

fn work_item_status_id(status: StudioArtifactWorkItemStatus) -> &'static str {
    match status {
        StudioArtifactWorkItemStatus::Pending => "pending",
        StudioArtifactWorkItemStatus::Blocked => "blocked",
        StudioArtifactWorkItemStatus::Running => "running",
        StudioArtifactWorkItemStatus::Succeeded => "succeeded",
        StudioArtifactWorkItemStatus::Failed => "failed",
        StudioArtifactWorkItemStatus::Skipped => "skipped",
        StudioArtifactWorkItemStatus::Rejected => "rejected",
    }
}

fn pipeline_status_for_phase(
    phase_id: &str,
    renderer: StudioRendererKind,
    lifecycle_state: StudioArtifactLifecycleState,
    has_files: bool,
    preview_ready: bool,
) -> &'static str {
    match phase_id {
        "intake" | "routing" | "requirements" | "specification" | "planner" => "complete",
        "swarm_execution" | "merge" => match lifecycle_state {
            StudioArtifactLifecycleState::Draft | StudioArtifactLifecycleState::Planned => {
                "pending"
            }
            StudioArtifactLifecycleState::Materializing
            | StudioArtifactLifecycleState::Rendering
            | StudioArtifactLifecycleState::Implementing => "active",
            StudioArtifactLifecycleState::Verifying
            | StudioArtifactLifecycleState::Ready
            | StudioArtifactLifecycleState::Partial => "complete",
            StudioArtifactLifecycleState::Blocked => {
                if has_files {
                    "complete"
                } else {
                    "blocked"
                }
            }
            StudioArtifactLifecycleState::Failed => {
                if has_files {
                    "complete"
                } else {
                    "failed"
                }
            }
        },
        "materialization" => match lifecycle_state {
            StudioArtifactLifecycleState::Draft | StudioArtifactLifecycleState::Planned => {
                "pending"
            }
            StudioArtifactLifecycleState::Materializing => "active",
            StudioArtifactLifecycleState::Rendering
            | StudioArtifactLifecycleState::Implementing
            | StudioArtifactLifecycleState::Verifying
            | StudioArtifactLifecycleState::Ready
            | StudioArtifactLifecycleState::Partial => "complete",
            StudioArtifactLifecycleState::Blocked => {
                if has_files {
                    "complete"
                } else {
                    "blocked"
                }
            }
            StudioArtifactLifecycleState::Failed => {
                if has_files {
                    "complete"
                } else {
                    "failed"
                }
            }
        },
        "execution" => {
            if renderer == StudioRendererKind::WorkspaceSurface {
                match lifecycle_state {
                    StudioArtifactLifecycleState::Draft
                    | StudioArtifactLifecycleState::Planned
                    | StudioArtifactLifecycleState::Materializing => "pending",
                    StudioArtifactLifecycleState::Rendering
                    | StudioArtifactLifecycleState::Implementing => "active",
                    StudioArtifactLifecycleState::Verifying
                    | StudioArtifactLifecycleState::Ready
                    | StudioArtifactLifecycleState::Partial => "complete",
                    StudioArtifactLifecycleState::Blocked => "blocked",
                    StudioArtifactLifecycleState::Failed => "failed",
                }
            } else {
                match lifecycle_state {
                    StudioArtifactLifecycleState::Draft | StudioArtifactLifecycleState::Planned => {
                        "pending"
                    }
                    StudioArtifactLifecycleState::Materializing
                    | StudioArtifactLifecycleState::Rendering => "active",
                    StudioArtifactLifecycleState::Implementing
                    | StudioArtifactLifecycleState::Verifying
                    | StudioArtifactLifecycleState::Ready
                    | StudioArtifactLifecycleState::Partial => "complete",
                    StudioArtifactLifecycleState::Blocked => {
                        if has_files {
                            "complete"
                        } else {
                            "blocked"
                        }
                    }
                    StudioArtifactLifecycleState::Failed => {
                        if has_files {
                            "complete"
                        } else {
                            "failed"
                        }
                    }
                }
            }
        }
        "verification" => match lifecycle_state {
            StudioArtifactLifecycleState::Draft
            | StudioArtifactLifecycleState::Planned
            | StudioArtifactLifecycleState::Materializing
            | StudioArtifactLifecycleState::Rendering => "pending",
            StudioArtifactLifecycleState::Implementing
            | StudioArtifactLifecycleState::Verifying => "active",
            StudioArtifactLifecycleState::Ready => "complete",
            StudioArtifactLifecycleState::Partial | StudioArtifactLifecycleState::Blocked => {
                "blocked"
            }
            StudioArtifactLifecycleState::Failed => "failed",
        },
        "repair" => match lifecycle_state {
            StudioArtifactLifecycleState::Draft
            | StudioArtifactLifecycleState::Planned
            | StudioArtifactLifecycleState::Materializing => "pending",
            StudioArtifactLifecycleState::Rendering
            | StudioArtifactLifecycleState::Implementing
            | StudioArtifactLifecycleState::Verifying => "active",
            StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial => {
                "complete"
            }
            StudioArtifactLifecycleState::Blocked => "blocked",
            StudioArtifactLifecycleState::Failed => "failed",
        },
        "presentation" => {
            if renderer == StudioRendererKind::WorkspaceSurface {
                match lifecycle_state {
                    StudioArtifactLifecycleState::Ready if preview_ready => "complete",
                    StudioArtifactLifecycleState::Ready
                    | StudioArtifactLifecycleState::Partial
                    | StudioArtifactLifecycleState::Blocked
                        if has_files =>
                    {
                        "blocked"
                    }
                    StudioArtifactLifecycleState::Failed => "failed",
                    _ => "pending",
                }
            } else {
                match lifecycle_state {
                    StudioArtifactLifecycleState::Ready => "complete",
                    StudioArtifactLifecycleState::Partial
                    | StudioArtifactLifecycleState::Blocked => {
                        if has_files {
                            "blocked"
                        } else {
                            "pending"
                        }
                    }
                    StudioArtifactLifecycleState::Failed => "failed",
                    _ => "pending",
                }
            }
        }
        "reply" => match lifecycle_state {
            StudioArtifactLifecycleState::Ready => "complete",
            StudioArtifactLifecycleState::Partial | StudioArtifactLifecycleState::Blocked => {
                "blocked"
            }
            StudioArtifactLifecycleState::Failed => "failed",
            _ => "pending",
        },
        _ => "pending",
    }
}

fn pipeline_step_for_phase(
    id: &str,
    label: &str,
    renderer: StudioRendererKind,
    lifecycle_state: StudioArtifactLifecycleState,
    has_files: bool,
    preview_ready: bool,
    summary: impl Into<String>,
    outputs: Vec<String>,
    verification_gate: Option<&str>,
) -> StudioArtifactPipelineStep {
    pipeline_step(
        id,
        execution_stage_for_pipeline_phase(id),
        label,
        pipeline_status_for_phase(id, renderer, lifecycle_state, has_files, preview_ready),
        summary,
        outputs,
        verification_gate,
    )
}

fn truncate_pipeline_output(value: impl AsRef<str>, limit: usize) -> String {
    let value = value.as_ref().trim();
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        format!(
            "{}…",
            value.chars().take(limit).collect::<String>().trim_end()
        )
    }
}

fn repair_pass_count(materialization: &StudioArtifactMaterializationContract) -> usize {
    materialization
        .candidate_summaries
        .iter()
        .filter_map(|candidate| candidate.convergence.as_ref())
        .filter(|trace| trace.pass_kind != "initial")
        .count()
}

fn validation_obligation_counts(
    materialization: &StudioArtifactMaterializationContract,
) -> Option<(usize, usize, usize)> {
    let evaluation = materialization.render_evaluation.as_ref().or_else(|| {
        materialization
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .and_then(|candidate| candidate.render_evaluation.as_ref())
            .or_else(|| {
                materialization
                    .winning_candidate_id
                    .as_ref()
                    .and_then(|winner_id| {
                        materialization
                            .candidate_summaries
                            .iter()
                            .find(|candidate| &candidate.candidate_id == winner_id)
                            .and_then(|candidate| candidate.render_evaluation.as_ref())
                    })
            })
    })?;
    Some((
        evaluation.cleared_required_obligation_count(),
        evaluation.required_obligation_count(),
        evaluation.failed_required_obligation_count(),
    ))
}

fn judge_classification_id(classification: StudioArtifactJudgeClassification) -> &'static str {
    match classification {
        StudioArtifactJudgeClassification::Pass => "pass",
        StudioArtifactJudgeClassification::Repairable => "repairable",
        StudioArtifactJudgeClassification::Blocked => "blocked",
    }
}

fn outcome_kind_label(kind: StudioOutcomeKind) -> &'static str {
    match kind {
        StudioOutcomeKind::Conversation => "conversation",
        StudioOutcomeKind::ToolWidget => "tool_widget",
        StudioOutcomeKind::Visualizer => "visualizer",
        StudioOutcomeKind::Artifact => "artifact",
    }
}

fn pipeline_steps_for_non_artifact_route(
    studio_session: &StudioArtifactSession,
) -> Vec<StudioArtifactPipelineStep> {
    let materialization = &studio_session.materialization;
    let outcome_request = &studio_session.outcome_request;
    let route_kind = outcome_kind_label(outcome_request.outcome_kind);
    let lifecycle_state = studio_session.lifecycle_state;
    let status = match lifecycle_state {
        StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial => "complete",
        StudioArtifactLifecycleState::Blocked => "blocked",
        StudioArtifactLifecycleState::Failed => "failed",
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => "active",
    };
    let prompt_excerpt = truncate_pipeline_output(&materialization.normalized_intent, 88);
    let has_swarm_execution = materialization
        .swarm_execution
        .as_ref()
        .map(|summary| summary.enabled)
        .unwrap_or(false);
    let verification_gate = "Verification state, not worker prose, authorizes Studio replies.";

    let mut steps = vec![
        pipeline_step(
            "intake",
            execution_stage_for_pipeline_phase("intake"),
            "Intake",
            "complete",
            "Studio captured the request and preserved it as a typed outcome turn.",
            vec![prompt_excerpt],
            None,
        ),
        pipeline_step(
            "routing",
            execution_stage_for_pipeline_phase("routing"),
            "Outcome routing",
            status,
            format!(
                "The typed router intentionally kept this request on the {} surface.",
                route_kind.replace('_', " ")
            ),
            vec![
                route_kind.to_string(),
                materialization.request_kind.clone(),
                materialization
                    .swarm_execution
                    .as_ref()
                    .map(|summary| format!("strategy:{}", summary.strategy))
                    .unwrap_or_else(|| "strategy:plan_execute".to_string()),
            ],
            None,
        ),
    ];

    if let Some(plan) = materialization.swarm_plan.as_ref() {
        steps.push(pipeline_step(
            "planner",
            execution_stage_for_pipeline_phase("planner"),
            "Planner",
            status,
            "Studio locked the shared execution plan before handing the request to the non-artifact lane.",
            vec![
                plan.strategy.clone(),
                format!("work_items:{}", plan.work_items.len()),
                plan.parallelism_mode.clone(),
            ],
            None,
        ));
    }

    if has_swarm_execution {
        steps.push(pipeline_step(
            "swarm_execution",
            execution_stage_for_pipeline_phase("swarm_execution"),
            "Shared execution",
            status,
            "The shared execution envelope recorded worker receipts without pretending an artifact renderer ran.",
            {
                let mut outputs = vec![format!(
                    "worker_receipts:{}",
                    materialization.swarm_worker_receipts.len()
                )];
                if let Some(summary) = materialization.swarm_execution.as_ref() {
                    outputs.push(format!(
                        "progress:{}/{}",
                        summary.completed_work_items, summary.total_work_items
                    ));
                    outputs.push(format!("adapter:{}", summary.adapter_label));
                }
                if let Some(envelope) = materialization.execution_envelope.as_ref() {
                    if !envelope.dispatch_batches.is_empty() {
                        outputs.push(format!(
                            "dispatch_batches:{}",
                            envelope.dispatch_batches.len()
                        ));
                    }
                    if !envelope.graph_mutation_receipts.is_empty() {
                        outputs.push(format!(
                            "graph_mutations:{}",
                            envelope.graph_mutation_receipts.len()
                        ));
                    }
                    if !envelope.replan_receipts.is_empty() {
                        outputs.push(format!("replans:{}", envelope.replan_receipts.len()));
                    }
                }
                outputs
            },
            Some("Shared execution receipts must remain truthful about the active outcome surface."),
        ));
    }

    steps.extend([
        pipeline_step(
            "verification",
            execution_stage_for_pipeline_phase("verification"),
            "Verification",
            status,
            "Studio verified the selected non-artifact route before composing the reply state.",
            materialization
                .swarm_verification_receipts
                .iter()
                .map(|receipt| format!("{} ({})", receipt.kind, receipt.status))
                .collect::<Vec<_>>(),
            Some(verification_gate),
        ),
        pipeline_step(
            "reply",
            execution_stage_for_pipeline_phase("reply"),
            "Reply",
            status,
            "Studio composes the user-facing summary from shared execution state, not from an implied artifact renderer.",
            vec![studio_session.verified_reply.summary.clone()],
            Some(verification_gate),
        ),
    ]);

    steps
}

pub(super) fn pipeline_steps_for_state(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    manifest: &StudioArtifactManifest,
    materialization: &StudioArtifactMaterializationContract,
    lifecycle_state: StudioArtifactLifecycleState,
    build_session: Option<&BuildArtifactSession>,
    taste_memory: Option<&StudioArtifactTasteMemory>,
) -> Vec<StudioArtifactPipelineStep> {
    let trimmed_intent = intent.trim();
    let prompt_excerpt = if trimmed_intent.chars().count() > 88 {
        format!(
            "{}…",
            trimmed_intent
                .chars()
                .take(88)
                .collect::<String>()
                .trim_end()
        )
    } else {
        trimmed_intent.to_string()
    };
    let has_files = !manifest.files.is_empty() || !materialization.file_writes.is_empty();
    let execution_strategy = materialization
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.strategy)
        .unwrap_or(StudioExecutionStrategy::PlanExecute);
    let mode_decision = materialization
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.mode_decision.as_ref());
    let completion_invariant = materialization
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.completion_invariant.as_ref());
    let has_swarm_execution = matches!(
        execution_strategy,
        StudioExecutionStrategy::MicroSwarm | StudioExecutionStrategy::AdaptiveWorkGraph
    ) || materialization
        .swarm_execution
        .as_ref()
        .map(|summary| summary.enabled)
        .unwrap_or(false);
    let show_execution_step = request.renderer == StudioRendererKind::WorkspaceSurface
        || build_session.is_some()
        || has_swarm_execution
        || materialization
            .execution_envelope
            .as_ref()
            .map(|envelope| {
                !envelope.worker_receipts.is_empty()
                    || !envelope.dispatch_batches.is_empty()
                    || !envelope.live_previews.is_empty()
            })
            .unwrap_or(false);
    let preview_ready = build_session
        .and_then(|session| session.preview_url.as_ref())
        .is_some()
        && manifest.primary_tab == "preview";
    let verification_gate = "Verification state, not worker prose, authorizes Studio replies.";
    let prepared_context_resolution = materialization.prepared_context_resolution.as_ref();
    let mut spec_outputs = vec![
        artifact_class_id_for_request(request),
        renderer_kind_id(request.renderer).to_string(),
        presentation_surface_id(request.presentation_surface).to_string(),
        persistence_mode_id(request.persistence).to_string(),
    ];
    if let Some(resolution) = prepared_context_resolution {
        spec_outputs.push(format!("prepared_context:{}", resolution.status));
    }
    if let Some(blueprint) = materialization.blueprint.as_ref() {
        spec_outputs.push(format!("blueprint:{}", blueprint.scaffold_family));
        if !blueprint.component_plan.is_empty() {
            spec_outputs.push(format!("component_plan:{}", blueprint.component_plan.len()));
        }
        if !blueprint.skill_needs.is_empty() {
            spec_outputs.push(format!("skill_needs:{}", blueprint.skill_needs.len()));
        }
    }
    if let Some(artifact_ir) = materialization.artifact_ir.as_ref() {
        spec_outputs.push(format!("ir_nodes:{}", artifact_ir.semantic_structure.len()));
        spec_outputs.push(format!(
            "ir_interactions:{}",
            artifact_ir.interaction_graph.len()
        ));
        if !artifact_ir.component_bindings.is_empty() {
            spec_outputs.push(format!(
                "component_packs:{}",
                artifact_ir.component_bindings.join(" · ")
            ));
        }
    }
    if !materialization.selected_skills.is_empty() {
        spec_outputs.push(format!(
            "selected_skills:{}",
            materialization.selected_skills.len()
        ));
    }
    let file_outputs = if !materialization.file_writes.is_empty() {
        materialization
            .file_writes
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    } else {
        manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    };
    let candidate_count = materialization.candidate_summaries.len();
    let repair_passes = repair_pass_count(materialization);
    let obligation_counts = validation_obligation_counts(materialization);
    let show_repair_step = has_swarm_execution
        || repair_passes > 0
        || materialization.failure.is_some()
        || manifest.verification.failure.is_some();
    let swarm_receipt_count = materialization.swarm_worker_receipts.len();
    let winner_summary = materialization.winning_candidate_id.as_ref().map(|winner| {
        if let Some(rationale) = materialization.winning_candidate_rationale.as_ref() {
            format!(
                "winner:{} ({})",
                winner,
                truncate_pipeline_output(rationale, 72)
            )
        } else {
            format!("winner:{winner}")
        }
    });
    let mut materialization_outputs = Vec::new();
    if has_swarm_execution {
        if let Some(summary) = materialization.swarm_execution.as_ref() {
            materialization_outputs.push(format!(
                "swarm:{}/{}",
                summary.completed_work_items, summary.total_work_items
            ));
            materialization_outputs.push(format!("adapter:{}", summary.adapter_label));
        }
    } else if candidate_count > 0 {
        materialization_outputs.push(format!("candidates:{candidate_count}"));
    }
    if let Some(winner) = winner_summary {
        materialization_outputs.push(winner);
    }
    if let Some((cleared, required, failed)) = obligation_counts {
        materialization_outputs.push(format!("obligations:{cleared}/{required}"));
        if failed > 0 {
            materialization_outputs.push(format!("failed_obligations:{failed}"));
        }
    }
    if repair_passes > 0 {
        materialization_outputs.push(format!("repair_passes:{repair_passes}"));
    }
    if let Some(origin) = materialization.output_origin.as_ref() {
        materialization_outputs.push(format!("origin:{origin:?}").to_ascii_lowercase());
    }
    materialization_outputs.extend(file_outputs.iter().take(3).cloned());
    if file_outputs.len() > 3 {
        materialization_outputs.push(format!("files:{}", file_outputs.len()));
    }
    let execution_outputs = if let Some(session) = build_session {
        if !session.receipts.is_empty() {
            session
                .receipts
                .iter()
                .map(|receipt| format!("{} ({})", receipt.title, receipt.status))
                .collect()
        } else {
            materialization
                .command_intents
                .iter()
                .map(|intent| intent.label.clone())
                .collect()
        }
    } else {
        let mut outputs = if has_swarm_execution {
            materialization
                .swarm_worker_receipts
                .iter()
                .take(4)
                .map(|receipt| {
                    format!(
                        "{} ({})",
                        format_status_label(worker_role_id(receipt.role)),
                        format_status_label(work_item_status_id(receipt.status))
                    )
                })
                .collect::<Vec<_>>()
        } else {
            manifest
                .files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>()
        };
        if !materialization.selected_skills.is_empty() {
            outputs.push(format!(
                "skills:{}",
                materialization
                    .selected_skills
                    .iter()
                    .map(|skill| skill.name.clone())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" · ")
            ));
        }
        outputs
    };
    let mut verification_outputs = if !materialization.verification_steps.is_empty() {
        materialization
            .verification_steps
            .iter()
            .map(|step| format!("{} ({})", step.label, step.status))
            .collect::<Vec<_>>()
    } else {
        vec![manifest.verification.summary.clone()]
    };
    if let Some(artifact_ir) = materialization.artifact_ir.as_ref() {
        if !artifact_ir.static_audit_expectations.is_empty() {
            verification_outputs.push(format!(
                "audit_targets:{}",
                artifact_ir.static_audit_expectations.len()
            ));
        }
    }
    if let Some(judge) = materialization.judge.as_ref() {
        verification_outputs.push(format!(
            "judge:{}",
            judge_classification_id(judge.classification)
        ));
        if !judge.issue_classes.is_empty() {
            verification_outputs.push(format!("issues:{}", judge.issue_classes.join(" · ")));
        }
        if !judge.repair_hints.is_empty() {
            verification_outputs.push(format!("repair_hints:{}", judge.repair_hints.len()));
        }
    }
    if has_swarm_execution {
        verification_outputs.extend(
            materialization
                .swarm_verification_receipts
                .iter()
                .map(|receipt| format!("{} ({})", receipt.kind, receipt.status)),
        );
    }
    if let Some(invariant) = completion_invariant {
        let invariant_status = match invariant.status {
            ioi_api::execution::ExecutionCompletionInvariantStatus::Pending => "pending",
            ioi_api::execution::ExecutionCompletionInvariantStatus::Satisfied => "satisfied",
            ioi_api::execution::ExecutionCompletionInvariantStatus::Blocked => "blocked",
        };
        verification_outputs.push(format!("completion:{invariant_status}"));
        if !invariant.remaining_obligations.is_empty() {
            verification_outputs.push(format!(
                "remaining:{}",
                invariant.remaining_obligations.join(" · ")
            ));
        }
    }
    if let Some(failure) = manifest.verification.failure.as_ref() {
        verification_outputs.push(format!("failure:{}", failure.code));
    }
    let presentation_outputs = if preview_ready {
        vec![
            "preview".to_string(),
            build_session
                .and_then(|session| session.preview_url.clone())
                .unwrap_or_default(),
        ]
    } else {
        let mut outputs = vec![
            manifest.primary_tab.clone(),
            format!("{} file(s)", manifest.files.len()),
        ];
        if repair_passes > 0 {
            outputs.push(format!("repair_passes:{repair_passes}"));
        }
        outputs
    };
    let requirements_outputs = {
        let mut outputs = request.scope.mutation_boundary.clone();
        if outputs.is_empty() {
            outputs.push("artifact".to_string());
        }
        if request.verification.require_render {
            outputs.push("require_render".to_string());
        }
        if request.verification.require_export {
            outputs.push("require_export".to_string());
        }
        outputs
    };
    let brief_outputs = if let Some(brief) = materialization.artifact_brief.as_ref() {
        let mut outputs = vec![
            format!(
                "subject:{}",
                truncate_pipeline_output(&brief.subject_domain, 48)
            ),
            format!("audience:{}", truncate_pipeline_output(&brief.audience, 48)),
            format!("concepts:{}", brief.required_concepts.len()),
        ];
        if brief.has_required_interaction_goals() {
            outputs.push(format!(
                "interactions:{}",
                brief.required_interaction_goal_count()
            ));
        }
        outputs
    } else {
        vec!["brief:pending".to_string()]
    };
    let brief_status = if materialization.artifact_brief.is_some() {
        "complete"
    } else if lifecycle_state == StudioArtifactLifecycleState::Failed {
        "failed"
    } else if lifecycle_state == StudioArtifactLifecycleState::Blocked {
        "blocked"
    } else if matches!(
        lifecycle_state,
        StudioArtifactLifecycleState::Materializing
            | StudioArtifactLifecycleState::Rendering
            | StudioArtifactLifecycleState::Implementing
            | StudioArtifactLifecycleState::Verifying
            | StudioArtifactLifecycleState::Ready
            | StudioArtifactLifecycleState::Partial
    ) {
        "active"
    } else {
        "pending"
    };
    let skill_discovery_resolution = materialization.skill_discovery_resolution.as_ref();
    let skill_discovery_outputs = if let Some(resolution) = skill_discovery_resolution {
        let mut outputs = vec![
            format!("guidance_evaluated:{}", resolution.guidance_evaluated),
            format!("guidance_recommended:{}", resolution.guidance_recommended),
            format!("guidance_found:{}", resolution.guidance_found),
            format!("guidance_attached:{}", resolution.guidance_attached),
            format!("skill_needs:{}", resolution.skill_need_count),
            format!("selected_skills:{}", resolution.selected_skill_count),
        ];
        if !resolution.search_scope.is_empty() {
            outputs.push(format!("search_scope:{}", resolution.search_scope));
        }
        if !resolution.selected_skill_names.is_empty() {
            outputs.push(format!(
                "skills:{}",
                resolution.selected_skill_names.join(" · ")
            ));
        }
        if let Some(failure_reason) = resolution.failure_reason.as_ref() {
            outputs.push(format!(
                "failure_reason:{}",
                truncate_pipeline_output(failure_reason, 72)
            ));
        }
        outputs
    } else {
        vec!["guidance_evaluated:pending".to_string()]
    };
    let skill_discovery_status = if let Some(resolution) = skill_discovery_resolution {
        match resolution.status.trim().to_ascii_lowercase().as_str() {
            "resolved" | "complete" => "complete",
            "blocked" => "blocked",
            "failed" => "failed",
            "active" | "working" => "active",
            _ => "active",
        }
    } else if materialization.artifact_brief.is_some()
        && matches!(
            lifecycle_state,
            StudioArtifactLifecycleState::Materializing
                | StudioArtifactLifecycleState::Rendering
                | StudioArtifactLifecycleState::Implementing
                | StudioArtifactLifecycleState::Verifying
                | StudioArtifactLifecycleState::Ready
                | StudioArtifactLifecycleState::Partial
        )
    {
        "active"
    } else if lifecycle_state == StudioArtifactLifecycleState::Failed {
        "failed"
    } else if lifecycle_state == StudioArtifactLifecycleState::Blocked {
        "blocked"
    } else {
        "pending"
    };
    let guidance_attached = skill_discovery_resolution
        .map(|resolution| resolution.guidance_attached)
        .unwrap_or(false);
    let reply_outputs = {
        let mut outputs = vec![manifest.verification.summary.clone()];
        if let Some(taste_memory) = taste_memory {
            outputs.push(format!(
                "taste_memory:{}",
                truncate_pipeline_output(&taste_memory.summary, 72)
            ));
        }
        outputs
    };

    let mut steps = vec![
        pipeline_step_for_phase(
            "intake",
            "Intake",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "Studio captured the request and established the active artifact context.",
            vec![prompt_excerpt],
            None,
        ),
        pipeline_step_for_phase(
            "routing",
            "Outcome routing",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "The typed router chose the artifact branch intentionally.",
            vec![
                "artifact".to_string(),
                artifact_class_id_for_request(request),
                renderer_kind_id(request.renderer).to_string(),
                format!(
                    "strategy:{}",
                    pipeline_execution_strategy_id(execution_strategy)
                ),
                mode_decision
                    .map(|decision| {
                        format!(
                            "requested:{}",
                            pipeline_execution_strategy_id(decision.requested_strategy)
                        )
                    })
                    .unwrap_or_else(|| "requested:implicit".to_string()),
            ],
            None,
        ),
        pipeline_step_for_phase(
            "requirements",
            "Requirements",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "Studio captured the requested scope, mutation boundary, and persistence contract.",
            requirements_outputs,
            None,
        ),
        pipeline_step_for_phase(
            "specification",
            "Artifact spec",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            if let Some(blueprint) = materialization.blueprint.as_ref() {
                format!(
                    "Studio locked the typed artifact spec around the {} scaffold with explicit structure and interaction contracts.",
                    blueprint.scaffold_family
                )
            } else {
                "Artifact class, renderer, presentation surface, and substrate are explicit."
                    .to_string()
            },
            spec_outputs,
            None,
        ),
        pipeline_step(
            "brief",
            ExecutionStage::Plan,
            "Artifact brief",
            brief_status,
            if let Some(brief) = materialization.artifact_brief.as_ref() {
                format!(
                    "Studio grounded the request into a typed artifact brief about {} before authoring.",
                    truncate_pipeline_output(&brief.subject_domain, 48)
                )
            } else {
                "Studio is grounding the request into a typed artifact brief before authoring can begin."
                    .to_string()
            },
            brief_outputs,
            None,
        ),
        pipeline_step(
            "skill_discovery",
            ExecutionStage::Plan,
            "Skill discovery",
            skill_discovery_status,
            if let Some(resolution) = skill_discovery_resolution {
                resolution.rationale.clone()
            } else {
                "Studio is deciding whether this request should attach runtime guidance before authoring."
                    .to_string()
            },
            skill_discovery_outputs,
            None,
        ),
    ];
    if guidance_attached {
        steps.push(pipeline_step(
            "skill_read",
            ExecutionStage::Plan,
            "Read skill guidance",
            if materialization.selected_skills.is_empty() {
                "active"
            } else {
                "complete"
            },
            if materialization.selected_skills.len() == 1 {
                format!(
                    "Studio attached {} before authoring the artifact.",
                    materialization.selected_skills[0].name
                )
            } else {
                format!(
                    "Studio attached {} selected skill guides before authoring.",
                    materialization.selected_skills.len()
                )
            },
            materialization
                .selected_skills
                .iter()
                .map(|skill| skill.name.clone())
                .collect(),
            None,
        ));
    }
    if has_swarm_execution {
        steps.push(pipeline_step_for_phase(
            "planner",
            "Planner",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "Studio locked one canonical artifact plan and explicit worker scopes before authoring.",
            materialization
                .swarm_plan
                .as_ref()
                .map(|plan| {
                    let mut outputs = vec![
                        plan.strategy.clone(),
                        format!("work_items:{}", plan.work_items.len()),
                        plan.parallelism_mode.clone(),
                    ];
                    if let Some(decomposition_type) = plan.decomposition_type.as_ref() {
                        outputs.push(decomposition_type.clone());
                    }
                    outputs
                })
                .unwrap_or_else(|| vec!["planner_pending".to_string()]),
            None,
        ));
        steps.push(pipeline_step_for_phase(
            "swarm_execution",
            if execution_strategy == StudioExecutionStrategy::MicroSwarm {
                "Micro swarm"
            } else {
                "Adaptive work graph"
            },
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "Scoped workers patched the same canonical artifact instead of drafting competing full candidates.",
            {
                let mut outputs = vec![format!("worker_receipts:{swarm_receipt_count}")];
                if let Some(summary) = materialization.swarm_execution.as_ref() {
                    outputs.push(format!(
                        "progress:{}/{}",
                        summary.completed_work_items, summary.total_work_items
                    ));
                    outputs.push(format!("verification:{}", summary.verification_status));
                }
                if let Some(invariant) = completion_invariant {
                    let invariant_status = match invariant.status {
                        ioi_api::execution::ExecutionCompletionInvariantStatus::Pending => {
                            "pending"
                        }
                        ioi_api::execution::ExecutionCompletionInvariantStatus::Satisfied => {
                            "satisfied"
                        }
                        ioi_api::execution::ExecutionCompletionInvariantStatus::Blocked => {
                            "blocked"
                        }
                    };
                    outputs.push(format!("invariant:{invariant_status}"));
                    if !invariant.remaining_obligations.is_empty() {
                        outputs.push(format!(
                            "remaining:{}",
                            invariant.remaining_obligations.len()
                        ));
                    }
                }
                if let Some(envelope) = materialization.execution_envelope.as_ref() {
                    if !envelope.dispatch_batches.is_empty() {
                        outputs.push(format!(
                            "dispatch_batches:{}",
                            envelope.dispatch_batches.len()
                        ));
                    }
                    if !envelope.graph_mutation_receipts.is_empty() {
                        outputs.push(format!(
                            "graph_mutations:{}",
                            envelope.graph_mutation_receipts.len()
                        ));
                    }
                    if !envelope.repair_receipts.is_empty() {
                        outputs.push(format!("repair_receipts:{}", envelope.repair_receipts.len()));
                    }
                }
                outputs
            },
            Some("Worker receipts must retain bounded ownership and status."),
        ));
        steps.push(pipeline_step_for_phase(
            "merge",
            "Merge",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            "Deterministic patch gating and merge receipts reconciled worker output onto one artifact state.",
            materialization
                .swarm_merge_receipts
                .iter()
                .take(4)
                .map(|receipt| {
                    format!(
                        "{} ({})",
                        receipt.work_item_id,
                        format_status_label(work_item_status_id(receipt.status))
                    )
                })
                .collect::<Vec<_>>(),
            Some("Out-of-scope patches must be rejected before the artifact can advance."),
        ));
    }
    steps.push(pipeline_step_for_phase(
        "materialization",
        "Materialization",
        request.renderer,
        lifecycle_state,
        has_files,
        preview_ready,
        if candidate_count > 0 {
            if let Some((cleared, required, failed)) = obligation_counts {
                format!(
                    "Studio drafted {} candidate(s) and cleared {}/{} required obligations{}.",
                    candidate_count,
                    cleared,
                    required,
                    if repair_passes > 0 {
                        format!(
                            "; {} bounded repair attempt(s) were tracked separately",
                            repair_passes
                        )
                    } else if failed > 0 {
                        format!("; {failed} obligation(s) remained unresolved in prior attempts")
                    } else {
                        String::new()
                    }
                )
            } else {
                format!(
                    "Studio drafted {} candidate(s) and selected the strongest winner.",
                    candidate_count
                )
            }
        } else {
            "Studio is creating the files or workspace required by the manifest.".to_string()
        },
        materialization_outputs,
        Some("Files or scaffold receipts must exist before the artifact can present."),
    ));
    if show_execution_step {
        steps.push(pipeline_step_for_phase(
            "execution",
            "Execution",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            if request.renderer == StudioRendererKind::WorkspaceSurface {
                "Workspace commands and retries stay bounded under kernel authority."
            } else {
                "Single-file generation completed inside the selected renderer substrate."
            },
            execution_outputs,
            Some("Execution receipts must exist for every command-backed step."),
        ));
    }
    steps.push(pipeline_step_for_phase(
        "verification",
        "Verification",
        request.renderer,
        lifecycle_state,
        has_files,
        preview_ready,
        if let Some(judge) = materialization.judge.as_ref() {
            format!(
                "Static audits and acceptance judging classified the artifact as {} before Studio surfaced it.",
                judge_classification_id(judge.classification)
            )
        } else {
            manifest.verification.summary.clone()
        },
        verification_outputs,
        Some(
            "Render, build, preview, or export checks must pass before Studio can claim success.",
        ),
    ));
    if show_repair_step {
        steps.push(pipeline_step_for_phase(
            "repair",
            "Repair",
            request.renderer,
            lifecycle_state,
            has_files,
            preview_ready,
            if has_swarm_execution {
                "Repair stays bounded to cited judge or verification failures on the merged artifact."
                    .to_string()
            } else {
                "Repair tracks bounded follow-up passes when verification cites contradictions."
                    .to_string()
            },
            if has_swarm_execution {
                let mut outputs = materialization
                    .swarm_change_receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.work_item_id == "repair"
                            || receipt.work_item_id.starts_with("repair-pass-")
                    })
                    .map(|receipt| format!("repair_ops:{}", receipt.operation_count))
                    .collect::<Vec<_>>();
                if let Some(envelope) = materialization.execution_envelope.as_ref() {
                    if !envelope.repair_receipts.is_empty() {
                        outputs.push(format!("repair_receipts:{}", envelope.repair_receipts.len()));
                    }
                    if !envelope.replan_receipts.is_empty() {
                        outputs.push(format!("replans:{}", envelope.replan_receipts.len()));
                    }
                }
                outputs
            } else if repair_passes > 0 {
                vec![format!("repair_passes:{repair_passes}")]
            } else {
                vec!["repair_not_needed".to_string()]
            },
            Some("Repair may patch only cited failures, not restart the artifact wholesale."),
        ));
    }
    steps.push(pipeline_step_for_phase(
        "presentation",
        "Presentation",
        request.renderer,
        lifecycle_state,
        has_files,
        preview_ready,
        if preview_ready {
            "Studio is leading with verified preview because the preview contract passed."
        } else {
            "Studio is presenting only the artifact surfaces that currently exist."
        },
        presentation_outputs,
        Some("Preview becomes primary only after verified render or preview health exists."),
    ));
    steps.push(pipeline_step_for_phase(
        "reply",
        "Verified reply",
        request.renderer,
        lifecycle_state,
        has_files,
        preview_ready,
        "Studio composes the user-facing summary from artifact state and verification.",
        reply_outputs,
        Some(verification_gate),
    ));
    steps
}

pub(super) fn refresh_pipeline_steps(
    studio_session: &mut StudioArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) {
    let Some(request) = studio_session.outcome_request.artifact.as_ref() else {
        studio_session.materialization.pipeline_steps =
            pipeline_steps_for_non_artifact_route(studio_session);
        return;
    };
    studio_session.materialization.pipeline_steps = pipeline_steps_for_state(
        &studio_session.materialization.normalized_intent,
        request,
        &studio_session.artifact_manifest,
        &studio_session.materialization,
        studio_session.lifecycle_state,
        build_session,
        studio_session.taste_memory.as_ref(),
    );
}

pub(super) fn build_command_intents() -> Vec<StudioArtifactMaterializationCommandIntent> {
    vec![
        StudioArtifactMaterializationCommandIntent {
            id: "install".to_string(),
            kind: "install".to_string(),
            label: "Install dependencies".to_string(),
            command: "npm install --no-audit --no-fund".to_string(),
        },
        StudioArtifactMaterializationCommandIntent {
            id: "build".to_string(),
            kind: "build".to_string(),
            label: "Validate build".to_string(),
            command: "npm run build".to_string(),
        },
        StudioArtifactMaterializationCommandIntent {
            id: "preview".to_string(),
            kind: "preview".to_string(),
            label: "Launch preview".to_string(),
            command: "npm run preview -- --host 127.0.0.1 --port <assigned>".to_string(),
        },
    ]
}
