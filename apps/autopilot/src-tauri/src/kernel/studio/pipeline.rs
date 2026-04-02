use crate::models::{
    BuildArtifactSession, StudioArtifactLifecycleState, StudioArtifactManifest,
    StudioArtifactMaterializationCommandIntent, StudioArtifactMaterializationContract,
    StudioArtifactMaterializationVerificationStep, StudioArtifactPipelineStage,
    StudioArtifactPipelineStep, StudioArtifactSession, StudioOutcomeArtifactRequest,
    StudioRendererKind,
};
use ioi_api::studio::{StudioArtifactJudgeClassification, StudioArtifactTasteMemory};

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
    stage: StudioArtifactPipelineStage,
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

fn pipeline_status_for_stage(
    stage: StudioArtifactPipelineStage,
    renderer: StudioRendererKind,
    lifecycle_state: StudioArtifactLifecycleState,
    has_files: bool,
    preview_ready: bool,
) -> &'static str {
    match stage {
        StudioArtifactPipelineStage::Intake
        | StudioArtifactPipelineStage::Routing
        | StudioArtifactPipelineStage::Requirements
        | StudioArtifactPipelineStage::Specification => "complete",
        StudioArtifactPipelineStage::Materialization => match lifecycle_state {
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
        StudioArtifactPipelineStage::Execution => {
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
        StudioArtifactPipelineStage::Verification => match lifecycle_state {
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
        StudioArtifactPipelineStage::Presentation => {
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
        StudioArtifactPipelineStage::Reply => match lifecycle_state {
            StudioArtifactLifecycleState::Ready => "complete",
            StudioArtifactLifecycleState::Partial | StudioArtifactLifecycleState::Blocked => {
                "blocked"
            }
            StudioArtifactLifecycleState::Failed => "failed",
            _ => "pending",
        },
    }
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

fn judge_classification_id(classification: StudioArtifactJudgeClassification) -> &'static str {
    match classification {
        StudioArtifactJudgeClassification::Pass => "pass",
        StudioArtifactJudgeClassification::Repairable => "repairable",
        StudioArtifactJudgeClassification::Blocked => "blocked",
    }
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
    let preview_ready = build_session
        .and_then(|session| session.preview_url.as_ref())
        .is_some()
        && manifest.primary_tab == "preview";
    let verification_gate = "Verification state, not worker prose, authorizes Studio replies.";
    let mut spec_outputs = vec![
        artifact_class_id_for_request(request),
        renderer_kind_id(request.renderer).to_string(),
        presentation_surface_id(request.presentation_surface).to_string(),
        persistence_mode_id(request.persistence).to_string(),
    ];
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
    if candidate_count > 0 {
        materialization_outputs.push(format!("candidates:{candidate_count}"));
    }
    if let Some(winner) = winner_summary {
        materialization_outputs.push(winner);
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
        let mut outputs = manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
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

    vec![
        pipeline_step(
            "intake",
            StudioArtifactPipelineStage::Intake,
            "Intake",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Intake,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            "Studio captured the request and established the active artifact context.",
            vec![prompt_excerpt],
            None,
        ),
        pipeline_step(
            "routing",
            StudioArtifactPipelineStage::Routing,
            "Outcome routing",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Routing,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            "The typed router chose the artifact branch intentionally.",
            vec![
                "artifact".to_string(),
                artifact_class_id_for_request(request),
                renderer_kind_id(request.renderer).to_string(),
            ],
            None,
        ),
        pipeline_step(
            "requirements",
            StudioArtifactPipelineStage::Requirements,
            "Requirements",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Requirements,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            "Studio captured the requested scope, mutation boundary, and persistence contract.",
            requirements_outputs,
            None,
        ),
        pipeline_step(
            "specification",
            StudioArtifactPipelineStage::Specification,
            "Artifact spec",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Specification,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
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
            "materialization",
            StudioArtifactPipelineStage::Materialization,
            "Materialization",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Materialization,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            if candidate_count > 0 {
                format!(
                    "Studio drafted {} candidate(s), selected the strongest winner, and tracked {} repair pass(es).",
                    candidate_count, repair_passes
                )
            } else {
                "Studio is creating the files or workspace required by the manifest.".to_string()
            },
            materialization_outputs,
            Some("Files or scaffold receipts must exist before the artifact can present."),
        ),
        pipeline_step(
            "execution",
            StudioArtifactPipelineStage::Execution,
            "Execution",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Execution,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            if request.renderer == StudioRendererKind::WorkspaceSurface {
                "Workspace commands and retries stay bounded under kernel authority."
            } else {
                "Single-file generation completed inside the selected renderer substrate."
            },
            execution_outputs,
            Some("Execution receipts must exist for every command-backed step."),
        ),
        pipeline_step(
            "verification",
            StudioArtifactPipelineStage::Verification,
            "Verification",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Verification,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
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
        ),
        pipeline_step(
            "presentation",
            StudioArtifactPipelineStage::Presentation,
            "Presentation",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Presentation,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            if preview_ready {
                "Studio is leading with verified preview because the preview contract passed."
            } else {
                "Studio is presenting only the artifact surfaces that currently exist."
            },
            presentation_outputs,
            Some("Preview becomes primary only after verified render or preview health exists."),
        ),
        pipeline_step(
            "reply",
            StudioArtifactPipelineStage::Reply,
            "Verified reply",
            pipeline_status_for_stage(
                StudioArtifactPipelineStage::Reply,
                request.renderer,
                lifecycle_state,
                has_files,
                preview_ready,
            ),
            "Studio composes the user-facing summary from artifact state and verification.",
            reply_outputs,
            Some(verification_gate),
        ),
    ]
}

pub(super) fn refresh_pipeline_steps(
    studio_session: &mut StudioArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) {
    let Some(request) = studio_session.outcome_request.artifact.as_ref() else {
        studio_session.materialization.pipeline_steps.clear();
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
