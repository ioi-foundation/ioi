use super::content_session::attach_non_artifact_studio_session;
use super::revisions::persist_studio_artifact_exemplar;
use super::workspace_build::run_build_supervisor_for_proof;
use super::*;
use ioi_api::execution::{execution_strategy_for_outcome, ExecutionEnvelope};
use ioi_api::studio::{
    StudioArtifactExemplar, StudioArtifactMergeReceipt, StudioArtifactPatchReceipt,
    StudioArtifactSwarmExecutionSummary, StudioArtifactSwarmPlan,
    StudioArtifactVerificationReceipt, StudioArtifactWorkerReceipt,
};
use std::time::Duration;

pub(crate) fn run_studio_current_task_turn_for_proof(
    task: &mut AgentTask,
    intent: &str,
    memory_runtime: Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
) -> Result<(), String> {
    let route_timeout =
        super::content_session::studio_routing_timeout_for_runtime(&inference_runtime);
    run_studio_current_task_turn_for_proof_with_route_timeout(
        task,
        intent,
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        workspace_root_base,
        route_timeout,
    )
}

pub(crate) fn run_studio_current_task_turn_for_proof_with_route_timeout(
    task: &mut AgentTask,
    intent: &str,
    memory_runtime: Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
    route_timeout: Duration,
) -> Result<(), String> {
    let active_artifact_id = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task
        .studio_session
        .as_ref()
        .map(|session| studio_refinement_context_for_session(&memory_runtime, session));
    let active_widget_state = task
        .studio_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    let runtime_provenance = inference_runtime.studio_runtime_provenance();
    if runtime_provenance.kind == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable {
        attach_blocked_studio_failure_session(
            task,
            intent,
            active_artifact_id,
            runtime_provenance,
            StudioArtifactFailure {
                kind: StudioArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message:
                    "Studio cannot route or materialize artifacts because inference is unavailable."
                        .to_string(),
            },
        );
        return Ok(());
    }

    let runtime_provenance = inference_runtime.studio_runtime_provenance();
    let outcome_request = match super::content_session::studio_outcome_request_with_runtime_timeout(
        inference_runtime.clone(),
        intent,
        active_artifact_id.clone(),
        active_refinement.as_ref(),
        active_widget_state,
        route_timeout,
    ) {
        Ok(outcome_request) => outcome_request,
        Err(error) => {
            attach_blocked_studio_failure_session(
                task,
                intent,
                active_artifact_id,
                runtime_provenance,
                StudioArtifactFailure {
                    kind: StudioArtifactFailureKind::RoutingFailure,
                    code: "routing_failure".to_string(),
                    message: error,
                },
            );
            return Ok(());
        }
    };
    task.studio_outcome = Some(outcome_request.clone());

    if outcome_request.needs_clarification {
        attach_blocked_route_failure_session_for_proof(
            task,
            intent,
            active_artifact_id,
            &runtime_provenance,
            &outcome_request,
        );
        return Ok(());
    }

    if outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
        attach_non_artifact_studio_session(task, intent, runtime_provenance, &outcome_request);
        apply_studio_authoritative_status(task, None);
        return Ok(());
    }

    if refine_current_non_workspace_artifact_turn_for_proof(
        task,
        intent,
        outcome_request.clone(),
        &memory_runtime,
        inference_runtime.clone(),
        acceptance_inference_runtime.clone(),
    )? {
        return Ok(());
    }

    prepare_task_for_studio_with_request_for_proof(
        task,
        intent,
        outcome_request,
        &memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        workspace_root_base,
    )
}

fn attach_blocked_route_failure_session_for_proof(
    task: &mut AgentTask,
    intent: &str,
    active_artifact_id: Option<String>,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) {
    let message = if outcome_request.needs_clarification {
        let question = outcome_request
            .clarification_questions
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "Studio requested clarification before it could stay on the artifact path."
                    .to_string()
            });
        format!(
            "Studio could not materialize the artifact because routing requested clarification: {}",
            question
        )
    } else {
        format!(
            "Studio routed this proof prompt to {} instead of artifact materialization.",
            match outcome_request.outcome_kind {
                StudioOutcomeKind::Conversation => "conversation",
                StudioOutcomeKind::ToolWidget => "tool_widget",
                StudioOutcomeKind::Visualizer => "visualizer",
                StudioOutcomeKind::Artifact => "artifact",
            }
        )
    };
    attach_blocked_studio_failure_session(
        task,
        intent,
        active_artifact_id,
        provenance.clone(),
        StudioArtifactFailure {
            kind: StudioArtifactFailureKind::RoutingFailure,
            code: "routing_failure".to_string(),
            message,
        },
    );
    task.studio_outcome = Some(outcome_request.clone());
}

fn prepare_task_for_studio_with_request_for_proof(
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
) -> Result<(), String> {
    let artifact_request = outcome_request
        .artifact
        .clone()
        .ok_or_else(|| "Studio artifact outcome missing artifact request".to_string())?;
    let renderer_kind = artifact_request.renderer;
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title = derive_artifact_title(intent);
    let summary = summary_for_request(&artifact_request, &title);
    let studio_session_id = Uuid::new_v4().to_string();
    let created_at = now_iso();
    let mut attached_artifact_ids = Vec::new();
    let mut manifest_files: Vec<StudioArtifactManifestFile> = Vec::new();
    let mut materialization = materialization_contract_for_request(
        intent,
        &artifact_request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let workspace_root = if renderer_kind == StudioRendererKind::WorkspaceSurface {
        Some(workspace_root_base.join(&studio_session_id))
    } else {
        None
    };
    let mut initial_lifecycle_state = if renderer_kind == StudioRendererKind::WorkspaceSurface {
        StudioArtifactLifecycleState::Materializing
    } else {
        StudioArtifactLifecycleState::Ready
    };
    let mut non_workspace_verification_summary: Option<String> = None;
    let mut artifact_brief: Option<StudioArtifactBrief> = None;
    let mut edit_intent: Option<StudioArtifactEditIntent> = None;
    let mut candidate_summaries = Vec::<StudioArtifactCandidateSummary>::new();
    let mut winning_candidate_id: Option<String> = None;
    let mut winning_candidate_rationale: Option<String> = None;
    let mut execution_envelope: Option<ExecutionEnvelope> = None;
    let mut swarm_plan: Option<StudioArtifactSwarmPlan> = None;
    let mut swarm_execution: Option<StudioArtifactSwarmExecutionSummary> = None;
    let mut swarm_worker_receipts = Vec::<StudioArtifactWorkerReceipt>::new();
    let mut swarm_change_receipts = Vec::<StudioArtifactPatchReceipt>::new();
    let mut swarm_merge_receipts = Vec::<StudioArtifactMergeReceipt>::new();
    let mut swarm_verification_receipts = Vec::<StudioArtifactVerificationReceipt>::new();
    let mut render_evaluation: Option<ioi_api::studio::StudioArtifactRenderEvaluation> = None;
    let mut validation: Option<StudioArtifactValidationResult> = None;
    let mut output_origin: Option<StudioArtifactOutputOrigin> = None;
    let mut production_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut acceptance_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut fallback_used = false;
    let mut ux_lifecycle: Option<StudioArtifactUxLifecycle> = None;
    let mut failure: Option<crate::models::StudioArtifactFailure> = None;
    let mut taste_memory: Option<StudioArtifactTasteMemory> = None;
    let mut preparation_needs: Option<ioi_api::studio::StudioArtifactPreparationNeeds> = None;
    let mut prepared_context_resolution: Option<
        ioi_api::studio::StudioArtifactPreparedContextResolution,
    > = None;
    let mut skill_discovery_resolution: Option<
        ioi_api::studio::StudioArtifactSkillDiscoveryResolution,
    > = None;
    let mut retrieved_exemplars = Vec::<StudioArtifactExemplar>::new();
    let mut selected_targets = Vec::<StudioArtifactSelectionTarget>::new();

    if renderer_kind == StudioRendererKind::WorkspaceSurface {
        production_provenance = Some(inference_runtime.studio_runtime_provenance());
        acceptance_provenance = Some(acceptance_inference_runtime.studio_runtime_provenance());
        output_origin = production_provenance
            .as_ref()
            .map(output_origin_from_runtime_provenance);
    }

    let mut build_session = if let Some(root) = workspace_root.as_ref() {
        let recipe = select_workspace_recipe(&artifact_request);
        let package_name = package_name_for_title(&title);
        let scaffold = scaffold_workspace(
            recipe,
            artifact_request
                .presentation_variant_id
                .as_deref()
                .and_then(parse_static_html_archetype_id),
            root,
            &title,
            &package_name,
        )?;
        materialization.file_writes = scaffold.file_writes.clone();
        materialization.command_intents = build_command_intents();
        materialization.preview_intent = Some(StudioArtifactMaterializationPreviewIntent {
            label: "Preview lane".to_string(),
            url: None,
            status: "pending".to_string(),
        });
        materialization.verification_steps = vec![
            verification_step("scaffold", "Scaffold workspace", "success"),
            verification_step("install", "Install dependencies", "pending"),
            verification_step("validation", "Validate build", "pending"),
            verification_step("preview", "Verify preview", "pending"),
        ];
        let mut build_session = BuildArtifactSession {
            session_id: Uuid::new_v4().to_string(),
            studio_session_id: studio_session_id.clone(),
            workspace_root: root.to_string_lossy().to_string(),
            entry_document: recipe.entry_document().to_string(),
            preview_url: None,
            preview_process_id: None,
            scaffold_recipe_id: recipe.id().to_string(),
            presentation_variant_id: artifact_request.presentation_variant_id.clone(),
            package_manager: "npm".to_string(),
            build_status: "scaffolded".to_string(),
            verification_status: "pending".to_string(),
            receipts: vec![StudioBuildReceipt {
                receipt_id: Uuid::new_v4().to_string(),
                kind: "scaffold".to_string(),
                title: format!("Scaffolded {} workspace", recipe.label()),
                status: "success".to_string(),
                summary: format!(
                    "Materialized {} starter files in {} using the {} recipe.",
                    scaffold.file_writes.len(),
                    root.display(),
                    recipe.label()
                ),
                started_at: created_at.clone(),
                finished_at: Some(now_iso()),
                artifact_ids: Vec::new(),
                command: None,
                exit_code: Some(0),
                duration_ms: Some(0),
                failure_class: None,
                replay_classification: Some("replay_safe".to_string()),
            }],
            current_worker_execution: StudioCodeWorkerLease {
                backend: "hosted-fallback".to_string(),
                planner_authority: "kernel".to_string(),
                allowed_mutation_scope: mutation_scope_for_recipe(root, recipe),
                allowed_command_classes: vec![
                    "install".to_string(),
                    "build".to_string(),
                    "preview".to_string(),
                    "repair".to_string(),
                ],
                execution_state: "preparing".to_string(),
                retry_classification: Some("retry_required".to_string()),
                last_summary: Some(format!(
                    "Kernel owns routing. Studio materialized a {} workspace so the artifact can open real code and preview lenses under bounded supervision.",
                    recipe.label()
                )),
            },
            current_lens: "code".to_string(),
            available_lenses: BUILD_LENSES_IN_PROGRESS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ready_lenses: vec!["code".to_string()],
            retry_count: 0,
            last_failure_summary: None,
        };
        let receipt_artifact = create_receipt_report_artifact_for_memory_runtime(
            memory_runtime,
            &thread_id,
            &title,
            &build_session.receipts[0],
        );
        build_session.receipts[0]
            .artifact_ids
            .push(receipt_artifact.artifact_id.clone());
        attached_artifact_ids.push(receipt_artifact.artifact_id.clone());
        task.artifacts.push(receipt_artifact);
        Some(build_session)
    } else {
        None
    };

    let renderer_session = build_session
        .as_ref()
        .map(build_session_to_renderer_session);

    if build_session.is_none() {
        let materialized_artifact =
            materialize_non_workspace_artifact_with_dependencies_and_execution_strategy(
                memory_runtime,
                Some(inference_runtime),
                Some(acceptance_inference_runtime),
                &thread_id,
                &title,
                intent,
                &artifact_request,
                None,
                None,
                outcome_request.execution_strategy,
            )?;
        initial_lifecycle_state = materialized_artifact.lifecycle_state;
        non_workspace_verification_summary =
            Some(materialized_artifact.verification_summary.clone());
        artifact_brief = Some(materialized_artifact.brief.clone());
        preparation_needs = materialized_artifact.preparation_needs.clone();
        prepared_context_resolution = materialized_artifact.prepared_context_resolution.clone();
        skill_discovery_resolution = materialized_artifact.skill_discovery_resolution.clone();
        edit_intent = materialized_artifact.edit_intent.clone();
        candidate_summaries = materialized_artifact.candidate_summaries.clone();
        winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
        winning_candidate_rationale = materialized_artifact.winning_candidate_rationale.clone();
        execution_envelope = materialized_artifact.execution_envelope.clone();
        swarm_plan = materialized_artifact.swarm_plan.clone();
        swarm_execution = materialized_artifact.swarm_execution.clone();
        swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
        swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
        swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
        swarm_verification_receipts = materialized_artifact.swarm_verification_receipts.clone();
        render_evaluation = materialized_artifact.render_evaluation.clone();
        validation = materialized_artifact.validation.clone();
        output_origin = Some(materialized_artifact.output_origin);
        production_provenance = materialized_artifact.production_provenance.clone();
        acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
        fallback_used = materialized_artifact.fallback_used;
        ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
        failure = materialized_artifact.failure.clone();
        taste_memory = materialized_artifact.taste_memory.clone();
        retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
        selected_targets = materialized_artifact.selected_targets.clone();
        attached_artifact_ids.extend(
            materialized_artifact
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.clone()),
        );
        task.artifacts
            .extend(materialized_artifact.artifacts.clone());
        manifest_files = materialized_artifact.files.clone();
        materialization
            .file_writes
            .extend(materialized_artifact.file_writes.clone());
        materialization
            .notes
            .extend(materialized_artifact.notes.clone());
    }

    let mut artifact_manifest = artifact_manifest_for_request(
        &title,
        &artifact_request,
        &attached_artifact_ids,
        build_session.as_ref(),
        renderer_session.as_ref(),
        initial_lifecycle_state,
    );

    let contract_artifact = create_contract_artifact_for_memory_runtime(
        memory_runtime,
        &thread_id,
        &title,
        &materialization,
    );
    attached_artifact_ids.push(contract_artifact.artifact_id.clone());
    task.artifacts.push(contract_artifact);

    artifact_manifest.artifact_id = attached_artifact_ids
        .first()
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    artifact_manifest.files = if manifest_files.is_empty() {
        manifest_files_for_request(&artifact_request, build_session.as_ref())
    } else {
        manifest_files
    };
    if let Some(summary) = non_workspace_verification_summary {
        artifact_manifest.verification = StudioArtifactManifestVerification {
            status: verification_status_for_lifecycle(initial_lifecycle_state),
            lifecycle_state: initial_lifecycle_state,
            summary,
            production_provenance: production_provenance.clone(),
            acceptance_provenance: acceptance_provenance.clone(),
            failure: failure.clone(),
        };
    }
    materialization.artifact_brief = artifact_brief.clone();
    materialization.preparation_needs = preparation_needs.clone();
    materialization.prepared_context_resolution = prepared_context_resolution.clone();
    materialization.skill_discovery_resolution = skill_discovery_resolution.clone();
    materialization.edit_intent = edit_intent.clone();
    materialization.candidate_summaries = candidate_summaries.clone();
    materialization.winning_candidate_id = winning_candidate_id.clone();
    materialization.winning_candidate_rationale = winning_candidate_rationale.clone();
    materialization.swarm_plan = swarm_plan.clone();
    materialization.swarm_execution = swarm_execution.clone();
    materialization.swarm_worker_receipts = swarm_worker_receipts.clone();
    materialization.swarm_change_receipts = swarm_change_receipts.clone();
    materialization.swarm_merge_receipts = swarm_merge_receipts.clone();
    materialization.swarm_verification_receipts = swarm_verification_receipts.clone();
    materialization.execution_envelope = execution_envelope.clone().or_else(|| {
        super::content_session::artifact_execution_envelope_for_contract(
            outcome_request.execution_mode_decision.clone(),
            outcome_request.execution_strategy,
            &materialization,
        )
    });
    materialization.render_evaluation = render_evaluation;
    materialization.validation = validation.clone();
    materialization.output_origin = output_origin;
    materialization.production_provenance = production_provenance.clone();
    materialization.acceptance_provenance = acceptance_provenance.clone();
    materialization.fallback_used = fallback_used;
    materialization.ux_lifecycle = ux_lifecycle;
    materialization.failure = failure.clone();
    materialization.retrieved_exemplars = retrieved_exemplars.clone();
    materialization.navigator_nodes = navigator_nodes_for_manifest(&artifact_manifest);
    let verified_reply = verified_reply_from_manifest(&title, &artifact_manifest);

    let mut studio_session = StudioArtifactSession {
        session_id: studio_session_id.clone(),
        thread_id: thread_id.clone(),
        artifact_id: attached_artifact_ids
            .first()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        title,
        summary,
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: if renderer_kind == StudioRendererKind::WorkspaceSurface {
            "workspace".to_string()
        } else {
            "logical".to_string()
        },
        navigator_nodes: navigator_nodes_for_manifest(&artifact_manifest),
        attached_artifact_ids,
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest,
        verified_reply,
        lifecycle_state: initial_lifecycle_state,
        status: lifecycle_state_label(initial_lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory,
        retrieved_exemplars,
        selected_targets,
        widget_state: None,
        ux_lifecycle,
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: build_session
            .as_ref()
            .map(|session| session.session_id.clone()),
        workspace_root: workspace_root
            .as_ref()
            .map(|root| root.to_string_lossy().to_string()),
        renderer_session_id: renderer_session
            .as_ref()
            .map(|session| session.session_id.clone()),
    };
    if let Some(build_session) = build_session.as_mut() {
        run_build_supervisor_for_proof(&mut studio_session, build_session)?;
    } else {
        refresh_pipeline_steps(&mut studio_session, build_session.as_ref());
    }
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    sync_workspace_manifest_file(&studio_session);

    let artifact_refs = task
        .artifacts
        .iter()
        .map(|artifact| ArtifactRef {
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
        })
        .collect::<Vec<_>>();

    task.events.push(build_event(
        &thread_id,
        task.progress,
        EventType::Receipt,
        format!("Studio created {}", studio_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&artifact_request),
            "navigator_backing_mode": studio_session.navigator_backing_mode,
            "build_session_id": studio_session.build_session_id,
        }),
        serde_json::to_value(&studio_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.studio_session = Some(studio_session);
    task.renderer_session = renderer_session;
    task.build_session = build_session;
    Ok(())
}

fn refine_current_non_workspace_artifact_turn_for_proof(
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
) -> Result<bool, String> {
    if !should_refine_current_non_workspace_artifact(task, &outcome_request) {
        return Ok(false);
    }

    let Some(mut studio_session) = task.studio_session.clone() else {
        return Ok(false);
    };
    let Some(request) = outcome_request.artifact.clone() else {
        return Ok(false);
    };
    let refinement = studio_refinement_context_for_session(memory_runtime, &studio_session);
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let mut materialized_artifact =
        materialize_non_workspace_artifact_with_dependencies_and_execution_strategy(
            memory_runtime,
            Some(inference_runtime.clone()),
            Some(acceptance_inference_runtime.clone()),
            &thread_id,
            &studio_session.title,
            intent,
            &request,
            Some(&refinement),
            None,
            outcome_request.execution_strategy,
        )?;
    let selected_targets = if materialized_artifact.selected_targets.is_empty() {
        materialized_artifact
            .edit_intent
            .as_ref()
            .map(|edit_intent| edit_intent.selected_targets.clone())
            .unwrap_or_default()
    } else {
        materialized_artifact.selected_targets.clone()
    };
    let taste_memory = derive_studio_taste_memory(
        refinement.taste_memory.as_ref(),
        &materialized_artifact.brief,
        materialized_artifact.blueprint.as_ref(),
        materialized_artifact.artifact_ir.as_ref(),
        materialized_artifact.edit_intent.as_ref(),
        materialized_artifact.validation.as_ref(),
    );
    materialized_artifact.selected_targets = selected_targets.clone();
    materialized_artifact.taste_memory = taste_memory.clone();

    let title = if matches!(
        materialized_artifact
            .edit_intent
            .as_ref()
            .map(|edit_intent| edit_intent.mode),
        Some(StudioArtifactEditMode::Replace | StudioArtifactEditMode::Create)
    ) {
        derive_artifact_title(intent)
    } else {
        studio_session.title.clone()
    };
    let summary = if materialized_artifact
        .edit_intent
        .as_ref()
        .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
    {
        format!(
            "Studio refined '{}' in place through the {} renderer and preserved revision continuity.",
            title,
            renderer_kind_id(request.renderer)
        )
    } else {
        summary_for_request(&request, &title)
    };

    task.artifacts
        .extend(materialized_artifact.artifacts.iter().cloned());

    studio_session.title = title.clone();
    studio_session.summary = summary.clone();
    studio_session.navigator_backing_mode = "logical".to_string();
    studio_session.attached_artifact_ids.extend(
        materialized_artifact
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone()),
    );
    studio_session.outcome_request = outcome_request.clone();
    studio_session.artifact_manifest.title = title.clone();
    studio_session.artifact_manifest.artifact_class = request.artifact_class;
    studio_session.artifact_manifest.renderer = request.renderer;
    studio_session.artifact_manifest.primary_tab =
        if request.renderer == StudioRendererKind::DownloadCard {
            "download".to_string()
        } else {
            "render".to_string()
        };
    studio_session.artifact_manifest.tabs = manifest_tabs_for_request(&request, None);
    studio_session.artifact_manifest.files = materialized_artifact.files.clone();
    studio_session.artifact_manifest.verification = StudioArtifactManifestVerification {
        status: verification_status_for_lifecycle(materialized_artifact.lifecycle_state),
        lifecycle_state: materialized_artifact.lifecycle_state,
        summary: materialized_artifact.verification_summary.clone(),
        production_provenance: materialized_artifact.production_provenance.clone(),
        acceptance_provenance: materialized_artifact.acceptance_provenance.clone(),
        failure: materialized_artifact.failure.clone(),
    };
    studio_session.available_lenses = studio_session
        .artifact_manifest
        .tabs
        .iter()
        .map(|tab| tab.id.clone())
        .collect();
    if !studio_session
        .available_lenses
        .iter()
        .any(|lens| lens == &studio_session.current_lens)
    {
        studio_session.current_lens = studio_session.artifact_manifest.primary_tab.clone();
    }

    let mut materialization = materialization_contract_for_request(
        intent,
        &request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request)),
    );
    super::content_session::apply_materialized_artifact_to_contract(
        &mut materialization,
        &request,
        &materialized_artifact,
        outcome_request.execution_mode_decision.clone(),
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request)),
    );
    materialization.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);

    studio_session.materialization = materialization;
    studio_session.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
    studio_session.verified_reply =
        verified_reply_from_manifest(&title, &studio_session.artifact_manifest);
    studio_session.lifecycle_state = materialized_artifact.lifecycle_state;
    studio_session.status =
        lifecycle_state_label(materialized_artifact.lifecycle_state).to_string();
    studio_session.taste_memory = taste_memory;
    studio_session.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    studio_session.selected_targets = selected_targets;
    studio_session.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    studio_session.updated_at = now_iso();
    refresh_pipeline_steps(&mut studio_session, None);

    let (branch_id, branch_label, parent_revision_id) =
        revision_branch_identity(&studio_session, materialized_artifact.edit_intent.as_ref());
    let revision = revision_for_session(
        &studio_session,
        intent,
        branch_id,
        branch_label,
        parent_revision_id,
    );
    studio_session.active_revision_id = Some(revision.revision_id.clone());
    studio_session.revisions.push(revision.clone());
    match persist_studio_artifact_exemplar(
        memory_runtime,
        Some(inference_runtime.clone()),
        &studio_session,
        &revision,
    ) {
        Ok(Some(exemplar)) => studio_session.materialization.notes.push(format!(
            "Archived exemplar {} for {} / {}.",
            exemplar.record_id,
            renderer_kind_id(exemplar.renderer),
            exemplar.scaffold_family
        )),
        Ok(None) => {}
        Err(error) => studio_session
            .materialization
            .notes
            .push(format!("Exemplar archival skipped: {error}")),
    }

    let artifact_refs = task
        .artifacts
        .iter()
        .map(|artifact| ArtifactRef {
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
        })
        .collect::<Vec<_>>();
    task.events.push(build_event(
        &thread_id,
        task.progress,
        EventType::Receipt,
        format!("Studio refined {}", studio_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&request),
            "mode": materialized_artifact
                .edit_intent
                .as_ref()
                .map(|edit_intent| format!("{:?}", edit_intent.mode).to_lowercase()),
            "revision_id": revision.revision_id,
            "branch_id": revision.branch_id,
        }),
        serde_json::to_value(&studio_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.studio_session = Some(studio_session);
    task.renderer_session = None;
    task.build_session = None;
    Ok(true)
}
