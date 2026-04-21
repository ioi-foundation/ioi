use super::content_session::attach_non_artifact_chat_session;
use super::revisions::persist_chat_artifact_exemplar;
use super::workspace_build::run_build_supervisor_for_proof;
use super::*;
use ioi_api::execution::{execution_strategy_for_outcome, ExecutionEnvelope};
use ioi_api::runtime_harness::{
    ArtifactRenderEvaluation as ChatArtifactRenderEvaluation,
    ChatArtifactExemplar as ChatArtifactExemplar,
    ChatArtifactMergeReceipt as ChatArtifactMergeReceipt,
    ChatArtifactPatchReceipt as ChatArtifactPatchReceipt,
    ChatArtifactPreparedContextResolution as ChatArtifactPreparedContextResolution,
    ChatArtifactPreparationNeeds as ChatArtifactPreparationNeeds,
    ChatArtifactSkillDiscoveryResolution as ChatArtifactSkillDiscoveryResolution,
    ChatArtifactSwarmExecutionSummary as ChatArtifactSwarmExecutionSummary,
    ChatArtifactSwarmPlan as ChatArtifactSwarmPlan,
    ChatArtifactVerificationReceipt as ChatArtifactVerificationReceipt,
    ChatArtifactWorkerReceipt as ChatArtifactWorkerReceipt,
};
use std::time::Duration;

pub(crate) fn run_chat_current_task_turn_for_proof(
    task: &mut AgentTask,
    intent: &str,
    memory_runtime: Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
) -> Result<(), String> {
    let route_timeout =
        super::content_session::chat_routing_timeout_for_runtime(&inference_runtime);
    run_chat_current_task_turn_for_proof_with_route_timeout(
        task,
        intent,
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        workspace_root_base,
        route_timeout,
    )
}

pub(crate) fn run_chat_current_task_turn_for_proof_with_route_timeout(
    task: &mut AgentTask,
    intent: &str,
    memory_runtime: Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
    route_timeout: Duration,
) -> Result<(), String> {
    let active_artifact_id = task
        .chat_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task
        .chat_session
        .as_ref()
        .map(|session| chat_refinement_context_for_session(&memory_runtime, session));
    let active_widget_state = task
        .chat_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    let runtime_provenance = inference_runtime.chat_runtime_provenance();
    if runtime_provenance.kind == crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable {
        attach_blocked_chat_failure_session(
            task,
            intent,
            active_artifact_id,
            runtime_provenance,
            ChatArtifactFailure {
                kind: ChatArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message:
                    "Chat cannot route or materialize artifacts because inference is unavailable."
                        .to_string(),
            },
        );
        return Ok(());
    }

    let runtime_provenance = inference_runtime.chat_runtime_provenance();
    let outcome_request = match super::content_session::chat_outcome_request_with_runtime_timeout(
        inference_runtime.clone(),
        intent,
        active_artifact_id.clone(),
        active_refinement.as_ref(),
        active_widget_state,
        route_timeout,
    ) {
        Ok(outcome_request) => outcome_request,
        Err(error) => {
            attach_blocked_chat_failure_session(
                task,
                intent,
                active_artifact_id,
                runtime_provenance,
                ChatArtifactFailure {
                    kind: ChatArtifactFailureKind::RoutingFailure,
                    code: "routing_failure".to_string(),
                    message: error,
                },
            );
            return Ok(());
        }
    };
    task.chat_outcome = Some(outcome_request.clone());

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

    if outcome_request.outcome_kind != ChatOutcomeKind::Artifact {
        attach_non_artifact_chat_session(task, intent, runtime_provenance, &outcome_request);
        apply_chat_authoritative_status(task, None);
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

    prepare_task_for_chat_with_request_for_proof(
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
    provenance: &crate::models::ChatRuntimeProvenance,
    outcome_request: &ChatOutcomeRequest,
) {
    let message = if outcome_request.needs_clarification {
        let question = outcome_request
            .clarification_questions
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "Chat requested clarification before it could stay on the artifact path."
                    .to_string()
            });
        format!(
            "Chat could not materialize the artifact because routing requested clarification: {}",
            question
        )
    } else {
        format!(
            "Chat routed this proof prompt to {} instead of artifact materialization.",
            match outcome_request.outcome_kind {
                ChatOutcomeKind::Conversation => "conversation",
                ChatOutcomeKind::ToolWidget => "tool_widget",
                ChatOutcomeKind::Visualizer => "visualizer",
                ChatOutcomeKind::Artifact => "artifact",
            }
        )
    };
    attach_blocked_chat_failure_session(
        task,
        intent,
        active_artifact_id,
        provenance.clone(),
        ChatArtifactFailure {
            kind: ChatArtifactFailureKind::RoutingFailure,
            code: "routing_failure".to_string(),
            message,
        },
    );
    task.chat_outcome = Some(outcome_request.clone());
}

fn prepare_task_for_chat_with_request_for_proof(
    task: &mut AgentTask,
    intent: &str,
    outcome_request: ChatOutcomeRequest,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
    workspace_root_base: &Path,
) -> Result<(), String> {
    let artifact_request = outcome_request
        .artifact
        .clone()
        .ok_or_else(|| "Chat artifact outcome missing artifact request".to_string())?;
    let renderer_kind = artifact_request.renderer;
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title = derive_artifact_title(intent);
    let summary = summary_for_request(&artifact_request, &title);
    let chat_session_id = Uuid::new_v4().to_string();
    let created_at = now_iso();
    let mut attached_artifact_ids = Vec::new();
    let mut manifest_files: Vec<ChatArtifactManifestFile> = Vec::new();
    let mut materialization = materialization_contract_for_request(
        intent,
        &artifact_request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let workspace_root = if renderer_kind == ChatRendererKind::WorkspaceSurface {
        Some(workspace_root_base.join(&chat_session_id))
    } else {
        None
    };
    let mut initial_lifecycle_state = if renderer_kind == ChatRendererKind::WorkspaceSurface {
        ChatArtifactLifecycleState::Materializing
    } else {
        ChatArtifactLifecycleState::Ready
    };
    let mut non_workspace_verification_summary: Option<String> = None;
    let mut artifact_brief: Option<ChatArtifactBrief> = None;
    let mut edit_intent: Option<ChatArtifactEditIntent> = None;
    let mut candidate_summaries = Vec::<ChatArtifactCandidateSummary>::new();
    let mut winning_candidate_id: Option<String> = None;
    let mut winning_candidate_rationale: Option<String> = None;
    let mut execution_envelope: Option<ExecutionEnvelope> = None;
    let mut swarm_plan: Option<ChatArtifactSwarmPlan> = None;
    let mut swarm_execution: Option<ChatArtifactSwarmExecutionSummary> = None;
    let mut swarm_worker_receipts = Vec::<ChatArtifactWorkerReceipt>::new();
    let mut swarm_change_receipts = Vec::<ChatArtifactPatchReceipt>::new();
    let mut swarm_merge_receipts = Vec::<ChatArtifactMergeReceipt>::new();
    let mut swarm_verification_receipts = Vec::<ChatArtifactVerificationReceipt>::new();
    let mut render_evaluation: Option<ioi_api::runtime_harness::ArtifactRenderEvaluation> =
        None;
    let mut validation: Option<ChatArtifactValidationResult> = None;
    let mut output_origin: Option<ChatArtifactOutputOrigin> = None;
    let mut production_provenance: Option<crate::models::ChatRuntimeProvenance> = None;
    let mut acceptance_provenance: Option<crate::models::ChatRuntimeProvenance> = None;
    let mut fallback_used = false;
    let mut ux_lifecycle: Option<ChatArtifactUxLifecycle> = None;
    let mut failure: Option<crate::models::ChatArtifactFailure> = None;
    let mut taste_memory: Option<ChatArtifactTasteMemory> = None;
    let mut preparation_needs: Option<ioi_api::runtime_harness::ChatArtifactPreparationNeeds> =
        None;
    let mut prepared_context_resolution: Option<
        ioi_api::runtime_harness::ChatArtifactPreparedContextResolution,
    > = None;
    let mut skill_discovery_resolution: Option<
        ioi_api::runtime_harness::ChatArtifactSkillDiscoveryResolution,
    > = None;
    let mut retrieved_exemplars = Vec::<ChatArtifactExemplar>::new();
    let mut selected_targets = Vec::<ChatArtifactSelectionTarget>::new();

    if renderer_kind == ChatRendererKind::WorkspaceSurface {
        production_provenance = Some(inference_runtime.chat_runtime_provenance());
        acceptance_provenance = Some(acceptance_inference_runtime.chat_runtime_provenance());
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
        materialization.preview_intent = Some(ChatArtifactMaterializationPreviewIntent {
            label: "Preview lane".to_string(),
            url: None,
            status: "pending".to_string(),
        });
        for step in &mut materialization.operator_steps {
            if step.step_id == "workspace_scaffold" {
                step.status = ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete;
                step.detail = "Scaffold workspace completed.".to_string();
                step.finished_at_ms = Some(step.finished_at_ms.unwrap_or(0));
            }
        }
        let mut build_session = BuildArtifactSession {
            session_id: Uuid::new_v4().to_string(),
            chat_session_id: chat_session_id.clone(),
            workspace_root: root.to_string_lossy().to_string(),
            entry_document: recipe.entry_document().to_string(),
            preview_url: None,
            preview_process_id: None,
            scaffold_recipe_id: recipe.id().to_string(),
            presentation_variant_id: artifact_request.presentation_variant_id.clone(),
            package_manager: "npm".to_string(),
            build_status: "scaffolded".to_string(),
            verification_status: "pending".to_string(),
            receipts: vec![ChatBuildReceipt {
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
            current_worker_execution: ChatCodeWorkerLease {
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
                    "Kernel owns routing. Chat materialized a {} workspace so the artifact can open real code and preview lenses under bounded supervision.",
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
        artifact_manifest.verification = ChatArtifactManifestVerification {
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
    let retrieved_sources = materialization.retrieved_sources.clone();

    let mut chat_session = ChatArtifactSession {
        session_id: chat_session_id.clone(),
        thread_id: thread_id.clone(),
        artifact_id: attached_artifact_ids
            .first()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        origin_prompt_event_id: None,
        title,
        summary,
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: if renderer_kind == ChatRendererKind::WorkspaceSurface {
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
        retrieved_sources,
        selected_targets,
        widget_state: None,
        ux_lifecycle,
        active_operator_run: None,
        operator_run_history: Vec::new(),
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
        run_build_supervisor_for_proof(&mut chat_session, build_session)?;
    } else {
        refresh_pipeline_steps(&mut chat_session, build_session.as_ref());
    }
    let initial_revision = initial_revision_for_session(&chat_session, intent);
    chat_session.active_revision_id = Some(initial_revision.revision_id.clone());
    chat_session.revisions = vec![initial_revision];
    sync_workspace_manifest_file(&chat_session);

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
        format!("Chat created {}", chat_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&artifact_request),
            "navigator_backing_mode": chat_session.navigator_backing_mode,
            "build_session_id": chat_session.build_session_id,
        }),
        serde_json::to_value(&chat_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.chat_session = Some(chat_session);
    task.renderer_session = renderer_session;
    task.build_session = build_session;
    Ok(())
}

fn refine_current_non_workspace_artifact_turn_for_proof(
    task: &mut AgentTask,
    intent: &str,
    outcome_request: ChatOutcomeRequest,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    acceptance_inference_runtime: Arc<dyn InferenceRuntime>,
) -> Result<bool, String> {
    if !should_refine_current_non_workspace_artifact(task, &outcome_request) {
        return Ok(false);
    }

    let Some(mut chat_session) = task.chat_session.clone() else {
        return Ok(false);
    };
    let Some(request) = outcome_request.artifact.clone() else {
        return Ok(false);
    };
    let refinement = chat_refinement_context_for_session(memory_runtime, &chat_session);
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let mut materialized_artifact =
        materialize_non_workspace_artifact_with_dependencies_and_execution_strategy(
            memory_runtime,
            Some(inference_runtime.clone()),
            Some(acceptance_inference_runtime.clone()),
            &thread_id,
            &chat_session.title,
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
    let taste_memory = derive_chat_taste_memory(
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
        Some(ChatArtifactEditMode::Replace | ChatArtifactEditMode::Create)
    ) {
        derive_artifact_title(intent)
    } else {
        chat_session.title.clone()
    };
    let summary = if materialized_artifact
        .edit_intent
        .as_ref()
        .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
    {
        format!(
            "Chat refined '{}' in place through the {} renderer and preserved revision continuity.",
            title,
            renderer_kind_id(request.renderer)
        )
    } else {
        summary_for_request(&request, &title)
    };

    task.artifacts
        .extend(materialized_artifact.artifacts.iter().cloned());

    chat_session.title = title.clone();
    chat_session.summary = summary.clone();
    chat_session.navigator_backing_mode = "logical".to_string();
    chat_session.attached_artifact_ids.extend(
        materialized_artifact
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone()),
    );
    chat_session.outcome_request = outcome_request.clone();
    chat_session.artifact_manifest.title = title.clone();
    chat_session.artifact_manifest.artifact_class = request.artifact_class;
    chat_session.artifact_manifest.renderer = request.renderer;
    chat_session.artifact_manifest.primary_tab =
        if request.renderer == ChatRendererKind::DownloadCard {
            "download".to_string()
        } else {
            "render".to_string()
        };
    chat_session.artifact_manifest.tabs = manifest_tabs_for_request(&request, None);
    chat_session.artifact_manifest.files = materialized_artifact.files.clone();
    chat_session.artifact_manifest.verification = ChatArtifactManifestVerification {
        status: verification_status_for_lifecycle(materialized_artifact.lifecycle_state),
        lifecycle_state: materialized_artifact.lifecycle_state,
        summary: materialized_artifact.verification_summary.clone(),
        production_provenance: materialized_artifact.production_provenance.clone(),
        acceptance_provenance: materialized_artifact.acceptance_provenance.clone(),
        failure: materialized_artifact.failure.clone(),
    };
    chat_session.available_lenses = chat_session
        .artifact_manifest
        .tabs
        .iter()
        .map(|tab| tab.id.clone())
        .collect();
    if !chat_session
        .available_lenses
        .iter()
        .any(|lens| lens == &chat_session.current_lens)
    {
        chat_session.current_lens = chat_session.artifact_manifest.primary_tab.clone();
    }

    let mut materialization = materialization_contract_for_request(
        intent,
        &request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&request)),
    );
    super::content_session::apply_materialized_artifact_to_contract(
        &mut materialization,
        &request,
        &materialized_artifact,
        outcome_request.execution_mode_decision.clone(),
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&request)),
    );
    materialization.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);

    chat_session.materialization = materialization;
    chat_session.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);
    chat_session.verified_reply =
        verified_reply_from_manifest(&title, &chat_session.artifact_manifest);
    chat_session.lifecycle_state = materialized_artifact.lifecycle_state;
    chat_session.status = lifecycle_state_label(materialized_artifact.lifecycle_state).to_string();
    chat_session.taste_memory = taste_memory;
    chat_session.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    chat_session.selected_targets = selected_targets;
    chat_session.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    chat_session.updated_at = now_iso();
    refresh_pipeline_steps(&mut chat_session, None);

    let (branch_id, branch_label, parent_revision_id) =
        revision_branch_identity(&chat_session, materialized_artifact.edit_intent.as_ref());
    let revision = revision_for_session(
        &chat_session,
        intent,
        branch_id,
        branch_label,
        parent_revision_id,
    );
    chat_session.active_revision_id = Some(revision.revision_id.clone());
    chat_session.revisions.push(revision.clone());
    match persist_chat_artifact_exemplar(
        memory_runtime,
        Some(inference_runtime.clone()),
        &chat_session,
        &revision,
    ) {
        Ok(Some(exemplar)) => chat_session.materialization.notes.push(format!(
            "Archived exemplar {} for {} / {}.",
            exemplar.record_id,
            renderer_kind_id(exemplar.renderer),
            exemplar.scaffold_family
        )),
        Ok(None) => {}
        Err(error) => chat_session
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
        format!("Chat refined {}", chat_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&request),
            "mode": materialized_artifact
                .edit_intent
                .as_ref()
                .map(|edit_intent| format!("{:?}", edit_intent.mode).to_lowercase()),
            "revision_id": revision.revision_id,
            "branch_id": revision.branch_id,
        }),
        serde_json::to_value(&chat_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.chat_session = Some(chat_session);
    task.renderer_session = None;
    task.build_session = None;
    Ok(true)
}
