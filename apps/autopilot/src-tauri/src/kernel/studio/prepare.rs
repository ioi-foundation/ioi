use super::*;

fn publish_current_task_progress(
    app: &AppHandle,
    task: &mut AgentTask,
    current_step: impl Into<String>,
) {
    task.phase = AgentPhase::Running;
    task.current_step = current_step.into();

    let task_id = task.id.clone();
    let task_snapshot = task.clone();
    let state = app.state::<Mutex<AppState>>();
    let mut memory_runtime = None;
    let mut replaced_current_task = false;

    if let Ok(mut guard) = state.lock() {
        memory_runtime = guard.memory_runtime.clone();
        if let Some(current_task) = guard.current_task.as_mut() {
            if current_task.id == task_id {
                *current_task = task_snapshot.clone();
                replaced_current_task = true;
            }
        }
    }

    if !replaced_current_task {
        return;
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task_snapshot);
    }

    let _ = app.emit("task-updated", &task_snapshot);
}

pub fn maybe_prepare_task_for_studio(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<(), String> {
    publish_current_task_progress(app, task, "Routing the request...");
    let active_artifact_id = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.studio_session.as_ref().and_then(|session| {
        app.state::<Mutex<AppState>>()
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .memory_runtime
                    .as_ref()
                    .map(|runtime| studio_refinement_context_for_session(runtime, session))
            })
    });
    if let Some(runtime) = app_studio_routing_inference_runtime(app) {
        if runtime.studio_runtime_provenance().kind
            == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
        {
            let failure = StudioArtifactFailure {
                kind: StudioArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message:
                    "Studio cannot route or materialize artifacts because inference is unavailable."
                        .to_string(),
            };
            attach_blocked_studio_failure_session(
                task,
                intent,
                active_artifact_id,
                runtime.studio_runtime_provenance(),
                failure,
            );
            return Ok(());
        }
    } else {
        attach_blocked_studio_failure_session(
            task,
            intent,
            active_artifact_id,
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
            StudioArtifactFailure {
                kind: StudioArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message: "Studio cannot route or materialize artifacts because inference runtime is unavailable."
                    .to_string(),
            },
        );
        return Ok(());
    }
    let outcome_request = match studio_outcome_request(
        app,
        intent,
        active_artifact_id.clone(),
        active_refinement.as_ref(),
    ) {
        Ok(outcome_request) => outcome_request,
        Err(error) => {
            let provenance = app_studio_routing_inference_runtime(app)
                .map(|runtime| runtime.studio_runtime_provenance())
                .unwrap_or(crate::models::StudioRuntimeProvenance {
                    kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                    label: "inference unavailable".to_string(),
                    model: None,
                    endpoint: None,
                });
            attach_blocked_studio_failure_session(
                task,
                intent,
                active_artifact_id,
                provenance,
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

    if outcome_request.needs_clarification
        || outcome_request.outcome_kind != StudioOutcomeKind::Artifact
    {
        apply_non_artifact_route_state(task, &outcome_request);
        publish_current_task_progress(app, task, task.current_step.clone());
        return Ok(());
    }

    maybe_prepare_task_for_studio_with_request(app, task, intent, outcome_request)
}

fn maybe_prepare_task_for_studio_with_request(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
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
    let mut materialization =
        materialization_contract_for_request(intent, &artifact_request, &summary);
    let workspace_root = if renderer_kind == StudioRendererKind::WorkspaceSurface {
        Some(workspace_root_for(app, &studio_session_id))
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
    let mut judge: Option<StudioArtifactJudgeResult> = None;
    let mut output_origin: Option<StudioArtifactOutputOrigin> = None;
    let mut production_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut acceptance_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut fallback_used = false;
    let mut ux_lifecycle: Option<StudioArtifactUxLifecycle> = None;
    let mut failure: Option<crate::models::StudioArtifactFailure> = None;
    let mut taste_memory: Option<StudioArtifactTasteMemory> = None;
    let mut selected_targets = Vec::<StudioArtifactSelectionTarget>::new();
    let app_runtime_provenance =
        app_inference_runtime(app).map(|runtime| runtime.studio_runtime_provenance());
    let app_acceptance_runtime_provenance =
        app_acceptance_inference_runtime(app).map(|runtime| runtime.studio_runtime_provenance());

    if renderer_kind == StudioRendererKind::WorkspaceSurface {
        production_provenance = Some(app_runtime_provenance.unwrap_or(
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
        acceptance_provenance = Some(app_acceptance_runtime_provenance.unwrap_or(
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
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
        Some(BuildArtifactSession {
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
        })
    } else {
        None
    };

    let renderer_session = build_session
        .as_ref()
        .map(build_session_to_renderer_session);

    if build_session.is_none() {
        publish_current_task_progress(app, task, "Drafting artifact candidates...");
        let materialized_artifact = materialize_non_workspace_artifact(
            app,
            &thread_id,
            &title,
            intent,
            &artifact_request,
            None,
        )?;
        publish_current_task_progress(app, task, "Verifying artifact output...");
        initial_lifecycle_state = materialized_artifact.lifecycle_state;
        non_workspace_verification_summary =
            Some(materialized_artifact.verification_summary.clone());
        artifact_brief = Some(materialized_artifact.brief.clone());
        edit_intent = materialized_artifact.edit_intent.clone();
        candidate_summaries = materialized_artifact.candidate_summaries.clone();
        winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
        winning_candidate_rationale = materialized_artifact.winning_candidate_rationale.clone();
        judge = materialized_artifact.judge.clone();
        output_origin = Some(materialized_artifact.output_origin);
        production_provenance = materialized_artifact.production_provenance.clone();
        acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
        fallback_used = materialized_artifact.fallback_used;
        ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
        failure = materialized_artifact.failure.clone();
        taste_memory = materialized_artifact.taste_memory.clone();
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
    } else {
        publish_current_task_progress(app, task, "Preparing workspace surface...");
    }

    publish_current_task_progress(app, task, "Finalizing artifact session...");
    let mut artifact_manifest = artifact_manifest_for_request(
        &title,
        &artifact_request,
        &attached_artifact_ids,
        build_session.as_ref(),
        renderer_session.as_ref(),
        initial_lifecycle_state,
    );

    if let Some(artifact) = create_contract_artifact(app, &thread_id, &title, &materialization) {
        attached_artifact_ids.push(artifact.artifact_id.clone());
        task.artifacts.push(artifact);
    }

    if let Some(build) = build_session.as_mut() {
        if let Some(receipt_artifact) =
            create_receipt_report_artifact(app, &thread_id, &title, &build.receipts[0])
        {
            build.receipts[0]
                .artifact_ids
                .push(receipt_artifact.artifact_id.clone());
            attached_artifact_ids.push(receipt_artifact.artifact_id.clone());
            task.artifacts.push(receipt_artifact);
        }
    }

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
    materialization.edit_intent = edit_intent.clone();
    materialization.candidate_summaries = candidate_summaries.clone();
    materialization.winning_candidate_id = winning_candidate_id.clone();
    materialization.winning_candidate_rationale = winning_candidate_rationale.clone();
    materialization.judge = judge.clone();
    materialization.output_origin = output_origin;
    materialization.production_provenance = production_provenance.clone();
    materialization.acceptance_provenance = acceptance_provenance.clone();
    materialization.fallback_used = fallback_used;
    materialization.ux_lifecycle = ux_lifecycle;
    materialization.failure = failure.clone();
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
        selected_targets,
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
    refresh_pipeline_steps(&mut studio_session, build_session.as_ref());
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

    task.studio_session = Some(studio_session.clone());
    task.renderer_session = renderer_session.clone();
    task.build_session = build_session.clone();

    if let Some(build_session) = build_session {
        spawn_build_supervisor(app.clone(), studio_session, build_session);
    }

    Ok(())
}

pub fn maybe_prepare_current_task_for_studio_turn(
    app: &AppHandle,
    intent: &str,
) -> Result<(), String> {
    let state = app.state::<Mutex<AppState>>();
    let (mut task, memory_runtime) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        let Some(task) = guard.current_task.clone() else {
            return Ok(());
        };
        (task, guard.memory_runtime.clone())
    };
    let current_artifact_id = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.studio_session.as_ref().and_then(|session| {
        memory_runtime
            .as_ref()
            .map(|runtime| studio_refinement_context_for_session(runtime, session))
    });
    let outcome_request =
        studio_outcome_request(app, intent, current_artifact_id, active_refinement.as_ref())?;

    task.studio_outcome = Some(outcome_request.clone());

    let previous_build_session_id = task
        .build_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_studio_session_id = task
        .studio_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_artifact_count = task.artifacts.len();
    let previous_phase = task.phase.clone();
    let previous_current_step = task.current_step.clone();
    let previous_outcome_request_id = task
        .studio_outcome
        .as_ref()
        .map(|request| request.request_id.clone());
    let previous_studio_lifecycle = task
        .studio_session
        .as_ref()
        .map(|session| session.lifecycle_state);
    let previous_revision_count = task
        .studio_session
        .as_ref()
        .map(|session| session.revisions.len());
    let previous_file_count = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_manifest.files.len());

    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact
        && !outcome_request.needs_clarification
    {
        if !maybe_refine_current_non_workspace_artifact_turn(
            app,
            &mut task,
            intent,
            outcome_request.clone(),
        )? {
            maybe_prepare_task_for_studio_with_request(app, &mut task, intent, outcome_request)?;
        }
    } else {
        apply_non_artifact_route_state(&mut task, &outcome_request);
    }

    if task_is_studio_authoritative(&task) {
        apply_studio_authoritative_status(&mut task, None);
    }

    let studio_changed = previous_studio_session_id
        != task
            .studio_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let build_changed = previous_build_session_id
        != task
            .build_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let artifacts_changed = previous_artifact_count != task.artifacts.len();
    let phase_changed = previous_phase != task.phase;
    let current_step_changed = previous_current_step != task.current_step;
    let outcome_changed = previous_outcome_request_id
        != task
            .studio_outcome
            .as_ref()
            .map(|request| request.request_id.clone());
    let lifecycle_changed = previous_studio_lifecycle
        != task
            .studio_session
            .as_ref()
            .map(|session| session.lifecycle_state);
    let revision_count_changed = previous_revision_count
        != task
            .studio_session
            .as_ref()
            .map(|session| session.revisions.len());
    let file_count_changed = previous_file_count
        != task
            .studio_session
            .as_ref()
            .map(|session| session.artifact_manifest.files.len());

    if !studio_changed
        && !build_changed
        && !artifacts_changed
        && !phase_changed
        && !current_step_changed
        && !outcome_changed
        && !lifecycle_changed
        && !revision_count_changed
        && !file_count_changed
    {
        return Ok(());
    }

    if let Some(previous_build_session_id) = previous_build_session_id {
        if task
            .build_session
            .as_ref()
            .is_none_or(|session| session.session_id != previous_build_session_id)
        {
            kill_preview_process(&previous_build_session_id);
        }
    }

    {
        let mut guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        if let Some(current_task) = guard.current_task.as_mut() {
            *current_task = task.clone();
        }
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task);
    }

    let _ = app.emit("task-updated", &task);
    Ok(())
}

pub(super) fn apply_non_artifact_route_state(
    task: &mut AgentTask,
    outcome_request: &StudioOutcomeRequest,
) {
    task.current_step = if outcome_request.needs_clarification {
        "Studio needs clarification before selecting the correct outcome surface.".to_string()
    } else {
        match outcome_request.outcome_kind {
            StudioOutcomeKind::Conversation => {
                "Studio routed this request to conversation. No artifact was materialized."
                    .to_string()
            }
            StudioOutcomeKind::ToolWidget => {
                "Studio routed this request to a tool-widget outcome. No artifact was materialized."
                    .to_string()
            }
            StudioOutcomeKind::Visualizer => {
                "Studio routed this request to a visualizer outcome. No artifact was materialized."
                    .to_string()
            }
            StudioOutcomeKind::Artifact => task.current_step.clone(),
        }
    };
}
