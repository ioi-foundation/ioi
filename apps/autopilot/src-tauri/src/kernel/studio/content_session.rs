use super::*;
use std::time::Duration;

pub(super) fn studio_routing_timeout_for_runtime(runtime: &Arc<dyn InferenceRuntime>) -> Duration {
    let seconds = [
        "AUTOPILOT_STUDIO_ROUTING_TIMEOUT_SECS",
        "IOI_STUDIO_ROUTING_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.studio_runtime_provenance().kind {
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => 45,
        _ => 20,
    });

    Duration::from_secs(seconds)
}

pub(super) struct MaterializedContentArtifact {
    pub(super) artifacts: Vec<Artifact>,
    pub(super) files: Vec<StudioArtifactManifestFile>,
    pub(super) file_writes: Vec<StudioArtifactMaterializationFileWrite>,
    pub(super) notes: Vec<String>,
    pub(super) brief: StudioArtifactBrief,
    pub(super) edit_intent: Option<StudioArtifactEditIntent>,
    pub(super) candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    pub(super) winning_candidate_id: Option<String>,
    pub(super) winning_candidate_rationale: Option<String>,
    pub(super) judge: Option<StudioArtifactJudgeResult>,
    pub(super) output_origin: StudioArtifactOutputOrigin,
    pub(super) production_provenance: Option<crate::models::StudioRuntimeProvenance>,
    pub(super) acceptance_provenance: Option<crate::models::StudioRuntimeProvenance>,
    pub(super) fallback_used: bool,
    pub(super) ux_lifecycle: StudioArtifactUxLifecycle,
    pub(super) failure: Option<crate::models::StudioArtifactFailure>,
    pub(super) taste_memory: Option<StudioArtifactTasteMemory>,
    pub(super) selected_targets: Vec<StudioArtifactSelectionTarget>,
    pub(super) lifecycle_state: StudioArtifactLifecycleState,
    pub(super) verification_summary: String,
}

fn default_studio_outcome_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
) -> StudioOutcomeRequest {
    StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Conversation,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: None,
    }
}

fn studio_failure_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::ReportBundle,
        deliverable_shape: StudioArtifactDeliverableShape::FileSet,
        renderer: StudioRendererKind::BundleManifest,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    }
}

pub(super) fn attach_blocked_studio_failure_session(
    task: &mut AgentTask,
    intent: &str,
    active_artifact_id: Option<String>,
    provenance: crate::models::StudioRuntimeProvenance,
    failure: StudioArtifactFailure,
) {
    let request = studio_failure_request();
    let outcome_request = StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: intent.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Artifact,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: Some(request.clone()),
    };
    let title = derive_artifact_title(intent);
    let summary = failure.message.clone();
    let judge = StudioArtifactJudgeResult {
        classification: ioi_api::studio::StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        strongest_contradiction: Some(summary.clone()),
        rationale: summary.clone(),
    };
    let artifact_manifest = StudioArtifactManifest {
        artifact_id: Uuid::new_v4().to_string(),
        title: title.clone(),
        artifact_class: request.artifact_class,
        renderer: request.renderer,
        primary_tab: "evidence".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "evidence".to_string(),
            label: "Evidence".to_string(),
            kind: StudioArtifactTabKind::Evidence,
            renderer: None,
            file_path: None,
            lens: Some("evidence".to_string()),
        }],
        files: Vec::new(),
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Blocked,
            lifecycle_state: StudioArtifactLifecycleState::Blocked,
            summary: summary.clone(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance.clone()),
            failure: Some(failure.clone()),
        },
        storage: None,
    };
    let mut materialization = materialization_contract_for_request(intent, &request, &summary);
    materialization.artifact_brief = Some(blocked_failure_brief(
        &title,
        intent,
        request.renderer,
        &summary,
        Vec::new(),
    ));
    materialization.judge = Some(judge);
    materialization.output_origin = Some(output_origin_from_runtime_provenance(&provenance));
    materialization.production_provenance = Some(provenance.clone());
    materialization.acceptance_provenance = Some(provenance.clone());
    let failure_kind = failure.kind;
    materialization.failure = Some(failure);
    materialization.summary = summary.clone();
    materialization.ux_lifecycle = Some(StudioArtifactUxLifecycle::Draft);
    materialization.notes.push(match failure_kind {
        StudioArtifactFailureKind::InferenceUnavailable => {
            "Studio stopped before routing because inference was unavailable and no substitute artifact was allowed."
                .to_string()
        }
        StudioArtifactFailureKind::RoutingFailure => {
            "Studio stopped before opening the artifact because typed outcome routing did not complete successfully."
                .to_string()
        }
        _ => "Studio stopped before opening the artifact because verification could not authorize a usable primary artifact view."
            .to_string(),
    });
    let mut studio_session = StudioArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id: artifact_manifest.artifact_id.clone(),
        title: title.clone(),
        summary: summary.clone(),
        current_lens: "evidence".to_string(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes: Vec::new(),
        attached_artifact_ids: Vec::new(),
        available_lenses: vec!["evidence".to_string()],
        materialization,
        outcome_request: outcome_request.clone(),
        verified_reply: verified_reply_from_manifest(&title, &artifact_manifest),
        artifact_manifest,
        lifecycle_state: StudioArtifactLifecycleState::Blocked,
        status: lifecycle_state_label(StudioArtifactLifecycleState::Blocked).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        selected_targets: Vec::new(),
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Draft),
        created_at: now_iso(),
        updated_at: now_iso(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    refresh_pipeline_steps(&mut studio_session, None);
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    task.studio_outcome = Some(outcome_request);
    task.studio_session = Some(studio_session);
}

pub(super) fn studio_outcome_request(
    app: &AppHandle,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    let Some(runtime) = app_studio_routing_inference_runtime(app) else {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    };

    studio_outcome_request_with_runtime(
        runtime,
        trimmed_intent,
        active_artifact_id,
        active_artifact,
    )
}

pub(super) fn studio_outcome_request_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomeRequest, String> {
    let timeout = studio_routing_timeout_for_runtime(&runtime);
    studio_outcome_request_with_runtime_timeout(
        runtime,
        intent,
        active_artifact_id,
        active_artifact,
        timeout,
    )
}

pub(super) fn studio_outcome_request_with_runtime_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    timeout: Duration,
) -> Result<StudioOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    let planning = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            timeout,
            plan_studio_outcome_with_runtime(
                runtime,
                trimmed_intent,
                active_artifact_id.as_deref(),
                active_artifact,
            ),
        )
        .await
    }) {
        Ok(Ok(payload)) => payload,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err(format!(
                "Studio outcome planning timed out after {}s while routing the request.",
                timeout.as_secs()
            ))
        }
    };

    let mut outcome_kind = planning.outcome_kind;
    let mut needs_clarification = planning.needs_clarification;
    let mut clarification_questions = planning.clarification_questions;
    let artifact = planning.artifact;
    if outcome_kind == StudioOutcomeKind::Artifact && artifact.is_none() {
        outcome_kind = StudioOutcomeKind::Conversation;
        needs_clarification = true;
        clarification_questions.push(
            "What artifact should Studio create: document, visual, single-file interactive surface, downloadable file, or workspace project?"
                .to_string(),
        );
    }

    Ok(StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: trimmed_intent.to_string(),
        active_artifact_id,
        outcome_kind,
        confidence: planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        clarification_questions,
        artifact,
    })
}

pub(super) fn artifact_class_id_for_request(request: &StudioOutcomeArtifactRequest) -> String {
    match request.artifact_class {
        StudioArtifactClass::WorkspaceProject => "workspace_project".to_string(),
        StudioArtifactClass::CompoundBundle => "compound_bundle".to_string(),
        StudioArtifactClass::Document => "document".to_string(),
        StudioArtifactClass::Visual => "visual".to_string(),
        StudioArtifactClass::InteractiveSingleFile => "interactive_single_file".to_string(),
        StudioArtifactClass::DownloadableFile => "downloadable_file".to_string(),
        StudioArtifactClass::CodePatch => "code_patch".to_string(),
        StudioArtifactClass::ReportBundle => "report_bundle".to_string(),
    }
}

pub(super) fn renderer_kind_id(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::HtmlIframe => "html_iframe",
        StudioRendererKind::JsxSandbox => "jsx_sandbox",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "pdf_embed",
        StudioRendererKind::DownloadCard => "download_card",
        StudioRendererKind::WorkspaceSurface => "workspace_surface",
        StudioRendererKind::BundleManifest => "bundle_manifest",
    }
}

pub(super) fn presentation_surface_id(surface: StudioPresentationSurface) -> &'static str {
    match surface {
        StudioPresentationSurface::Inline => "inline",
        StudioPresentationSurface::SidePanel => "side_panel",
        StudioPresentationSurface::Overlay => "overlay",
        StudioPresentationSurface::TabbedPanel => "tabbed_panel",
    }
}

pub(super) fn persistence_mode_id(mode: StudioArtifactPersistenceMode) -> &'static str {
    match mode {
        StudioArtifactPersistenceMode::Ephemeral => "ephemeral",
        StudioArtifactPersistenceMode::ArtifactScoped => "artifact_scoped",
        StudioArtifactPersistenceMode::SharedArtifactScoped => "shared_artifact_scoped",
        StudioArtifactPersistenceMode::WorkspaceFilesystem => "workspace_filesystem",
    }
}

pub(super) fn lifecycle_state_label(state: StudioArtifactLifecycleState) -> &'static str {
    match state {
        StudioArtifactLifecycleState::Draft => "draft",
        StudioArtifactLifecycleState::Planned => "planned",
        StudioArtifactLifecycleState::Materializing => "materializing",
        StudioArtifactLifecycleState::Rendering => "rendering",
        StudioArtifactLifecycleState::Implementing => "implementing",
        StudioArtifactLifecycleState::Verifying => "verifying",
        StudioArtifactLifecycleState::Ready => "ready",
        StudioArtifactLifecycleState::Partial => "partial",
        StudioArtifactLifecycleState::Blocked => "blocked",
        StudioArtifactLifecycleState::Failed => "failed",
    }
}

pub(super) fn summary_for_request(request: &StudioOutcomeArtifactRequest, title: &str) -> String {
    match request.renderer {
        StudioRendererKind::WorkspaceSurface => format!(
            "Studio provisioned '{}' as an artifact backed by the workspace_surface renderer and is supervising scaffold, verification, and preview under kernel authority.",
            title
        ),
        StudioRendererKind::Markdown => format!(
            "Studio created '{}' as a markdown artifact with a side-panel document surface.",
            title
        ),
        StudioRendererKind::HtmlIframe => format!(
            "Studio created '{}' as a single-file HTML artifact rendered in an isolated frame.",
            title
        ),
        StudioRendererKind::JsxSandbox => format!(
            "Studio created '{}' as a JSX sandbox artifact with source and render tabs.",
            title
        ),
        StudioRendererKind::Svg => format!(
            "Studio created '{}' as a vector artifact rendered inline.",
            title
        ),
        StudioRendererKind::Mermaid => format!(
            "Studio created '{}' as a mermaid diagram artifact with a renderable graph surface.",
            title
        ),
        StudioRendererKind::PdfEmbed => format!(
            "Studio created '{}' as a PDF artifact with inline preview and download support.",
            title
        ),
        StudioRendererKind::DownloadCard => format!(
            "Studio created '{}' as a downloadable artifact with explicit export handling.",
            title
        ),
        StudioRendererKind::BundleManifest => format!(
            "Studio created '{}' as a bundle-manifest artifact with structured source and evidence tabs.",
            title
        ),
    }
}

pub(super) fn materialization_contract_for_request(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    summary: &str,
) -> StudioArtifactMaterializationContract {
    let verification_steps = if request.renderer == StudioRendererKind::WorkspaceSurface {
        vec![
            verification_step("scaffold", "Scaffold workspace", "pending"),
            verification_step("install", "Install dependencies", "pending"),
            verification_step("validation", "Validate build", "pending"),
            verification_step("preview", "Verify preview", "pending"),
        ]
    } else {
        vec![
            verification_step("materialize", "Materialize artifact", "success"),
            verification_step("verify", "Verify artifact contract", "success"),
        ]
    };

    StudioArtifactMaterializationContract {
        version: 3,
        request_kind: artifact_class_id_for_request(request),
        normalized_intent: intent.trim().to_string(),
        summary: summary.to_string(),
        artifact_brief: None,
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        judge: None,
        output_origin: None,
        production_provenance: None,
        acceptance_provenance: None,
        fallback_used: false,
        ux_lifecycle: None,
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        verification_steps,
        pipeline_steps: Vec::new(),
        notes: vec![
            "Conversation remains the control plane; this artifact is the work product."
                .to_string(),
            "Renderer choice is explicit in the typed outcome request.".to_string(),
            "Verification state, not worker prose, authorizes the final Studio summary."
                .to_string(),
        ],
    }
}

pub(super) fn should_refine_current_non_workspace_artifact(
    task: &AgentTask,
    outcome_request: &StudioOutcomeRequest,
) -> bool {
    let Some(studio_session) = task.studio_session.as_ref() else {
        return false;
    };
    let Some(current_request) = studio_session.outcome_request.artifact.as_ref() else {
        return false;
    };
    let Some(next_request) = outcome_request.artifact.as_ref() else {
        return false;
    };

    current_request.renderer != StudioRendererKind::WorkspaceSurface
        && next_request.renderer != StudioRendererKind::WorkspaceSurface
        && current_request.renderer == next_request.renderer
}

pub(super) fn maybe_refine_current_non_workspace_artifact_turn(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
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
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime is unavailable for Studio refinement.".to_string())?;

    let refinement = studio_refinement_context_for_session(&memory_runtime, &studio_session);
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let mut materialized_artifact = materialize_non_workspace_artifact(
        app,
        &thread_id,
        &studio_session.title,
        intent,
        &request,
        Some(&refinement),
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
        materialized_artifact.edit_intent.as_ref(),
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

    let mut materialization = materialization_contract_for_request(intent, &request, &summary);
    materialization.file_writes = materialized_artifact.file_writes.clone();
    materialization.notes = materialized_artifact.notes.clone();
    materialization.artifact_brief = Some(materialized_artifact.brief.clone());
    materialization.edit_intent = materialized_artifact.edit_intent.clone();
    materialization.candidate_summaries = materialized_artifact.candidate_summaries.clone();
    materialization.winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
    materialization.winning_candidate_rationale =
        materialized_artifact.winning_candidate_rationale.clone();
    materialization.judge = materialized_artifact.judge.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
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
