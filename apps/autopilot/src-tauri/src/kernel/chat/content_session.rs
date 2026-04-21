use super::operator_run::{
    refresh_active_operator_run_from_session, start_operator_run_for_session,
};
use super::revisions::persist_chat_artifact_exemplar;
use super::*;
use crate::models::ChatVerifiedReply;
use ioi_api::execution::{
    annotate_execution_envelope, build_execution_envelope_from_swarm,
    build_execution_envelope_from_swarm_with_receipts, completion_invariant_for_direct_execution,
    derive_execution_mode_decision, execution_domain_kind_for_outcome,
    execution_strategy_for_outcome, plan_swarm_dispatch_batches, ExecutionBudgetSummary,
    ExecutionCompletionInvariantStatus, ExecutionDomainKind, ExecutionEnvelope, ExecutionStage,
    SwarmChangeReceipt, SwarmExecutionSummary, SwarmMergeReceipt, SwarmPlan,
    SwarmVerificationReceipt, SwarmWorkItemStatus, SwarmWorkerReceipt, SwarmWorkerResultKind,
};
use ioi_api::runtime_harness::{
    derive_chat_topology_projection, ArtifactOperatorPhase, ArtifactOperatorRunMode,
    ArtifactOperatorRunStatus, ArtifactOperatorStep, ArtifactSourceReference,
    ChatArtifactBlueprint as ChatArtifactBlueprint,
    ChatArtifactExemplar as ChatArtifactExemplar,
    ChatArtifactGenerationProgress as ChatArtifactGenerationProgress,
    ChatArtifactGenerationProgressObserver as ChatArtifactGenerationProgressObserver,
    ChatArtifactIR as ChatArtifactIR,
    ChatArtifactPreparationNeeds as ChatArtifactPreparationNeeds,
    ChatArtifactPreparedContextResolution as ChatArtifactPreparedContextResolution,
    ChatArtifactRenderEvaluation as ChatArtifactRenderEvaluation,
    ChatArtifactSelectedSkill as ChatArtifactSelectedSkill,
    ChatArtifactSkillDiscoveryResolution as ChatArtifactSkillDiscoveryResolution,
    ChatIntentContext,
};
use ioi_types::app::{
    RoutingRouteDecision, ChatExecutionModeDecision as ChatExecutionModeDecision,
    ChatExecutionStrategy as ChatExecutionStrategy, ChatNormalizedRequestFrame,
    ChatRetainedWidgetState as ChatRetainedWidgetState,
};
use std::time::Duration;

mod clarification;
mod connectors;
mod non_artifact;
mod non_artifact_surface;
mod route_contract;

#[cfg(test)]
pub(super) use self::apply_connector_routing_from_catalog_entries as apply_connector_catalog_to_outcome_request;
pub(super) use self::clarification::clarification_request_for_outcome_request;
use self::clarification::specialized_domain_clarification_question;
pub(super) use self::connectors::{
    infer_connector_route_context_from_catalog, merge_connector_route_context,
};
pub(super) use self::non_artifact::attach_non_artifact_chat_session;
pub(super) use self::non_artifact_surface::refresh_non_artifact_chat_surface;
pub(crate) use self::route_contract::runtime_handoff_prompt_prefix_for_task;
pub(super) use self::route_contract::{
    append_route_contract_event, artifact_execution_envelope_for_contract,
    build_route_contract_payload, non_artifact_route_status_message,
};
#[cfg(test)]
pub(super) use ioi_api::runtime_harness::route_decision_for_outcome_request;

pub(super) fn chat_routing_timeout_for_runtime(runtime: &Arc<dyn InferenceRuntime>) -> Duration {
    let seconds = [
        "AUTOPILOT_STUDIO_ROUTING_TIMEOUT_SECS",
        "IOI_CHAT_ROUTING_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.chat_runtime_provenance().kind {
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime
            if crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") =>
        {
            90
        }
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime => 45,
        _ => 20,
    });

    Duration::from_secs(seconds)
}

pub(super) struct MaterializedContentArtifact {
    pub(super) artifacts: Vec<Artifact>,
    pub(super) files: Vec<ChatArtifactManifestFile>,
    pub(super) file_writes: Vec<ChatArtifactMaterializationFileWrite>,
    pub(super) notes: Vec<String>,
    pub(super) brief: ChatArtifactBrief,
    pub(super) preparation_needs: Option<ChatArtifactPreparationNeeds>,
    pub(super) prepared_context_resolution: Option<ChatArtifactPreparedContextResolution>,
    pub(super) skill_discovery_resolution: Option<ChatArtifactSkillDiscoveryResolution>,
    pub(super) blueprint: Option<ChatArtifactBlueprint>,
    pub(super) artifact_ir: Option<ChatArtifactIR>,
    pub(super) selected_skills: Vec<ChatArtifactSelectedSkill>,
    pub(super) retrieved_exemplars: Vec<ChatArtifactExemplar>,
    pub(super) retrieved_sources: Vec<ArtifactSourceReference>,
    pub(super) edit_intent: Option<ChatArtifactEditIntent>,
    pub(super) candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    pub(super) winning_candidate_id: Option<String>,
    pub(super) winning_candidate_rationale: Option<String>,
    pub(super) execution_envelope: Option<ExecutionEnvelope>,
    pub(super) swarm_plan: Option<SwarmPlan>,
    pub(super) swarm_execution: Option<SwarmExecutionSummary>,
    pub(super) swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    pub(super) swarm_change_receipts: Vec<SwarmChangeReceipt>,
    pub(super) swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    pub(super) swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    pub(super) render_evaluation: Option<ChatArtifactRenderEvaluation>,
    pub(super) validation: Option<ChatArtifactValidationResult>,
    pub(super) output_origin: ChatArtifactOutputOrigin,
    pub(super) production_provenance: Option<crate::models::ChatRuntimeProvenance>,
    pub(super) acceptance_provenance: Option<crate::models::ChatRuntimeProvenance>,
    pub(super) fallback_used: bool,
    pub(super) ux_lifecycle: ChatArtifactUxLifecycle,
    pub(super) failure: Option<crate::models::ChatArtifactFailure>,
    pub(super) taste_memory: Option<ChatArtifactTasteMemory>,
    pub(super) selected_targets: Vec<ChatArtifactSelectionTarget>,
    pub(super) lifecycle_state: ChatArtifactLifecycleState,
    pub(super) verification_summary: String,
    pub(super) operator_steps: Vec<ArtifactOperatorStep>,
}

fn default_chat_outcome_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
) -> ChatOutcomeRequest {
    let mut request = ChatOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: execution_strategy_for_outcome(ChatOutcomeKind::Conversation, None),
        execution_mode_decision: None,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: Vec::new(),
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    refresh_outcome_request_topology(&mut request, None);
    request
}

fn default_blocked_artifact_request() -> ChatOutcomeArtifactRequest {
    ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::Markdown,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    }
}

fn blocked_artifact_outcome_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
) -> ChatOutcomeRequest {
    let artifact = default_blocked_artifact_request();
    let mut request = ChatOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: execution_strategy_for_outcome(
            ChatOutcomeKind::Artifact,
            Some(&artifact),
        ),
        execution_mode_decision: None,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            "routing_failed_closed".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(artifact),
    };
    refresh_outcome_request_topology(&mut request, None);
    request
}

pub(super) fn chat_outcome_request(
    app: &AppHandle,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
    active_widget_state: Option<&ChatRetainedWidgetState>,
) -> Result<ChatOutcomeRequest, String> {
    let runtime =
        super::task_state::app_chat_routing_inference_runtime(app).ok_or_else(|| {
            "Chat outcome routing runtime is unavailable while routing the request.".to_string()
        })?;
    let timeout = chat_routing_timeout_for_runtime(&runtime);
    let mut outcome_request = chat_outcome_request_with_runtime_timeout(
        runtime,
        intent,
        active_artifact_id,
        active_artifact,
        active_widget_state,
        timeout,
    )?;
    apply_connector_routing_from_catalog(app, &mut outcome_request);
    refresh_outcome_request_topology(&mut outcome_request, active_widget_state);
    apply_retained_widget_state_resolution(&mut outcome_request, active_widget_state);
    Ok(outcome_request)
}

pub(super) fn chat_outcome_request_with_runtime_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
    active_widget_state: Option<&ChatRetainedWidgetState>,
    timeout: Duration,
) -> Result<ChatOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_chat_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    let planning = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            timeout,
            plan_chat_outcome_with_runtime(
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
                "Chat outcome planning timed out after {}s while routing the request.",
                timeout.as_secs()
            ))
        }
    };

    let planner_execution_strategy = planning.execution_strategy;
    let outcome_kind = planning.outcome_kind;
    let needs_clarification = planning.needs_clarification;
    let clarification_questions = planning.clarification_questions;
    let artifact = planning.artifact;
    if outcome_kind == ChatOutcomeKind::Artifact && artifact.is_none() {
        return Err(
            "Chat outcome planning returned an artifact route without an artifact contract."
                .to_string(),
        );
    }
    let requested_strategy = planner_execution_strategy;
    let execution_mode_decision = derive_execution_mode_decision(
        outcome_kind,
        artifact.as_ref(),
        requested_strategy,
        planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        active_artifact_id.is_some(),
    );
    let execution_strategy = execution_mode_decision.resolved_strategy;

    let mut outcome_request = ChatOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: trimmed_intent.to_string(),
        active_artifact_id,
        outcome_kind,
        execution_strategy,
        execution_mode_decision: Some(execution_mode_decision),
        confidence: planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        clarification_questions,
        routing_hints: planning.routing_hints,
        lane_frame: planning.lane_frame,
        request_frame: planning.request_frame,
        source_selection: planning.source_selection,
        retained_lane_state: planning.retained_lane_state,
        lane_transitions: planning.lane_transitions,
        orchestration_state: planning.orchestration_state,
        artifact,
    };
    refresh_outcome_request_topology(&mut outcome_request, active_widget_state);
    apply_retained_widget_state_resolution(&mut outcome_request, active_widget_state);
    Ok(outcome_request)
}

pub(super) fn apply_connector_routing_from_catalog_entries(
    outcome_request: &mut ChatOutcomeRequest,
    connectors: &[crate::kernel::connectors::ConnectorCatalogEntry],
) {
    let Some(context) =
        infer_connector_route_context_from_catalog(&outcome_request.raw_prompt, connectors)
    else {
        return;
    };
    merge_connector_route_context(outcome_request, context);
}

fn apply_connector_routing_from_catalog(
    app: &AppHandle,
    outcome_request: &mut ChatOutcomeRequest,
) {
    let state = app.state::<Mutex<AppState>>();
    let connectors =
        tauri::async_runtime::block_on(crate::kernel::connectors::connector_list_catalog(state));
    let Ok(connectors) = connectors else {
        return;
    };
    apply_connector_routing_from_catalog_entries(outcome_request, &connectors);
}

pub(super) fn attach_blocked_chat_failure_session(
    task: &mut AgentTask,
    prompt: &str,
    active_artifact_id: Option<String>,
    provenance: crate::models::ChatRuntimeProvenance,
    failure: crate::models::ChatArtifactFailure,
) {
    let outcome_request = task
        .chat_outcome
        .clone()
        .or_else(|| {
            task.chat_session
                .as_ref()
                .map(|session| session.outcome_request.clone())
        })
        .unwrap_or_else(|| blocked_artifact_outcome_request(prompt, active_artifact_id));
    let request = outcome_request
        .artifact
        .clone()
        .unwrap_or_else(default_blocked_artifact_request);
    let title = task
        .chat_session
        .as_ref()
        .map(|session| session.title.clone())
        .unwrap_or_else(|| derive_artifact_title(prompt));
    let summary = failure.message.clone();
    let mut materialization = materialization_contract_for_request(
        prompt,
        &request,
        &title,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let execution_envelope = artifact_execution_envelope_for_contract(
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
        &materialization,
    );
    let materialized_artifact = blocked_materialized_artifact_from_error(
        &title,
        prompt,
        &request,
        None,
        &failure.message,
        None,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        execution_envelope,
        None,
        None,
        Vec::new(),
        Some(provenance.clone()),
        Some(provenance.clone()),
    );
    apply_materialized_artifact_to_contract(
        &mut materialization,
        &request,
        &materialized_artifact,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );

    let lifecycle_state = ChatArtifactLifecycleState::Blocked;
    let mut artifact_manifest =
        artifact_manifest_for_request(&title, &request, &[], None, None, lifecycle_state);
    artifact_manifest.files = materialized_artifact.files.clone();
    artifact_manifest.verification.summary = materialized_artifact.verification_summary.clone();
    artifact_manifest.verification.production_provenance = Some(provenance.clone());
    artifact_manifest.verification.acceptance_provenance = Some(provenance.clone());
    artifact_manifest.verification.failure = Some(failure.clone());
    let navigator_nodes = navigator_nodes_for_manifest(&artifact_manifest);
    materialization.navigator_nodes = navigator_nodes.clone();

    let mut verified_reply = verified_reply_from_manifest(&title, &artifact_manifest);
    verified_reply.summary = failure.message.clone();
    verified_reply.production_provenance = Some(provenance.clone());
    verified_reply.acceptance_provenance = Some(provenance.clone());
    verified_reply.failure = Some(failure.clone());
    if !verified_reply
        .evidence
        .iter()
        .any(|item| item == &failure.code)
    {
        verified_reply.evidence.push(failure.code.clone());
    }
    if !verified_reply
        .evidence
        .iter()
        .any(|item| item == &failure.message)
    {
        verified_reply.evidence.push(failure.message.clone());
    }

    let created_at = now_iso();
    let mut chat_session = ChatArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id: artifact_manifest.artifact_id.clone(),
        origin_prompt_event_id: None,
        title: title.clone(),
        summary: summary.clone(),
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes,
        attached_artifact_ids: Vec::new(),
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest,
        verified_reply,
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: materialized_artifact.taste_memory.clone(),
        retrieved_exemplars: materialized_artifact.retrieved_exemplars.clone(),
        retrieved_sources: materialized_artifact.retrieved_sources.clone(),
        selected_targets: materialized_artifact.selected_targets.clone(),
        widget_state: None,
        ux_lifecycle: Some(materialized_artifact.ux_lifecycle),
        active_operator_run: None,
        operator_run_history: Vec::new(),
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    start_operator_run_for_session(
        &mut chat_session,
        task.events.iter().rev().find_map(|event| {
            event
                .details
                .get("kind")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("user_input"))
                .then(|| event.event_id.as_str())
        }),
        ArtifactOperatorRunMode::Create,
    );
    refresh_active_operator_run_from_session(&mut chat_session, None);
    refresh_pipeline_steps(&mut chat_session, None);
    let initial_revision = initial_revision_for_session(&chat_session, prompt);
    chat_session.active_revision_id = Some(initial_revision.revision_id.clone());
    chat_session.revisions = vec![initial_revision];

    task.chat_outcome = Some(outcome_request.clone());
    task.chat_session = Some(chat_session);
    task.renderer_session = None;
    task.build_session = None;
    task.gate_info = None;
    task.pending_request_hash = None;
    task.credential_request = None;
    task.clarification_request = clarification_request_for_outcome_request(&outcome_request);
    append_route_contract_event(
        task,
        &outcome_request,
        "Chat route blocked",
        &summary,
        false,
    );
}

fn request_frame_has_clarification_slots(frame: &ChatNormalizedRequestFrame) -> bool {
    match frame {
        ChatNormalizedRequestFrame::Weather(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        ChatNormalizedRequestFrame::Sports(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        ChatNormalizedRequestFrame::Places(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        ChatNormalizedRequestFrame::Recipe(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        ChatNormalizedRequestFrame::MessageCompose(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        ChatNormalizedRequestFrame::UserInput(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
    }
}

fn request_frame_matches_retained_widget_state(
    frame: &ChatNormalizedRequestFrame,
    active_widget_state: Option<&ChatRetainedWidgetState>,
) -> bool {
    let Some(widget_state) = active_widget_state else {
        return false;
    };
    let expected_family = match frame {
        ChatNormalizedRequestFrame::Weather(_) => "weather",
        ChatNormalizedRequestFrame::Sports(_) => "sports",
        ChatNormalizedRequestFrame::Places(_) => "places",
        ChatNormalizedRequestFrame::Recipe(_) => "recipe",
        ChatNormalizedRequestFrame::MessageCompose(_) => "message",
        ChatNormalizedRequestFrame::UserInput(_) => "user_input",
    };
    widget_state.widget_family.as_deref() == Some(expected_family)
}

fn apply_retained_widget_state_resolution(
    outcome_request: &mut ChatOutcomeRequest,
    active_widget_state: Option<&ChatRetainedWidgetState>,
) {
    let Some(frame) = outcome_request.request_frame.as_ref() else {
        return;
    };
    if !request_frame_matches_retained_widget_state(frame, active_widget_state) {
        return;
    }
    if request_frame_has_clarification_slots(frame) {
        return;
    }
    if outcome_request.needs_clarification {
        outcome_request.needs_clarification = false;
        outcome_request.clarification_questions.clear();
    }
    if !outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "retained_widget_state_applied")
    {
        outcome_request
            .routing_hints
            .push("retained_widget_state_applied".to_string());
    }
}

fn apply_request_frame_clarification_resolution(outcome_request: &mut ChatOutcomeRequest) {
    let Some(frame) = outcome_request.request_frame.as_ref() else {
        return;
    };
    if !request_frame_has_clarification_slots(frame) {
        return;
    }
    outcome_request.needs_clarification = true;
    if outcome_request.clarification_questions.is_empty() {
        if let Some(question) = specialized_domain_clarification_question(outcome_request) {
            outcome_request.clarification_questions.push(question);
        }
    }
    if !outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "request_frame_clarification_required")
    {
        outcome_request
            .routing_hints
            .push("request_frame_clarification_required".to_string());
    }
}

pub(super) fn refresh_outcome_request_topology(
    outcome_request: &mut ChatOutcomeRequest,
    active_widget_state: Option<&ChatRetainedWidgetState>,
) {
    let projection = derive_chat_topology_projection(
        &outcome_request.raw_prompt,
        outcome_request.active_artifact_id.as_deref(),
        active_widget_state,
        outcome_request.outcome_kind,
        outcome_request.execution_strategy,
        outcome_request.execution_mode_decision.as_ref(),
        outcome_request.confidence,
        outcome_request.needs_clarification,
        &outcome_request.clarification_questions,
        &outcome_request.routing_hints,
        outcome_request.artifact.as_ref(),
    );
    outcome_request.lane_frame = projection.lane_frame;
    outcome_request.request_frame = projection.request_frame;
    outcome_request.source_selection = projection.source_selection;
    outcome_request.retained_lane_state = projection.retained_lane_state;
    outcome_request.lane_transitions = projection.lane_transitions;
    outcome_request.orchestration_state = projection.orchestration_state;
    apply_request_frame_clarification_resolution(outcome_request);
}

pub(super) fn artifact_class_id_for_request(request: &ChatOutcomeArtifactRequest) -> String {
    match request.artifact_class {
        ChatArtifactClass::WorkspaceProject => "workspace_project".to_string(),
        ChatArtifactClass::CompoundBundle => "compound_bundle".to_string(),
        ChatArtifactClass::Document => "document".to_string(),
        ChatArtifactClass::Visual => "visual".to_string(),
        ChatArtifactClass::InteractiveSingleFile => "interactive_single_file".to_string(),
        ChatArtifactClass::DownloadableFile => "downloadable_file".to_string(),
        ChatArtifactClass::CodePatch => "code_patch".to_string(),
        ChatArtifactClass::ReportBundle => "report_bundle".to_string(),
    }
}

pub(super) fn renderer_kind_id(renderer: ChatRendererKind) -> &'static str {
    match renderer {
        ChatRendererKind::Markdown => "markdown",
        ChatRendererKind::HtmlIframe => "html_iframe",
        ChatRendererKind::JsxSandbox => "jsx_sandbox",
        ChatRendererKind::Svg => "svg",
        ChatRendererKind::Mermaid => "mermaid",
        ChatRendererKind::PdfEmbed => "pdf_embed",
        ChatRendererKind::DownloadCard => "download_card",
        ChatRendererKind::WorkspaceSurface => "workspace_surface",
        ChatRendererKind::BundleManifest => "bundle_manifest",
    }
}

pub(super) fn presentation_surface_id(surface: ChatPresentationSurface) -> &'static str {
    match surface {
        ChatPresentationSurface::Inline => "inline",
        ChatPresentationSurface::SidePanel => "side_panel",
        ChatPresentationSurface::Overlay => "overlay",
        ChatPresentationSurface::TabbedPanel => "tabbed_panel",
    }
}

pub(super) fn persistence_mode_id(mode: ChatArtifactPersistenceMode) -> &'static str {
    match mode {
        ChatArtifactPersistenceMode::Ephemeral => "ephemeral",
        ChatArtifactPersistenceMode::ArtifactScoped => "artifact_scoped",
        ChatArtifactPersistenceMode::SharedArtifactScoped => "shared_artifact_scoped",
        ChatArtifactPersistenceMode::WorkspaceFilesystem => "workspace_filesystem",
    }
}

pub(super) fn lifecycle_state_label(state: ChatArtifactLifecycleState) -> &'static str {
    match state {
        ChatArtifactLifecycleState::Draft => "draft",
        ChatArtifactLifecycleState::Planned => "planned",
        ChatArtifactLifecycleState::Materializing => "materializing",
        ChatArtifactLifecycleState::Rendering => "rendering",
        ChatArtifactLifecycleState::Implementing => "implementing",
        ChatArtifactLifecycleState::Verifying => "verifying",
        ChatArtifactLifecycleState::Ready => "ready",
        ChatArtifactLifecycleState::Partial => "partial",
        ChatArtifactLifecycleState::Blocked => "blocked",
        ChatArtifactLifecycleState::Failed => "failed",
    }
}

pub(super) fn summary_for_request(request: &ChatOutcomeArtifactRequest, title: &str) -> String {
    match request.renderer {
        ChatRendererKind::WorkspaceSurface => format!(
            "Chat provisioned '{}' as an artifact backed by the workspace_surface renderer and is supervising scaffold, verification, and preview under kernel authority.",
            title
        ),
        ChatRendererKind::Markdown => format!(
            "Chat created '{}' as a markdown artifact with a side-panel document surface.",
            title
        ),
        ChatRendererKind::HtmlIframe => format!(
            "Chat created '{}' as a single-file HTML artifact rendered in an isolated frame.",
            title
        ),
        ChatRendererKind::JsxSandbox => format!(
            "Chat created '{}' as a JSX sandbox artifact with source and render tabs.",
            title
        ),
        ChatRendererKind::Svg => format!(
            "Chat created '{}' as a vector artifact rendered inline.",
            title
        ),
        ChatRendererKind::Mermaid => format!(
            "Chat created '{}' as a mermaid diagram artifact with a renderable graph surface.",
            title
        ),
        ChatRendererKind::PdfEmbed => format!(
            "Chat created '{}' as a PDF artifact with inline preview and download support.",
            title
        ),
        ChatRendererKind::DownloadCard => format!(
            "Chat created '{}' as a downloadable artifact with explicit export handling.",
            title
        ),
        ChatRendererKind::BundleManifest => format!(
            "Chat created '{}' as a bundle-manifest artifact with structured source and evidence tabs.",
            title
        ),
    }
}

pub(super) fn materialization_contract_for_request(
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    summary: &str,
    execution_mode_decision: Option<ChatExecutionModeDecision>,
    execution_strategy: ChatExecutionStrategy,
) -> ChatArtifactMaterializationContract {
    let operator_steps = if request.renderer == ChatRendererKind::WorkspaceSurface {
        vec![
            pending_operator_step(
                "workspace_scaffold",
                ArtifactOperatorPhase::VerifyArtifact,
                "Scaffold workspace",
            ),
            pending_operator_step(
                "workspace_install",
                ArtifactOperatorPhase::VerifyArtifact,
                "Install dependencies",
            ),
            pending_operator_step(
                "workspace_validation",
                ArtifactOperatorPhase::VerifyArtifact,
                "Validate build",
            ),
            pending_operator_step(
                "workspace_preview",
                ArtifactOperatorPhase::VerifyArtifact,
                "Verify preview",
            ),
        ]
    } else {
        vec![
            pending_operator_step(
                "materialize_artifact",
                ArtifactOperatorPhase::AuthorArtifact,
                "Materialize artifact",
            ),
            pending_operator_step(
                "verify_artifact_contract",
                ArtifactOperatorPhase::VerifyArtifact,
                "Verify artifact contract",
            ),
        ]
    };
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        execution_mode_decision.clone(),
        Some(completion_invariant_for_direct_execution(
            execution_strategy,
            Vec::new(),
            vec!["verify".to_string()],
            ExecutionCompletionInvariantStatus::Pending,
        )),
    );

    ChatArtifactMaterializationContract {
        version: 7,
        request_kind: artifact_class_id_for_request(request),
        normalized_intent: intent.trim().to_string(),
        summary: summary.to_string(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        validation: None,
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
        operator_steps,
        pipeline_steps: Vec::new(),
        notes: vec![
            "Conversation remains the control plane; this artifact is the work product."
                .to_string(),
            "Renderer choice is explicit in the typed outcome request.".to_string(),
            "Verification state, not worker prose, authorizes the final Chat summary."
                .to_string(),
        ],
    }
}

fn pending_operator_step(
    step_id: &str,
    phase: ArtifactOperatorPhase,
    label: &str,
) -> ArtifactOperatorStep {
    ArtifactOperatorStep {
        step_id: step_id.to_string(),
        origin_prompt_event_id: String::new(),
        phase,
        engine: "chat".to_string(),
        status: ArtifactOperatorRunStatus::Pending,
        label: label.to_string(),
        detail: format!("{label} is pending."),
        started_at_ms: 0,
        finished_at_ms: None,
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }
}

pub(super) fn apply_materialized_artifact_to_contract(
    materialization: &mut ChatArtifactMaterializationContract,
    _request: &ChatOutcomeArtifactRequest,
    materialized_artifact: &MaterializedContentArtifact,
    execution_mode_decision: Option<ChatExecutionModeDecision>,
    execution_strategy: ChatExecutionStrategy,
) {
    materialization.file_writes = materialized_artifact.file_writes.clone();
    materialization.notes = materialized_artifact.notes.clone();
    materialization.artifact_brief = Some(materialized_artifact.brief.clone());
    materialization.preparation_needs = materialized_artifact.preparation_needs.clone();
    materialization.prepared_context_resolution =
        materialized_artifact.prepared_context_resolution.clone();
    materialization.skill_discovery_resolution =
        materialized_artifact.skill_discovery_resolution.clone();
    materialization.blueprint = materialized_artifact.blueprint.clone();
    materialization.artifact_ir = materialized_artifact.artifact_ir.clone();
    materialization.selected_skills = materialized_artifact.selected_skills.clone();
    materialization.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    materialization.retrieved_sources = materialized_artifact.retrieved_sources.clone();
    materialization.edit_intent = materialized_artifact.edit_intent.clone();
    materialization.candidate_summaries = materialized_artifact.candidate_summaries.clone();
    materialization.winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
    materialization.winning_candidate_rationale =
        materialized_artifact.winning_candidate_rationale.clone();
    materialization.swarm_plan = materialized_artifact.swarm_plan.clone();
    materialization.swarm_execution = materialized_artifact.swarm_execution.clone();
    materialization.swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
    materialization.swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
    materialization.swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
    materialization.swarm_verification_receipts =
        materialized_artifact.swarm_verification_receipts.clone();
    materialization.operator_steps = materialized_artifact.operator_steps.clone();
    materialization.execution_envelope =
        materialized_artifact
            .execution_envelope
            .clone()
            .or_else(|| {
                artifact_execution_envelope_for_contract(
                    execution_mode_decision,
                    execution_strategy,
                    materialization,
                )
            });
    materialization.render_evaluation = materialized_artifact.render_evaluation.clone();
    materialization.validation = materialized_artifact.validation.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
}

pub(super) fn should_refine_current_non_workspace_artifact(
    task: &AgentTask,
    outcome_request: &ChatOutcomeRequest,
) -> bool {
    let Some(chat_session) = task.chat_session.as_ref() else {
        return false;
    };
    let Some(current_request) = chat_session.outcome_request.artifact.as_ref() else {
        return false;
    };
    let Some(next_request) = outcome_request.artifact.as_ref() else {
        return false;
    };

    current_request.renderer != ChatRendererKind::WorkspaceSurface
        && next_request.renderer != ChatRendererKind::WorkspaceSurface
        && current_request.renderer == next_request.renderer
}

pub(super) fn maybe_refine_current_non_workspace_artifact_turn(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: ChatOutcomeRequest,
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
    let origin_prompt_event_id = task.events.iter().rev().find_map(|event| {
        event
            .details
            .get("kind")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("user_input"))
            .then(|| event.event_id.clone())
    });
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime is unavailable for Chat refinement.".to_string())?;

    let refinement = chat_refinement_context_for_session(&memory_runtime, &chat_session);
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    chat_session.origin_prompt_event_id = origin_prompt_event_id.clone();
    start_operator_run_for_session(
        &mut chat_session,
        origin_prompt_event_id.as_deref(),
        ArtifactOperatorRunMode::Edit,
    );
    refresh_active_operator_run_from_session(&mut chat_session, None);
    task.chat_outcome = Some(outcome_request.clone());
    task.chat_session = Some(chat_session.clone());
    super::prepare::publish_current_task_snapshot(app, task);
    let connector_grounding =
        ioi_api::runtime_harness::artifact_connector_grounding_for_outcome_request(
            &outcome_request,
        );
    let progress_app = app.clone();
    let progress_task_id = task.id.clone();
    let progress_observer =
        std::sync::Arc::new(move |progress: ChatArtifactGenerationProgress| {
            super::prepare::publish_current_task_generation_progress(
                &progress_app,
                &progress_task_id,
                &progress,
            );
        }) as ChatArtifactGenerationProgressObserver;
    let mut materialized_artifact =
        materialize_non_workspace_artifact_with_execution_strategy_and_progress_observer(
            app,
            &thread_id,
            &chat_session.title,
            intent,
            &request,
            Some(&refinement),
            connector_grounding.as_ref(),
            outcome_request.execution_strategy,
            Some(progress_observer),
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
        outcome_request.execution_strategy,
    );
    materialization.file_writes = materialized_artifact.file_writes.clone();
    materialization.notes = materialized_artifact.notes.clone();
    materialization.artifact_brief = Some(materialized_artifact.brief.clone());
    materialization.preparation_needs = materialized_artifact.preparation_needs.clone();
    materialization.prepared_context_resolution =
        materialized_artifact.prepared_context_resolution.clone();
    materialization.skill_discovery_resolution =
        materialized_artifact.skill_discovery_resolution.clone();
    materialization.blueprint = materialized_artifact.blueprint.clone();
    materialization.artifact_ir = materialized_artifact.artifact_ir.clone();
    materialization.selected_skills = materialized_artifact.selected_skills.clone();
    materialization.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    materialization.retrieved_sources = materialized_artifact.retrieved_sources.clone();
    materialization.edit_intent = materialized_artifact.edit_intent.clone();
    materialization.candidate_summaries = materialized_artifact.candidate_summaries.clone();
    materialization.winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
    materialization.winning_candidate_rationale =
        materialized_artifact.winning_candidate_rationale.clone();
    materialization.swarm_plan = materialized_artifact.swarm_plan.clone();
    materialization.swarm_execution = materialized_artifact.swarm_execution.clone();
    materialization.swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
    materialization.swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
    materialization.swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
    materialization.swarm_verification_receipts =
        materialized_artifact.swarm_verification_receipts.clone();
    materialization.render_evaluation = materialized_artifact.render_evaluation.clone();
    materialization.validation = materialized_artifact.validation.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
    materialization.execution_envelope =
        materialized_artifact
            .execution_envelope
            .clone()
            .or_else(|| {
                artifact_execution_envelope_for_contract(
                    outcome_request.execution_mode_decision.clone(),
                    outcome_request.execution_strategy,
                    &materialization,
                )
            });
    materialization.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);

    chat_session.materialization = materialization;
    chat_session.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);
    chat_session.verified_reply =
        verified_reply_from_manifest(&title, &chat_session.artifact_manifest);
    chat_session.lifecycle_state = materialized_artifact.lifecycle_state;
    chat_session.status = lifecycle_state_label(materialized_artifact.lifecycle_state).to_string();
    chat_session.taste_memory = taste_memory;
    chat_session.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    chat_session.retrieved_sources = materialized_artifact.retrieved_sources.clone();
    chat_session.selected_targets = selected_targets;
    chat_session.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    chat_session.updated_at = now_iso();
    chat_session.origin_prompt_event_id = origin_prompt_event_id.clone();
    refresh_active_operator_run_from_session(&mut chat_session, None);
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
        &memory_runtime,
        app_inference_runtime(app),
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
