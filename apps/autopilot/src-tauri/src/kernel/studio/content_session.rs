use super::revisions::persist_studio_artifact_exemplar;
use super::*;
use crate::models::StudioVerifiedReply;
use ioi_api::execution::{
    annotate_execution_envelope, block_swarm_work_item_on, build_execution_envelope_from_swarm,
    build_execution_envelope_from_swarm_with_receipts, completion_invariant_for_direct_execution,
    derive_execution_mode_decision, execution_domain_kind_for_outcome,
    execution_strategy_for_outcome, plan_swarm_dispatch_batches, spawn_follow_up_swarm_work_item,
    ExecutionBudgetSummary, ExecutionCompletionInvariantStatus, ExecutionDomainKind,
    ExecutionEnvelope, ExecutionGraphMutationReceipt, ExecutionReplanReceipt, ExecutionStage,
    SwarmChangeReceipt, SwarmExecutionSummary, SwarmMergeReceipt, SwarmPlan,
    SwarmVerificationReceipt, SwarmWorkItem, SwarmWorkItemStatus, SwarmWorkerReceipt,
    SwarmWorkerResultKind, SwarmWorkerRole,
};
use ioi_api::studio::{
    derive_studio_domain_policy_bundle, derive_studio_topology_projection, StudioArtifactBlueprint,
    StudioArtifactExemplar, StudioArtifactIR, StudioArtifactPreparationNeeds,
    StudioArtifactPreparedContextResolution, StudioArtifactRenderEvaluation,
    StudioArtifactRuntimeNarrationEvent, StudioArtifactSelectedSkill,
    StudioArtifactSkillDiscoveryResolution, StudioIntentContext,
};
use ioi_types::app::{
    RoutingEffectiveToolSurface, RoutingRouteDecision, StudioExecutionModeDecision,
    StudioExecutionStrategy, StudioLaneFamily, StudioNormalizedRequestFrame,
    StudioRetainedWidgetState,
};
use std::time::Duration;

mod clarification;
mod connectors;
mod non_artifact;
mod route_contract;

#[cfg(test)]
pub(super) use self::clarification::clarification_request_for_outcome_request;
use self::clarification::specialized_domain_clarification_question;
pub(super) use self::connectors::{
    infer_connector_route_context_from_catalog, merge_connector_route_context,
};
pub(super) use self::non_artifact::{
    attach_non_artifact_studio_session, refresh_non_artifact_studio_surface,
};
#[cfg(test)]
pub(super) use self::route_contract::route_decision_for_outcome_request;
pub(crate) use self::route_contract::runtime_handoff_prompt_prefix_for_task;
pub(super) use self::route_contract::{
    append_route_contract_event, artifact_execution_envelope_for_contract,
    build_route_contract_payload, non_artifact_route_status_message,
};

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
    pub(super) preparation_needs: Option<StudioArtifactPreparationNeeds>,
    pub(super) prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    pub(super) skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    pub(super) blueprint: Option<StudioArtifactBlueprint>,
    pub(super) artifact_ir: Option<StudioArtifactIR>,
    pub(super) selected_skills: Vec<StudioArtifactSelectedSkill>,
    pub(super) retrieved_exemplars: Vec<StudioArtifactExemplar>,
    pub(super) edit_intent: Option<StudioArtifactEditIntent>,
    pub(super) candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    pub(super) winning_candidate_id: Option<String>,
    pub(super) winning_candidate_rationale: Option<String>,
    pub(super) execution_envelope: Option<ExecutionEnvelope>,
    pub(super) swarm_plan: Option<SwarmPlan>,
    pub(super) swarm_execution: Option<SwarmExecutionSummary>,
    pub(super) swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    pub(super) swarm_change_receipts: Vec<SwarmChangeReceipt>,
    pub(super) swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    pub(super) swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    pub(super) render_evaluation: Option<StudioArtifactRenderEvaluation>,
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
    pub(super) runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
}

fn default_studio_outcome_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
) -> StudioOutcomeRequest {
    let mut request = StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: execution_strategy_for_outcome(StudioOutcomeKind::Conversation, None),
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

fn is_likely_contextual_widget_follow_up(intent: &str) -> bool {
    let normalized = intent.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    let starts_fresh_request = [
        "find",
        "show",
        "give",
        "list",
        "draft",
        "write",
        "make",
        "create",
        "plan",
        "build",
        "generate",
        "tell",
        "recommend",
        "search",
        "look up",
        "book",
        "buy",
        "compose",
        "reply",
        "summarize",
        "explain",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(&format!("{prefix} ")))
        || [
            "find",
            "show",
            "give",
            "list",
            "draft",
            "write",
            "make",
            "create",
            "plan",
            "build",
            "generate",
            "tell",
            "recommend",
            "search",
            "look up",
            "book",
            "buy",
            "compose",
            "reply",
            "summarize",
            "explain",
        ]
        .iter()
        .any(|prefix| normalized == *prefix);

    let contextual_prefix = [
        "how about",
        "what about",
        "and",
        "also",
        "instead",
        "then",
        "tomorrow",
        "next",
        "same",
        "that",
        "those",
        "them",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix));
    if contextual_prefix {
        return true;
    }

    if [
        " instead",
        " tomorrow",
        " next one",
        " same one",
        " that one",
        " those",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return true;
    }

    if normalized.ends_with('?') {
        return false;
    }

    if [
        "near",
        "around",
        "within",
        "in",
        "at",
        "by",
        "for",
        "via",
        "through",
        "on",
        "slack",
        "email",
        "gmail",
        "text",
        "sms",
        "chat",
        "today",
        "tomorrow",
        "tonight",
        "this weekend",
        "this week",
        "next week",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
    {
        return true;
    }

    let word_count = normalized
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .count();
    if !starts_fresh_request
        && word_count <= 6
        && (normalized.contains(',') || normalized.ends_with('.'))
    {
        return true;
    }

    !starts_fresh_request && word_count <= 3 && normalized.len() <= 48
}

fn retained_widget_follow_up_route_hint(widget_family: &str) -> Option<&'static str> {
    match widget_family {
        "weather" => Some("tool_widget:weather"),
        "sports" => Some("tool_widget:sports"),
        "places" => Some("tool_widget:places"),
        "recipe" => Some("tool_widget:recipe"),
        "user_input" => Some("tool_widget:user_input"),
        _ => None,
    }
}

pub(super) fn contextual_retained_widget_follow_up_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioOutcomeRequest> {
    let widget_state = active_widget_state?;
    let widget_family = widget_state.widget_family.as_deref()?;
    let routing_hint = retained_widget_follow_up_route_hint(widget_family)?;
    if !is_likely_contextual_widget_follow_up(raw_prompt) {
        return None;
    }

    let requested_strategy = execution_strategy_for_outcome(StudioOutcomeKind::ToolWidget, None);
    let execution_mode_decision = derive_execution_mode_decision(
        StudioOutcomeKind::ToolWidget,
        None,
        requested_strategy,
        0.92,
        false,
        active_artifact_id.is_some(),
    );
    let execution_strategy = execution_mode_decision.resolved_strategy;
    let mut outcome_request = StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::ToolWidget,
        execution_strategy,
        execution_mode_decision: Some(execution_mode_decision),
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            routing_hint.to_string(),
            "retained_widget_follow_up".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    refresh_outcome_request_topology(&mut outcome_request, active_widget_state);
    apply_retained_widget_state_resolution(&mut outcome_request, active_widget_state);
    Some(outcome_request)
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
    let mut outcome_request = StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: intent.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy: execution_strategy_for_outcome(
            StudioOutcomeKind::Artifact,
            Some(&request),
        ),
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
        artifact: Some(request.clone()),
    };
    refresh_outcome_request_topology(&mut outcome_request, None);
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
        issue_classes: vec!["failure_session".to_string()],
        repair_hints: vec![
            "Resolve the upstream studio failure and rerun materialization before surfacing the artifact."
                .to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![summary.clone()],
        file_findings: Vec::new(),
        aesthetic_verdict: "not_evaluated_due_to_failure_session".to_string(),
        interaction_verdict: "not_evaluated_due_to_failure_session".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("generation_retry".to_string()),
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
    let mut materialization = materialization_contract_for_request(
        intent,
        &request,
        &summary,
        None,
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request)),
    );
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
        retrieved_exemplars: Vec::new(),
        selected_targets: Vec::new(),
        widget_state: None,
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
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Result<StudioOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    if let Some(request) = contextual_retained_widget_follow_up_request(
        trimmed_intent,
        active_artifact_id.clone(),
        active_widget_state,
    ) {
        return Ok(request);
    }

    let Some(runtime) = app_studio_routing_inference_runtime(app) else {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    };

    let mut outcome_request = studio_outcome_request_with_runtime(
        runtime,
        trimmed_intent,
        active_artifact_id,
        active_artifact,
        active_widget_state,
    )?;

    let state = app.state::<std::sync::Mutex<crate::models::AppState>>();
    let connectors =
        tauri::async_runtime::block_on(crate::kernel::connectors::connector_list_catalog(state))
            .unwrap_or_default();
    if let Some(connector_context) =
        infer_connector_route_context_from_catalog(trimmed_intent, &connectors)
    {
        merge_connector_route_context(&mut outcome_request, connector_context);
        refresh_outcome_request_topology(&mut outcome_request, active_widget_state);
        apply_retained_widget_state_resolution(&mut outcome_request, active_widget_state);
    }

    Ok(outcome_request)
}

pub(super) fn studio_outcome_request_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Result<StudioOutcomeRequest, String> {
    let timeout = studio_routing_timeout_for_runtime(&runtime);
    studio_outcome_request_with_runtime_timeout(
        runtime,
        intent,
        active_artifact_id,
        active_artifact,
        active_widget_state,
        timeout,
    )
}

pub(super) fn studio_outcome_request_with_runtime_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
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

    let planner_execution_strategy = planning.execution_strategy;
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
    let requested_strategy = if outcome_kind != planning.outcome_kind
        || (outcome_kind == StudioOutcomeKind::Artifact && artifact.is_none())
    {
        execution_strategy_for_outcome(outcome_kind, artifact.as_ref())
    } else {
        planner_execution_strategy
    };
    let execution_mode_decision = derive_execution_mode_decision(
        outcome_kind,
        artifact.as_ref(),
        requested_strategy,
        planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        active_artifact_id.is_some(),
    );
    let execution_strategy = execution_mode_decision.resolved_strategy;

    let mut outcome_request = StudioOutcomeRequest {
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

fn request_frame_has_clarification_slots(frame: &StudioNormalizedRequestFrame) -> bool {
    match frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        StudioNormalizedRequestFrame::Sports(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        StudioNormalizedRequestFrame::Places(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        StudioNormalizedRequestFrame::Recipe(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        StudioNormalizedRequestFrame::MessageCompose(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
        StudioNormalizedRequestFrame::UserInput(frame) => {
            !frame.clarification_required_slots.is_empty()
        }
    }
}

fn request_frame_matches_retained_widget_state(
    frame: &StudioNormalizedRequestFrame,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> bool {
    let Some(widget_state) = active_widget_state else {
        return false;
    };
    let expected_family = match frame {
        StudioNormalizedRequestFrame::Weather(_) => "weather",
        StudioNormalizedRequestFrame::Sports(_) => "sports",
        StudioNormalizedRequestFrame::Places(_) => "places",
        StudioNormalizedRequestFrame::Recipe(_) => "recipe",
        StudioNormalizedRequestFrame::MessageCompose(_) => "message",
        StudioNormalizedRequestFrame::UserInput(_) => "user_input",
    };
    widget_state.widget_family.as_deref() == Some(expected_family)
}

fn apply_retained_widget_state_resolution(
    outcome_request: &mut StudioOutcomeRequest,
    active_widget_state: Option<&StudioRetainedWidgetState>,
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

fn apply_request_frame_clarification_resolution(outcome_request: &mut StudioOutcomeRequest) {
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
    outcome_request: &mut StudioOutcomeRequest,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) {
    let projection = derive_studio_topology_projection(
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
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
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
            verification_step("materialize", "Materialize artifact", "pending"),
            verification_step("verify", "Verify artifact contract", "pending"),
        ]
    };
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
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

    StudioArtifactMaterializationContract {
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
        runtime_narration_events: Vec::new(),
        notes: vec![
            "Conversation remains the control plane; this artifact is the work product."
                .to_string(),
            "Renderer choice is explicit in the typed outcome request.".to_string(),
            "Verification state, not worker prose, authorizes the final Studio summary."
                .to_string(),
        ],
    }
}

pub(super) fn verification_steps_for_materialized_artifact(
    request: &StudioOutcomeArtifactRequest,
    materialized_artifact: &MaterializedContentArtifact,
) -> Vec<crate::models::StudioArtifactMaterializationVerificationStep> {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return Vec::new();
    }

    let materialize_status = if !materialized_artifact.files.is_empty()
        || !materialized_artifact.file_writes.is_empty()
    {
        "success"
    } else if matches!(
        materialized_artifact.lifecycle_state,
        StudioArtifactLifecycleState::Failed | StudioArtifactLifecycleState::Blocked
    ) {
        "blocked"
    } else {
        "pending"
    };
    let verify_status = match materialized_artifact.lifecycle_state {
        StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial => "success",
        StudioArtifactLifecycleState::Failed | StudioArtifactLifecycleState::Blocked => "blocked",
        _ => "pending",
    };

    vec![
        verification_step("materialize", "Materialize artifact", materialize_status),
        verification_step("verify", "Verify artifact contract", verify_status),
    ]
}

pub(super) fn apply_materialized_artifact_to_contract(
    materialization: &mut StudioArtifactMaterializationContract,
    request: &StudioOutcomeArtifactRequest,
    materialized_artifact: &MaterializedContentArtifact,
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
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
    materialization.verification_steps =
        verification_steps_for_materialized_artifact(request, materialized_artifact);
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
    materialization.judge = materialized_artifact.judge.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
    materialization.runtime_narration_events =
        materialized_artifact.runtime_narration_events.clone();
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
        materialized_artifact.blueprint.as_ref(),
        materialized_artifact.artifact_ir.as_ref(),
        materialized_artifact.edit_intent.as_ref(),
        materialized_artifact.judge.as_ref(),
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
        outcome_request.execution_strategy,
    );
    let resolved_verification_steps =
        verification_steps_for_materialized_artifact(&request, &materialized_artifact);
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
    materialization.judge = materialized_artifact.judge.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
    if !resolved_verification_steps.is_empty() {
        materialization.verification_steps = resolved_verification_steps;
    }
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
        &memory_runtime,
        app_inference_runtime(app),
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
