//! Shared route/topology/policy semantics for the Studio harness.
//!
//! The functions in this module should stay provenance-free and product-shell
//! agnostic. They compute reusable runtime semantics such as lane/topology
//! projections, route decisions, source selection, verification state, and
//! non-artifact execution policy.
//!
//! UI-specific presentation, session lifecycle mutation, and shell-only render
//! surfaces should remain in the Autopilot Studio kernel.

use super::intent_signals::StudioIntentContext;
use super::runtime_locality::runtime_locality_scope_hint;
use super::specialized_policy::{
    studio_request_frame_clarification_slots, studio_request_frame_missing_slots,
    studio_specialized_domain_kind, studio_specialized_domain_policy,
};
use super::types::{
    ArtifactConnectorGrounding, ArtifactOperatorPhase, ArtifactOperatorRunStatus,
    ArtifactOperatorStep,
};
use crate::execution::{
    block_swarm_work_item_on, spawn_follow_up_swarm_work_item, ExecutionCompletionInvariant,
    ExecutionCompletionInvariantStatus, ExecutionGraphMutationReceipt, ExecutionReplanReceipt,
    SwarmPlan, SwarmVerificationPolicy, SwarmVerificationReceipt, SwarmWorkItem,
    SwarmWorkItemStatus, SwarmWorkerReceipt, SwarmWorkerResultKind, SwarmWorkerRole,
};
use ioi_types::app::{
    RoutingEffectiveToolSurface, RoutingRouteDecision, StudioArtifactClass,
    StudioArtifactLifecycleState, StudioArtifactManifest, StudioArtifactManifestVerification,
    StudioArtifactVerificationStatus, StudioCheckpointState, StudioClarificationMode,
    StudioClarificationPolicy, StudioCompletionInvariant, StudioDomainLaneFrame,
    StudioDomainPolicyBundle, StudioExecutionModeDecision, StudioExecutionStrategy,
    StudioExecutionSubstrate, StudioFallbackMode, StudioFallbackPolicy, StudioLaneFamily,
    StudioLaneTransition, StudioLaneTransitionKind, StudioMessageComposeRequestFrame,
    StudioNormalizedRequestFrame, StudioObjectiveState, StudioOrchestrationState,
    StudioOutcomeArtifactRequest, StudioOutcomeKind, StudioOutcomeRequest,
    StudioPlacesRequestFrame, StudioPolicyContractSummary, StudioPresentationPolicy,
    StudioRecipeRequestFrame, StudioRendererKind, StudioRetainedLaneState,
    StudioRetainedWidgetState, StudioRiskProfile, StudioRiskSensitivity, StudioRuntimeProvenance,
    StudioSourceFamily, StudioSourceRankingEntry, StudioSourceSelection, StudioSportsRequestFrame,
    StudioTaskUnitState, StudioTransformationPolicy, StudioUserInputRequestFrame,
    StudioVerificationContract, StudioWeatherRequestFrame, StudioWidgetStateBinding,
    StudioWorkStatus,
};
use serde_json::json;

#[derive(Debug, Clone, PartialEq)]
pub struct TopologyProjection {
    pub lane_frame: Option<StudioDomainLaneFrame>,
    pub request_frame: Option<StudioNormalizedRequestFrame>,
    pub source_selection: Option<StudioSourceSelection>,
    pub retained_lane_state: Option<StudioRetainedLaneState>,
    pub lane_transitions: Vec<StudioLaneTransition>,
    pub orchestration_state: Option<StudioOrchestrationState>,
}
pub type StudioTopologyProjection = TopologyProjection;

pub fn derive_studio_topology_projection(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
    outcome_kind: StudioOutcomeKind,
    execution_strategy: StudioExecutionStrategy,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
    confidence: f32,
    needs_clarification: bool,
    clarification_questions: &[String],
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> TopologyProjection {
    let context = StudioIntentContext::new(intent);
    let request_frame = derive_request_frame(&context, routing_hints, active_widget_state);
    let primary_lane = primary_lane_family(
        &context,
        outcome_kind,
        routing_hints,
        artifact,
        request_frame.as_ref(),
    );
    let lane_frame = Some(StudioDomainLaneFrame {
        primary_lane,
        secondary_lanes: secondary_lane_families(
            primary_lane,
            request_frame.as_ref(),
            routing_hints,
            artifact,
        ),
        primary_goal: primary_goal(
            intent,
            primary_lane,
            outcome_kind,
            routing_hints,
            request_frame.as_ref(),
            artifact,
        ),
        tool_widget_family: tool_widget_family_hint(routing_hints).map(str::to_string),
        currentness_pressure: routing_hint_flag(routing_hints, "currentness_override")
            || matches!(
                tool_widget_family_hint(routing_hints),
                Some("weather" | "sports" | "places")
            )
            || context.currentness_pressure(),
        workspace_grounding_required: routing_hint_flag(
            routing_hints,
            "workspace_grounding_required",
        ) || artifact.is_some_and(|request| {
            matches!(
                request.artifact_class,
                StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
            )
        }),
        persistent_deliverable_requested: outcome_kind == StudioOutcomeKind::Artifact,
        active_artifact_follow_up: active_artifact_id.is_some(),
        lane_confidence: if confidence.is_finite() {
            confidence.clamp(0.0, 1.0)
        } else {
            0.0
        },
    });
    let source_selection = Some(derive_source_selection(
        &context,
        primary_lane,
        request_frame.as_ref(),
        routing_hints,
        active_artifact_id,
    ));
    let retained_lane_state = Some(StudioRetainedLaneState {
        active_lane: if needs_clarification && primary_lane != StudioLaneFamily::Conversation {
            primary_lane
        } else {
            primary_lane
        },
        active_tool_widget_family: tool_widget_family_hint(routing_hints).map(str::to_string),
        active_artifact_id: active_artifact_id.map(str::to_string),
        unresolved_clarification_question: clarification_questions.first().cloned(),
        selected_provider_family: routing_hint_value(routing_hints, "selected_provider_family:"),
        selected_provider_route_label: routing_hint_value(
            routing_hints,
            "selected_provider_route_label:",
        ),
        selected_source_family: source_selection
            .as_ref()
            .map(|selection| selection.selected_source),
    });
    let lane_transitions = derive_lane_transitions(
        primary_lane,
        lane_frame
            .as_ref()
            .map(|frame| frame.secondary_lanes.as_slice())
            .unwrap_or(&[]),
        request_frame.as_ref(),
        needs_clarification,
        clarification_questions,
        routing_hints,
    );
    let orchestration_state = derive_orchestration_state(
        intent,
        primary_lane,
        outcome_kind,
        execution_strategy,
        execution_mode_decision,
        needs_clarification,
        clarification_questions,
        request_frame.as_ref(),
    );

    StudioTopologyProjection {
        lane_frame,
        request_frame,
        source_selection,
        retained_lane_state,
        lane_transitions,
        orchestration_state,
    }
}

pub fn derive_studio_domain_policy_bundle(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    source_selection: Option<&StudioSourceSelection>,
    outcome_kind: StudioOutcomeKind,
    routing_hints: &[String],
    needs_clarification: bool,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioDomainPolicyBundle {
    let retained_widget_state = merge_retained_widget_state(request_frame, active_widget_state);
    let clarification_policy = derive_clarification_policy(
        request_frame,
        needs_clarification,
        retained_widget_state.as_ref(),
    );
    let fallback_policy = derive_fallback_policy(
        lane_frame,
        request_frame,
        routing_hints,
        needs_clarification,
    );
    let presentation_policy = derive_presentation_policy(
        lane_frame,
        request_frame,
        outcome_kind,
        retained_widget_state.as_ref(),
    );
    let transformation_policy = derive_transformation_policy(request_frame, outcome_kind);
    let risk_profile = derive_risk_profile(lane_frame, request_frame, routing_hints);
    let verification_contract =
        derive_verification_contract(lane_frame, request_frame, outcome_kind, needs_clarification);
    let source_ranking = derive_source_ranking(request_frame, source_selection);

    StudioDomainPolicyBundle {
        clarification_policy,
        fallback_policy,
        presentation_policy,
        transformation_policy,
        risk_profile,
        verification_contract,
        policy_contract: Some(StudioPolicyContractSummary {
            bindings: vec![
                "lane_frame".to_string(),
                "request_frame".to_string(),
                "source_selection".to_string(),
                "route_decision.effective_tool_surface".to_string(),
                "domain_policy_bundle".to_string(),
            ],
            hidden_instruction_dependency: false,
            rationale:
                "Lane choice, fallback posture, source ranking, presentation, and verification are retained as typed runtime receipts."
                    .to_string(),
        }),
        source_ranking,
        retained_widget_state,
    }
}

fn routing_hint_flag(routing_hints: &[String], needle: &str) -> bool {
    routing_hints.iter().any(|hint| hint == needle)
}

fn routing_hint_value(routing_hints: &[String], prefix: &str) -> Option<String> {
    routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix(prefix))
        .map(str::to_string)
}

pub fn artifact_connector_grounding_for_outcome_request(
    outcome_request: &StudioOutcomeRequest,
) -> Option<ArtifactConnectorGrounding> {
    if outcome_request.outcome_kind != StudioOutcomeKind::Artifact
        || !routing_hint_flag(&outcome_request.routing_hints, "connector_intent_detected")
    {
        return None;
    }

    Some(ArtifactConnectorGrounding {
        connector_id: routing_hint_value(&outcome_request.routing_hints, "selected_connector_id:"),
        provider_family: routing_hint_value(
            &outcome_request.routing_hints,
            "selected_provider_family:",
        ),
        target_label: routing_hint_value(&outcome_request.routing_hints, "connector_target_label:"),
    })
}

pub fn route_family_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> &'static str {
    if let Some(lane_frame) = outcome_request.lane_frame.as_ref() {
        return match lane_frame.primary_lane {
            StudioLaneFamily::Research => "research",
            StudioLaneFamily::Coding => "coding",
            StudioLaneFamily::Integrations => "integrations",
            StudioLaneFamily::Communication => "communication",
            StudioLaneFamily::UserInput => "user_input",
            StudioLaneFamily::Visualizer => "artifacts",
            StudioLaneFamily::Artifact => "artifacts",
            StudioLaneFamily::ToolWidget => "tool_widget",
            StudioLaneFamily::Conversation | StudioLaneFamily::General => "general",
        };
    }

    let widget_family = tool_widget_family_hint(&outcome_request.routing_hints);
    if routing_hint_flag(&outcome_request.routing_hints, "connector_intent_detected") {
        return "integrations";
    }
    if routing_hint_flag(
        &outcome_request.routing_hints,
        "workspace_grounding_required",
    ) {
        return "coding";
    }
    if let Some(artifact) = outcome_request.artifact.as_ref() {
        if matches!(
            artifact.artifact_class,
            StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
        ) || artifact.renderer == StudioRendererKind::WorkspaceSurface
            || artifact.execution_substrate == StudioExecutionSubstrate::WorkspaceRuntime
        {
            return "coding";
        }
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact
        || outcome_request.outcome_kind == StudioOutcomeKind::Visualizer
    {
        return "artifacts";
    }
    if outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "currentness_override")
        || matches!(
            widget_family,
            Some("weather" | "sports" | "places" | "recipe")
        )
    {
        return "research";
    }
    "general"
}

pub fn selected_route_label_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> String {
    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            if matches!(
                outcome_request.request_frame.as_ref(),
                Some(StudioNormalizedRequestFrame::MessageCompose(_))
            ) {
                format!(
                    "communication_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if let Some(route_label) = routing_hint_value(
                &outcome_request.routing_hints,
                "selected_provider_route_label:",
            ) {
                format!(
                    "conversation_{}_{}",
                    route_label,
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(
                &outcome_request.routing_hints,
                "workspace_grounding_required",
            ) {
                format!(
                    "conversation_workspace_grounded_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(&outcome_request.routing_hints, "currentness_override") {
                format!(
                    "conversation_currentness_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(&outcome_request.routing_hints, "connector_intent_detected")
            {
                format!(
                    "conversation_connector_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else {
                format!(
                    "conversation_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            }
        }
        StudioOutcomeKind::ToolWidget => {
            match tool_widget_family_hint(&outcome_request.routing_hints) {
                Some(widget_family) => format!("tool_widget_{widget_family}"),
                None => "tool_widget".to_string(),
            }
        }
        StudioOutcomeKind::Visualizer => "inline_visualizer".to_string(),
        StudioOutcomeKind::Artifact => {
            let renderer = outcome_request
                .artifact
                .as_ref()
                .map(|artifact| renderer_kind_id(artifact.renderer))
                .unwrap_or("bundle_manifest");
            format!("artifact_{renderer}")
        }
    }
}

pub fn route_decision_for_outcome_request(
    outcome_request: &StudioOutcomeRequest,
) -> RoutingRouteDecision {
    let currentness_override = outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "currentness_override");
    let tool_widget_family = tool_widget_family_hint(&outcome_request.routing_hints);
    let file_output_intent = file_output_intent_for_outcome_request(outcome_request);
    let skill_prep_required = skill_prep_required_for_outcome_request(outcome_request);
    let mut direct_answer_blockers = Vec::<String>::new();
    if outcome_request.needs_clarification {
        direct_answer_blockers.push("clarification_required".to_string());
    }
    if currentness_override {
        direct_answer_blockers.push("currentness_override".to_string());
    }
    if routing_hint_flag(
        &outcome_request.routing_hints,
        "workspace_grounding_required",
    ) {
        direct_answer_blockers.push("workspace_grounding_required".to_string());
    }
    if tool_widget_family.is_some() {
        direct_answer_blockers.push("tool_widget_surface_selected".to_string());
    }
    if request_frame_surface_hint(outcome_request).is_some() {
        direct_answer_blockers.push("structured_surface_selected".to_string());
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Visualizer {
        direct_answer_blockers.push("inline_visual_surface_selected".to_string());
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact {
        direct_answer_blockers.push("persistent_artifact_requested".to_string());
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Conversation
        && outcome_request.execution_strategy != StudioExecutionStrategy::SinglePass
        && !outcome_request.needs_clarification
        && !currentness_override
    {
        direct_answer_blockers.push("planned_execution_selected".to_string());
    }
    if routing_hint_flag(&outcome_request.routing_hints, "connector_missing") {
        direct_answer_blockers.push("connector_unavailable".to_string());
    }
    if routing_hint_flag(&outcome_request.routing_hints, "connector_auth_required") {
        direct_answer_blockers.push("connector_auth_required".to_string());
    }
    let raw_output_intent = output_intent_for_outcome_request(outcome_request);
    let direct_answer_allowed =
        raw_output_intent == "direct_inline" && direct_answer_blockers.is_empty();
    let output_intent = if raw_output_intent == "direct_inline" && !direct_answer_allowed {
        "tool_execution"
    } else {
        raw_output_intent
    };

    RoutingRouteDecision {
        route_family: route_family_for_outcome_request(outcome_request).to_string(),
        direct_answer_allowed,
        direct_answer_blockers,
        currentness_override,
        connector_candidate_count: routing_hint_value(
            &outcome_request.routing_hints,
            "connector_candidate_count:",
        )
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0),
        selected_provider_family: routing_hint_value(
            &outcome_request.routing_hints,
            "selected_provider_family:",
        ),
        selected_provider_route_label: routing_hint_value(
            &outcome_request.routing_hints,
            "selected_provider_route_label:",
        ),
        connector_first_preference: routing_hint_flag(
            &outcome_request.routing_hints,
            "connector_intent_detected",
        ),
        narrow_tool_preference: narrow_tool_preference_for_outcome_request(outcome_request),
        file_output_intent,
        artifact_output_intent: outcome_request.outcome_kind == StudioOutcomeKind::Artifact,
        inline_visual_intent: outcome_request.outcome_kind == StudioOutcomeKind::Visualizer,
        skill_prep_required,
        output_intent: output_intent.to_string(),
        effective_tool_surface: effective_tool_surface_for_outcome_request(outcome_request),
    }
}

pub fn route_topology_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> &'static str {
    match outcome_request.execution_strategy {
        StudioExecutionStrategy::SinglePass | StudioExecutionStrategy::DirectAuthor => {
            "single_agent"
        }
        StudioExecutionStrategy::AdaptiveWorkGraph => "planner_specialist_verifier",
        StudioExecutionStrategy::PlanExecute | StudioExecutionStrategy::MicroSwarm => {
            "planner_specialist"
        }
    }
}

pub fn verifier_state_for_outcome_event(
    outcome_request: &StudioOutcomeRequest,
    completed: bool,
) -> &'static str {
    if outcome_request.needs_clarification {
        return "blocked";
    }
    if completed {
        return "passed";
    }
    if routing_hint_flag(&outcome_request.routing_hints, "currentness_override") {
        return "active";
    }
    if routing_hint_flag(
        &outcome_request.routing_hints,
        "workspace_grounding_required",
    ) {
        return "active";
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact
        || outcome_request.execution_strategy != StudioExecutionStrategy::SinglePass
    {
        return "active";
    }
    "not_engaged"
}

pub fn non_artifact_route_status_message(outcome_request: &StudioOutcomeRequest) -> String {
    if outcome_request.needs_clarification {
        return "Studio needs clarification before selecting the correct outcome surface."
            .to_string();
    }

    let base = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "Studio routed this request to conversation.",
        StudioOutcomeKind::ToolWidget => "Studio routed this request to a tool-widget surface.",
        StudioOutcomeKind::Visualizer => "Studio routed this request to a visualizer surface.",
        StudioOutcomeKind::Artifact => "Studio routed this request to artifact materialization.",
    };

    let continuation = if outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "currentness_override")
    {
        " Continuing on the main runtime with currentness pressure in view."
    } else if let Some(widget_family) = outcome_request
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
    {
        return format!(
            "{base} Continuing on the main runtime with a narrow {widget_family} surface preference."
        );
    } else if outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "inline_visual_requested")
    {
        " Continuing on the main runtime with inline visual intent preserved."
    } else {
        " Continuing on the main runtime without opening an artifact renderer."
    };

    format!("{base}{continuation}")
}

pub fn non_artifact_route_summary(outcome_request: &StudioOutcomeRequest) -> String {
    if outcome_request.needs_clarification {
        let question = outcome_request
            .clarification_questions
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "Studio needs clarification before it can choose the correct outcome surface."
                    .to_string()
            });
        return format!(
            "Studio paused before selecting the outcome surface because it needs clarification: {}",
            question
        );
    }

    let base = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "Studio routed this request to conversation.",
        StudioOutcomeKind::ToolWidget => "Studio routed this request to a tool-widget surface.",
        StudioOutcomeKind::Visualizer => "Studio routed this request to a visualizer surface.",
        StudioOutcomeKind::Artifact => "Studio routed this request to artifact materialization.",
    };
    let reason_fragments = studio_route_hint_reason_fragments(outcome_request);
    if reason_fragments.is_empty() {
        format!(
            "{base} Studio kept the artifact lane closed and preserved route receipts for downstream execution."
        )
    } else {
        format!(
            "{base} {} Studio kept the artifact lane closed and preserved route receipts for downstream execution.",
            reason_fragments.join(" ")
        )
    }
}

pub fn build_studio_runtime_handoff_prompt_prefix(
    outcome_request: &StudioOutcomeRequest,
    workspace_root: Option<&str>,
) -> String {
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let selected_route = selected_route_label_for_outcome_request(outcome_request);
    let primary_tools = if route_decision
        .effective_tool_surface
        .primary_tools
        .is_empty()
    {
        "none".to_string()
    } else {
        route_decision
            .effective_tool_surface
            .primary_tools
            .join(", ")
    };
    let fallback_tools = if route_decision
        .effective_tool_surface
        .broad_fallback_tools
        .is_empty()
    {
        "none".to_string()
    } else {
        route_decision
            .effective_tool_surface
            .broad_fallback_tools
            .join(", ")
    };
    let blockers = if route_decision.direct_answer_blockers.is_empty() {
        "none".to_string()
    } else {
        route_decision.direct_answer_blockers.join(", ")
    };

    let mut execution_rules = vec![
        "Honor this Studio route contract unless the user explicitly changes the task.".to_string(),
    ];
    if !route_decision.direct_answer_allowed {
        execution_rules.push(
            "Do not answer from memory alone; gather evidence through the projected tool path first."
                .to_string(),
        );
    }
    if route_decision.narrow_tool_preference
        && !route_decision
            .effective_tool_surface
            .primary_tools
            .is_empty()
    {
        execution_rules.push(
            "Prefer the primary tools before broad fallbacks, and only escalate if the narrow path cannot satisfy the request."
                .to_string(),
        );
    }
    if routing_hint_flag(
        &outcome_request.routing_hints,
        "workspace_grounding_required",
    ) {
        execution_rules.push(
            "Treat local workspace inspection as mandatory for this turn; inspect the repo before answering."
                .to_string(),
        );
        execution_rules.push(
            "Do not substitute browser or computer-use actions for repo inspection unless the workspace path is genuinely blocked."
                .to_string(),
        );
    }
    if routing_hint_flag(&outcome_request.routing_hints, "currentness_override") {
        execution_rules.push(
            "Fresh external information is required here; use current retrieval before answering."
                .to_string(),
        );
    }
    if routing_hint_flag(&outcome_request.routing_hints, "connector_intent_detected") {
        execution_rules.push(
            "Prefer the selected connector/provider route over generic fallbacks.".to_string(),
        );
    }

    let workspace_line = workspace_root
        .map(|root| format!("workspace_root: {root}"))
        .unwrap_or_else(|| "workspace_root: unresolved".to_string());

    format!(
        "STUDIO ROUTE CONTRACT:\n\
         - selected_route: {selected_route}\n\
         - route_family: {route_family}\n\
         - output_intent: {output_intent}\n\
         - direct_answer_allowed: {direct_answer_allowed}\n\
         - direct_answer_blockers: {blockers}\n\
         - primary_tools: {primary_tools}\n\
         - broad_fallback_tools: {fallback_tools}\n\
         - {workspace_line}\n\
         \n\
         EXECUTION RULES:\n\
         - {rules}\n",
        route_family = route_decision.route_family,
        output_intent = route_decision.output_intent,
        direct_answer_allowed = route_decision.direct_answer_allowed,
        rules = execution_rules.join("\n- "),
    )
}

pub fn non_artifact_route_notes(outcome_request: &StudioOutcomeRequest) -> Vec<String> {
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let mut notes = vec![
        format!("Route family: {}", route_decision.route_family),
        format!("Output intent: {}", route_decision.output_intent),
    ];
    if !route_decision
        .effective_tool_surface
        .projected_tools
        .is_empty()
    {
        notes.push(format!(
            "Projected surface: {}",
            route_decision
                .effective_tool_surface
                .projected_tools
                .join(", ")
        ));
    }
    notes
}

pub fn non_artifact_verification_receipts(
    outcome_request: &StudioOutcomeRequest,
) -> Vec<SwarmVerificationReceipt> {
    let status = if outcome_request.needs_clarification {
        "blocked"
    } else {
        "ready"
    };
    let route_detail = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "conversation surface",
        StudioOutcomeKind::ToolWidget => "tool-widget surface",
        StudioOutcomeKind::Visualizer => "visualizer surface",
        StudioOutcomeKind::Artifact => "artifact surface",
    };

    vec![
        SwarmVerificationReceipt {
            id: "route_verification".to_string(),
            kind: "route_verification".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "Studio blocked execution because clarification is still required.".to_string()
            } else {
                format!(
                    "Studio verified that this request belongs on the {}.",
                    route_detail
                )
            },
            details: if outcome_request.needs_clarification {
                outcome_request.clarification_questions.clone()
            } else {
                outcome_request.routing_hints.clone()
            },
        },
        SwarmVerificationReceipt {
            id: "reply_surface".to_string(),
            kind: "reply_surface".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "The shared reply lane is blocked until the user answers the clarification."
                    .to_string()
            } else {
                "The shared reply lane remains available and no artifact renderer is required."
                    .to_string()
            },
            details: {
                let mut details = vec![format!(
                    "strategy:{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )];
                details.extend(outcome_request.routing_hints.iter().cloned());
                details
            },
        },
    ]
}

pub fn non_artifact_operator_steps(
    outcome_request: &StudioOutcomeRequest,
) -> Vec<ArtifactOperatorStep> {
    vec![
        ArtifactOperatorStep {
            step_id: "verify_route".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "non_artifact_route".to_string(),
            status: ArtifactOperatorRunStatus::Complete,
            label: "Verify route".to_string(),
            detail: "Verify route completed.".to_string(),
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        },
        ArtifactOperatorStep {
            step_id: "verify_reply_surface".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "non_artifact_route".to_string(),
            status: if outcome_request.needs_clarification {
                ArtifactOperatorRunStatus::Blocked
            } else {
                ArtifactOperatorRunStatus::Complete
            },
            label: "Verify reply surface".to_string(),
            detail: if outcome_request.needs_clarification {
                "Verify reply surface is blocked.".to_string()
            } else {
                "Verify reply surface completed.".to_string()
            },
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        },
    ]
}

pub fn non_artifact_swarm_plan(outcome_request: &StudioOutcomeRequest) -> SwarmPlan {
    let outcome_kind_id = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "conversation",
        StudioOutcomeKind::ToolWidget => "tool_widget",
        StudioOutcomeKind::Visualizer => "visualizer",
        StudioOutcomeKind::Artifact => "artifact",
    };
    let execution_domain = format!("studio_{outcome_kind_id}");
    let adapter_label = format!(
        "{outcome_kind_id}_{}_v1",
        execution_strategy_id(outcome_request.execution_strategy)
    );
    let responder_title = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "Conversation handoff",
        StudioOutcomeKind::ToolWidget => "Tool-widget handoff",
        StudioOutcomeKind::Visualizer => "Visualizer handoff",
        StudioOutcomeKind::Artifact => "Artifact handoff",
    };
    let responder_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Keep the request on the conversation surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::ToolWidget => {
            "Keep the request on the tool-widget surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Visualizer => {
            "Keep the request on the visualizer surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Artifact => {
            "Keep the request on the artifact surface and preserve the shared execution evidence."
        }
    };

    SwarmPlan {
        version: 1,
        strategy: execution_strategy_id(outcome_request.execution_strategy).to_string(),
        execution_domain,
        adapter_label,
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some(format!(
            "Route the request onto the {outcome_kind_id} surface and preserve truthful execution evidence."
        )),
        decomposition_hypothesis: Some(
            "The request can be satisfied with a small known non-artifact work graph."
                .to_string(),
        ),
        decomposition_type: Some("small_graph_functional_decomposition".to_string()),
        first_frontier_ids: vec!["handoff".to_string()],
        spawn_conditions: vec![
            "Spawn a clarification gate only when the router discovers unresolved ambiguity."
                .to_string(),
        ],
        prune_conditions: vec![
            "Prune clarification work once the reply handoff is already unblocked.".to_string(),
        ],
        merge_strategy: Some("typed_reply_surface_projection".to_string()),
        verification_strategy: Some("route_truth_before_reply".to_string()),
        fallback_collapse_strategy: Some(
            "Collapse to the reply handoff once clarification obligations are satisfied."
                .to_string(),
        ),
        completion_invariant: Some(ExecutionCompletionInvariant {
            summary:
                "Complete once the mandatory non-artifact handoff is satisfied and route truth is preserved."
                    .to_string(),
            status: ExecutionCompletionInvariantStatus::Satisfied,
            required_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            satisfied_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            speculative_work_item_ids: if outcome_request.needs_clarification {
                vec!["clarification_gate".to_string()]
            } else {
                Vec::new()
            },
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["route_truth".to_string()],
            satisfied_verification_ids: vec!["route_truth".to_string()],
            required_artifact_paths: Vec::new(),
            remaining_obligations: Vec::new(),
            allows_early_exit: true,
        }),
        work_items: vec![
            SwarmWorkItem {
                id: "planner".to_string(),
                title: "Outcome planner".to_string(),
                role: SwarmWorkerRole::Planner,
                summary:
                    "Lock the correct non-artifact route and execution strategy before any downstream handoff."
                        .to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "route_context".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Outcome route is explicit.".to_string(),
                    "Execution strategy is explicit.".to_string(),
                ],
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
            SwarmWorkItem {
                id: "handoff".to_string(),
                title: responder_title.to_string(),
                role: SwarmWorkerRole::Responder,
                summary: responder_summary.to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "execution_plan".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Studio reply remains truthful about the chosen surface.".to_string(),
                    "No artifact renderer is implied when none was invoked.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
        ],
    }
}

pub fn apply_non_artifact_clarification_gate(
    swarm_plan: &mut SwarmPlan,
    outcome_request: &StudioOutcomeRequest,
) -> (
    Vec<ExecutionGraphMutationReceipt>,
    Vec<ExecutionReplanReceipt>,
) {
    if !outcome_request.needs_clarification {
        return (Vec::new(), Vec::new());
    }

    let clarification_gate = SwarmWorkItem {
        id: "clarification_gate".to_string(),
        title: "Clarification gate".to_string(),
        role: SwarmWorkerRole::Coordinator,
        summary: "Hold the response until the user answers the required clarification questions."
            .to_string(),
        spawned_from_id: Some("planner".to_string()),
        read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        lease_requirements: Vec::new(),
        acceptance_criteria: vec![
            "Clarification questions stay visible.".to_string(),
            "Responder stays blocked until clarification arrives.".to_string(),
        ],
        dependency_ids: vec!["planner".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Blocking),
        retry_budget: Some(0),
        status: SwarmWorkItemStatus::Blocked,
    };
    let clarification_gate_id = clarification_gate.id.clone();
    let clarification_details = outcome_request.clarification_questions.clone();
    let _ = spawn_follow_up_swarm_work_item(swarm_plan, clarification_gate);
    let _ = block_swarm_work_item_on(
        swarm_plan,
        "handoff",
        std::slice::from_ref(&clarification_gate_id),
    );

    (
        vec![ExecutionGraphMutationReceipt {
            id: "clarification-gate-spawned".to_string(),
            mutation_kind: "subtask_spawned".to_string(),
            status: "applied".to_string(),
            summary:
                "The planner discovered a clarification dependency and spawned a gate before reply handoff."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            affected_work_item_ids: vec![clarification_gate_id.clone(), "handoff".to_string()],
            details: clarification_details.clone(),
        }],
        vec![ExecutionReplanReceipt {
            id: "clarification-replan".to_string(),
            status: "blocked".to_string(),
            summary:
                "Shared execution widened the plan with a clarification gate before the responder could finalize."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            spawned_work_item_ids: vec![clarification_gate_id],
            blocked_work_item_ids: vec!["handoff".to_string()],
            details: clarification_details,
        }],
    )
}

pub fn non_artifact_worker_receipts(
    outcome_request: &StudioOutcomeRequest,
    provenance: &StudioRuntimeProvenance,
    swarm_plan: &SwarmPlan,
    now: &str,
) -> Vec<SwarmWorkerReceipt> {
    let handoff_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Conversation stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::ToolWidget => {
            "Tool-widget stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Visualizer => {
            "Visualizer stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Artifact => "Artifact stayed primary.",
    };

    let clarification_questions = outcome_request.clarification_questions.clone();
    let planner_spawned_items = if outcome_request.needs_clarification {
        vec!["clarification_gate".to_string()]
    } else {
        Vec::new()
    };
    let handoff_status = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "handoff")
        .map(|item| item.status)
        .unwrap_or(SwarmWorkItemStatus::Succeeded);

    let mut receipts = vec![SwarmWorkerReceipt {
        work_item_id: "planner".to_string(),
        role: SwarmWorkerRole::Planner,
        status: SwarmWorkItemStatus::Succeeded,
        result_kind: Some(if outcome_request.needs_clarification {
            SwarmWorkerResultKind::DependencyDiscovered
        } else {
            SwarmWorkerResultKind::Completed
        }),
        summary: format!(
            "Selected the {} route with the {} strategy.",
            match outcome_request.outcome_kind {
                StudioOutcomeKind::Conversation => "conversation",
                StudioOutcomeKind::ToolWidget => "tool_widget",
                StudioOutcomeKind::Visualizer => "visualizer",
                StudioOutcomeKind::Artifact => "artifact",
            },
            execution_strategy_id(outcome_request.execution_strategy)
        ),
        started_at: now.to_string(),
        finished_at: Some(now.to_string()),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "route_context".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: planner_spawned_items,
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: if outcome_request.needs_clarification {
            clarification_questions.clone()
        } else {
            let mut notes = vec!["No artifact files were requested on this route.".to_string()];
            notes.extend(outcome_request.routing_hints.iter().cloned());
            notes
        },
        failure: None,
    }];
    if outcome_request.needs_clarification {
        receipts.push(SwarmWorkerReceipt {
            work_item_id: "clarification_gate".to_string(),
            role: SwarmWorkerRole::Coordinator,
            status: SwarmWorkItemStatus::Blocked,
            result_kind: Some(SwarmWorkerResultKind::Blocked),
            summary:
                "Clarification is required before the shared responder can safely finalize the route."
                    .to_string(),
            started_at: now.to_string(),
            finished_at: Some(now.to_string()),
            runtime: provenance.clone(),
            read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: Vec::new(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: None,
            notes: clarification_questions.clone(),
            failure: None,
        });
    }
    receipts.push(SwarmWorkerReceipt {
        work_item_id: "handoff".to_string(),
        role: SwarmWorkerRole::Responder,
        status: handoff_status,
        result_kind: Some(if outcome_request.needs_clarification {
            SwarmWorkerResultKind::Blocked
        } else {
            SwarmWorkerResultKind::Completed
        }),
        summary: handoff_summary.to_string(),
        started_at: now.to_string(),
        finished_at: Some(now.to_string()),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "execution_plan".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: if outcome_request.needs_clarification {
            vec!["clarification_gate".to_string()]
        } else {
            Vec::new()
        },
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: vec![
            "Studio kept the shared execution evidence instead of surfacing a blocked artifact failure."
                .to_string(),
            outcome_request.routing_hints.join(" · "),
        ],
        failure: if outcome_request.needs_clarification {
            Some("Clarification is still required before reply handoff can complete.".to_string())
        } else {
            None
        },
    });
    receipts
}

pub fn verification_status_for_lifecycle(
    lifecycle_state: StudioArtifactLifecycleState,
) -> StudioArtifactVerificationStatus {
    match lifecycle_state {
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => StudioArtifactVerificationStatus::Pending,
        StudioArtifactLifecycleState::Ready => StudioArtifactVerificationStatus::Ready,
        StudioArtifactLifecycleState::Blocked => StudioArtifactVerificationStatus::Blocked,
        StudioArtifactLifecycleState::Failed => StudioArtifactVerificationStatus::Failed,
        StudioArtifactLifecycleState::Partial => StudioArtifactVerificationStatus::Partial,
    }
}

pub fn verified_reply_evidence_for_manifest(
    verification: &StudioArtifactManifestVerification,
    manifest: &StudioArtifactManifest,
) -> Vec<String> {
    let mut evidence = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if let Some(provenance) = verification.production_provenance.as_ref() {
        evidence.push(format!(
            "production provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(provenance) = verification.acceptance_provenance.as_ref() {
        evidence.push(format!(
            "acceptance provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(failure) = verification.failure.as_ref() {
        evidence.push(format!("failure: {} ({})", failure.message, failure.code));
    }
    evidence
}

pub fn non_artifact_verified_reply_evidence(
    outcome_request: &StudioOutcomeRequest,
    provenance_label: &str,
) -> Vec<String> {
    vec![
        format!(
            "outcome:{}",
            match outcome_request.outcome_kind {
                StudioOutcomeKind::Conversation => "conversation",
                StudioOutcomeKind::ToolWidget => "tool_widget",
                StudioOutcomeKind::Visualizer => "visualizer",
                StudioOutcomeKind::Artifact => "artifact",
            }
        ),
        format!(
            "strategy:{}",
            execution_strategy_id(outcome_request.execution_strategy)
        ),
        format!("provenance:{provenance_label}"),
    ]
    .into_iter()
    .chain(
        outcome_request
            .routing_hints
            .iter()
            .map(|hint| format!("route_hint:{hint}")),
    )
    .collect()
}

pub fn non_artifact_route_title(intent: &str, outcome_request: &StudioOutcomeRequest) -> String {
    let trimmed = intent.trim();
    let base = if trimmed.is_empty() {
        "Untitled request".to_string()
    } else {
        let mut words = trimmed.split_whitespace();
        let summary = words.by_ref().take(8).collect::<Vec<_>>().join(" ");
        if words.next().is_some() {
            format!("{summary}...")
        } else {
            summary
        }
    };

    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => format!("Conversation route · {base}"),
        StudioOutcomeKind::ToolWidget => format!("Tool widget route · {base}"),
        StudioOutcomeKind::Visualizer => format!("Visualizer route · {base}"),
        StudioOutcomeKind::Artifact => base,
    }
}

pub fn build_studio_route_contract_payload(
    outcome_request: &StudioOutcomeRequest,
    completed: bool,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> serde_json::Value {
    let domain_policy_bundle = derive_studio_domain_policy_bundle(
        outcome_request.lane_frame.as_ref(),
        outcome_request.request_frame.as_ref(),
        outcome_request.source_selection.as_ref(),
        outcome_request.outcome_kind,
        &outcome_request.routing_hints,
        outcome_request.needs_clarification,
        retained_widget_state,
    );
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let verifier_state = verifier_state_for_outcome_event(outcome_request, completed);
    json!({
        "selected_route": selected_route_label_for_outcome_request(outcome_request),
        "route_family": route_decision.route_family,
        "topology": route_topology_for_outcome_request(outcome_request),
        "planner_authority": "kernel",
        "verifier_state": verifier_state,
        "verifier_outcome": if completed { Some("pass") } else { None::<&str> },
        "route_decision": route_decision,
        "lane_frame": outcome_request.lane_frame,
        "request_frame": outcome_request.request_frame,
        "source_selection": outcome_request.source_selection,
        "retained_lane_state": outcome_request.retained_lane_state,
        "lane_transitions": outcome_request.lane_transitions,
        "orchestration_state": outcome_request.orchestration_state,
        "domain_policy_bundle": domain_policy_bundle,
    })
}

fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn renderer_kind_id(renderer: StudioRendererKind) -> &'static str {
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

fn request_frame_surface_hint(outcome_request: &StudioOutcomeRequest) -> Option<&'static str> {
    match outcome_request.request_frame.as_ref() {
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => Some("message_compose"),
        Some(StudioNormalizedRequestFrame::UserInput(_)) => Some("user_input"),
        _ => None,
    }
}

fn file_output_intent_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> bool {
    let Some(artifact) = outcome_request.artifact.as_ref() else {
        return false;
    };

    if outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
        return false;
    }

    matches!(
        artifact.artifact_class,
        StudioArtifactClass::Document
            | StudioArtifactClass::DownloadableFile
            | StudioArtifactClass::CompoundBundle
            | StudioArtifactClass::CodePatch
            | StudioArtifactClass::ReportBundle
    ) || matches!(
        artifact.renderer,
        StudioRendererKind::PdfEmbed | StudioRendererKind::DownloadCard
    )
}

fn skill_prep_required_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> bool {
    let Some(artifact) = outcome_request.artifact.as_ref() else {
        return false;
    };

    if outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
        return false;
    }

    matches!(
        artifact.artifact_class,
        StudioArtifactClass::DownloadableFile
            | StudioArtifactClass::CompoundBundle
            | StudioArtifactClass::WorkspaceProject
            | StudioArtifactClass::CodePatch
            | StudioArtifactClass::ReportBundle
    ) || matches!(
        artifact.execution_substrate,
        StudioExecutionSubstrate::BinaryGenerator | StudioExecutionSubstrate::WorkspaceRuntime
    ) || matches!(
        artifact.renderer,
        StudioRendererKind::PdfEmbed
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::WorkspaceSurface
    )
}

fn narrow_tool_preference_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> bool {
    tool_widget_family_hint(&outcome_request.routing_hints).is_some()
        || request_frame_surface_hint(outcome_request).is_some()
        || routing_hint_flag(&outcome_request.routing_hints, "narrow_surface_preferred")
        || routing_hint_flag(
            &outcome_request.routing_hints,
            "workspace_grounding_required",
        )
        || routing_hint_flag(&outcome_request.routing_hints, "connector_intent_detected")
        || outcome_request.outcome_kind == StudioOutcomeKind::Visualizer
}

fn output_intent_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> &'static str {
    if matches!(
        outcome_request.request_frame.as_ref(),
        Some(StudioNormalizedRequestFrame::MessageCompose(_))
            | Some(StudioNormalizedRequestFrame::UserInput(_))
    ) {
        return "tool_execution";
    }

    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation
            if outcome_request.execution_strategy == StudioExecutionStrategy::SinglePass
                && !outcome_request.needs_clarification
                && tool_widget_family_hint(&outcome_request.routing_hints).is_none()
                && !outcome_request
                    .routing_hints
                    .iter()
                    .any(|hint| hint == "workspace_grounding_required")
                && !outcome_request
                    .routing_hints
                    .iter()
                    .any(|hint| hint == "currentness_override")
                && !outcome_request
                    .routing_hints
                    .iter()
                    .any(|hint| hint == "connector_intent_detected") =>
        {
            "direct_inline"
        }
        StudioOutcomeKind::ToolWidget => "tool_execution",
        StudioOutcomeKind::Visualizer => "inline_visual",
        StudioOutcomeKind::Artifact => "artifact",
        StudioOutcomeKind::Conversation => "tool_execution",
    }
}

fn effective_tool_surface_for_outcome_request(
    outcome_request: &StudioOutcomeRequest,
) -> RoutingEffectiveToolSurface {
    let mut primary_tools = Vec::<String>::new();
    let mut broad_fallback_tools = Vec::<String>::new();
    if let Some(connector_id) =
        routing_hint_value(&outcome_request.routing_hints, "selected_connector_id:")
    {
        primary_tools.push(format!("connector:{connector_id}"));
    }
    if let Some(route_label) = routing_hint_value(
        &outcome_request.routing_hints,
        "selected_provider_route_label:",
    ) {
        primary_tools.push(format!("provider_route:{route_label}"));
    }
    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            if let Some(surface_hint) = request_frame_surface_hint(outcome_request) {
                match surface_hint {
                    "message_compose" => primary_tools.push("message_compose_v1".to_string()),
                    "user_input" => primary_tools.push("ask_user_input_v0".to_string()),
                    _ => {}
                }
            } else if routing_hint_flag(&outcome_request.routing_hints, "currentness_override") {
                primary_tools.push("web_search".to_string());
                primary_tools.push("web_fetch".to_string());
            } else if routing_hint_flag(
                &outcome_request.routing_hints,
                "workspace_grounding_required",
            ) {
                primary_tools.push("view".to_string());
                primary_tools.push("bash_tool".to_string());
            }
        }
        StudioOutcomeKind::ToolWidget => {
            match tool_widget_family_hint(&outcome_request.routing_hints) {
                Some("weather") => {
                    primary_tools.push("weather_fetch".to_string());
                    broad_fallback_tools.push("web_search".to_string());
                }
                Some("sports") => {
                    primary_tools.push("fetch_sports_data".to_string());
                    broad_fallback_tools.push("web_search".to_string());
                }
                Some("places") => {
                    primary_tools.push("places_search".to_string());
                    primary_tools.push("places_map_display_v0".to_string());
                    broad_fallback_tools.push("web_search".to_string());
                }
                Some("recipe") => primary_tools.push("recipe_display_v0".to_string()),
                Some("user_input") => primary_tools.push("ask_user_input_v0".to_string()),
                Some(other) => primary_tools.push(format!("tool_widget:{other}")),
                None => primary_tools.push("tool_widget".to_string()),
            }
        }
        StudioOutcomeKind::Visualizer => {
            primary_tools.push("visualize:show_widget".to_string());
        }
        StudioOutcomeKind::Artifact => {
            let renderer = outcome_request
                .artifact
                .as_ref()
                .map(|artifact| renderer_kind_id(artifact.renderer))
                .unwrap_or("bundle_manifest");
            primary_tools.push(format!("studio_renderer:{renderer}"));
        }
    }

    RoutingEffectiveToolSurface {
        projected_tools: primary_tools.clone(),
        primary_tools,
        broad_fallback_tools,
        diagnostic_tools: outcome_request
            .routing_hints
            .iter()
            .map(|hint| format!("route_hint:{hint}"))
            .collect(),
    }
}

fn studio_route_hint_reason_fragments(outcome_request: &StudioOutcomeRequest) -> Vec<String> {
    let mut fragments = Vec::<String>::new();
    for hint in &outcome_request.routing_hints {
        match hint.as_str() {
            "currentness_override" => fragments.push(
                "Currentness pressure makes a shared answer lane safer than precommitting to a persistent artifact."
                    .to_string(),
            ),
            "no_persistent_artifact_requested" => {
                fragments.push("The prompt does not ask for a persistent artifact.".to_string())
            }
            "inline_visual_requested" => fragments.push(
                "The prompt asks for an inline visual rather than a saved file.".to_string(),
            ),
            "narrow_surface_preferred" => fragments.push(
                "A narrow first-party surface beats a broad fallback here.".to_string(),
            ),
            "connector_preferred" => fragments.push(
                "A matching connector route is available and outranks a broad built-in fallback."
                    .to_string(),
            ),
            "connector_missing" => fragments.push(
                "The prompt points at a connector-backed surface that this runtime does not expose yet."
                    .to_string(),
            ),
            "connector_auth_required" => fragments.push(
                "A matching connector exists, but Studio still needs authentication before it can use it."
                    .to_string(),
            ),
            "connector_identity_auto_selected" => fragments.push(
                "Studio found one connected route and skipped a redundant identity clarification."
                    .to_string(),
            ),
            "connector_tiebreaker:narrow_connector" => fragments.push(
                "A dedicated connector beat a broader platform route for the same task class."
                    .to_string(),
            ),
            "connector_tiebreaker:explicit_provider_mention" => fragments.push(
                "The prompt explicitly named a provider, so Studio kept that connector route in front."
                    .to_string(),
            ),
            "shared_answer_surface" => fragments.push(
                "Studio can preserve route truth without stealing the main runtime reply."
                    .to_string(),
            ),
            _ if hint.starts_with("tool_widget:") => {
                let widget = hint.trim_start_matches("tool_widget:");
                fragments.push(format!(
                    "The request maps cleanly to the {widget} tool-widget family."
                ));
            }
            _ => {}
        }
    }
    fragments
}

fn tool_widget_family_hint(routing_hints: &[String]) -> Option<&str> {
    routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

fn widget_binding_value(
    active_widget_state: Option<&StudioRetainedWidgetState>,
    key: &str,
) -> Option<String> {
    active_widget_state.and_then(|state| {
        state
            .bindings
            .iter()
            .find(|binding| binding.key == key)
            .map(|binding| binding.value.clone())
    })
}

fn runtime_locality_scope_for_context(context: &StudioIntentContext) -> Option<String> {
    context
        .requests_runtime_locality()
        .then(runtime_locality_scope_hint)
        .flatten()
}

fn is_self_referential_places_anchor(anchor: &str) -> bool {
    matches!(
        anchor.trim().to_ascii_lowercase().as_str(),
        "me" | "my area"
            | "current area"
            | "current location"
            | "here"
            | "around here"
            | "where i am"
    )
}

fn derive_request_frame(
    context: &StudioIntentContext,
    routing_hints: &[String],
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioNormalizedRequestFrame> {
    if matches!(tool_widget_family_hint(routing_hints), Some("weather"))
        || context.tool_widget_family() == Some("weather")
    {
        let inferred_locations = context.extract_weather_scopes();
        let retained_location = widget_binding_value(active_widget_state, "weather.location");
        let assumed_location = runtime_locality_scope_for_context(context).or(retained_location);
        let missing_slots = if inferred_locations.is_empty() && assumed_location.is_none() {
            vec!["location".to_string()]
        } else {
            Vec::new()
        };
        let clarification_required_slots =
            if routing_hint_flag(routing_hints, "location_required_for_weather_advice")
                || (routing_hint_flag(routing_hints, "tool_widget:weather")
                    && !missing_slots.is_empty())
            {
                missing_slots.clone()
            } else {
                Vec::new()
            };
        return Some(StudioNormalizedRequestFrame::Weather(
            StudioWeatherRequestFrame {
                inferred_locations,
                assumed_location,
                temporal_scope: context
                    .weather_temporal_scope()
                    .map(str::to_string)
                    .or_else(|| {
                        widget_binding_value(active_widget_state, "weather.temporal_scope")
                    }),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("sports"))
        || context.tool_widget_family() == Some("sports")
    {
        let league = context
            .sports_league()
            .map(str::to_string)
            .or_else(|| widget_binding_value(active_widget_state, "sports.league"));
        let team_or_target = context
            .sports_team_target()
            .or_else(|| widget_binding_value(active_widget_state, "sports.target"));
        let mut missing_slots = Vec::new();
        if league.is_none() {
            missing_slots.push("league".to_string());
        }
        if team_or_target.is_none() {
            missing_slots.push("target".to_string());
        }
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:sports")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Sports(
            StudioSportsRequestFrame {
                league,
                team_or_target,
                data_scope: context
                    .sports_data_scope()
                    .map(str::to_string)
                    .or_else(|| widget_binding_value(active_widget_state, "sports.data_scope")),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("places"))
        || context.tool_widget_family() == Some("places")
    {
        let runtime_locality_scope = runtime_locality_scope_for_context(context);
        let search_anchor = context
            .places_anchor_phrase()
            .filter(|anchor| !is_self_referential_places_anchor(anchor))
            .or_else(|| runtime_locality_scope.clone());
        let category = context
            .places_category_label()
            .map(str::to_string)
            .or_else(|| widget_binding_value(active_widget_state, "places.category"));
        let location_scope = if search_anchor.is_some() {
            search_anchor.clone()
        } else {
            runtime_locality_scope
                .or_else(|| widget_binding_value(active_widget_state, "places.location_scope"))
        };
        let mut missing_slots = Vec::new();
        if category.is_none() {
            missing_slots.push("category".to_string());
        }
        if location_scope.is_none() {
            missing_slots.push("location".to_string());
        }
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:places")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Places(
            StudioPlacesRequestFrame {
                search_anchor,
                category,
                location_scope,
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("recipe"))
        || context.tool_widget_family() == Some("recipe")
    {
        let dish = context
            .recipe_dish()
            .or_else(|| widget_binding_value(active_widget_state, "recipe.dish"));
        let missing_slots = if dish.is_none() {
            vec!["dish".to_string()]
        } else {
            Vec::new()
        };
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:recipe")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Recipe(
            StudioRecipeRequestFrame {
                dish,
                servings: context
                    .recipe_servings()
                    .or_else(|| widget_binding_value(active_widget_state, "recipe.servings")),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("user_input"))
        || routing_hint_flag(routing_hints, "prioritization_request")
        || routing_hint_flag(routing_hints, "prioritization_guidance_request")
        || context.requests_prioritization()
    {
        let explicit_options_present = context.explicit_prioritization_options();
        let missing_slots = if explicit_options_present {
            Vec::new()
        } else {
            vec!["options".to_string()]
        };
        let clarification_required_slots =
            if (routing_hint_flag(routing_hints, "tool_widget:user_input")
                || context.requests_prioritization())
                && !missing_slots.is_empty()
            {
                missing_slots.clone()
            } else {
                Vec::new()
            };
        return Some(StudioNormalizedRequestFrame::UserInput(
            StudioUserInputRequestFrame {
                interaction_kind: Some(
                    widget_binding_value(active_widget_state, "user_input.interaction_kind")
                        .unwrap_or_else(|| {
                            if routing_hint_flag(routing_hints, "prioritization_request")
                                || routing_hint_flag(
                                    routing_hints,
                                    "prioritization_guidance_request",
                                )
                            {
                                "prioritization".to_string()
                            } else {
                                "selection".to_string()
                            }
                        }),
                ),
                explicit_options_present,
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    let message_channel = context
        .message_channel()
        .map(str::to_string)
        .or_else(|| widget_binding_value(active_widget_state, "message.channel"));
    let message_purpose = context
        .message_purpose()
        .map(str::to_string)
        .or_else(|| widget_binding_value(active_widget_state, "message.purpose"));
    let message_recipient_context = context
        .message_recipient_context()
        .or_else(|| widget_binding_value(active_widget_state, "message.recipient_context"));
    if routing_hint_flag(routing_hints, "message_compose_surface")
        || context.prefers_message_compose_surface()
        || message_channel.is_some()
    {
        let mut missing_slots = Vec::new();
        if message_channel.is_none() {
            missing_slots.push("channel".to_string());
        }
        if message_purpose.is_none() {
            missing_slots.push("purpose".to_string());
        }
        if message_recipient_context.is_none()
            && matches!(
                message_purpose.as_deref(),
                Some("draft" | "reply" | "compose")
            )
        {
            missing_slots.push("recipient_context".to_string());
        }
        return Some(StudioNormalizedRequestFrame::MessageCompose(
            StudioMessageComposeRequestFrame {
                channel: message_channel,
                recipient_context: message_recipient_context,
                purpose: message_purpose,
                clarification_required_slots: missing_slots.clone(),
                missing_slots,
            },
        ));
    }

    None
}

fn request_frame_kind(frame: &StudioNormalizedRequestFrame) -> &'static str {
    match frame {
        StudioNormalizedRequestFrame::Weather(_) => "weather",
        StudioNormalizedRequestFrame::Sports(_) => "sports",
        StudioNormalizedRequestFrame::Places(_) => "places",
        StudioNormalizedRequestFrame::Recipe(_) => "recipe",
        StudioNormalizedRequestFrame::MessageCompose(_) => "message",
        StudioNormalizedRequestFrame::UserInput(_) => "user_input",
    }
}

fn merge_retained_widget_state(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioRetainedWidgetState> {
    let mut state = active_widget_state
        .cloned()
        .unwrap_or(StudioRetainedWidgetState {
            widget_family: None,
            bindings: Vec::new(),
            last_updated_at: None,
        });
    let Some(frame) = request_frame else {
        return if state.bindings.is_empty() && state.widget_family.is_none() {
            None
        } else {
            Some(state)
        };
    };

    state.widget_family = Some(request_frame_kind(frame).to_string());
    let mut upsert = |key: &str, value: Option<String>, source: &str| {
        let Some(value) = value else {
            return;
        };
        if value.trim().is_empty() {
            return;
        }
        if let Some(existing) = state.bindings.iter_mut().find(|binding| binding.key == key) {
            existing.value = value;
            existing.source = source.to_string();
        } else {
            state.bindings.push(StudioWidgetStateBinding {
                key: key.to_string(),
                value,
                source: source.to_string(),
            });
        }
    };

    match frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            upsert(
                "weather.location",
                frame
                    .inferred_locations
                    .first()
                    .cloned()
                    .or_else(|| frame.assumed_location.clone()),
                "request_frame",
            );
            upsert(
                "weather.temporal_scope",
                frame.temporal_scope.clone(),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Sports(frame) => {
            upsert("sports.league", frame.league.clone(), "request_frame");
            upsert(
                "sports.target",
                frame.team_or_target.clone(),
                "request_frame",
            );
            upsert(
                "sports.data_scope",
                frame.data_scope.clone(),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Places(frame) => {
            upsert("places.category", frame.category.clone(), "request_frame");
            upsert(
                "places.location_scope",
                frame
                    .location_scope
                    .clone()
                    .or_else(|| frame.search_anchor.clone()),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Recipe(frame) => {
            upsert("recipe.dish", frame.dish.clone(), "request_frame");
            upsert("recipe.servings", frame.servings.clone(), "request_frame");
        }
        StudioNormalizedRequestFrame::MessageCompose(frame) => {
            upsert("message.channel", frame.channel.clone(), "request_frame");
            upsert(
                "message.recipient_context",
                frame.recipient_context.clone(),
                "request_frame",
            );
            upsert("message.purpose", frame.purpose.clone(), "request_frame");
        }
        StudioNormalizedRequestFrame::UserInput(frame) => {
            upsert(
                "user_input.interaction_kind",
                frame.interaction_kind.clone(),
                "request_frame",
            );
        }
    }

    Some(state)
}

fn derive_clarification_policy(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    needs_clarification: bool,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioClarificationPolicy> {
    let Some(frame) = request_frame else {
        return needs_clarification.then(|| StudioClarificationPolicy {
            mode: StudioClarificationMode::BlockUntilClarified,
            assumed_bindings: Vec::new(),
            blocking_slots: Vec::new(),
            rationale:
                "The lane is blocked on unresolved clarification before execution can continue."
                    .to_string(),
        });
    };
    let blocking_slots = studio_request_frame_clarification_slots(frame).to_vec();
    let rationale = studio_specialized_domain_kind(Some(frame))
        .map(studio_specialized_domain_policy)
        .map(|policy| policy.clarification_rationale.to_string())
        .unwrap_or_else(|| {
            "The selected lane clarifies only when required slots remain unresolved.".to_string()
        });
    let assumed_bindings: Vec<String> = retained_widget_state
        .map(|state| {
            state
                .bindings
                .iter()
                .map(|binding| binding.key.clone())
                .collect()
        })
        .unwrap_or_default();
    Some(StudioClarificationPolicy {
        mode: if blocking_slots.is_empty() && !assumed_bindings.is_empty() {
            StudioClarificationMode::AssumeFromRetainedState
        } else if needs_clarification || !blocking_slots.is_empty() {
            StudioClarificationMode::BlockUntilClarified
        } else {
            StudioClarificationMode::ClarifyOnMissingSlots
        },
        assumed_bindings,
        blocking_slots,
        rationale,
    })
}

fn derive_fallback_policy(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    needs_clarification: bool,
) -> Option<StudioFallbackPolicy> {
    let primary_lane = lane_frame?.primary_lane;
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    Some(StudioFallbackPolicy {
        mode: if needs_clarification {
            StudioFallbackMode::BlockUntilClarified
        } else if let Some(policy) = specialized_policy {
            policy.fallback_mode
        } else {
            StudioFallbackMode::AllowRankedFallbacks
        },
        primary_lane,
        fallback_lanes: lane_frame
            .map(|frame| frame.secondary_lanes.clone())
            .unwrap_or_default(),
        trigger_signals: routing_hints
            .iter()
            .filter(|hint| {
                matches!(
                    hint.as_str(),
                    "currentness_override"
                        | "connector_missing"
                        | "connector_auth_required"
                        | "connector_preferred"
                        | "narrow_surface_preferred"
                        | "retained_widget_state_applied"
                        | "retained_widget_follow_up"
                )
            })
            .cloned()
            .collect(),
        rationale: if let Some(policy) = specialized_policy {
            policy.fallback_rationale.to_string()
        } else {
            "General and communication lanes may escalate through ranked fallbacks when the primary path is unavailable.".to_string()
        },
    })
}

fn derive_presentation_policy(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioPresentationPolicy> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let primary_surface = if let Some(policy) = specialized_policy {
        policy.presentation_surface
    } else {
        match outcome_kind {
            StudioOutcomeKind::Artifact => "artifact_surface",
            StudioOutcomeKind::Visualizer => "inline_visualizer",
            _ => match request_frame {
                None => match outcome_kind {
                    StudioOutcomeKind::ToolWidget => "tool_widget_surface",
                    StudioOutcomeKind::Conversation => "reply_surface",
                    StudioOutcomeKind::Artifact => "artifact_surface",
                    StudioOutcomeKind::Visualizer => "inline_visualizer",
                },
                Some(_) => "tool_widget_surface",
            },
        }
    };
    Some(StudioPresentationPolicy {
        primary_surface: primary_surface.to_string(),
        widget_family: retained_widget_state
            .and_then(|state| state.widget_family.clone())
            .or_else(|| lane_frame.and_then(|frame| frame.tool_widget_family.clone()))
            .or_else(|| specialized_policy.and_then(|policy| policy.widget_family.map(str::to_string))),
        renderer: if let Some(policy) = specialized_policy {
            policy.renderer
        } else {
            match outcome_kind {
                StudioOutcomeKind::Artifact => None,
                StudioOutcomeKind::Visualizer => Some(StudioRendererKind::Mermaid),
                _ => Some(StudioRendererKind::HtmlIframe),
            }
        },
        tab_priority: if let Some(policy) = specialized_policy {
            policy
                .tab_priority
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            match outcome_kind {
                StudioOutcomeKind::Artifact => vec![
                    "render".to_string(),
                    "source".to_string(),
                    "evidence".to_string(),
                ],
                _ => vec!["render".to_string(), "evidence".to_string()],
            }
        },
        rationale: specialized_policy
            .map(|policy| policy.presentation_rationale.to_string())
            .unwrap_or_else(|| {
                "Studio prefers a route-shaped parity surface so the desktop shell shows the active lane instead of collapsing to a generic summary."
                    .to_string()
            }),
    })
}

fn derive_transformation_policy(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
) -> Option<StudioTransformationPolicy> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let (output_shape, ordered_steps, rationale) = match outcome_kind {
        StudioOutcomeKind::Artifact => (
            "persistent_artifact",
            vec![
                "plan_artifact".to_string(),
                "materialize_files".to_string(),
                "verify_surface".to_string(),
            ],
            "Artifact turns transform the request into a persistent deliverable with file-backed verification.".to_string(),
        ),
        StudioOutcomeKind::Visualizer => (
            "inline_visual",
            vec!["draft_visual".to_string(), "project_inline_surface".to_string()],
            "Visualizer turns transform the request into an inline visual projection.".to_string(),
        ),
        _ => {
            if let Some(policy) = specialized_policy {
                (
                    policy.output_shape,
                    policy
                        .ordered_steps
                        .iter()
                        .map(|entry| (*entry).to_string())
                        .collect(),
                    policy.transformation_rationale.to_string(),
                )
            } else {
                (
                    "direct_or_tool_backed_reply",
                    vec!["route".to_string(), "answer".to_string()],
                    "General turns either answer directly or land through the selected route-backed reply surface.".to_string(),
                )
            }
        }
    };
    Some(StudioTransformationPolicy {
        output_shape: output_shape.to_string(),
        ordered_steps,
        rationale,
    })
}

fn derive_risk_profile(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> Option<StudioRiskProfile> {
    let Some(frame) = lane_frame else {
        return None;
    };
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let (sensitivity, mut reasons) = if let Some(policy) = specialized_policy {
        (
            policy.sensitivity,
            policy
                .base_risk_reasons
                .iter()
                .map(|reason| (*reason).to_string())
                .collect(),
        )
    } else {
        match frame.primary_lane {
            StudioLaneFamily::Communication | StudioLaneFamily::Integrations => (
                StudioRiskSensitivity::Medium,
                vec!["connector-backed communication can affect external systems".to_string()],
            ),
            StudioLaneFamily::Coding | StudioLaneFamily::Artifact => (
                StudioRiskSensitivity::Medium,
                vec![
                    "persistent outputs or workspace-backed work need explicit verification"
                        .to_string(),
                ],
            ),
            _ => (StudioRiskSensitivity::Low, Vec::new()),
        }
    };
    if matches!(request_frame, Some(StudioNormalizedRequestFrame::Places(_))) {
        reasons.push(
            "ranked place recommendations should stay grounded in the requested location scope"
                .to_string(),
        );
    }
    if routing_hints
        .iter()
        .any(|hint| hint == "connector_auth_required")
    {
        reasons
            .push("execution remains blocked until connector authentication completes".to_string());
    }
    Some(StudioRiskProfile {
        sensitivity,
        reasons,
        approval_required: false,
        user_visible_guardrails: if let Some(policy) = specialized_policy {
            policy
                .user_visible_guardrails
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            match sensitivity {
                StudioRiskSensitivity::Low => {
                    vec!["Show the selected lane and source before answering.".to_string()]
                }
                StudioRiskSensitivity::Medium | StudioRiskSensitivity::High => vec![
                    "Show the selected lane, provider, and verification gate before completion."
                        .to_string(),
                ],
            }
        },
    })
}

fn derive_verification_contract(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
) -> Option<StudioVerificationContract> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let strategy = if outcome_kind == StudioOutcomeKind::Artifact {
        "artifact_contract"
    } else if let Some(policy) = specialized_policy {
        policy.verification_strategy
    } else {
        match outcome_kind {
            StudioOutcomeKind::Visualizer => "inline_visual_contract",
            _ => "route_contract",
        }
    };
    Some(StudioVerificationContract {
        strategy: strategy.to_string(),
        required_checks: if outcome_kind == StudioOutcomeKind::Artifact {
            vec![
                "artifact_contract_recorded".to_string(),
                "artifact_surface_rendered".to_string(),
            ]
        } else if let Some(policy) = specialized_policy {
            policy
                .verification_required_checks
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            {
                if matches!(
                    lane_frame.map(|frame| frame.primary_lane),
                    Some(StudioLaneFamily::Research)
                ) {
                    vec![
                        "selected_source_recorded".to_string(),
                        "reply_surface_rendered".to_string(),
                    ]
                } else {
                    vec!["route_contract_recorded".to_string()]
                }
            }
        },
        completion_gate: if needs_clarification {
            "blocked_on_clarification".to_string()
        } else {
            "surface_and_route_verified".to_string()
        },
    })
}

fn derive_source_ranking(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    source_selection: Option<&StudioSourceSelection>,
) -> Vec<StudioSourceRankingEntry> {
    let Some(selection) = source_selection else {
        return Vec::new();
    };
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let mut ordered_sources = vec![selection.selected_source];
    for source in &selection.candidate_sources {
        if !ordered_sources.contains(source) {
            ordered_sources.push(*source);
        }
    }
    ordered_sources
        .into_iter()
        .enumerate()
        .map(|(index, source)| StudioSourceRankingEntry {
            source,
            rank: index as u32 + 1,
            rationale: if source == selection.selected_source {
                specialized_policy
                    .map(|policy| policy.selected_source_rationale.to_string())
                    .unwrap_or_else(|| "Selected as the active source for this turn.".to_string())
            } else {
                specialized_policy
                    .map(|policy| policy.fallback_source_rationale.to_string())
                    .unwrap_or_else(|| {
                        "Retained as an ordered fallback or supporting source.".to_string()
                    })
            },
        })
        .collect()
}

fn primary_lane_family(
    context: &StudioIntentContext,
    outcome_kind: StudioOutcomeKind,
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> StudioLaneFamily {
    if matches!(
        request_frame,
        Some(StudioNormalizedRequestFrame::MessageCompose(_))
    ) {
        return StudioLaneFamily::Communication;
    }
    if routing_hint_flag(routing_hints, "connector_intent_detected") {
        return StudioLaneFamily::Integrations;
    }
    if routing_hint_flag(routing_hints, "workspace_grounding_required")
        || artifact.is_some_and(|request| {
            matches!(
                request.artifact_class,
                StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
            )
        })
    {
        return StudioLaneFamily::Coding;
    }
    if outcome_kind == StudioOutcomeKind::Artifact {
        return StudioLaneFamily::Artifact;
    }
    if outcome_kind == StudioOutcomeKind::Visualizer {
        return StudioLaneFamily::Visualizer;
    }
    if outcome_kind == StudioOutcomeKind::ToolWidget {
        return match request_frame {
            Some(StudioNormalizedRequestFrame::Weather(_))
            | Some(StudioNormalizedRequestFrame::Sports(_))
            | Some(StudioNormalizedRequestFrame::Places(_))
            | Some(StudioNormalizedRequestFrame::Recipe(_)) => StudioLaneFamily::Research,
            Some(StudioNormalizedRequestFrame::UserInput(_)) => StudioLaneFamily::UserInput,
            _ => StudioLaneFamily::ToolWidget,
        };
    }
    if routing_hint_flag(routing_hints, "currentness_override") || context.currentness_pressure() {
        return StudioLaneFamily::Research;
    }
    StudioLaneFamily::Conversation
}

fn secondary_lane_families(
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> Vec<StudioLaneFamily> {
    let mut lanes = Vec::new();
    let mut push_unique = |lane: StudioLaneFamily| {
        if lane != primary_lane && !lanes.contains(&lane) {
            lanes.push(lane);
        }
    };

    match primary_lane {
        StudioLaneFamily::Research => {
            if tool_widget_family_hint(routing_hints).is_some() {
                push_unique(StudioLaneFamily::ToolWidget);
            }
            push_unique(StudioLaneFamily::Conversation);
        }
        StudioLaneFamily::Integrations => {
            push_unique(StudioLaneFamily::Conversation);
            if matches!(
                request_frame,
                Some(StudioNormalizedRequestFrame::MessageCompose(_))
            ) {
                push_unique(StudioLaneFamily::Communication);
            }
        }
        StudioLaneFamily::Communication => {
            if routing_hint_flag(routing_hints, "connector_intent_detected") {
                push_unique(StudioLaneFamily::Integrations);
            }
        }
        StudioLaneFamily::UserInput => {
            push_unique(StudioLaneFamily::ToolWidget);
            push_unique(StudioLaneFamily::Conversation);
        }
        StudioLaneFamily::Coding => {
            if artifact.is_some() {
                push_unique(StudioLaneFamily::Artifact);
            }
        }
        StudioLaneFamily::Artifact => {
            if artifact.is_some_and(|request| {
                matches!(
                    request.artifact_class,
                    StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
                )
            }) {
                push_unique(StudioLaneFamily::Coding);
            }
            match request_frame {
                Some(
                    StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_),
                ) => {
                    push_unique(StudioLaneFamily::Research);
                    push_unique(StudioLaneFamily::ToolWidget);
                }
                Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
                    push_unique(StudioLaneFamily::Communication);
                }
                Some(StudioNormalizedRequestFrame::UserInput(_)) => {
                    push_unique(StudioLaneFamily::UserInput);
                    push_unique(StudioLaneFamily::ToolWidget);
                }
                None => {}
            }
        }
        _ => {}
    }

    lanes
}

fn primary_goal(
    intent: &str,
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    _routing_hints: &[String],
    request_frame: Option<&StudioNormalizedRequestFrame>,
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> String {
    match request_frame {
        Some(StudioNormalizedRequestFrame::Weather(_)) => {
            "Resolve the weather scope and return current conditions for the requested location.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Sports(_)) => {
            "Resolve the sports target and return the requested current sports context.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Places(_)) => {
            "Resolve the place category and anchor location before searching the map surface.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Recipe(_)) => {
            "Turn the recipe request into a concise, kitchen-usable deliverable.".to_string()
        }
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
            "Compose a message that fits the requested channel, audience, and purpose.".to_string()
        }
        Some(StudioNormalizedRequestFrame::UserInput(_)) => {
            "Collect structured user input before continuing with the requested comparison or prioritization.".to_string()
        }
        None => match primary_lane {
            StudioLaneFamily::Research => {
                "Gather fresh evidence before answering in the shared reply lane.".to_string()
            }
            StudioLaneFamily::Coding => {
                "Ground the answer or change in the current workspace before responding."
                    .to_string()
            }
            StudioLaneFamily::Artifact => match artifact {
                Some(request) if matches!(request.artifact_class, StudioArtifactClass::WorkspaceProject) => {
                    "Create the requested workspace-backed artifact and verify the live build."
                        .to_string()
                }
                _ => "Create the requested persistent artifact and verify its contract."
                    .to_string(),
            },
            StudioLaneFamily::Visualizer => {
                "Return an inline visual without opening a persistent artifact lane.".to_string()
            }
            StudioLaneFamily::Integrations => {
                "Use the selected connector-backed route instead of a generic fallback.".to_string()
            }
            _ if outcome_kind == StudioOutcomeKind::Conversation => {
                format!("Answer the request directly: {}.", summarize_prompt_fragment(intent))
            }
            _ => "Advance the selected Studio route while preserving route truth.".to_string(),
        },
    }
}

fn summarize_prompt_fragment(intent: &str) -> String {
    let trimmed = intent.trim();
    let mut summary = trimmed.chars().take(80).collect::<String>();
    if trimmed.chars().count() > 80 {
        summary.push('…');
    }
    summary
}

fn derive_source_selection(
    context: &StudioIntentContext,
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    active_artifact_id: Option<&str>,
) -> StudioSourceSelection {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let mut candidate_sources = Vec::new();
    let mut push_unique = |source: StudioSourceFamily| {
        if !candidate_sources.contains(&source) {
            candidate_sources.push(source);
        }
    };

    if active_artifact_id.is_some() {
        push_unique(StudioSourceFamily::ArtifactContext);
    }
    if context.references_previous_conversation() {
        push_unique(StudioSourceFamily::ConversationRetrieval);
    }
    if context.references_memory_context() {
        push_unique(StudioSourceFamily::Memory);
    }
    push_unique(StudioSourceFamily::ConversationContext);

    let selected_source = if active_artifact_id.is_some() {
        StudioSourceFamily::ArtifactContext
    } else if routing_hint_flag(routing_hints, "connector_intent_detected") {
        push_unique(StudioSourceFamily::Connector);
        StudioSourceFamily::Connector
    } else if routing_hint_flag(routing_hints, "workspace_grounding_required") {
        push_unique(StudioSourceFamily::Workspace);
        StudioSourceFamily::Workspace
    } else if routing_hint_flag(routing_hints, "currentness_override")
        || primary_lane == StudioLaneFamily::Research
        || matches!(
            request_frame,
            Some(
                StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_)
            )
        )
    {
        if matches!(
            request_frame,
            Some(
                StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_)
                    | StudioNormalizedRequestFrame::UserInput(_)
            )
        ) {
            push_unique(StudioSourceFamily::SpecializedTool);
            push_unique(StudioSourceFamily::WebSearch);
            StudioSourceFamily::SpecializedTool
        } else {
            push_unique(StudioSourceFamily::WebSearch);
            StudioSourceFamily::WebSearch
        }
    } else if matches!(
        request_frame,
        Some(StudioNormalizedRequestFrame::MessageCompose(_))
    ) {
        if routing_hint_flag(routing_hints, "connector_intent_detected") {
            push_unique(StudioSourceFamily::Connector);
            StudioSourceFamily::Connector
        } else {
            StudioSourceFamily::DirectAnswer
        }
    } else if context.references_memory_context() {
        StudioSourceFamily::Memory
    } else if context.references_previous_conversation() {
        StudioSourceFamily::ConversationRetrieval
    } else {
        StudioSourceFamily::DirectAnswer
    };

    push_unique(selected_source);

    let explicit_user_source = active_artifact_id.is_some()
        || routing_hint_flag(routing_hints, "connector_intent_detected")
        || routing_hint_flag(routing_hints, "workspace_grounding_required")
        || routing_hint_flag(routing_hints, "currentness_override")
        || tool_widget_family_hint(routing_hints).is_some()
        || context.references_previous_conversation()
        || context.references_memory_context();

    let fallback_reason = if routing_hint_flag(routing_hints, "connector_missing") {
        Some("connector route is preferred but unavailable in this runtime".to_string())
    } else if routing_hint_flag(routing_hints, "connector_auth_required") {
        Some("connector route is preferred but still needs authentication".to_string())
    } else if request_frame
        .is_some_and(|frame| !studio_request_frame_missing_slots(frame).is_empty())
    {
        Some(
            specialized_policy
                .map(|policy| policy.missing_slot_fallback_reason.to_string())
                .unwrap_or_else(|| {
                    "required lane slots are still missing, so execution is blocked on clarification"
                        .to_string()
                }),
        )
    } else {
        None
    };

    StudioSourceSelection {
        candidate_sources,
        selected_source,
        explicit_user_source,
        fallback_reason,
    }
}

fn derive_lane_transitions(
    primary_lane: StudioLaneFamily,
    secondary_lanes: &[StudioLaneFamily],
    request_frame: Option<&StudioNormalizedRequestFrame>,
    needs_clarification: bool,
    clarification_questions: &[String],
    routing_hints: &[String],
) -> Vec<StudioLaneTransition> {
    let mut transitions = vec![StudioLaneTransition {
        transition_kind: StudioLaneTransitionKind::Planned,
        from_lane: None,
        to_lane: primary_lane,
        reason: planned_transition_reason(primary_lane, request_frame, routing_hints),
        evidence: planned_transition_evidence(primary_lane, request_frame, routing_hints),
    }];

    for secondary_lane in secondary_lanes {
        transitions.push(StudioLaneTransition {
            transition_kind: StudioLaneTransitionKind::Planned,
            from_lane: Some(primary_lane),
            to_lane: *secondary_lane,
            reason: secondary_transition_reason(primary_lane, *secondary_lane, request_frame),
            evidence: secondary_transition_evidence(primary_lane, *secondary_lane, routing_hints),
        });
    }

    if needs_clarification && primary_lane != StudioLaneFamily::Conversation {
        transitions.push(StudioLaneTransition {
            transition_kind: StudioLaneTransitionKind::Reactive,
            from_lane: Some(primary_lane),
            to_lane: StudioLaneFamily::Conversation,
            reason: "Clarification is required before Studio can continue in the selected lane."
                .to_string(),
            evidence: clarification_questions.to_vec(),
        });
    }

    transitions
}

fn planned_transition_reason(
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> String {
    match request_frame {
        Some(StudioNormalizedRequestFrame::Weather(_)) => {
            "The prompt maps to a weather-specific lane with location-bound tool semantics."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::Sports(_)) => {
            "The prompt maps to a sports-specific lane with team and league semantics.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Places(_)) => {
            "The prompt maps to a places lane with category and anchor-location semantics."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::Recipe(_)) => {
            "The prompt maps to a recipe lane that benefits from a specialized response shape."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
            "The prompt is best treated as a communication/composition task.".to_string()
        }
        Some(StudioNormalizedRequestFrame::UserInput(_)) => {
            "The prompt benefits from a structured user-input lane before execution.".to_string()
        }
        None => {
            if routing_hint_flag(routing_hints, "connector_intent_detected") {
                "A connector-capable route outranks a broad fallback here.".to_string()
            } else if routing_hint_flag(routing_hints, "workspace_grounding_required") {
                "The request must be grounded in the current workspace.".to_string()
            } else {
                format!("Studio selected the {:?} lane for this turn.", primary_lane)
                    .to_ascii_lowercase()
            }
        }
    }
}

fn planned_transition_evidence(
    _primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> Vec<String> {
    let mut evidence = routing_hints.to_vec();
    if let Some(frame) = request_frame {
        evidence.push(match frame {
            StudioNormalizedRequestFrame::Weather(_) => "request_frame:weather".to_string(),
            StudioNormalizedRequestFrame::Sports(_) => "request_frame:sports".to_string(),
            StudioNormalizedRequestFrame::Places(_) => "request_frame:places".to_string(),
            StudioNormalizedRequestFrame::Recipe(_) => "request_frame:recipe".to_string(),
            StudioNormalizedRequestFrame::MessageCompose(_) => {
                "request_frame:message_compose".to_string()
            }
            StudioNormalizedRequestFrame::UserInput(_) => "request_frame:user_input".to_string(),
        });
    }
    evidence
}

fn secondary_transition_reason(
    primary_lane: StudioLaneFamily,
    secondary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> String {
    match (primary_lane, secondary_lane, request_frame) {
        (
            StudioLaneFamily::Communication,
            StudioLaneFamily::Integrations,
            Some(StudioNormalizedRequestFrame::MessageCompose(_)),
        ) => {
            "The message lane will lean on a connected provider when one is available.".to_string()
        }
        (StudioLaneFamily::Research, StudioLaneFamily::ToolWidget, _) => {
            "The research lane can land through a specialized tool-widget surface.".to_string()
        }
        (StudioLaneFamily::UserInput, StudioLaneFamily::ToolWidget, _) => {
            "The structured input lane projects through the user-input widget.".to_string()
        }
        (StudioLaneFamily::Artifact, StudioLaneFamily::Coding, _) => {
            "The artifact lane depends on workspace-grounded coding support.".to_string()
        }
        _ => format!(
            "Studio retained the {:?} lane as a secondary assist for this turn.",
            secondary_lane
        )
        .to_ascii_lowercase(),
    }
}

fn secondary_transition_evidence(
    primary_lane: StudioLaneFamily,
    secondary_lane: StudioLaneFamily,
    routing_hints: &[String],
) -> Vec<String> {
    let mut evidence = routing_hints.to_vec();
    evidence.push(
        format!("secondary_lane:{:?}->{:?}", primary_lane, secondary_lane).to_ascii_lowercase(),
    );
    evidence
}

fn derive_orchestration_state(
    intent: &str,
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    execution_strategy: StudioExecutionStrategy,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
    needs_clarification: bool,
    clarification_questions: &[String],
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> Option<StudioOrchestrationState> {
    let should_surface = needs_clarification
        || outcome_kind == StudioOutcomeKind::Artifact
        || !matches!(execution_strategy, StudioExecutionStrategy::SinglePass)
        || matches!(
            primary_lane,
            StudioLaneFamily::Research
                | StudioLaneFamily::Coding
                | StudioLaneFamily::Integrations
                | StudioLaneFamily::Communication
                | StudioLaneFamily::UserInput
        );
    if !should_surface {
        return None;
    }

    let objective_status = if needs_clarification {
        StudioWorkStatus::Blocked
    } else {
        StudioWorkStatus::InProgress
    };
    let objective = StudioObjectiveState {
        objective_id: "studio_objective".to_string(),
        title: summarize_prompt_fragment(intent),
        status: objective_status,
        success_criteria: success_criteria_for_lane(primary_lane, outcome_kind),
    };
    let tasks = orchestration_tasks(
        primary_lane,
        outcome_kind,
        needs_clarification,
        request_frame,
    );
    let checkpoints = vec![
        StudioCheckpointState {
            checkpoint_id: "route_contract".to_string(),
            label: "Route contract recorded".to_string(),
            status: StudioWorkStatus::Complete,
            summary: "Studio captured a typed route, source, and lane contract.".to_string(),
        },
        StudioCheckpointState {
            checkpoint_id: "lane_readiness".to_string(),
            label: "Lane readiness".to_string(),
            status: if needs_clarification {
                StudioWorkStatus::Blocked
            } else {
                StudioWorkStatus::Pending
            },
            summary: if needs_clarification {
                clarification_questions
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Studio is waiting for clarification.".to_string())
            } else {
                "Studio can continue into lane execution.".to_string()
            },
        },
    ];
    let completion_invariant = Some(StudioCompletionInvariant {
        summary: completion_invariant_summary(primary_lane, outcome_kind),
        satisfied: false,
        outstanding_requirements: outstanding_requirements(
            primary_lane,
            outcome_kind,
            needs_clarification,
            request_frame,
            execution_mode_decision,
        ),
    });

    Some(StudioOrchestrationState {
        objective: Some(objective),
        tasks,
        checkpoints,
        completion_invariant,
    })
}

fn success_criteria_for_lane(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
) -> Vec<String> {
    match primary_lane {
        StudioLaneFamily::Research => vec![
            "Resolve the required scope for the research lane.".to_string(),
            "Return a grounded answer rather than a speculative reply.".to_string(),
        ],
        StudioLaneFamily::Coding => vec![
            "Inspect or mutate the workspace in the correct boundary.".to_string(),
            "Surface verification truth alongside the result.".to_string(),
        ],
        StudioLaneFamily::Integrations => vec![
            "Use the selected connector-backed route when available.".to_string(),
            "Avoid broad fallbacks unless the preferred connector path is blocked.".to_string(),
        ],
        StudioLaneFamily::Artifact if outcome_kind == StudioOutcomeKind::Artifact => vec![
            "Materialize the requested artifact.".to_string(),
            "Verify the artifact contract before promoting it.".to_string(),
        ],
        _ => vec!["Finish the selected Studio lane truthfully.".to_string()],
    }
}

fn orchestration_tasks(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> Vec<StudioTaskUnitState> {
    let blocked_or_pending = if needs_clarification {
        StudioWorkStatus::Blocked
    } else {
        StudioWorkStatus::Pending
    };
    let execution_lane = match primary_lane {
        StudioLaneFamily::Communication if outcome_kind != StudioOutcomeKind::Artifact => {
            StudioLaneFamily::Communication
        }
        lane => lane,
    };

    match primary_lane {
        StudioLaneFamily::Artifact => vec![
            StudioTaskUnitState {
                task_id: "artifact_brief".to_string(),
                label: "Lock the deliverable contract".to_string(),
                status: if needs_clarification {
                    StudioWorkStatus::Blocked
                } else {
                    StudioWorkStatus::InProgress
                },
                lane_family: StudioLaneFamily::Artifact,
                depends_on: Vec::new(),
                summary: Some(
                    "Studio should keep the artifact request coherent before generation."
                        .to_string(),
                ),
            },
            StudioTaskUnitState {
                task_id: "artifact_materialize".to_string(),
                label: "Materialize the artifact".to_string(),
                status: blocked_or_pending,
                lane_family: StudioLaneFamily::Artifact,
                depends_on: vec!["artifact_brief".to_string()],
                summary: None,
            },
            StudioTaskUnitState {
                task_id: "artifact_verify".to_string(),
                label: "Verify the artifact contract".to_string(),
                status: blocked_or_pending,
                lane_family: StudioLaneFamily::Artifact,
                depends_on: vec!["artifact_materialize".to_string()],
                summary: None,
            },
        ],
        _ => {
            let resolve_label = if let Some(frame) = request_frame {
                match frame {
                    StudioNormalizedRequestFrame::Weather(_) => {
                        "Resolve the weather scope".to_string()
                    }
                    StudioNormalizedRequestFrame::Sports(_) => {
                        "Resolve the sports target".to_string()
                    }
                    StudioNormalizedRequestFrame::Places(_) => {
                        "Resolve the places request frame".to_string()
                    }
                    StudioNormalizedRequestFrame::Recipe(_) => {
                        "Resolve the recipe request frame".to_string()
                    }
                    StudioNormalizedRequestFrame::MessageCompose(_) => {
                        "Resolve the message composition frame".to_string()
                    }
                    StudioNormalizedRequestFrame::UserInput(_) => {
                        "Resolve the required options".to_string()
                    }
                }
            } else {
                "Resolve the lane inputs".to_string()
            };
            vec![
                StudioTaskUnitState {
                    task_id: "lane_inputs".to_string(),
                    label: resolve_label,
                    status: if needs_clarification {
                        StudioWorkStatus::Blocked
                    } else {
                        StudioWorkStatus::InProgress
                    },
                    lane_family: execution_lane,
                    depends_on: Vec::new(),
                    summary: Some(
                        "Studio should make the lane contract explicit before execution."
                            .to_string(),
                    ),
                },
                StudioTaskUnitState {
                    task_id: "lane_execute".to_string(),
                    label: "Execute the selected lane".to_string(),
                    status: blocked_or_pending,
                    lane_family: execution_lane,
                    depends_on: vec!["lane_inputs".to_string()],
                    summary: None,
                },
                StudioTaskUnitState {
                    task_id: "lane_finish".to_string(),
                    label: "Finish the response truthfully".to_string(),
                    status: blocked_or_pending,
                    lane_family: StudioLaneFamily::Conversation,
                    depends_on: vec!["lane_execute".to_string()],
                    summary: None,
                },
            ]
        }
    }
}

fn completion_invariant_summary(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
) -> String {
    match primary_lane {
        StudioLaneFamily::Artifact if outcome_kind == StudioOutcomeKind::Artifact => {
            "The requested artifact exists and its verification contract is surfaced truthfully."
                .to_string()
        }
        StudioLaneFamily::Research => {
            "The answer is grounded in the selected fresh-information lane.".to_string()
        }
        StudioLaneFamily::Coding => {
            "The result is grounded in the current workspace and paired with verification truth."
                .to_string()
        }
        StudioLaneFamily::Integrations => {
            "Studio uses the selected connector-backed route or makes the blocking condition explicit."
                .to_string()
        }
        _ => "Studio finishes the selected lane without hiding blockers or substitutions.".to_string(),
    }
}

fn outstanding_requirements(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
) -> Vec<String> {
    let mut requirements = Vec::new();
    if needs_clarification {
        requirements.push("resolve_clarification".to_string());
    }
    if let Some(frame) = request_frame {
        match frame {
            StudioNormalizedRequestFrame::Weather(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Sports(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Places(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Recipe(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::MessageCompose(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::UserInput(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
        }
    }
    if outcome_kind == StudioOutcomeKind::Artifact {
        requirements.push("materialize_artifact".to_string());
        requirements.push("verify_artifact".to_string());
    } else {
        requirements.push("execute_lane".to_string());
        requirements.push("deliver_response".to_string());
    }
    if execution_mode_decision.is_some_and(|decision| decision.work_graph_required) {
        requirements.push("complete_work_graph".to_string());
    }
    if primary_lane == StudioLaneFamily::Coding {
        requirements.push("workspace_verification".to_string());
    }
    requirements
}
