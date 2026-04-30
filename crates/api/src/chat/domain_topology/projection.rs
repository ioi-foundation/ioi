#[derive(Debug, Clone, PartialEq)]
pub struct TopologyProjection {
    pub lane_request: Option<ChatLaneRequest>,
    pub normalized_request: Option<ChatNormalizedRequest>,
    pub source_decision: Option<ChatSourceDecision>,
    pub retained_lane_state: Option<ChatRetainedLaneState>,
    pub lane_transitions: Vec<ChatLaneTransition>,
    pub orchestration_state: Option<ChatOrchestrationState>,
}
pub type ChatTopologyProjection = TopologyProjection;

pub fn derive_chat_topology_projection(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_widget_state: Option<&ChatRetainedWidgetState>,
    outcome_kind: ChatOutcomeKind,
    execution_strategy: ChatExecutionStrategy,
    execution_mode_decision: Option<&ChatExecutionModeDecision>,
    confidence: f32,
    needs_clarification: bool,
    clarification_questions: &[String],
    decision_evidence: &[String],
    artifact: Option<&ChatOutcomeArtifactRequest>,
) -> TopologyProjection {
    let context = ChatIntentContext::new(intent);
    let active_tool_widget_family =
        active_tool_widget_family(&context, decision_evidence, active_widget_state);
    let normalized_request =
        derive_normalized_request(&context, decision_evidence, active_widget_state);
    let primary_lane = primary_lane_family(
        &context,
        outcome_kind,
        decision_evidence,
        artifact,
        normalized_request.as_ref(),
    );
    let lane_request = Some(ChatLaneRequest {
        primary_lane,
        secondary_lanes: secondary_lane_families(
            primary_lane,
            normalized_request.as_ref(),
            decision_evidence,
            artifact,
        ),
        primary_goal: primary_goal(
            intent,
            primary_lane,
            outcome_kind,
            decision_evidence,
            normalized_request.as_ref(),
            artifact,
        ),
        tool_widget_family: active_tool_widget_family.map(str::to_string),
        currentness_pressure: decision_evidence_item_flag(
            decision_evidence,
            "currentness_override",
        ) || matches!(
            active_tool_widget_family,
            Some("weather" | "sports" | "places")
        ) || context.currentness_pressure(),
        workspace_grounding_required: decision_evidence_item_flag(
            decision_evidence,
            "workspace_grounding_required",
        ) || artifact.is_some_and(|request| {
            matches!(
                request.artifact_class,
                ChatArtifactClass::WorkspaceProject | ChatArtifactClass::CodePatch
            )
        }),
        persistent_deliverable_requested: outcome_kind == ChatOutcomeKind::Artifact,
        active_artifact_follow_up: active_artifact_id.is_some(),
        lane_confidence: if confidence.is_finite() {
            confidence.clamp(0.0, 1.0)
        } else {
            0.0
        },
    });
    let source_decision = Some(derive_source_decision(
        &context,
        primary_lane,
        normalized_request.as_ref(),
        decision_evidence,
        active_artifact_id,
    ));
    let retained_lane_state = Some(ChatRetainedLaneState {
        active_lane: if needs_clarification && primary_lane != ChatLaneFamily::Conversation {
            primary_lane
        } else {
            primary_lane
        },
        active_tool_widget_family: tool_widget_family_hint(decision_evidence).map(str::to_string),
        active_artifact_id: active_artifact_id.map(str::to_string),
        unresolved_clarification_question: clarification_questions.first().cloned(),
        selected_provider_family: decision_evidence_item_value(
            decision_evidence,
            "selected_provider_family:",
        ),
        selected_provider_route_label: decision_evidence_item_value(
            decision_evidence,
            "selected_provider_route_label:",
        ),
        selected_source_family: source_decision
            .as_ref()
            .map(|selection| selection.selected_source),
    });
    let lane_transitions = derive_lane_transitions(
        primary_lane,
        lane_request
            .as_ref()
            .map(|frame| frame.secondary_lanes.as_slice())
            .unwrap_or(&[]),
        normalized_request.as_ref(),
        needs_clarification,
        clarification_questions,
        decision_evidence,
    );
    let orchestration_state = derive_orchestration_state(
        intent,
        primary_lane,
        outcome_kind,
        execution_strategy,
        execution_mode_decision,
        needs_clarification,
        clarification_questions,
        normalized_request.as_ref(),
    );

    ChatTopologyProjection {
        lane_request,
        normalized_request,
        source_decision,
        retained_lane_state,
        lane_transitions,
        orchestration_state,
    }
}

pub fn derive_chat_domain_policy_bundle(
    lane_request: Option<&ChatLaneRequest>,
    normalized_request: Option<&ChatNormalizedRequest>,
    source_decision: Option<&ChatSourceDecision>,
    outcome_kind: ChatOutcomeKind,
    decision_evidence: &[String],
    needs_clarification: bool,
    active_widget_state: Option<&ChatRetainedWidgetState>,
) -> ChatDomainPolicyBundle {
    let retained_widget_state =
        merge_retained_widget_state(normalized_request, active_widget_state);
    let clarification_policy = derive_clarification_policy(
        normalized_request,
        needs_clarification,
        retained_widget_state.as_ref(),
    );
    let fallback_policy = derive_fallback_policy(
        lane_request,
        normalized_request,
        decision_evidence,
        needs_clarification,
    );
    let presentation_policy = derive_presentation_policy(
        lane_request,
        normalized_request,
        outcome_kind,
        retained_widget_state.as_ref(),
    );
    let transformation_policy = derive_transformation_policy(normalized_request, outcome_kind);
    let risk_profile = derive_risk_profile(lane_request, normalized_request, decision_evidence);
    let verification_contract = derive_verification_contract(
        lane_request,
        normalized_request,
        outcome_kind,
        needs_clarification,
    );
    let source_ranking = derive_source_ranking(normalized_request, source_decision);

    ChatDomainPolicyBundle {
        clarification_policy,
        fallback_policy,
        presentation_policy,
        transformation_policy,
        risk_profile,
        verification_contract,
        policy_contract: Some(ChatPolicyContractSummary {
            bindings: vec![
                "lane_request".to_string(),
                "normalized_request".to_string(),
                "source_decision".to_string(),
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

fn decision_evidence_item_flag(decision_evidence: &[String], needle: &str) -> bool {
    decision_evidence.iter().any(|hint| hint == needle)
}

fn decision_evidence_item_value(decision_evidence: &[String], prefix: &str) -> Option<String> {
    decision_evidence
        .iter()
        .find_map(|hint| hint.strip_prefix(prefix))
        .map(str::to_string)
}

pub fn artifact_connector_grounding_for_outcome_request(
    outcome_request: &ChatOutcomeRequest,
) -> Option<ArtifactConnectorGrounding> {
    if outcome_request.outcome_kind != ChatOutcomeKind::Artifact
        || !decision_evidence_item_flag(
            &outcome_request.decision_evidence,
            "connector_intent_detected",
        )
    {
        return None;
    }

    Some(ArtifactConnectorGrounding {
        connector_id: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "selected_connector_id:",
        ),
        provider_family: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "selected_provider_family:",
        ),
        target_label: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "connector_target_label:",
        ),
    })
}

pub fn route_family_for_outcome_request(outcome_request: &ChatOutcomeRequest) -> &'static str {
    if let Some(lane_request) = outcome_request.lane_request.as_ref() {
        return match lane_request.primary_lane {
            ChatLaneFamily::Research => "research",
            ChatLaneFamily::Coding => "coding",
            ChatLaneFamily::Integrations => "integrations",
            ChatLaneFamily::Communication => "communication",
            ChatLaneFamily::UserInput => "user_input",
            ChatLaneFamily::Visualizer => "artifacts",
            ChatLaneFamily::Artifact => "artifacts",
            ChatLaneFamily::ToolWidget => "tool_widget",
            ChatLaneFamily::Conversation | ChatLaneFamily::General => "general",
        };
    }

    let widget_family = tool_widget_family_hint(&outcome_request.decision_evidence);
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "connector_intent_detected",
    ) {
        return "integrations";
    }
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "workspace_grounding_required",
    ) {
        return "coding";
    }
    if let Some(artifact) = outcome_request.artifact.as_ref() {
        if matches!(
            artifact.artifact_class,
            ChatArtifactClass::WorkspaceProject | ChatArtifactClass::CodePatch
        ) || artifact.renderer == ChatRendererKind::WorkspaceSurface
            || artifact.execution_substrate == ChatExecutionSubstrate::WorkspaceRuntime
        {
            return "coding";
        }
    }
    if outcome_request.outcome_kind == ChatOutcomeKind::Artifact
        || outcome_request.outcome_kind == ChatOutcomeKind::Visualizer
    {
        return "artifacts";
    }
    if outcome_request
        .decision_evidence
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

pub fn selected_route_label_for_outcome_request(outcome_request: &ChatOutcomeRequest) -> String {
    match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => {
            if matches!(
                outcome_request.normalized_request.as_ref(),
                Some(ChatNormalizedRequest::MessageCompose(_))
            ) {
                format!(
                    "communication_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if let Some(route_label) = decision_evidence_item_value(
                &outcome_request.decision_evidence,
                "selected_provider_route_label:",
            ) {
                format!(
                    "conversation_{}_{}",
                    route_label,
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if decision_evidence_item_flag(
                &outcome_request.decision_evidence,
                "workspace_grounding_required",
            ) {
                format!(
                    "conversation_workspace_grounded_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if decision_evidence_item_flag(
                &outcome_request.decision_evidence,
                "currentness_override",
            ) {
                format!(
                    "conversation_currentness_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if decision_evidence_item_flag(
                &outcome_request.decision_evidence,
                "connector_intent_detected",
            ) {
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
        ChatOutcomeKind::ToolWidget => {
            match tool_widget_family_hint(&outcome_request.decision_evidence) {
                Some(widget_family) => format!("tool_widget_{widget_family}"),
                None => "tool_widget".to_string(),
            }
        }
        ChatOutcomeKind::Visualizer => "inline_visualizer".to_string(),
        ChatOutcomeKind::Artifact => {
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
    outcome_request: &ChatOutcomeRequest,
) -> RoutingRouteDecision {
    let currentness_override = outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "currentness_override");
    let tool_widget_family = tool_widget_family_hint(&outcome_request.decision_evidence);
    let file_output_intent = file_output_intent_for_outcome_request(outcome_request);
    let skill_prep_required = skill_prep_required_for_outcome_request(outcome_request);
    let mut direct_answer_blockers = Vec::<String>::new();
    if outcome_request.needs_clarification {
        direct_answer_blockers.push("clarification_required".to_string());
    }
    if currentness_override {
        direct_answer_blockers.push("currentness_override".to_string());
    }
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "workspace_grounding_required",
    ) {
        direct_answer_blockers.push("workspace_grounding_required".to_string());
    }
    if tool_widget_family.is_some() {
        direct_answer_blockers.push("tool_widget_surface_selected".to_string());
    }
    if normalized_request_surface_hint(outcome_request).is_some() {
        direct_answer_blockers.push("structured_surface_selected".to_string());
    }
    if outcome_request.outcome_kind == ChatOutcomeKind::Visualizer {
        direct_answer_blockers.push("inline_visual_surface_selected".to_string());
    }
    if outcome_request.outcome_kind == ChatOutcomeKind::Artifact {
        direct_answer_blockers.push("persistent_artifact_requested".to_string());
    }
    if outcome_request.outcome_kind == ChatOutcomeKind::Conversation
        && outcome_request.execution_strategy != ChatExecutionStrategy::SinglePass
        && !outcome_request.needs_clarification
        && !currentness_override
    {
        direct_answer_blockers.push("planned_execution_selected".to_string());
    }
    if decision_evidence_item_flag(&outcome_request.decision_evidence, "connector_missing") {
        direct_answer_blockers.push("connector_unavailable".to_string());
    }
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "connector_auth_required",
    ) {
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
        connector_candidate_count: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "connector_candidate_count:",
        )
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0),
        selected_provider_family: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "selected_provider_family:",
        ),
        selected_provider_route_label: decision_evidence_item_value(
            &outcome_request.decision_evidence,
            "selected_provider_route_label:",
        ),
        connector_first_preference: decision_evidence_item_flag(
            &outcome_request.decision_evidence,
            "connector_intent_detected",
        ),
        narrow_tool_preference: narrow_tool_preference_for_outcome_request(outcome_request),
        file_output_intent,
        artifact_output_intent: outcome_request.outcome_kind == ChatOutcomeKind::Artifact,
        inline_visual_intent: outcome_request.outcome_kind == ChatOutcomeKind::Visualizer,
        skill_prep_required,
        output_intent: output_intent.to_string(),
        effective_tool_surface: effective_tool_surface_for_outcome_request(outcome_request),
    }
}

pub fn route_topology_for_outcome_request(outcome_request: &ChatOutcomeRequest) -> &'static str {
    match outcome_request.execution_strategy {
        ChatExecutionStrategy::SinglePass | ChatExecutionStrategy::DirectAuthor => "single_agent",
        ChatExecutionStrategy::AdaptiveWorkGraph => "planner_specialist_verifier",
        ChatExecutionStrategy::PlanExecute | ChatExecutionStrategy::MicroSwarm => {
            "planner_specialist"
        }
    }
}

pub fn verifier_state_for_outcome_event(
    outcome_request: &ChatOutcomeRequest,
    completed: bool,
) -> &'static str {
    if outcome_request.needs_clarification {
        return "blocked";
    }
    if completed {
        return "passed";
    }
    if decision_evidence_item_flag(&outcome_request.decision_evidence, "currentness_override") {
        return "active";
    }
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "workspace_grounding_required",
    ) {
        return "active";
    }
    if outcome_request.outcome_kind == ChatOutcomeKind::Artifact
        || outcome_request.execution_strategy != ChatExecutionStrategy::SinglePass
    {
        return "active";
    }
    "not_engaged"
}

pub fn inline_answer_status_message(outcome_request: &ChatOutcomeRequest) -> String {
    if outcome_request.needs_clarification {
        return "Chat needs clarification before preparing the right answer surface.".to_string();
    }

    let base = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => "Chat prepared a direct answer.",
        ChatOutcomeKind::ToolWidget => "Chat prepared an interactive tool surface.",
        ChatOutcomeKind::Visualizer => "Chat prepared a visual answer surface.",
        ChatOutcomeKind::Artifact => "Chat prepared an artifact workspace.",
    };

    let continuation = if outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "currentness_override")
    {
        " Current information needs stay attached."
    } else if let Some(widget_family) = outcome_request
        .decision_evidence
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
    {
        return format!("{base} Keeping the {widget_family} surface preference attached.");
    } else if outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "inline_visual_requested")
    {
        " Inline visual intent stays attached."
    } else {
        " No artifact renderer is needed."
    };

    format!("{base}{continuation}")
}

pub fn inline_answer_route_summary(outcome_request: &ChatOutcomeRequest) -> String {
    if outcome_request.needs_clarification {
        let question = outcome_request
            .clarification_questions
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "Chat needs clarification before it can choose the correct outcome surface."
                    .to_string()
            });
        return format!(
            "Chat paused before selecting the outcome surface because it needs clarification: {}",
            question
        );
    }

    let base = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => "Chat routed this request to conversation.",
        ChatOutcomeKind::ToolWidget => "Chat routed this request to a tool-widget surface.",
        ChatOutcomeKind::Visualizer => "Chat routed this request to a visualizer surface.",
        ChatOutcomeKind::Artifact => "Chat routed this request to artifact materialization.",
    };
    let reason_fragments = chat_route_hint_reason_fragments(outcome_request);
    if reason_fragments.is_empty() {
        format!(
            "{base} Chat kept the artifact lane closed and preserved route receipts for downstream execution."
        )
    } else {
        format!(
            "{base} {} Chat kept the artifact lane closed and preserved route receipts for downstream execution.",
            reason_fragments.join(" ")
        )
    }
}

pub fn build_chat_runtime_handoff_prompt_prefix(
    outcome_request: &ChatOutcomeRequest,
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
        "Honor this Chat route contract unless the user explicitly changes the task.".to_string(),
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
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
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
    if decision_evidence_item_flag(&outcome_request.decision_evidence, "currentness_override") {
        execution_rules.push(
            "Fresh external information is required here; use current retrieval before answering."
                .to_string(),
        );
    }
    if decision_evidence_item_flag(
        &outcome_request.decision_evidence,
        "connector_intent_detected",
    ) {
        execution_rules.push(
            "Prefer the selected connector/provider route over generic fallbacks.".to_string(),
        );
    }

    let workspace_line = workspace_root
        .map(|root| format!("workspace_root: {root}"))
        .unwrap_or_else(|| "workspace_root: unresolved".to_string());

    format!(
        "CHAT ARTIFACT ROUTE CONTRACT:\n\
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

pub fn inline_answer_route_notes(outcome_request: &ChatOutcomeRequest) -> Vec<String> {
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

pub fn inline_answer_verification_receipts(
    outcome_request: &ChatOutcomeRequest,
) -> Vec<SwarmVerificationReceipt> {
    let status = if outcome_request.needs_clarification {
        "blocked"
    } else {
        "ready"
    };
    let route_detail = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => "conversation surface",
        ChatOutcomeKind::ToolWidget => "tool-widget surface",
        ChatOutcomeKind::Visualizer => "visualizer surface",
        ChatOutcomeKind::Artifact => "artifact surface",
    };

    vec![
        SwarmVerificationReceipt {
            id: "route_verification".to_string(),
            kind: "route_verification".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "Chat blocked execution because clarification is still required.".to_string()
            } else {
                format!(
                    "Chat verified that this request belongs on the {}.",
                    route_detail
                )
            },
            details: if outcome_request.needs_clarification {
                outcome_request.clarification_questions.clone()
            } else {
                outcome_request.decision_evidence.clone()
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
                details.extend(outcome_request.decision_evidence.iter().cloned());
                details
            },
        },
    ]
}

pub fn inline_answer_operator_steps(
    outcome_request: &ChatOutcomeRequest,
) -> Vec<ArtifactOperatorStep> {
    vec![
        ArtifactOperatorStep {
            step_id: "verify_route".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "inline_answer_route".to_string(),
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
            engine: "inline_answer_route".to_string(),
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

pub fn inline_answer_swarm_plan(outcome_request: &ChatOutcomeRequest) -> SwarmPlan {
    let outcome_kind_id = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => "conversation",
        ChatOutcomeKind::ToolWidget => "tool_widget",
        ChatOutcomeKind::Visualizer => "visualizer",
        ChatOutcomeKind::Artifact => "artifact",
    };
    let execution_domain = format!("chat_{outcome_kind_id}");
    let adapter_label = format!(
        "{outcome_kind_id}_{}_v1",
        execution_strategy_id(outcome_request.execution_strategy)
    );
    let responder_title = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => "Conversation handoff",
        ChatOutcomeKind::ToolWidget => "Tool-widget handoff",
        ChatOutcomeKind::Visualizer => "Visualizer handoff",
        ChatOutcomeKind::Artifact => "Artifact handoff",
    };
    let responder_summary = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => {
            "Keep the request on the conversation surface and preserve the shared execution evidence."
        }
        ChatOutcomeKind::ToolWidget => {
            "Keep the request on the tool-widget surface and preserve the shared execution evidence."
        }
        ChatOutcomeKind::Visualizer => {
            "Keep the request on the visualizer surface and preserve the shared execution evidence."
        }
        ChatOutcomeKind::Artifact => {
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
                    "Chat reply remains truthful about the chosen surface.".to_string(),
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

pub fn apply_inline_answer_clarification_gate(
    swarm_plan: &mut SwarmPlan,
    outcome_request: &ChatOutcomeRequest,
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

pub fn inline_answer_worker_receipts(
    outcome_request: &ChatOutcomeRequest,
    provenance: &ChatRuntimeProvenance,
    swarm_plan: &SwarmPlan,
    now: &str,
) -> Vec<SwarmWorkerReceipt> {
    let handoff_summary = match outcome_request.outcome_kind {
        ChatOutcomeKind::Conversation => {
            "Conversation stayed primary and no artifact renderer was launched."
        }
        ChatOutcomeKind::ToolWidget => {
            "Tool-widget stayed primary and no artifact renderer was launched."
        }
        ChatOutcomeKind::Visualizer => {
            "Visualizer stayed primary and no artifact renderer was launched."
        }
        ChatOutcomeKind::Artifact => "Artifact stayed primary.",
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
                ChatOutcomeKind::Conversation => "conversation",
                ChatOutcomeKind::ToolWidget => "tool_widget",
                ChatOutcomeKind::Visualizer => "visualizer",
                ChatOutcomeKind::Artifact => "artifact",
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
            notes.extend(outcome_request.decision_evidence.iter().cloned());
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
            "Chat kept the shared execution evidence instead of surfacing a blocked artifact failure."
                .to_string(),
            outcome_request.decision_evidence.join(" · "),
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
    lifecycle_state: ChatArtifactLifecycleState,
) -> ChatArtifactVerificationStatus {
    match lifecycle_state {
        ChatArtifactLifecycleState::Draft
        | ChatArtifactLifecycleState::Planned
        | ChatArtifactLifecycleState::Materializing
        | ChatArtifactLifecycleState::Rendering
        | ChatArtifactLifecycleState::Implementing
        | ChatArtifactLifecycleState::Verifying => ChatArtifactVerificationStatus::Pending,
        ChatArtifactLifecycleState::Ready => ChatArtifactVerificationStatus::Ready,
        ChatArtifactLifecycleState::Blocked => ChatArtifactVerificationStatus::Blocked,
        ChatArtifactLifecycleState::Failed => ChatArtifactVerificationStatus::Failed,
        ChatArtifactLifecycleState::Partial => ChatArtifactVerificationStatus::Partial,
    }
}

pub fn verified_reply_evidence_for_manifest(
    verification: &ChatArtifactManifestVerification,
    manifest: &ChatArtifactManifest,
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

pub fn inline_answer_verified_reply_evidence(
    outcome_request: &ChatOutcomeRequest,
    provenance_label: &str,
) -> Vec<String> {
    vec![
        format!(
            "outcome:{}",
            match outcome_request.outcome_kind {
                ChatOutcomeKind::Conversation => "conversation",
                ChatOutcomeKind::ToolWidget => "tool_widget",
                ChatOutcomeKind::Visualizer => "visualizer",
                ChatOutcomeKind::Artifact => "artifact",
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
            .decision_evidence
            .iter()
            .map(|hint| format!("route_hint:{hint}")),
    )
    .collect()
}

pub fn inline_answer_route_title(intent: &str, outcome_request: &ChatOutcomeRequest) -> String {
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
        ChatOutcomeKind::Conversation => format!("Conversation route · {base}"),
        ChatOutcomeKind::ToolWidget => format!("Tool widget route · {base}"),
        ChatOutcomeKind::Visualizer => format!("Visualizer route · {base}"),
        ChatOutcomeKind::Artifact => base,
    }
}
