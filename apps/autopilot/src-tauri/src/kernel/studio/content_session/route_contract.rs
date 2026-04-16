use super::*;

pub(super) fn routing_hint_flag(outcome_request: &StudioOutcomeRequest, needle: &str) -> bool {
    outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == needle || hint.starts_with(&format!("{needle}:")))
}

pub(super) fn routing_hint_prefixed_value(
    outcome_request: &StudioOutcomeRequest,
    prefix: &str,
) -> Option<String> {
    outcome_request
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix(prefix))
        .map(str::to_string)
}

pub(super) fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn route_hint_reason_fragments(outcome_request: &StudioOutcomeRequest) -> Vec<String> {
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

fn tool_widget_family_hint(outcome_request: &StudioOutcomeRequest) -> Option<&str> {
    outcome_request
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

fn request_frame_surface_hint(outcome_request: &StudioOutcomeRequest) -> Option<&'static str> {
    match outcome_request.request_frame.as_ref() {
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => Some("message_compose"),
        Some(StudioNormalizedRequestFrame::UserInput(_)) => Some("user_input"),
        _ => None,
    }
}

fn route_family_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> &'static str {
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
    let widget_family = tool_widget_family_hint(outcome_request);
    if routing_hint_flag(outcome_request, "connector_intent_detected") {
        return "integrations";
    }
    if routing_hint_flag(outcome_request, "workspace_grounding_required") {
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
    tool_widget_family_hint(outcome_request).is_some()
        || request_frame_surface_hint(outcome_request).is_some()
        || routing_hint_flag(outcome_request, "narrow_surface_preferred")
        || routing_hint_flag(outcome_request, "workspace_grounding_required")
        || routing_hint_flag(outcome_request, "connector_intent_detected")
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
                && tool_widget_family_hint(outcome_request).is_none()
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
        routing_hint_prefixed_value(outcome_request, "selected_connector_id:")
    {
        primary_tools.push(format!("connector:{connector_id}"));
    }
    if let Some(route_label) =
        routing_hint_prefixed_value(outcome_request, "selected_provider_route_label:")
    {
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
            } else if routing_hint_flag(outcome_request, "currentness_override") {
                primary_tools.push("web_search".to_string());
                primary_tools.push("web_fetch".to_string());
            } else if routing_hint_flag(outcome_request, "workspace_grounding_required") {
                primary_tools.push("view".to_string());
                primary_tools.push("bash_tool".to_string());
            }
        }
        StudioOutcomeKind::ToolWidget => match tool_widget_family_hint(outcome_request) {
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
        },
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

pub(in crate::kernel::studio) fn route_decision_for_outcome_request(
    outcome_request: &StudioOutcomeRequest,
) -> RoutingRouteDecision {
    let currentness_override = outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "currentness_override");
    let tool_widget_family = tool_widget_family_hint(outcome_request);
    let file_output_intent = file_output_intent_for_outcome_request(outcome_request);
    let skill_prep_required = skill_prep_required_for_outcome_request(outcome_request);
    let mut direct_answer_blockers = Vec::<String>::new();
    if outcome_request.needs_clarification {
        direct_answer_blockers.push("clarification_required".to_string());
    }
    if currentness_override {
        direct_answer_blockers.push("currentness_override".to_string());
    }
    if routing_hint_flag(outcome_request, "workspace_grounding_required") {
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
    if routing_hint_flag(outcome_request, "connector_missing") {
        direct_answer_blockers.push("connector_unavailable".to_string());
    }
    if routing_hint_flag(outcome_request, "connector_auth_required") {
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
        connector_candidate_count: routing_hint_prefixed_value(
            outcome_request,
            "connector_candidate_count:",
        )
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0),
        selected_provider_family: routing_hint_prefixed_value(
            outcome_request,
            "selected_provider_family:",
        ),
        selected_provider_route_label: routing_hint_prefixed_value(
            outcome_request,
            "selected_provider_route_label:",
        ),
        connector_first_preference: routing_hint_flag(outcome_request, "connector_intent_detected"),
        narrow_tool_preference: narrow_tool_preference_for_outcome_request(outcome_request),
        file_output_intent,
        artifact_output_intent: outcome_request.outcome_kind == StudioOutcomeKind::Artifact,
        inline_visual_intent: outcome_request.outcome_kind == StudioOutcomeKind::Visualizer,
        skill_prep_required,
        output_intent: output_intent.to_string(),
        effective_tool_surface: effective_tool_surface_for_outcome_request(outcome_request),
    }
}

fn workspace_root_from_task(task: &AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.studio_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

pub(crate) fn runtime_handoff_prompt_prefix_for_task(task: &AgentTask) -> Option<String> {
    if super::task_state::task_requires_studio_primary_execution(task) {
        return None;
    }

    let outcome_request = task.studio_outcome.as_ref()?;
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let selected_route = selected_route_label(outcome_request);
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
    if routing_hint_flag(outcome_request, "workspace_grounding_required") {
        execution_rules.push(
            "Treat local workspace inspection as mandatory for this turn; inspect the repo before answering."
                .to_string(),
        );
        execution_rules.push(
            "Do not substitute browser or computer-use actions for repo inspection unless the workspace path is genuinely blocked."
                .to_string(),
        );
    }
    if routing_hint_flag(outcome_request, "currentness_override") {
        execution_rules.push(
            "Fresh external information is required here; use current retrieval before answering."
                .to_string(),
        );
    }
    if routing_hint_flag(outcome_request, "connector_intent_detected") {
        execution_rules.push(
            "Prefer the selected connector/provider route over generic fallbacks.".to_string(),
        );
    }

    let workspace_line = workspace_root_from_task(task)
        .map(|root| format!("workspace_root: {root}"))
        .unwrap_or_else(|| "workspace_root: unresolved".to_string());

    Some(format!(
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
    ))
}

fn topology_for_outcome_request(outcome_request: &StudioOutcomeRequest) -> &'static str {
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

fn selected_route_label(outcome_request: &StudioOutcomeRequest) -> String {
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
            } else if let Some(route_label) =
                routing_hint_prefixed_value(outcome_request, "selected_provider_route_label:")
            {
                format!(
                    "conversation_{}_{}",
                    route_label,
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(outcome_request, "workspace_grounding_required") {
                format!(
                    "conversation_workspace_grounded_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(outcome_request, "currentness_override") {
                format!(
                    "conversation_currentness_{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )
            } else if routing_hint_flag(outcome_request, "connector_intent_detected") {
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
        StudioOutcomeKind::ToolWidget => match tool_widget_family_hint(outcome_request) {
            Some(widget_family) => format!("tool_widget_{widget_family}"),
            None => "tool_widget".to_string(),
        },
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

fn verifier_state_for_outcome_event(
    outcome_request: &StudioOutcomeRequest,
    completed: bool,
) -> &'static str {
    if outcome_request.needs_clarification {
        return "blocked";
    }
    if completed {
        return "passed";
    }
    if routing_hint_flag(outcome_request, "currentness_override") {
        return "active";
    }
    if routing_hint_flag(outcome_request, "workspace_grounding_required") {
        return "active";
    }
    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact
        || outcome_request.execution_strategy != StudioExecutionStrategy::SinglePass
    {
        return "active";
    }
    "not_engaged"
}

fn build_route_contract_payload_with_widget_state(
    outcome_request: &StudioOutcomeRequest,
    completed: bool,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> serde_json::Value {
    let mut resolved_outcome_request = outcome_request.clone();
    super::refresh_outcome_request_topology(&mut resolved_outcome_request, retained_widget_state);
    let domain_policy_bundle = derive_studio_domain_policy_bundle(
        resolved_outcome_request.lane_frame.as_ref(),
        resolved_outcome_request.request_frame.as_ref(),
        resolved_outcome_request.source_selection.as_ref(),
        resolved_outcome_request.outcome_kind,
        &resolved_outcome_request.routing_hints,
        resolved_outcome_request.needs_clarification,
        retained_widget_state,
    );

    let route_decision = route_decision_for_outcome_request(&resolved_outcome_request);
    let verifier_state = verifier_state_for_outcome_event(&resolved_outcome_request, completed);
    json!({
        "selected_route": selected_route_label(&resolved_outcome_request),
        "route_family": route_decision.route_family,
        "topology": topology_for_outcome_request(&resolved_outcome_request),
        "planner_authority": "kernel",
        "verifier_state": verifier_state,
        "verifier_outcome": if completed { Some("pass") } else { None::<&str> },
        "route_decision": route_decision,
        "lane_frame": resolved_outcome_request.lane_frame,
        "request_frame": resolved_outcome_request.request_frame,
        "source_selection": resolved_outcome_request.source_selection,
        "retained_lane_state": resolved_outcome_request.retained_lane_state,
        "lane_transitions": resolved_outcome_request.lane_transitions,
        "orchestration_state": resolved_outcome_request.orchestration_state,
        "domain_policy_bundle": domain_policy_bundle,
    })
}

pub(in crate::kernel::studio) fn build_route_contract_payload(
    outcome_request: &StudioOutcomeRequest,
    completed: bool,
) -> serde_json::Value {
    build_route_contract_payload_with_widget_state(outcome_request, completed, None)
}

pub(in crate::kernel::studio) fn append_route_contract_event(
    task: &mut AgentTask,
    outcome_request: &StudioOutcomeRequest,
    title: impl Into<String>,
    summary: impl Into<String>,
    completed: bool,
) -> String {
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title_text = title.into();
    let summary_text = summary.into();
    let step_index = task
        .events
        .iter()
        .map(|event| event.step_index)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let payload = build_route_contract_payload_with_widget_state(
        outcome_request,
        completed,
        task.studio_session
            .as_ref()
            .and_then(|session| session.widget_state.as_ref()),
    );
    let input_refs = task
        .events
        .last()
        .map(|event| vec![event.event_id.clone()])
        .unwrap_or_default();
    let event = build_event(
        &thread_id,
        step_index,
        EventType::Receipt,
        title_text,
        payload.clone(),
        json!({
            "summary": summary_text,
            "route_decision": payload.get("route_decision").cloned().unwrap_or_else(|| json!({})),
            "selected_route": payload.get("selected_route").cloned().unwrap_or_else(|| json!("")),
            "route_family": payload.get("route_family").cloned().unwrap_or_else(|| json!("")),
            "topology": payload.get("topology").cloned().unwrap_or_else(|| json!("single_agent")),
            "planner_authority": payload.get("planner_authority").cloned().unwrap_or_else(|| json!("kernel")),
            "verifier_state": payload.get("verifier_state").cloned().unwrap_or_else(|| json!("not_engaged")),
            "verifier_outcome": payload.get("verifier_outcome").cloned().unwrap_or(serde_json::Value::Null),
            "lane_frame": payload.get("lane_frame").cloned().unwrap_or(serde_json::Value::Null),
            "request_frame": payload.get("request_frame").cloned().unwrap_or(serde_json::Value::Null),
            "source_selection": payload.get("source_selection").cloned().unwrap_or(serde_json::Value::Null),
            "retained_lane_state": payload.get("retained_lane_state").cloned().unwrap_or(serde_json::Value::Null),
            "lane_transitions": payload.get("lane_transitions").cloned().unwrap_or_else(|| json!([])),
            "orchestration_state": payload.get("orchestration_state").cloned().unwrap_or(serde_json::Value::Null),
        }),
        EventStatus::Success,
        Vec::<ArtifactRef>::new(),
        None,
        input_refs,
        None,
    );
    let event_id = event.event_id.clone();
    task.events.push(event);
    event_id
}

pub(in crate::kernel::studio) fn non_artifact_route_status_message(
    outcome_request: &StudioOutcomeRequest,
) -> String {
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

pub(in crate::kernel::studio) fn artifact_execution_envelope_for_contract(
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
    materialization: &StudioArtifactMaterializationContract,
) -> Option<ExecutionEnvelope> {
    let mut envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        materialization.swarm_plan.as_ref(),
        materialization.swarm_execution.as_ref(),
        &materialization.swarm_worker_receipts,
        &materialization.swarm_change_receipts,
        &materialization.swarm_merge_receipts,
        &materialization.swarm_verification_receipts,
    );
    annotate_execution_envelope(
        &mut envelope,
        execution_mode_decision,
        materialization
            .execution_envelope
            .as_ref()
            .and_then(|entry| entry.completion_invariant.clone()),
    );
    envelope
}

pub(super) fn non_artifact_route_summary(outcome_request: &StudioOutcomeRequest) -> String {
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
    let reason_fragments = route_hint_reason_fragments(outcome_request);
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
