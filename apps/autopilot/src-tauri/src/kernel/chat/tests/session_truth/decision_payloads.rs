#[test]
fn decision_record_payload_maps_weather_widget_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-route".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.96,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let lane_request = payload_object
        .get("lane_request")
        .and_then(|value| value.as_object())
        .expect("lane frame");
    assert_eq!(
        lane_request
            .get("primaryLane")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let normalized_request = payload_object
        .get("normalized_request")
        .and_then(|value| value.as_object())
        .expect("request frame");
    assert_eq!(
        normalized_request
            .get("kind")
            .and_then(|value| value.as_str()),
        Some("weather")
    );
    assert!(normalized_request
        .get("inferredLocations")
        .and_then(|value| value.as_array())
        .is_some_and(|locations| locations
            .iter()
            .any(|value| value.as_str() == Some("boston"))));
    let source_decision = payload_object
        .get("source_decision")
        .and_then(|value| value.as_object())
        .expect("source decision");
    assert_eq!(
        source_decision
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("specialized_tool")
    );
    assert!(payload_object
        .get("orchestration_state")
        .and_then(|value| value.as_object())
        .is_some());
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools
            .iter()
            .any(|tool| tool.as_str() == Some("weather_fetch"))));
    assert!(effective_tool_surface
        .get("broad_fallback_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_search"))));
}

#[test]
fn decision_record_payload_maps_recipe_widget_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "recipe-route".to_string(),
        raw_prompt: "How do I make carbonara for 3 people?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:recipe".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let lane_request = payload_object
        .get("lane_request")
        .and_then(|value| value.as_object())
        .expect("lane frame");
    assert_eq!(
        lane_request
            .get("primaryLane")
            .and_then(|value| value.as_str()),
        Some("research")
    );
}

#[test]
fn decision_record_payload_preserves_connector_source_decision_and_lane_transition() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "wallet_mail".to_string(),
        name: "Mail".to_string(),
        provider: "wallet.network".to_string(),
        category: "communication".to_string(),
        description: "Wallet-backed mail connector.".to_string(),
        status: "connected".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let context =
        infer_connector_route_context_from_catalog("Summarize my unread emails", &connectors)
            .expect("mail request should synthesize connector context");
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-route-payload".to_string(),
        raw_prompt: "Summarize my unread emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["shared_answer_surface".to_string()],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::merge_connector_route_context(&mut outcome_request, context);

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
    );
    let source_decision = payload_object
        .get("source_decision")
        .and_then(|value| value.as_object())
        .expect("source decision");
    assert_eq!(
        source_decision
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("connector")
    );
    let retained_lane_state = payload_object
        .get("retained_lane_state")
        .and_then(|value| value.as_object())
        .expect("retained lane state");
    assert_eq!(
        retained_lane_state
            .get("selectedProviderFamily")
            .and_then(|value| value.as_str()),
        Some("mail.wallet_network")
    );
    assert!(payload_object
        .get("lane_transitions")
        .and_then(|value| value.as_array())
        .is_some_and(|transitions| transitions.iter().any(|transition| {
            transition.get("toLane").and_then(|value| value.as_str()) == Some("integrations")
        })));
}

#[test]
fn decision_record_payload_maps_sports_widget_to_specialized_tool_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "sports-route".to_string(),
        raw_prompt: "What's the story with the Lakers this season?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:sports".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.as_str() == Some("fetch_sports_data"))
        }));
}

#[test]
fn decision_record_payload_maps_places_widget_to_search_and_map_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-route".to_string(),
        raw_prompt: "What are some good coffee shops near downtown Portland?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    let projected_tools = effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .expect("projected tools");
    assert!(projected_tools
        .iter()
        .any(|tool| tool.as_str() == Some("places_search")));
    assert!(projected_tools
        .iter()
        .any(|tool| tool.as_str() == Some("places_map_display_v0")));
}

#[test]
fn decision_record_payload_maps_currentness_conversation_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-route".to_string(),
        raw_prompt: "Who is the current Secretary-General of the UN?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::AdaptiveWorkGraph,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "currentness_override".to_string(),
            "no_persistent_artifact_requested".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("conversation_currentness_adaptive_work_graph")
    );
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    assert_eq!(
        payload_object
            .get("verifier_state")
            .and_then(|value| value.as_str()),
        Some("active")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_search"))));
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_fetch"))));
}

#[test]
fn decision_record_payload_maps_workspace_grounded_conversation_to_coding_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-route".to_string(),
        raw_prompt: "What npm script launches the desktop app in this repo?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.93,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "workspace_grounding_required".to_string(),
            "coding_workspace_context".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("conversation_workspace_grounded_single_pass")
    );
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("coding")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    assert_eq!(
        route_decision
            .get("direct_answer_allowed")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(route_decision
        .get("direct_answer_blockers")
        .and_then(|value| value.as_array())
        .is_some_and(|blockers| blockers
            .iter()
            .any(|blocker| blocker.as_str() == Some("workspace_grounding_required"))));
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("view"))));
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("bash_tool"))));
}

#[test]
fn workspace_grounded_chat_primary_route_does_not_emit_runtime_handoff_prefix() {
    let mut task = empty_task("What npm script launches the desktop app in this repo?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-handoff".to_string(),
        raw_prompt: "What npm script launches the desktop app in this repo?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.93,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "workspace_grounding_required".to_string(),
            "coding_workspace_context".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    super::content_session::attach_inline_answer_chat_session(
        &mut task,
        "What npm script launches the desktop app in this repo?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "test".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_requires_chat_primary_execution(&task));
    assert!(runtime_handoff_prompt_prefix_for_task(&task).is_none());
}
