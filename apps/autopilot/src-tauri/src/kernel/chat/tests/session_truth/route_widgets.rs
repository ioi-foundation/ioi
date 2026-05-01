#[test]
fn weather_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What is the weather in Boston today?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-request".to_string(),
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
        "What is the weather in Boston today?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn weather_scope_parser_extracts_multi_city_lists() {
    let scopes = super::prepare::extract_weather_scopes(
        "Compare the weather in three cities I'm considering moving to: Austin, Denver, and Portland",
    );

    assert_eq!(
        scopes,
        vec![
            "Austin".to_string(),
            "Denver".to_string(),
            "Portland".to_string()
        ]
    );
}

#[test]
fn weather_report_fallback_parser_condenses_wttr_report() {
    let summary = super::prepare::parse_weather_report_fallback(
        "Boston",
        "Weather report: boston\n\n                Mist\n   _ - _ - _ -  50 °F          \n    _ - _ - _   ↙ 2 mph        \n   _ - _ - _ -  1 mi           \n                0.0 in         \n",
    );

    assert_eq!(
        summary.as_deref(),
        Some("Boston: Mist 50 °F wind ↙ 2 mph visibility 1 mi precipitation 0.0 in."),
    );
}

#[test]
fn weather_tool_widget_follow_up_reuses_retained_location_scope() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-follow-up".to_string(),
        raw_prompt: "What's the weather in Boston this weekend?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_request: None,
        normalized_request: Some(ioi_types::app::chat::ChatNormalizedRequest::Weather(
            ioi_types::app::chat::ChatWeatherRequestFrame {
                inferred_locations: vec!["Boston".to_string()],
                assumed_location: None,
                temporal_scope: Some("tomorrow".to_string()),
                missing_slots: Vec::new(),
                clarification_required_slots: Vec::new(),
            },
        )),
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let scopes = super::prepare::weather_scopes_for_tool_widget(
        "How about tomorrow instead?",
        &outcome_request,
    );

    assert_eq!(scopes, vec!["Boston".to_string()]);
}

#[test]
fn sports_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What's the story with the Lakers this season?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "sports-request".to_string(),
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
        "What's the story with the Lakers this season?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn places_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What are some good coffee shops near downtown Portland?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-request".to_string(),
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
        "What are some good coffee shops near downtown Portland?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn conversation_single_pass_route_requires_chat_primary_execution() {
    let mut task = empty_task("What is the capital of Spain?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "conversation-request".to_string(),
        raw_prompt: "What is the capital of Spain?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["no_persistent_artifact_requested".to_string()],
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
        "What is the capital of Spain?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn workspace_grounded_single_pass_route_requires_chat_primary_execution() {
    let mut task = empty_task("What npm script launches the desktop app in this repo?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-single-pass".to_string(),
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
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn visualizer_route_requires_chat_primary_execution() {
    let mut task = empty_task("Show a simple mermaid diagram of the HTTP request lifecycle.");
    let outcome_request = ChatOutcomeRequest {
        request_id: "visualizer-request".to_string(),
        raw_prompt: "Show a simple mermaid diagram of the HTTP request lifecycle.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Visualizer,
        execution_strategy: ChatExecutionStrategy::DirectAuthor,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["no_persistent_artifact_requested".to_string()],
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
        "Show a simple mermaid diagram of the HTTP request lifecycle.",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn inline_answer_route_receipt_event_preserves_explicit_route_decision() {
    let mut task = empty_task("What is the capital of Spain?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "conversation-route".to_string(),
        raw_prompt: "What is the capital of Spain?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["no_persistent_artifact_requested".to_string()],
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
        "What is the capital of Spain?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    let route_event = task
        .events
        .iter()
        .find(|event| event.title == "Chat route decision")
        .expect("route decision event");
    let digest = route_event.digest.as_object().expect("route digest");
    assert_eq!(
        digest.get("route_family").and_then(|value| value.as_str()),
        Some("general")
    );
    let route_decision = digest
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision payload");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("direct_inline")
    );
    assert_eq!(
        route_decision
            .get("direct_answer_allowed")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}
