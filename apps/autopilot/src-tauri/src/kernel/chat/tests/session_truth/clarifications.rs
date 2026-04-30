#[test]
fn inline_answer_weather_route_builds_renderable_parity_surface_and_widget_state() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-widget".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.88,
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

    attach_inline_answer_chat_session(
        &mut task,
        "What is the weather in Boston today?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "local".to_string(),
            model: Some("fixture".to_string()),
            endpoint: None,
        },
        &outcome_request,
    );

    let session = task.chat_session.expect("chat session");
    assert_eq!(
        session.artifact_manifest.renderer,
        ChatRendererKind::HtmlIframe
    );
    assert_eq!(session.artifact_manifest.primary_tab, "render");
    assert!(session
        .artifact_manifest
        .files
        .iter()
        .any(|file| file.renderable && file.external_url.is_some()));
    assert_eq!(
        session
            .widget_state
            .as_ref()
            .and_then(|state| state.widget_family.as_deref()),
        Some("weather")
    );
}

#[test]
fn attach_inline_answer_session_preserves_retained_widget_state_during_topology_refresh() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let provenance = crate::models::ChatRuntimeProvenance {
        kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
        label: "local".to_string(),
        model: Some("fixture".to_string()),
        endpoint: None,
    };
    let initial_request = ChatOutcomeRequest {
        request_id: "weather-initial".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.9,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_request: None,
        normalized_request: Some(ioi_types::app::chat::ChatNormalizedRequest::Weather(
            ioi_types::app::chat::ChatWeatherRequestFrame {
                inferred_locations: vec!["Boston".to_string()],
                assumed_location: Some("Boston".to_string()),
                temporal_scope: Some("today".to_string()),
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
    attach_inline_answer_chat_session(
        &mut task,
        "What is the weather in Boston today?",
        provenance.clone(),
        &initial_request,
    );

    let active_artifact_id = task
        .chat_session
        .as_ref()
        .map(|session| session.artifact_manifest.artifact_id.clone());
    let follow_up_request = ChatOutcomeRequest {
        request_id: "weather-follow-up".to_string(),
        raw_prompt: "What about tomorrow?".to_string(),
        active_artifact_id,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.92,
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
    attach_inline_answer_chat_session(
        &mut task,
        "How about tomorrow instead?",
        provenance,
        &follow_up_request,
    );

    match task
        .chat_outcome
        .as_ref()
        .and_then(|request| request.normalized_request.as_ref())
        .expect("request frame after retained follow-up")
    {
        ioi_types::app::chat::ChatNormalizedRequest::Weather(frame) => {
            assert!(frame
                .assumed_location
                .as_deref()
                .is_some_and(|location| location.eq_ignore_ascii_case("Boston")));
            assert_eq!(frame.temporal_scope.as_deref(), Some("tomorrow"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    assert!(task
        .chat_outcome
        .as_ref()
        .expect("chat outcome")
        .decision_evidence
        .iter()
        .any(|hint| hint == "retained_widget_state_applied"));
    let follow_up_outcome = task.chat_outcome.as_ref().expect("chat outcome");
    assert_eq!(follow_up_outcome.outcome_kind, ChatOutcomeKind::ToolWidget);
    assert_eq!(
        follow_up_outcome
            .source_decision
            .as_ref()
            .expect("source decision")
            .selected_source,
        ioi_types::app::ChatSourceFamily::SpecializedTool
    );
}

#[test]
fn decision_record_payload_includes_domain_policy_bundle() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-policy".to_string(),
        raw_prompt: "Find coffee shops near downtown Portland".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.84,
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
    let object = payload.as_object().expect("payload object");
    let bundle = object
        .get("domain_policy_bundle")
        .and_then(|value| value.as_object())
        .expect("domain policy bundle");
    assert_eq!(
        bundle
            .get("presentationPolicy")
            .or_else(|| bundle.get("presentation_policy"))
            .and_then(|value| value
                .get("primarySurface")
                .or_else(|| value.get("primary_surface")))
            .and_then(|value| value.as_str()),
        Some("places_widget")
    );
    assert!(bundle
        .get("sourceRanking")
        .or_else(|| bundle.get("source_ranking"))
        .and_then(|value| value.as_array())
        .map(|entries| !entries.is_empty())
        .unwrap_or(false));
}

#[test]
fn weather_advice_clarification_surfaces_structured_scope_options() {
    with_runtime_locality_scope_hint_override(None, || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "weather-clarification".to_string(),
            raw_prompt: "Should I wear a jacket today?".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.9,
            needs_clarification: true,
            clarification_questions: vec![
                "What city should Chat check the weather for?".to_string()
            ],
            decision_evidence: vec![
                "tool_widget:weather".to_string(),
                "weather_advice_request".to_string(),
                "location_required_for_weather_advice".to_string(),
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

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("weather advice route should surface clarification UX");

        assert_eq!(
            request.question,
            "What city should Chat check the weather for?"
        );
        assert_eq!(request.options.len(), 2);
        assert_eq!(request.options[0].id, "share_city");
        assert!(request.options[0].recommended);
        assert_eq!(request.options[1].label, "General advice");
    });
}

#[test]
fn weather_advice_clarification_promotes_current_area_when_runtime_locality_exists() {
    with_runtime_locality_scope_hint_override(Some("Brooklyn, NY"), || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "weather-clarification-locality".to_string(),
            raw_prompt: "Should I wear a jacket today?".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.9,
            needs_clarification: true,
            clarification_questions: vec![
                "What city should Chat check the weather for?".to_string()
            ],
            decision_evidence: vec![
                "tool_widget:weather".to_string(),
                "weather_advice_request".to_string(),
                "location_required_for_weather_advice".to_string(),
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

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("weather advice route should surface clarification UX");

        assert_eq!(request.options.len(), 3);
        assert_eq!(request.options[0].id, "share_city");
        assert!(!request.options[0].recommended);
        assert_eq!(request.options[1].id, "use_current_area");
        assert!(request.options[1].recommended);
    });
}

#[test]
fn message_compose_clarification_uses_domain_specific_prompt_and_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "message-clarification".to_string(),
        raw_prompt: "Draft something to my landlord about the lease renewal.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.9,
        needs_clarification: true,
        clarification_questions: vec!["What channel should Chat use?".to_string()],
        decision_evidence: vec!["shared_answer_surface".to_string()],
        lane_request: None,
        normalized_request: Some(ioi_types::app::chat::ChatNormalizedRequest::MessageCompose(
            ioi_types::app::chat::ChatMessageComposeRequestFrame {
                channel: None,
                recipient_context: Some("landlord".to_string()),
                purpose: Some("draft".to_string()),
                missing_slots: vec!["channel".to_string()],
                clarification_required_slots: vec!["channel".to_string()],
            },
        )),
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("message route should surface clarification UX");

    assert_eq!(
        request.question,
        "Which channel should Chat draft this for: email, Slack, text, or chat?"
    );
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "draft_email");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "draft_slack");
    assert_eq!(request.options[2].id, "draft_text");
}

#[test]
fn places_clarification_uses_domain_specific_anchor_options() {
    with_runtime_locality_scope_hint_override(None, || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "places-clarification".to_string(),
            raw_prompt: "Find good coffee shops.".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.87,
            needs_clarification: true,
            clarification_questions: vec!["Where should Chat search?".to_string()],
            decision_evidence: vec![
                "tool_widget:places".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_request: None,
            normalized_request: Some(ioi_types::app::chat::ChatNormalizedRequest::Places(
                ioi_types::app::chat::ChatPlacesRequestFrame {
                    search_anchor: None,
                    category: Some("coffee shops".to_string()),
                    location_scope: None,
                    missing_slots: vec!["search_anchor".to_string()],
                    clarification_required_slots: vec!["search_anchor".to_string()],
                },
            )),
            source_decision: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("places route should surface clarification UX");

        assert_eq!(
            request.question,
            "Which neighborhood, city, or anchor location should Chat search around?"
        );
        assert_eq!(request.options.len(), 2);
        assert_eq!(request.options[0].id, "share_location_anchor");
        assert!(request.options[0].recommended);
        assert_eq!(request.options[1].id, "broad_city_recs");
    });
}

#[test]
fn places_clarification_surfaces_current_area_when_runtime_locality_exists() {
    with_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "places-clarification-locality".to_string(),
            raw_prompt: "Find good coffee shops.".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.87,
            needs_clarification: true,
            clarification_questions: vec!["Where should Chat search?".to_string()],
            decision_evidence: vec![
                "tool_widget:places".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_request: None,
            normalized_request: Some(ioi_types::app::chat::ChatNormalizedRequest::Places(
                ioi_types::app::chat::ChatPlacesRequestFrame {
                    search_anchor: None,
                    category: Some("coffee shops".to_string()),
                    location_scope: None,
                    missing_slots: vec!["search_anchor".to_string()],
                    clarification_required_slots: vec!["search_anchor".to_string()],
                },
            )),
            source_decision: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("places route should surface clarification UX");

        assert_eq!(request.options.len(), 3);
        assert_eq!(request.options[1].id, "use_current_area");
        assert!(request.options[1].recommended);
    });
}

#[test]
fn places_normalized_request_promotes_missing_anchor_into_clarification_gate() {
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "places-topology".to_string(),
        raw_prompt: "Find coffee shops open now.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.88,
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

    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request.needs_clarification);
    assert_eq!(
        outcome_request.clarification_questions,
        vec!["Which neighborhood, city, or anchor location should Chat search around?".to_string()]
    );
    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "normalized_request_clarification_required"));
    match outcome_request.normalized_request.as_ref() {
        Some(ioi_types::app::chat::ChatNormalizedRequest::Places(frame)) => {
            assert!(frame.clarification_required_slots.iter().any(|slot| {
                slot == "search_anchor" || slot == "location_scope" || slot == "location"
            }));
        }
        other => panic!("expected places request frame, got {other:?}"),
    }
}

#[test]
fn currentness_scope_clarification_surfaces_structured_topic_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-clarification".to_string(),
        raw_prompt: "What's happening this week?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.86,
        needs_clarification: true,
        clarification_questions: vec![
            "Do you mean local events, a specific topic, or general news this week?".to_string(),
        ],
        decision_evidence: vec![
            "currentness_override".to_string(),
            "currentness_scope_ambiguous".to_string(),
            "clarification_required_for_currentness".to_string(),
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

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("currentness clarification should surface structured options");

    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].label, "Local events");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "specific_topic");
    assert_eq!(request.options[2].id, "general_news");
}

#[test]
fn connector_catalog_application_routes_mail_intent_into_integrations_lane() {
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
            "mail.delete".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-delete-route".to_string(),
        raw_prompt: "Delete these emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.9,
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

    super::content_session::apply_connector_catalog_to_outcome_request(
        &mut outcome_request,
        &connectors,
    );
    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_intent_detected"));
    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_preferred"));
    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "selected_connector_id:mail.primary"));

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
}

#[test]
fn connector_catalog_application_preserves_connector_source_for_artifact_report_requests() {
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
            "mail.delete".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let artifact = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
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
    };
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-artifact-route".to_string(),
        raw_prompt: "Summarize my unread emails into an HTML report".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["persistent_artifact_requested".to_string()],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(artifact),
    };

    super::content_session::apply_connector_catalog_to_outcome_request(
        &mut outcome_request,
        &connectors,
    );
    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_intent_detected"));
    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("artifact_html_iframe")
    );
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
}

#[test]
fn prioritization_clarification_surfaces_structured_ranking_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "prioritization-clarification".to_string(),
        raw_prompt: "Help me prioritize my renovation projects".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: true,
        clarification_questions: vec![
            "What options or decision shape should Chat present?".to_string()
        ],
        decision_evidence: vec![
            "tool_widget:user_input".to_string(),
            "user_input_preferred".to_string(),
            "prioritization_request".to_string(),
            "structured_input_options_missing".to_string(),
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

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("prioritization clarification should surface structured ranking options");

    assert_eq!(
        request.question,
        "What should drive the ranking: impact, urgency, or return on investment?"
    );
    assert_eq!(
        request.evidence_snippet.as_deref(),
        Some(
            "Chat paused before selecting the outcome surface because it needs clarification: What should drive the ranking: impact, urgency, or return on investment?"
        )
    );
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "impact_first");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "urgency_first");
    assert_eq!(request.options[2].id, "roi_first");
}

#[test]
fn currentness_override_conversation_does_not_stay_chat_primary() {
    let mut task = empty_task("What is the latest OpenAI API pricing?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-override".to_string(),
        raw_prompt: "What is the latest OpenAI API pricing?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.94,
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
    super::content_session::attach_inline_answer_chat_session(
        &mut task,
        "What is the latest OpenAI API pricing?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(!task_requires_chat_primary_execution(&task));
}

