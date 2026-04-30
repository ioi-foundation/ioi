#[test]
fn clarification_inline_answer_route_stays_chat_primary() {
    let mut task = empty_task("Make me a report.");
    let outcome_request = ChatOutcomeRequest {
        request_id: "clarification-route".to_string(),
        raw_prompt: "Make me a report.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.75,
        needs_clarification: true,
        clarification_questions: vec!["What should the report cover?".to_string()],
        decision_evidence: vec![
            "artifact_clarification_required".to_string(),
            "under_specified_document_request".to_string(),
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
        "Make me a report.",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );
    super::apply_chat_authoritative_status(&mut task, None);

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
    assert_eq!(task.phase, AgentPhase::Gate);
    assert_eq!(
        task.clarification_request
            .as_ref()
            .map(|request| request.question.as_str()),
        Some("What should the report cover?")
    );
    assert!(task.current_step.contains("waiting for clarification"));
}

#[test]
fn missing_connector_reframes_impossible_workspace_clarification() {
    let connectors = vec![
        ConnectorCatalogEntry {
            id: "mail.primary".to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description: "Wallet-backed mail connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["mail.read.latest".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
        ConnectorCatalogEntry {
            id: "google.workspace".to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description: "Google Workspace connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["gmail".to_string(), "calendar".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
    ];
    let context = infer_connector_route_context_from_catalog(
        "Summarize my Slack unread messages",
        &connectors,
    )
    .expect("slack request should synthesize connector context");

    let mut outcome_request = ChatOutcomeRequest {
        request_id: "slack-missing".to_string(),
        raw_prompt: "Summarize my Slack unread messages".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: true,
        clarification_questions: vec!["Which Slack workspace should I monitor?".to_string()],
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

    assert_eq!(
        outcome_request.clarification_questions,
        vec![
            "Slack is not available in this runtime yet. Should Chat wait for you to connect it, or should I work from pasted data instead?"
                .to_string()
        ]
    );
    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_missing"));

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("missing connector route should surface clarification UX");
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "open_capabilities_to_connect");
    assert!(request.options[0].recommended);

    let route_decision = route_decision_for_outcome_request(&outcome_request);
    assert_eq!(route_decision.connector_candidate_count, 0);
    assert!(route_decision.connector_first_preference);
    assert!(route_decision.narrow_tool_preference);
    assert_eq!(route_decision.route_family, "integrations");
    assert!(route_decision
        .direct_answer_blockers
        .iter()
        .any(|blocker| blocker == "connector_unavailable"));
}

#[test]
fn connected_mail_route_clears_redundant_identity_clarification() {
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
        request_id: "mail-connected".to_string(),
        raw_prompt: "Summarize my unread emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: true,
        clarification_questions: vec!["Which inbox should Chat check?".to_string()],
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

    assert!(!outcome_request.needs_clarification);
    assert!(outcome_request.clarification_questions.is_empty());
    assert!(outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_identity_auto_selected"));

    let route_decision = route_decision_for_outcome_request(&outcome_request);
    assert_eq!(route_decision.connector_candidate_count, 1);
    assert_eq!(route_decision.route_family, "integrations");
    assert_eq!(
        route_decision.selected_provider_family.as_deref(),
        Some("mail.wallet_network")
    );
    assert_eq!(
        route_decision.selected_provider_route_label.as_deref(),
        Some("mail_connector")
    );
    assert!(route_decision.connector_first_preference);
    assert!(route_decision.narrow_tool_preference);
    assert!(route_decision
        .effective_tool_surface
        .primary_tools
        .iter()
        .any(|tool| tool == "connector:mail.primary"));
}

#[test]
fn generic_mail_prefers_dedicated_connector_over_broader_platform_route() {
    let connectors = vec![
        ConnectorCatalogEntry {
            id: "google.workspace".to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description: "Google Workspace connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["gmail".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
        ConnectorCatalogEntry {
            id: "mail.primary".to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description: "Wallet-backed mail connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "mail.read.latest".to_string(),
                "mail.list.recent".to_string(),
            ],
            last_sync_at_utc: None,
            notes: None,
        },
    ];
    let context =
        infer_connector_route_context_from_catalog("Summarize my unread emails", &connectors)
            .expect("mail request should synthesize connector context");

    assert!(context
        .decision_evidence
        .iter()
        .any(|hint| hint == "selected_connector_id:mail.primary"));
    assert!(context
        .decision_evidence
        .iter()
        .any(|hint| hint == "selected_provider_family:mail.wallet_network"));
    assert!(context
        .decision_evidence
        .iter()
        .any(|hint| hint == "connector_tiebreaker:narrow_connector"));
}

#[test]
fn downloadable_spreadsheet_prompt_does_not_trigger_connector_context() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "google.workspace".to_string(),
        plugin_id: "google_workspace".to_string(),
        name: "Google".to_string(),
        provider: "google".to_string(),
        category: "productivity".to_string(),
        description: "Google Workspace connector.".to_string(),
        status: "needs_auth".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec!["sheets".to_string()],
        last_sync_at_utc: None,
        notes: None,
    }];

    let context = infer_connector_route_context_from_catalog(
        "Create a budget spreadsheet with income and expense categories, monthly columns, SUM formulas for totals, conditional formatting for overages, and a summary chart",
        &connectors,
    );

    assert!(
        context.is_none(),
        "explicit downloadable spreadsheet prompts should stay on the artifact lane"
    );
}

#[test]
fn pure_draft_email_prompt_prefers_local_message_compose_over_connector_gate() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "mail_primary".to_string(),
        name: "Mail".to_string(),
        provider: "wallet".to_string(),
        category: "communication".to_string(),
        description: "Primary mail connector.".to_string(),
        status: "needs_auth".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec!["mail.read.latest".to_string()],
        last_sync_at_utc: None,
        notes: None,
    }];

    let context = infer_connector_route_context_from_catalog(
        "Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.",
        &connectors,
    );

    assert!(
        context.is_none(),
        "pure composition requests should stay on the communication lane instead of forcing connector auth"
    );
}

#[test]
fn document_artifact_decision_record_preserves_artifact_vs_file_split() {
    let outcome_request = test_outcome_request();
    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert_eq!(route_decision.route_family, "artifacts");
    assert!(route_decision.artifact_output_intent);
    assert!(route_decision.file_output_intent);
    assert!(!route_decision.inline_visual_intent);
    assert!(!route_decision.narrow_tool_preference);
    assert!(!route_decision.skill_prep_required);
    assert_eq!(route_decision.output_intent, "artifact");
}

#[test]
fn communication_decision_record_uses_tool_execution_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "message-route".to_string(),
        raw_prompt: "Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "email_draft".to_string(),
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
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
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
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.get("primary_tools"))
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools
            .iter()
            .any(|value| value.as_str() == Some("message_compose_v1"))));
    assert!(payload_object
        .get("orchestration_state")
        .and_then(|value| value.get("tasks"))
        .and_then(|value| value.as_array())
        .is_some_and(|tasks| tasks.len() >= 3));
}

#[test]
fn artifact_decision_record_prefers_artifact_surface_over_specialized_prompt_terms() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "itinerary-artifact".to_string(),
        raw_prompt: "Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "persistent_artifact_requested".to_string(),
            "generic_document_artifact_defaults_to_markdown".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(test_outcome_request().artifact.expect("artifact request")),
    };

    let payload = super::content_session::build_decision_record_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    let bundle = payload_object
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
        Some("artifact_surface")
    );
    assert!(bundle
        .get("verificationContract")
        .or_else(|| bundle.get("verification_contract"))
        .and_then(|value| value
            .get("requiredChecks")
            .or_else(|| value.get("required_checks")))
        .and_then(|value| value.as_array())
        .is_some_and(|checks| checks
            .iter()
            .any(|value| value.as_str() == Some("artifact_surface_rendered"))));
    assert!(payload_object
        .get("lane_request")
        .and_then(|value| value
            .get("secondaryLanes")
            .or_else(|| value.get("secondary_lanes")))
        .and_then(|value| value.as_array())
        .is_some_and(|lanes| lanes.iter().any(|value| value.as_str() == Some("research"))));
}

#[test]
fn conversation_with_tool_widget_hint_is_not_marked_direct_inline() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-inline-mismatch".to_string(),
        raw_prompt: "What are some good coffee shops near downtown Portland?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.74,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
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

    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert!(!route_decision.direct_answer_allowed);
    assert_eq!(route_decision.output_intent, "tool_execution");
    assert!(route_decision
        .direct_answer_blockers
        .iter()
        .any(|blocker| blocker == "tool_widget_surface_selected"));
}

#[test]
fn workspace_artifact_decision_record_uses_coding_family_and_workspace_prep() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-route".to_string(),
        raw_prompt:
            "Build a React + Vite workspace project for a task tracker with separate components"
                .to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "explicit_workspace_project_deliverable".to_string(),
            "workspace_runtime_required".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(test_workspace_request()),
    };

    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert_eq!(route_decision.route_family, "coding");
    assert!(route_decision.artifact_output_intent);
    assert!(!route_decision.file_output_intent);
    assert!(route_decision.skill_prep_required);
    assert_eq!(route_decision.output_intent, "artifact");
}

