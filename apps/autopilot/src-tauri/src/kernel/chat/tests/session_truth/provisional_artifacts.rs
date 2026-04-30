#[test]
fn provisional_artifact_route_state_emits_route_receipt_before_materialization() {
    let prompt = "A mortgage calculator where I can adjust rate, term, and down payment";
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let outcome_request = ChatOutcomeRequest {
        request_id: "interactive-artifact-route".to_string(),
        raw_prompt: prompt.to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::DirectAuthor,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["interactive_surface_requested".to_string()],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request.clone()),
    };
    let title = "Mortgage calculator";
    let summary = "Chat is preparing the interactive artifact.";
    let chat_session = super::prepare::provisional_non_workspace_chat_session(
        "thread-1",
        "chat-session-1",
        title,
        summary,
        "2026-04-15T00:00:00Z",
        &outcome_request,
        Some("prompt-evt-1"),
        materialization_contract_for_request(
            prompt,
            &request,
            summary,
            None,
            outcome_request.execution_strategy,
        ),
    )
    .expect("provisional session");
    let mut task = empty_task(prompt);

    super::prepare::seed_provisional_artifact_route_state(
        &mut task,
        &outcome_request,
        summary,
        chat_session,
        None,
        None,
    );

    let route_event = task
        .events
        .iter()
        .find(|event| event.title == "Chat route decision")
        .expect("route decision event");
    let digest = route_event.digest.as_object().expect("route digest");
    assert_eq!(
        digest
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("artifact_html_iframe")
    );
    let route_decision = digest
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision payload");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("artifact")
    );
    assert_eq!(
        route_decision
            .get("artifact_output_intent")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(task.chat_session.is_some());
}
