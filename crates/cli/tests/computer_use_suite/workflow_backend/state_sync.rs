fn sync_bridge_state_from_observation(
    session: &mut WorkflowSession,
    payload: WorkflowObservationPayload,
) {
    session.current_page =
        page_from_url(&payload.page_url).unwrap_or_else(|| session.current_page.clone());
    if let Some(ticket_id) = active_ticket_id_from_page(session) {
        session.active_ticket_id = ticket_id;
    }
    session.login_username = observation_value(&payload.interactive_elements, "#username")
        .unwrap_or_else(|| session.login_username.clone());
    session.login_password = observation_value(&payload.interactive_elements, "#password")
        .unwrap_or_else(|| session.login_password.clone());
    session.queue_search = observation_value(&payload.interactive_elements, "#queue-search")
        .unwrap_or_else(|| session.queue_search.clone());
    session.queue_status_filter =
        observation_selected_label(&payload.interactive_elements, "#queue-status-filter")
            .or_else(|| observation_value(&payload.interactive_elements, "#queue-status-filter"))
            .unwrap_or_else(|| session.queue_status_filter.clone());
    session.queue_sort = observation_selected_label(&payload.interactive_elements, "#queue-sort")
        .or_else(|| observation_value(&payload.interactive_elements, "#queue-sort"))
        .unwrap_or_else(|| session.queue_sort.clone());
    session.draft_assignee = observation_selected_label(&payload.interactive_elements, "#assignee")
        .or_else(|| observation_value(&payload.interactive_elements, "#assignee"))
        .unwrap_or_else(|| session.draft_assignee.clone());
    session.draft_status = observation_selected_label(&payload.interactive_elements, "#status")
        .or_else(|| observation_value(&payload.interactive_elements, "#status"))
        .unwrap_or_else(|| session.draft_status.clone());
    session.draft_note = observation_value(&payload.interactive_elements, "#note")
        .unwrap_or_else(|| session.draft_note.clone());
    maybe_complete_workflow_verification(session, Some(payload.visible_text_excerpt.as_str()));

    session.bridge_state.reward = session.reward;
    session.bridge_state.terminated = session.terminated;
    session.bridge_state.truncated = session.truncated;
    session.bridge_state.episode_step = session.bridge_state.episode_step.saturating_add(1);
    session.bridge_state.generation = session.bridge_state.generation.saturating_add(1);
    session.bridge_state.last_sync_ms = Some(now_ms());
    session.bridge_state.info = BridgeInfo {
        reason: Some("workflow_observation".to_string()),
        raw_reward: Some(session.reward),
        query_text: Some(session.spec.instruction.clone()),
        fields: workflow_fields(session),
        page_url: Some(payload.page_url),
        task_ready: Some(true),
        focused_tag: payload.focused_tag,
        focused_id: payload.focused_id,
        last_event: None,
        visible_text_excerpt: Some(payload.visible_text_excerpt),
        interactive_elements: payload.interactive_elements,
        scroll_targets: payload.scroll_targets,
        dom_elements: payload.dom_elements,
        trigger: None,
    };
}

fn sync_bridge_state_from_synthesized_page(session: &mut WorkflowSession) {
    let visible_text = workflow_visible_text(session, &session.current_page);
    maybe_complete_workflow_verification(session, Some(visible_text.as_str()));
    session.bridge_state.reward = session.reward;
    session.bridge_state.terminated = session.terminated;
    session.bridge_state.truncated = session.truncated;
    session.bridge_state.episode_step = session.bridge_state.episode_step.saturating_add(1);
    session.bridge_state.generation = session.bridge_state.generation.saturating_add(1);
    session.bridge_state.last_sync_ms = Some(now_ms());
    session.bridge_state.info = BridgeInfo {
        reason: Some("workflow_oracle".to_string()),
        raw_reward: Some(session.reward),
        query_text: Some(session.spec.instruction.clone()),
        fields: workflow_fields(session),
        page_url: Some(current_page_url(session)),
        task_ready: Some(true),
        focused_tag: None,
        focused_id: None,
        last_event: None,
        visible_text_excerpt: Some(visible_text),
        interactive_elements: synthesized_interactive_elements(session, &session.current_page),
        scroll_targets: Vec::new(),
        dom_elements: Vec::new(),
        trigger: None,
    };
}

