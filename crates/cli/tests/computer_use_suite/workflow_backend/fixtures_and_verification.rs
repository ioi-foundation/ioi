fn workflow_initial_tickets() -> BTreeMap<String, WorkflowTicketRecord> {
    [
        (
            "T-101",
            "Printer outage in west wing",
            "Facilities",
            "New",
            "Facilities",
            "",
        ),
        (
            "T-202",
            "Fiber handoff requires vendor logs",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-204",
            "Metro fiber outage",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-215",
            "Fiber maintenance escalation",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-303",
            "Invoice reminder needs correction",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
        (
            "T-310",
            "Recurring invoice delta",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
        (
            "T-318",
            "Invoice adjustment awaiting callback",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(
            index,
            (ticket_id, title, suggested_team, current_status, current_assignee, current_note),
        )| {
            (
                ticket_id.to_string(),
                WorkflowTicketRecord {
                    ticket_id: ticket_id.to_string(),
                    title: title.to_string(),
                    suggested_team: suggested_team.to_string(),
                    current_status: current_status.to_string(),
                    current_assignee: current_assignee.to_string(),
                    current_note: current_note.to_string(),
                    updated_revision: index as u64,
                },
            )
        },
    )
    .collect()
}

fn workflow_initial_history_entries() -> Vec<WorkflowHistoryEntry> {
    vec![
        WorkflowHistoryEntry {
            ticket_id: "T-204".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Queued vendor follow-up".to_string(),
            assignee: String::new(),
            status: "Awaiting Dispatch".to_string(),
            note: String::new(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-215".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Viewed ticket".to_string(),
            assignee: String::new(),
            status: "Awaiting Dispatch".to_string(),
            note: String::new(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-310".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Requested billing callback".to_string(),
            assignee: String::new(),
            status: "Pending Review".to_string(),
            note: "Awaiting customer callback".to_string(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-318".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Requested billing callback".to_string(),
            assignee: String::new(),
            status: "Pending Review".to_string(),
            note: "Awaiting customer callback".to_string(),
        },
    ]
}

fn display_assignee(value: &str) -> String {
    if value.trim().is_empty() {
        "Unassigned".to_string()
    } else {
        value.to_string()
    }
}

fn ticket_matches_search(ticket: &WorkflowTicketRecord, search: &str) -> bool {
    if search.is_empty() {
        return true;
    }
    let search = search.to_ascii_lowercase();
    ticket.ticket_id.to_ascii_lowercase().contains(&search)
        || ticket.title.to_ascii_lowercase().contains(&search)
        || ticket.suggested_team.to_ascii_lowercase().contains(&search)
}

fn queue_view_search(session: &WorkflowSession) -> &str {
    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && session.confirmation_seen
        && !session.queue_view_fresh
    {
        return session
            .stale_queue_snapshot
            .as_ref()
            .map(|snapshot| snapshot.search.as_str())
            .unwrap_or_else(|| session.queue_search.as_str());
    }
    session.queue_search.as_str()
}

fn queue_view_status_filter(session: &WorkflowSession) -> &str {
    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && session.confirmation_seen
        && !session.queue_view_fresh
    {
        return session
            .stale_queue_snapshot
            .as_ref()
            .map(|snapshot| snapshot.status_filter.as_str())
            .unwrap_or_else(|| session.queue_status_filter.as_str());
    }
    session.queue_status_filter.as_str()
}

fn queue_view_sort(session: &WorkflowSession) -> &str {
    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && session.confirmation_seen
        && !session.queue_view_fresh
    {
        return session
            .stale_queue_snapshot
            .as_ref()
            .map(|snapshot| snapshot.sort.as_str())
            .unwrap_or_else(|| session.queue_sort.as_str());
    }
    session.queue_sort.as_str()
}

fn queue_view_ticket_source(session: &WorkflowSession) -> &BTreeMap<String, WorkflowTicketRecord> {
    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && session.confirmation_seen
        && !session.queue_view_fresh
    {
        return session
            .stale_queue_snapshot
            .as_ref()
            .map(|snapshot| &snapshot.tickets)
            .unwrap_or(&session.tickets);
    }
    &session.tickets
}

fn visible_queue_tickets(session: &WorkflowSession) -> Vec<&WorkflowTicketRecord> {
    let mut tickets = queue_view_ticket_source(session)
        .values()
        .filter(|ticket| {
            (queue_view_status_filter(session).is_empty()
                || ticket.current_status == queue_view_status_filter(session))
                && ticket_matches_search(ticket, queue_view_search(session))
        })
        .collect::<Vec<_>>();
    if queue_view_sort(session) == "Recently Updated" {
        tickets.sort_by(|left, right| {
            right
                .updated_revision
                .cmp(&left.updated_revision)
                .then_with(|| left.ticket_id.cmp(&right.ticket_id))
        });
    } else {
        tickets.sort_by(|left, right| left.ticket_id.cmp(&right.ticket_id));
    }
    if matches!(
        session.spec.scenario,
        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory
    ) && queue_view_search(session).trim().is_empty()
    {
        tickets.truncate(2);
    }
    tickets
}

fn reset_draft_from_saved_ticket(session: &mut WorkflowSession, ticket_id: &str) {
    if let Some(ticket) = session.tickets.get(ticket_id) {
        session.draft_assignee = ticket.current_assignee.clone();
        session.draft_status = ticket.current_status.clone();
        session.draft_note = ticket.current_note.clone();
    }
}

fn capture_stale_queue_snapshot(session: &mut WorkflowSession) {
    if !matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder) {
        return;
    }
    session.stale_queue_snapshot = Some(WorkflowQueueSnapshot {
        tickets: session.tickets.clone(),
        search: session.queue_search.clone(),
        status_filter: session.queue_status_filter.clone(),
        sort: session.queue_sort.clone(),
    });
}

fn persist_ticket_update(session: &mut WorkflowSession, ticket_id: &str) {
    session.next_update_revision = session.next_update_revision.saturating_add(1);
    let updated_revision = session.next_update_revision;
    if let Some(ticket) = session.tickets.get_mut(ticket_id) {
        ticket.current_assignee = session.draft_assignee.clone();
        if !session.draft_status.is_empty() {
            ticket.current_status = session.draft_status.clone();
        }
        ticket.current_note = session.draft_note.clone();
        ticket.updated_revision = updated_revision;
    }
}

fn append_history_entry(session: &mut WorkflowSession, ticket_id: &str) {
    session.history_entries.push(WorkflowHistoryEntry {
        ticket_id: ticket_id.to_string(),
        actor: session.spec.username.clone(),
        action: "Saved dispatch update".to_string(),
        assignee: session.draft_assignee.clone(),
        status: session.draft_status.clone(),
        note: session.draft_note.clone(),
    });
}

fn target_ticket_matches_spec(session: &WorkflowSession) -> bool {
    let Some(ticket) = session.tickets.get(&session.spec.ticket_id) else {
        return false;
    };
    let status_matches =
        session.spec.status.is_empty() || ticket.current_status == session.spec.status;
    ticket.current_assignee == session.spec.assignee
        && ticket.current_note == session.spec.note
        && status_matches
}

fn maybe_complete_workflow_verification(session: &mut WorkflowSession, visible_text: Option<&str>) {
    maybe_complete_queue_verification(session, visible_text);
    maybe_complete_audit_history_verification(session, visible_text);
    maybe_complete_mutation_isolation_verification(session, visible_text);
    maybe_complete_stale_queue_reorder_verification(session, visible_text);
}

fn maybe_complete_queue_verification(session: &mut WorkflowSession, visible_text: Option<&str>) {
    if !matches!(session.spec.scenario, WorkflowScenario::QueueVerification)
        || !session.confirmation_seen
        || !matches!(session.current_page, WorkflowPage::Queue)
    {
        return;
    }
    let target_visible = visible_queue_tickets(session)
        .into_iter()
        .any(|ticket| ticket.ticket_id == session.spec.ticket_id);
    let observed_match = visible_text.is_some_and(|text| {
        text.contains(&session.spec.ticket_id)
            && text.contains(&session.spec.assignee)
            && text.contains(&session.spec.status)
    });
    if target_visible && observed_match && target_ticket_matches_spec(session) {
        session.queue_verified = true;
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn maybe_complete_audit_history_verification(
    session: &mut WorkflowSession,
    visible_text: Option<&str>,
) {
    if !matches!(session.spec.scenario, WorkflowScenario::AuditHistory)
        || !session.confirmation_seen
        || !matches!(session.current_page, WorkflowPage::History { .. })
    {
        return;
    }
    let history_match = target_history_entry(session);
    let observed_match = visible_text.is_some_and(|text| {
        text.contains(&session.spec.ticket_id)
            && text.contains(&session.spec.assignee)
            && text.contains(&session.spec.status)
            && text.contains(&session.spec.note)
    });
    if history_match.is_some() && observed_match && target_ticket_matches_spec(session) {
        session.history_verified = true;
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn maybe_complete_mutation_isolation_verification(
    session: &mut WorkflowSession,
    visible_text: Option<&str>,
) {
    if !matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        || !session.confirmation_seen
    {
        return;
    }

    if matches!(session.current_page, WorkflowPage::Queue) && !session.queue_verified {
        let visible_tickets = visible_queue_tickets(session);
        let target_visible = visible_tickets
            .iter()
            .any(|ticket| ticket.ticket_id == session.spec.ticket_id);
        let distractor_visible = visible_tickets
            .iter()
            .any(|ticket| ticket.ticket_id == session.spec.distractor_ticket_id);
        let observed_match = visible_text.is_some_and(|text| {
            text.contains(&session.spec.ticket_id)
                && text.contains(&session.spec.assignee)
                && text.contains(&session.spec.status)
                && text.contains(&session.spec.distractor_ticket_id)
                && text.contains(&display_assignee(&session.spec.distractor_assignee))
                && text.contains(&session.spec.distractor_status)
        });
        if target_visible
            && distractor_visible
            && observed_match
            && target_ticket_matches_spec(session)
            && distractor_ticket_matches_spec(session)
        {
            session.queue_verified = true;
        }
    }

    if matches!(
        session.current_page,
        WorkflowPage::History { ref ticket_id } if ticket_id == &session.spec.ticket_id
    ) && !session.history_verified
    {
        let observed_match = visible_text.is_some_and(|text| {
            text.contains(&session.spec.ticket_id)
                && text.contains(&session.spec.assignee)
                && text.contains(&session.spec.status)
                && text.contains(&session.spec.note)
        });
        if observed_match
            && target_history_entry(session).is_some()
            && target_ticket_matches_spec(session)
        {
            session.history_verified = true;
        }
    }

    if matches!(
        session.current_page,
        WorkflowPage::History { ref ticket_id } if ticket_id == &session.spec.distractor_ticket_id
    ) && !session.distractor_history_verified
    {
        let observed_match =
            visible_text.is_some_and(|text| text.contains(&session.spec.distractor_ticket_id));
        if observed_match
            && distractor_saved_update_entry(session).is_none()
            && distractor_ticket_matches_spec(session)
        {
            session.distractor_history_verified = true;
        }
    }

    if session.queue_verified
        && session.history_verified
        && session.distractor_history_verified
        && target_ticket_matches_spec(session)
        && distractor_ticket_matches_spec(session)
    {
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn maybe_complete_stale_queue_reorder_verification(
    session: &mut WorkflowSession,
    visible_text: Option<&str>,
) {
    if !matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        || !session.confirmation_seen
    {
        return;
    }

    if matches!(session.current_page, WorkflowPage::Queue) && !session.queue_verified {
        let visible_tickets = visible_queue_tickets(session);
        let target_position = visible_tickets
            .iter()
            .position(|ticket| ticket.ticket_id == session.spec.ticket_id)
            .map(|index| index + 1)
            .unwrap_or_default();
        let distractor_position = visible_tickets
            .iter()
            .position(|ticket| ticket.ticket_id == session.spec.distractor_ticket_id)
            .map(|index| index + 1)
            .unwrap_or_default();
        let observed_match = visible_text.is_some_and(|text| {
            text.contains(&session.spec.ticket_id)
                && text.contains(&session.spec.assignee)
                && text.contains(&session.spec.status)
                && text.contains(&session.spec.distractor_ticket_id)
                && text.contains(&display_assignee(&session.spec.distractor_assignee))
                && text.contains(&session.spec.distractor_status)
        });
        if session.queue_view_fresh
            && queue_view_sort(session) == session.spec.post_confirm_queue_sort
            && target_position > 0
            && distractor_position > 0
            && target_position < distractor_position
            && observed_match
            && target_ticket_matches_spec(session)
            && distractor_ticket_matches_spec(session)
        {
            session.queue_verified = true;
        }
    }

    if matches!(
        session.current_page,
        WorkflowPage::History { ref ticket_id } if ticket_id == &session.spec.distractor_ticket_id
    ) && !session.distractor_history_verified
    {
        let observed_match =
            visible_text.is_some_and(|text| text.contains(&session.spec.distractor_ticket_id));
        if observed_match
            && distractor_saved_update_entry(session).is_none()
            && distractor_ticket_matches_spec(session)
        {
            session.distractor_history_verified = true;
        }
    }

    if session.queue_verified
        && session.distractor_history_verified
        && target_ticket_matches_spec(session)
        && distractor_ticket_matches_spec(session)
    {
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn active_ticket_id_from_page(session: &WorkflowSession) -> Option<String> {
    match &session.current_page {
        WorkflowPage::Detail { ticket_id } => Some(ticket_id.clone()),
        WorkflowPage::History { ticket_id } => Some(ticket_id.clone()),
        WorkflowPage::Review | WorkflowPage::Confirmation => Some(session.active_ticket_id.clone()),
        WorkflowPage::Login | WorkflowPage::Queue => None,
    }
}

fn ticket_id_for_selector(session: &WorkflowSession, selector: &str) -> Option<String> {
    session
        .tickets
        .keys()
        .find(|ticket_id| selector == ticket_link_selector(ticket_id))
        .cloned()
}

fn ticket_id_for_history_selector(session: &WorkflowSession, selector: &str) -> Option<String> {
    session
        .tickets
        .keys()
        .find(|ticket_id| selector == ticket_history_link_selector(ticket_id))
        .cloned()
}

fn ticket_link_selector(ticket_id: &str) -> String {
    format!("#{}", ticket_link_id(ticket_id))
}

fn ticket_link_id(ticket_id: &str) -> String {
    format!("ticket-link-{}", sanitize_token(ticket_id))
}

fn ticket_history_link_selector(ticket_id: &str) -> String {
    format!("#{}", ticket_history_link_id(ticket_id))
}

fn ticket_history_link_id(ticket_id: &str) -> String {
    format!("ticket-history-link-{}", sanitize_token(ticket_id))
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
}

fn observation_value(elements: &[BridgeInteractiveElement], selector: &str) -> Option<String> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
        .and_then(|element| element.value.clone())
}

fn observation_selected_label(
    elements: &[BridgeInteractiveElement],
    selector: &str,
) -> Option<String> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
        .and_then(|element| element.selected_labels.first().cloned())
}

fn link(selector: &str, text: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "a".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: None,
        text: text.to_string(),
        value: None,
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn button(selector: &str, text: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "button".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: None,
        text: text.to_string(),
        value: None,
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn text_input(selector: &str, name: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "input".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some(name.to_string()),
        text: String::new(),
        value: Some(value.to_string()),
        input_type: Some("text".to_string()),
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn password_input(selector: &str, name: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        input_type: Some("password".to_string()),
        ..text_input(selector, name, value)
    }
}

fn text_area(selector: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "textarea".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some("note".to_string()),
        text: String::new(),
        value: Some(value.to_string()),
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn select_input(selector: &str, selected: &str) -> BridgeInteractiveElement {
    select_input_named(selector, "assignee", selected)
}

fn select_input_named(selector: &str, name: &str, selected: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "select".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some(name.to_string()),
        text: String::new(),
        value: Some(selected.to_string()),
        input_type: None,
        checked: None,
        selected_labels: if selected.is_empty() {
            Vec::new()
        } else {
            vec![selected.to_string()]
        },
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
