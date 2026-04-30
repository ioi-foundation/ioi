fn workflow_case_spec(case: &ComputerUseCase) -> Result<WorkflowCaseSpec> {
    match case.id.as_str() {
        "workflow_ticket_routing_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::TicketRouting,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-204\". Open ticket T-204 from the queue, assign it to Network Ops, add the note \"Escalate fiber outage to on-call\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-204".to_string(),
            ticket_id: "T-204".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: String::new(),
            queue_search: String::new(),
            queue_status_filter: String::new(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_ticket_routing_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::TicketRouting,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-310\". Open ticket T-310 from the queue, assign it to Billing Review, add the note \"Validate recurring invoice delta\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-310".to_string(),
            ticket_id: "T-310".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: String::new(),
            queue_search: String::new(),
            queue_status_filter: String::new(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_queue_verification_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::QueueVerification,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", set the queue status filter to \"Awaiting Dispatch\", open ticket T-215, assign it to Network Ops, set the status to \"Escalated\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, then return to the queue and stop only after the queue shows T-215 saved with assignee Network Ops and status Escalated.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Escalated".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_queue_verification_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::QueueVerification,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", set the queue status filter to \"Pending Review\", open ticket T-318, assign it to Billing Review, set the status to \"Pending Customer Reply\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, then return to the queue and stop only after the queue shows T-318 saved with assignee Billing Review and status Pending Customer Reply.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Customer Reply".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_audit_history_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::AuditHistory,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", keep the queue status filter on \"Awaiting Dispatch\", open ticket T-215 even though other fiber tickets remain visible, assign it to Network Ops, set the status to \"Escalated\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, open the audit history, and stop only after the audit history shows a saved dispatch update for T-215 with assignee Network Ops, status Escalated, and note \"Escalate fiber outage to on-call\". If the draft or saved history does not match, cancel or reopen the update and fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Escalated".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_audit_history_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::AuditHistory,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", keep the queue status filter on \"Pending Review\", open ticket T-318 even though other invoice tickets remain visible, assign it to Billing Review, set the status to \"Pending Customer Reply\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, open the audit history, and stop only after the audit history shows a saved dispatch update for T-318 with assignee Billing Review, status Pending Customer Reply, and note \"Validate recurring invoice delta\". If the draft or saved history does not match, cancel or reopen the update and fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Customer Reply".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_mutation_isolation_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::MutationIsolation,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", keep the queue status filter on \"Awaiting Dispatch\" so multiple similar fiber tickets remain visible, open ticket T-215, assign it to Network Ops, keep the status at \"Awaiting Dispatch\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, return to the queue, and stop only after typed verification shows T-215 changed while distractor ticket T-204 still shows assignee Unassigned and status Awaiting Dispatch. Then open audit history for T-215 and verify the saved dispatch update exists, open audit history for T-204 and verify no saved dispatch update was persisted there, and use cancel or reopen if the draft or saved state is wrong before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Awaiting Dispatch".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: "T-204".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Awaiting Dispatch".to_string(),
            distractor_note: String::new(),
        }),
        "workflow_mutation_isolation_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::MutationIsolation,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", keep the queue status filter on \"Pending Review\" so multiple similar invoice tickets remain visible, open ticket T-318, assign it to Billing Review, keep the status at \"Pending Review\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, return to the queue, and stop only after typed verification shows T-318 changed while distractor ticket T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-318 and verify the saved dispatch update exists, open audit history for T-310 and verify no saved dispatch update was persisted there, and use cancel or reopen if the draft or saved state is wrong before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Review".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            queue_sort: String::new(),
            post_confirm_queue_sort: String::new(),
            distractor_ticket_id: "T-310".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Pending Review".to_string(),
            distractor_note: String::new(),
        }),
        "workflow_stale_queue_reorder_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::StaleQueueReorder,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", keep the queue status filter on \"Awaiting Dispatch\", and leave the queue sort on \"Ticket ID\" so target ticket T-215 sits below distractor ticket T-204. Open T-215, assign it to Network Ops, keep the status at \"Awaiting Dispatch\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-215 moved above T-204 with assignee Network Ops while distractor T-204 still shows assignee Unassigned and status Awaiting Dispatch. Then open audit history for T-204 and verify no saved dispatch update was persisted there. If the queue view is stale, the sort is outdated, or the saved draft is wrong, refresh, reopen, or fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Awaiting Dispatch".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            queue_sort: "Ticket ID".to_string(),
            post_confirm_queue_sort: "Recently Updated".to_string(),
            distractor_ticket_id: "T-204".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Awaiting Dispatch".to_string(),
            distractor_note: String::new(),
        }),
        "workflow_stale_queue_reorder_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::StaleQueueReorder,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", keep the queue status filter on \"Pending Review\", and leave the queue sort on \"Ticket ID\" so target ticket T-318 sits below distractor ticket T-310. Open T-318, assign it to Billing Review, keep the status at \"Pending Review\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there. If the queue view is stale, the sort is outdated, or the saved draft is wrong, refresh, reopen, or fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Review".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            queue_sort: "Ticket ID".to_string(),
            post_confirm_queue_sort: "Recently Updated".to_string(),
            distractor_ticket_id: "T-310".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Pending Review".to_string(),
            distractor_note: String::new(),
        }),
        other => Err(anyhow!(
            "no workflow benchmark spec is defined for case '{}'",
            other
        )),
    }
}

async fn login_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Login;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Login)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn login_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<LoginFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.login_username = form.username.clone();
        session.login_password = form.password.clone();
        if session.login_username == session.spec.username
            && session.login_password == session.spec.password
        {
            session.current_page = WorkflowPage::Queue;
            format!("/workflow/{}/queue", session_id)
        } else {
            session.current_page = WorkflowPage::Login;
            format!("/workflow/{}/login", session_id)
        }
    })
    .unwrap_or_else(|| format!("/workflow/{}/login", session_id));
    Redirect::to(&target)
}

async fn queue_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Queue;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Queue)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn queue_filter_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<QueueFilterFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.queue_search = form.search.trim().to_string();
        session.queue_status_filter = form.status.trim().to_string();
        session.queue_sort = form.sort.trim().to_string();
        if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
            && session.confirmation_seen
        {
            session.queue_view_fresh = true;
            session.stale_queue_snapshot = None;
        }
        session.current_page = WorkflowPage::Queue;
        format!("/workflow/{}/queue", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn ticket_detail_page(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        if let Some(ticket) = session.tickets.get(&ticket_id) {
            session.draft_assignee = ticket.current_assignee.clone();
            session.draft_status = ticket.current_status.clone();
            session.draft_note = ticket.current_note.clone();
        }
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(
            session,
            &WorkflowPage::Detail {
                ticket_id: ticket_id.clone(),
            },
        )
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_assign_submit(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<AssignFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        session.draft_assignee = form.assignee.clone();
        session.draft_status = form.status.clone();
        session.draft_note = form.note.clone();
        match session.spec.scenario {
            WorkflowScenario::TicketRouting => {
                persist_ticket_update(session, &ticket_id);
                session.current_page = WorkflowPage::Confirmation;
                session.reward = if ticket_id == session.spec.ticket_id
                    && session.draft_assignee == session.spec.assignee
                    && session.draft_note == session.spec.note
                {
                    1.0
                } else {
                    0.0
                };
                session.terminated = true;
                session.truncated = false;
                format!("/workflow/{}/confirmation", session_id)
            }
            WorkflowScenario::QueueVerification
            | WorkflowScenario::AuditHistory
            | WorkflowScenario::MutationIsolation
            | WorkflowScenario::StaleQueueReorder => {
                session.current_page = WorkflowPage::Review;
                session.queue_verified = false;
                session.history_verified = false;
                session.distractor_history_verified = false;
                session.reward = 0.0;
                session.terminated = false;
                session.truncated = false;
                format!("/workflow/{}/review", session_id)
            }
        }
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Review;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Review)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn review_edit_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        let ticket_id = session.active_ticket_id.clone();
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        format!("/workflow/{}/tickets/{}", session_id, ticket_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_confirm_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        let ticket_id = session.active_ticket_id.clone();
        capture_stale_queue_snapshot(session);
        persist_ticket_update(session, &ticket_id);
        if matches!(
            session.spec.scenario,
            WorkflowScenario::AuditHistory
                | WorkflowScenario::MutationIsolation
                | WorkflowScenario::StaleQueueReorder
        ) {
            append_history_entry(session, &ticket_id);
        }
        session.current_page = WorkflowPage::Confirmation;
        session.confirmation_seen = true;
        if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder) {
            session.queue_view_fresh = false;
        }
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/confirmation", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_cancel_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        reset_draft_from_saved_ticket(session, &session.active_ticket_id.clone());
        session.current_page = WorkflowPage::Queue;
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.queue_view_fresh = true;
        session.stale_queue_snapshot = None;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/queue", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn confirmation_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Confirmation;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Confirmation)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_history_page(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        session.current_page = WorkflowPage::History {
            ticket_id: ticket_id.clone(),
        };
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(
            session,
            &WorkflowPage::History {
                ticket_id: ticket_id.clone(),
            },
        )
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_reopen_submit(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        reset_draft_from_saved_ticket(session, &ticket_id);
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.queue_view_fresh = true;
        session.stale_queue_snapshot = None;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/tickets/{}", session_id, ticket_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn observe_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Json(payload): Json<WorkflowObservationPayload>,
) -> Json<serde_json::Value> {
    let _ = with_session(&state.sessions, &session_id, |session| {
        sync_bridge_state_from_observation(session, payload);
    });
    Json(json!({ "ok": true }))
}

fn with_session<T>(
    sessions: &Arc<Mutex<BTreeMap<String, WorkflowSession>>>,
    session_id: &str,
    f: impl FnOnce(&mut WorkflowSession) -> T,
) -> Option<T> {
    let mut guard = sessions.lock().ok()?;
    let session = guard.get_mut(session_id)?;
    Some(f(session))
}

fn apply_oracle_step(
    session: &mut WorkflowSession,
    kind: &str,
    arguments: serde_json::Value,
) -> Result<()> {
    match kind {
        "type_selector" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let text = arguments
                .get("text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#username" => session.login_username = text.to_string(),
                "#password" => session.login_password = text.to_string(),
                "#queue-search" => session.queue_search = text.to_string(),
                "#note" => session.draft_note = text.to_string(),
                _ => {}
            }
        }
        "select_label" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let label = arguments
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#assignee" => session.draft_assignee = label.to_string(),
                "#status" => session.draft_status = label.to_string(),
                "#queue-status-filter" => session.queue_status_filter = label.to_string(),
                "#queue-sort" => session.queue_sort = label.to_string(),
                _ => {}
            }
        }
        "click_selector" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#sign-in" => {
                    if session.login_username == session.spec.username
                        && session.login_password == session.spec.password
                    {
                        session.current_page = WorkflowPage::Queue;
                    }
                }
                "#apply-filters" => {
                    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
                        && session.confirmation_seen
                    {
                        session.queue_view_fresh = true;
                        session.stale_queue_snapshot = None;
                    }
                    session.current_page = WorkflowPage::Queue;
                }
                "#submit-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    persist_ticket_update(session, &ticket_id);
                    session.current_page = WorkflowPage::Confirmation;
                    session.reward = if ticket_id == session.spec.ticket_id
                        && session.draft_assignee == session.spec.assignee
                        && session.draft_note == session.spec.note
                    {
                        1.0
                    } else {
                        0.0
                    };
                    session.terminated = true;
                    session.truncated = false;
                }
                "#review-update" => {
                    session.current_page = WorkflowPage::Review;
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#edit-update" => {
                    session.current_page = WorkflowPage::Detail {
                        ticket_id: session.active_ticket_id.clone(),
                    };
                }
                "#confirm-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    capture_stale_queue_snapshot(session);
                    persist_ticket_update(session, &ticket_id);
                    if matches!(
                        session.spec.scenario,
                        WorkflowScenario::AuditHistory
                            | WorkflowScenario::MutationIsolation
                            | WorkflowScenario::StaleQueueReorder
                    ) {
                        append_history_entry(session, &ticket_id);
                    }
                    session.current_page = WorkflowPage::Confirmation;
                    session.confirmation_seen = true;
                    if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder) {
                        session.queue_view_fresh = false;
                    }
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#cancel-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    reset_draft_from_saved_ticket(session, &ticket_id);
                    session.current_page = WorkflowPage::Queue;
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.queue_view_fresh = true;
                    session.stale_queue_snapshot = None;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#history-link" => {
                    session.current_page = WorkflowPage::History {
                        ticket_id: session.active_ticket_id.clone(),
                    };
                }
                "#reopen-ticket" => {
                    let ticket_id = session.active_ticket_id.clone();
                    reset_draft_from_saved_ticket(session, &ticket_id);
                    session.current_page = WorkflowPage::Detail { ticket_id };
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.queue_view_fresh = true;
                    session.stale_queue_snapshot = None;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#queue-link" => {
                    session.current_page = WorkflowPage::Queue;
                }
                _ if ticket_id_for_history_selector(session, selector).is_some() => {
                    let ticket_id =
                        ticket_id_for_history_selector(session, selector).unwrap_or_default();
                    session.active_ticket_id = ticket_id.clone();
                    session.current_page = WorkflowPage::History { ticket_id };
                }
                _ if ticket_id_for_selector(session, selector).is_some() => {
                    let ticket_id = ticket_id_for_selector(session, selector).unwrap_or_default();
                    session.active_ticket_id = ticket_id.clone();
                    if let Some(ticket) = session.tickets.get(&ticket_id) {
                        session.draft_assignee = ticket.current_assignee.clone();
                        session.draft_status = ticket.current_status.clone();
                        session.draft_note = ticket.current_note.clone();
                    }
                    session.current_page = WorkflowPage::Detail { ticket_id };
                }
                _ => {}
            }
        }
        other => {
            return Err(anyhow!(
                "workflow oracle step '{}' is not implemented",
                other
            ))
        }
    }
    Ok(())
}

