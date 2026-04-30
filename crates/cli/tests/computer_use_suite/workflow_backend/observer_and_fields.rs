fn workflow_observer_script(report_path: &str) -> String {
    format!(
        r##"(function () {{
  const reportUrl = "{report_path}";
  function selectorFor(el) {{
    if (!el.id) return null;
    return "#" + CSS.escape(el.id);
  }}
  function isVisible(el) {{
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") {{
      return false;
    }}
    return el.getClientRects().length > 0 || el.tagName.toLowerCase() === "option";
  }}
  function textFor(el) {{
    const tag = el.tagName.toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") {{
      return "";
    }}
    return (el.innerText || el.textContent || "").trim();
  }}
  function collectInteractive() {{
    return Array.from(document.querySelectorAll("a[id],button[id],input[id],textarea[id],select[id]")).map((el) => {{
      const tag = el.tagName.toLowerCase();
      const selectedLabels = tag === "select"
        ? Array.from(el.selectedOptions || []).map((item) => (item.textContent || "").trim()).filter(Boolean)
        : [];
      const value = ("value" in el) ? String(el.value || "") : null;
      return {{
        tag,
        id: el.id || null,
        selector: selectorFor(el),
        center_x: null,
        center_y: null,
        name: el.getAttribute("name"),
        text: textFor(el),
        value,
        input_type: el.getAttribute("type"),
        checked: ("checked" in el) ? !!el.checked : null,
        selected_labels: selectedLabels,
        class_list: Array.from(el.classList || []),
        visible: isVisible(el),
        disabled: !!el.disabled
      }};
    }});
  }}
  function sendObservation() {{
    const active = document.activeElement;
    fetch(reportUrl, {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify({{
        page_url: window.location.href,
        focused_tag: active ? active.tagName.toLowerCase() : null,
        focused_id: active && active.id ? active.id : null,
        visible_text_excerpt: (document.body.innerText || "").trim().slice(0, 4000),
        interactive_elements: collectInteractive(),
        scroll_targets: [],
        dom_elements: []
      }})
    }}).catch(() => {{}});
  }}
  let timer = null;
  function scheduleObservation() {{
    if (timer !== null) {{
      window.clearTimeout(timer);
    }}
    timer = window.setTimeout(() => {{
      timer = null;
      sendObservation();
    }}, 30);
  }}
  document.addEventListener("DOMContentLoaded", scheduleObservation);
  window.addEventListener("load", scheduleObservation);
  document.addEventListener("input", scheduleObservation, true);
  document.addEventListener("change", scheduleObservation, true);
  document.addEventListener("focusin", scheduleObservation, true);
  document.addEventListener("click", () => window.setTimeout(scheduleObservation, 20), true);
  scheduleObservation();
}})();"##,
        report_path = report_path
    )
}

fn history_entries_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Vec<&'a WorkflowHistoryEntry> {
    session
        .history_entries
        .iter()
        .rev()
        .filter(|entry| entry.ticket_id == ticket_id)
        .collect()
}

fn saved_update_entries_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Vec<&'a WorkflowHistoryEntry> {
    history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .filter(|entry| entry.action == "Saved dispatch update")
        .collect()
}

fn latest_saved_update_entry_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Option<&'a WorkflowHistoryEntry> {
    saved_update_entries_for_ticket(session, ticket_id)
        .into_iter()
        .next()
}

fn latest_history_entry_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Option<&'a WorkflowHistoryEntry> {
    history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .next()
}

fn history_entry_matches_spec(session: &WorkflowSession, entry: &WorkflowHistoryEntry) -> bool {
    entry.ticket_id == session.spec.ticket_id
        && entry.actor == session.spec.username
        && entry.assignee == session.spec.assignee
        && entry.status == session.spec.status
        && entry.note == session.spec.note
}

fn target_history_entry(session: &WorkflowSession) -> Option<&WorkflowHistoryEntry> {
    latest_saved_update_entry_for_ticket(session, &session.spec.ticket_id)
        .filter(|entry| history_entry_matches_spec(session, entry))
}

fn distractor_saved_update_entry(session: &WorkflowSession) -> Option<&WorkflowHistoryEntry> {
    latest_saved_update_entry_for_ticket(session, &session.spec.distractor_ticket_id)
}

fn distractor_ticket_matches_spec(session: &WorkflowSession) -> bool {
    let Some(ticket) = session.tickets.get(&session.spec.distractor_ticket_id) else {
        return false;
    };
    ticket.current_assignee == session.spec.distractor_assignee
        && ticket.current_note == session.spec.distractor_note
        && ticket.current_status == session.spec.distractor_status
}

fn workflow_fields(session: &WorkflowSession) -> Vec<BridgeField> {
    let saved_target = session.tickets.get(&session.spec.ticket_id);
    let saved_distractor = session.tickets.get(&session.spec.distractor_ticket_id);
    let latest_history = latest_history_entry_for_ticket(session, &session.spec.ticket_id);
    let history_match = target_history_entry(session);
    let distractor_saved_update = distractor_saved_update_entry(session);
    let visible_tickets = visible_queue_tickets(session);
    let target_queue_position = visible_tickets
        .iter()
        .position(|ticket| ticket.ticket_id == session.spec.ticket_id)
        .map(|index| index + 1)
        .unwrap_or_default();
    let distractor_queue_position = visible_tickets
        .iter()
        .position(|ticket| ticket.ticket_id == session.spec.distractor_ticket_id)
        .map(|index| index + 1)
        .unwrap_or_default();
    vec![
        BridgeField {
            key: "workflow_case_id".to_string(),
            value: session.spec.case_id.clone(),
        },
        BridgeField {
            key: "workflow_scenario".to_string(),
            value: match session.spec.scenario {
                WorkflowScenario::TicketRouting => "ticket_routing".to_string(),
                WorkflowScenario::QueueVerification => "queue_verification".to_string(),
                WorkflowScenario::AuditHistory => "audit_history".to_string(),
                WorkflowScenario::MutationIsolation => "mutation_isolation".to_string(),
                WorkflowScenario::StaleQueueReorder => "stale_queue_reorder".to_string(),
            },
        },
        BridgeField {
            key: "username".to_string(),
            value: session.spec.username.clone(),
        },
        BridgeField {
            key: "password".to_string(),
            value: session.spec.password.clone(),
        },
        BridgeField {
            key: "ticket_id".to_string(),
            value: session.spec.ticket_id.clone(),
        },
        BridgeField {
            key: "assignee".to_string(),
            value: session.spec.assignee.clone(),
        },
        BridgeField {
            key: "note".to_string(),
            value: session.spec.note.clone(),
        },
        BridgeField {
            key: "status".to_string(),
            value: session.spec.status.clone(),
        },
        BridgeField {
            key: "queue_search".to_string(),
            value: session.spec.queue_search.clone(),
        },
        BridgeField {
            key: "queue_status_filter".to_string(),
            value: session.spec.queue_status_filter.clone(),
        },
        BridgeField {
            key: "queue_sort".to_string(),
            value: session.spec.queue_sort.clone(),
        },
        BridgeField {
            key: "post_confirm_queue_sort".to_string(),
            value: session.spec.post_confirm_queue_sort.clone(),
        },
        BridgeField {
            key: "distractor_ticket_id".to_string(),
            value: session.spec.distractor_ticket_id.clone(),
        },
        BridgeField {
            key: "distractor_assignee".to_string(),
            value: session.spec.distractor_assignee.clone(),
        },
        BridgeField {
            key: "distractor_status".to_string(),
            value: session.spec.distractor_status.clone(),
        },
        BridgeField {
            key: "distractor_note".to_string(),
            value: session.spec.distractor_note.clone(),
        },
        BridgeField {
            key: "current_username".to_string(),
            value: session.login_username.clone(),
        },
        BridgeField {
            key: "current_password".to_string(),
            value: session.login_password.clone(),
        },
        BridgeField {
            key: "current_queue_search".to_string(),
            value: session.queue_search.clone(),
        },
        BridgeField {
            key: "current_queue_status_filter".to_string(),
            value: session.queue_status_filter.clone(),
        },
        BridgeField {
            key: "current_queue_sort".to_string(),
            value: session.queue_sort.clone(),
        },
        BridgeField {
            key: "queue_view_search".to_string(),
            value: queue_view_search(session).to_string(),
        },
        BridgeField {
            key: "queue_view_status_filter".to_string(),
            value: queue_view_status_filter(session).to_string(),
        },
        BridgeField {
            key: "queue_view_sort".to_string(),
            value: queue_view_sort(session).to_string(),
        },
        BridgeField {
            key: "queue_view_fresh".to_string(),
            value: session.queue_view_fresh.to_string(),
        },
        BridgeField {
            key: "active_ticket_id".to_string(),
            value: session.active_ticket_id.clone(),
        },
        BridgeField {
            key: "current_assignee".to_string(),
            value: session.draft_assignee.clone(),
        },
        BridgeField {
            key: "current_status".to_string(),
            value: session.draft_status.clone(),
        },
        BridgeField {
            key: "current_note".to_string(),
            value: session.draft_note.clone(),
        },
        BridgeField {
            key: "saved_assignee".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_status".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_note".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "confirmation_seen".to_string(),
            value: session.confirmation_seen.to_string(),
        },
        BridgeField {
            key: "queue_verified".to_string(),
            value: session.queue_verified.to_string(),
        },
        BridgeField {
            key: "history_verified".to_string(),
            value: session.history_verified.to_string(),
        },
        BridgeField {
            key: "distractor_history_verified".to_string(),
            value: session.distractor_history_verified.to_string(),
        },
        BridgeField {
            key: "history_event_exists".to_string(),
            value: history_match.is_some().to_string(),
        },
        BridgeField {
            key: "history_event_ticket_id".to_string(),
            value: latest_history
                .map(|entry| entry.ticket_id.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_actor".to_string(),
            value: latest_history
                .map(|entry| entry.actor.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_action".to_string(),
            value: latest_history
                .map(|entry| entry.action.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_assignee".to_string(),
            value: latest_history
                .map(|entry| entry.assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_status".to_string(),
            value: latest_history
                .map(|entry| entry.status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_note".to_string(),
            value: latest_history
                .map(|entry| entry.note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_count".to_string(),
            value: saved_update_entries_for_ticket(session, &session.spec.ticket_id)
                .len()
                .to_string(),
        },
        BridgeField {
            key: "saved_target_matches".to_string(),
            value: target_ticket_matches_spec(session).to_string(),
        },
        BridgeField {
            key: "target_queue_position".to_string(),
            value: target_queue_position.to_string(),
        },
        BridgeField {
            key: "distractor_queue_position".to_string(),
            value: distractor_queue_position.to_string(),
        },
        BridgeField {
            key: "queue_target_precedes_distractor".to_string(),
            value: (target_queue_position > 0
                && distractor_queue_position > 0
                && target_queue_position < distractor_queue_position)
                .to_string(),
        },
        BridgeField {
            key: "saved_distractor_assignee".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_status".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_note".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_matches".to_string(),
            value: distractor_ticket_matches_spec(session).to_string(),
        },
        BridgeField {
            key: "distractor_saved_update_exists".to_string(),
            value: distractor_saved_update.is_some().to_string(),
        },
        BridgeField {
            key: "distractor_saved_update_count".to_string(),
            value: saved_update_entries_for_ticket(session, &session.spec.distractor_ticket_id)
                .len()
                .to_string(),
        },
        BridgeField {
            key: "current_page_kind".to_string(),
            value: match session.current_page {
                WorkflowPage::Login => "login".to_string(),
                WorkflowPage::Queue => "queue".to_string(),
                WorkflowPage::Detail { .. } => "detail".to_string(),
                WorkflowPage::Review => "review".to_string(),
                WorkflowPage::Confirmation => "confirmation".to_string(),
                WorkflowPage::History { .. } => "history".to_string(),
            },
        },
    ]
}

fn workflow_visible_text(session: &WorkflowSession, page: &WorkflowPage) -> String {
    match page {
        WorkflowPage::Login => {
            format!(
                "Dispatch Console Sign in to continue. {}",
                session.spec.instruction
            )
        }
        WorkflowPage::Queue => {
            let rows = visible_queue_tickets(session)
                .into_iter()
                .map(|ticket| {
                    format!(
                        "{} {} {} {}",
                        ticket.ticket_id,
                        ticket.title,
                        ticket.current_status,
                        display_assignee(&ticket.current_assignee)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "Active dispatch queue. Search {}. Filter {}. Sort {}. Queue view fresh {}. Visible tickets {}. {}",
                queue_view_search(session),
                queue_view_status_filter(session),
                queue_view_sort(session),
                session.queue_view_fresh,
                rows,
                session.spec.instruction
            )
        }
        WorkflowPage::Detail { ticket_id } => format!(
            "Ticket {}. Assign team {}. Ticket status {}. Dispatch note {}. {}",
            ticket_id, session.draft_assignee, session.draft_status, session.draft_note, session.spec.instruction
        ),
        WorkflowPage::Review => format!(
            "Review queued update. Ticket {}. Draft assignee {}. Draft status {}. Draft note {}. {}",
            session.active_ticket_id, session.draft_assignee, session.draft_status, session.draft_note, session.spec.instruction
        ),
        WorkflowPage::Confirmation => {
            let saved_ticket = session
                .tickets
                .get(&session.active_ticket_id)
                .or_else(|| session.tickets.get(&session.spec.ticket_id));
            let saved_assignee = saved_ticket
                .map(|ticket| display_assignee(&ticket.current_assignee))
                .unwrap_or_else(|| "Unassigned".to_string());
            let saved_status = saved_ticket
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            let saved_note = saved_ticket
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default();
            format!(
                "Assignment confirmation. Ticket {} routed to {}. Saved status {}. Saved note {}. Queue verified {}. History verified {}. Distractor history verified {}. {}",
                session.active_ticket_id,
                saved_assignee,
                saved_status,
                saved_note,
                session.queue_verified,
                session.history_verified,
                session.distractor_history_verified,
                session.spec.instruction
            )
        }
        WorkflowPage::History { ticket_id } => {
            let entries = history_entries_for_ticket(session, ticket_id)
                .into_iter()
                .map(|entry| {
                    format!(
                        "{} {} {} {} {}",
                        entry.ticket_id, entry.actor, entry.assignee, entry.status, entry.note
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "Audit history for ticket {}. Entries {}. History verified {}. {}",
                ticket_id, entries, session.history_verified, session.spec.instruction
            )
        }
    }
}

fn synthesized_interactive_elements(
    session: &WorkflowSession,
    page: &WorkflowPage,
) -> Vec<BridgeInteractiveElement> {
    match page {
        WorkflowPage::Login => vec![
            text_input("#username", "username", &session.login_username),
            password_input("#password", "password", &session.login_password),
            button("#sign-in", "Sign in"),
        ],
        WorkflowPage::Queue => {
            let mut elements = match session.spec.scenario {
                WorkflowScenario::TicketRouting => Vec::new(),
                WorkflowScenario::QueueVerification
                | WorkflowScenario::AuditHistory
                | WorkflowScenario::MutationIsolation => vec![
                    text_input("#queue-search", "search", &session.queue_search),
                    select_input_named(
                        "#queue-status-filter",
                        "status",
                        &session.queue_status_filter,
                    ),
                    button("#apply-filters", "Apply filters"),
                ],
                WorkflowScenario::StaleQueueReorder => vec![
                    text_input("#queue-search", "search", &session.queue_search),
                    select_input_named(
                        "#queue-status-filter",
                        "status",
                        &session.queue_status_filter,
                    ),
                    select_input_named("#queue-sort", "sort", &session.queue_sort),
                    button("#apply-filters", "Apply filters"),
                ],
            };
            elements.extend(
                visible_queue_tickets(session)
                    .into_iter()
                    .flat_map(|ticket| {
                        let mut row_links = vec![link(
                            &ticket_link_selector(&ticket.ticket_id),
                            &ticket.ticket_id,
                        )];
                        if matches!(
                            session.spec.scenario,
                            WorkflowScenario::MutationIsolation
                                | WorkflowScenario::StaleQueueReorder
                        ) {
                            row_links.push(link(
                                &ticket_history_link_selector(&ticket.ticket_id),
                                "History",
                            ));
                        }
                        row_links
                    }),
            );
            elements
        }
        WorkflowPage::Detail { ticket_id } => {
            vec![
                link("#queue-link", "Queue"),
                select_input("#assignee", &session.draft_assignee),
                select_input_named("#status", "status", &session.draft_status),
                text_area("#note", &session.draft_note),
                button(
                    match session.spec.scenario {
                        WorkflowScenario::TicketRouting => "#submit-update",
                        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
                            "#review-update"
                        }
                        WorkflowScenario::MutationIsolation
                        | WorkflowScenario::StaleQueueReorder => "#review-update",
                    },
                    match session.spec.scenario {
                        WorkflowScenario::TicketRouting => "Submit update",
                        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
                            "Review update"
                        }
                        WorkflowScenario::MutationIsolation
                        | WorkflowScenario::StaleQueueReorder => "Review update",
                    },
                ),
                link(&ticket_link_selector(ticket_id), ticket_id),
            ]
        }
        WorkflowPage::Review => {
            let mut elements = vec![
                link("#queue-link", "Queue"),
                button("#edit-update", "Edit draft"),
                button("#confirm-update", "Confirm update"),
            ];
            if matches!(
                session.spec.scenario,
                WorkflowScenario::AuditHistory
                    | WorkflowScenario::MutationIsolation
                    | WorkflowScenario::StaleQueueReorder
            ) {
                elements.push(button("#cancel-update", "Cancel draft"));
            }
            elements
        }
        WorkflowPage::Confirmation => {
            let mut elements = vec![link("#queue-link", "Queue")];
            if matches!(
                session.spec.scenario,
                WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
            ) {
                elements.push(link("#history-link", "Open audit history"));
                elements.push(button("#reopen-ticket", "Reopen ticket"));
            } else if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder) {
                elements.push(button("#reopen-ticket", "Reopen ticket"));
            }
            elements
        }
        WorkflowPage::History { .. } => vec![
            link("#queue-link", "Queue"),
            link("#confirmation-link", "Confirmation"),
            button("#reopen-ticket", "Reopen ticket"),
        ],
    }
    .into_iter()
    .map(|mut element| {
        if matches!(page, WorkflowPage::Queue)
            && element.selector.as_deref()
                == Some(ticket_link_selector(&session.spec.ticket_id).as_str())
        {
            element.class_list.push("target-ticket".to_string());
        }
        element
    })
    .collect()
}

fn current_page_url(session: &WorkflowSession) -> String {
    match &session.current_page {
        WorkflowPage::Login => format!(
            "{}/workflow/{}/login",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Queue => format!(
            "{}/workflow/{}/queue",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Detail { ticket_id } => format!(
            "{}/workflow/{}/tickets/{}",
            session.base_url, session.bridge_state.session_id, ticket_id
        ),
        WorkflowPage::Review => format!(
            "{}/workflow/{}/review",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Confirmation => format!(
            "{}/workflow/{}/confirmation",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::History { ticket_id } => format!(
            "{}/workflow/{}/tickets/{}/history",
            session.base_url, session.bridge_state.session_id, ticket_id
        ),
    }
}

fn page_from_url(url: &str) -> Option<WorkflowPage> {
    if url.contains("/login") {
        return Some(WorkflowPage::Login);
    }
    if url.contains("/queue") {
        return Some(WorkflowPage::Queue);
    }
    if url.contains("/review") {
        return Some(WorkflowPage::Review);
    }
    if url.contains("/confirmation") {
        return Some(WorkflowPage::Confirmation);
    }
    let marker = "/tickets/";
    let start = url.find(marker)? + marker.len();
    let ticket_id = url[start..]
        .split('/')
        .next()
        .filter(|value| !value.is_empty())?;
    if url.contains("/history") {
        return Some(WorkflowPage::History {
            ticket_id: ticket_id.to_string(),
        });
    }
    Some(WorkflowPage::Detail {
        ticket_id: ticket_id.to_string(),
    })
}

