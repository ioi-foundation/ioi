fn render_page_html(session: &WorkflowSession, page: &WorkflowPage) -> String {
    let body = match page {
        WorkflowPage::Login => render_login_body(session),
        WorkflowPage::Queue => render_queue_body(session),
        WorkflowPage::Detail { ticket_id } => render_detail_body(session, ticket_id),
        WorkflowPage::Review => render_review_body(session),
        WorkflowPage::Confirmation => render_confirmation_body(session),
        WorkflowPage::History { ticket_id } => render_history_body(session, ticket_id),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dispatch Console</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f4f6fb; color: #172033; }}
    main {{ max-width: 960px; margin: 32px auto; padding: 24px; }}
    .shell {{ background: #fff; border: 1px solid #d4dceb; border-radius: 16px; box-shadow: 0 8px 24px rgba(23, 32, 51, 0.08); overflow: hidden; }}
    .topbar {{ padding: 18px 24px; background: linear-gradient(135deg, #183153, #2855a1); color: #fff; }}
    .content {{ padding: 24px; }}
    .breadcrumbs {{ font-size: 14px; color: #516178; margin-bottom: 16px; }}
    .grid {{ display: grid; gap: 16px; }}
    .two-col {{ grid-template-columns: 1.2fr 0.8fr; }}
    .panel {{ border: 1px solid #d4dceb; border-radius: 12px; padding: 16px; background: #fbfcff; }}
    .inline-actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .inline-form {{ margin: 0; }}
    label {{ display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; }}
    input, textarea, select {{ width: 100%; box-sizing: border-box; margin-bottom: 14px; border: 1px solid #b9c6db; border-radius: 10px; padding: 10px 12px; font: inherit; }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button, .button-link {{ display: inline-block; border: none; border-radius: 999px; padding: 10px 16px; background: #1f6feb; color: #fff; font: inherit; cursor: pointer; text-decoration: none; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e2e8f3; text-align: left; }}
    code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
    .status-pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #e4eefc; color: #1f4f96; font-size: 12px; font-weight: 700; }}
    .success {{ background: #e7f8ee; color: #19663e; }}
    .muted {{ color: #607086; }}
  </style>
</head>
<body>
  <main>
    <section class="shell">
      <div class="topbar">
        <strong>Dispatch Console</strong>
        <div>Deterministic workflow benchmark fixture</div>
      </div>
      <div class="content">
        {body}
      </div>
    </section>
  </main>
  <script>{script}</script>
</body>
</html>"#,
        body = body,
        script = workflow_observer_script(&format!(
            "/workflow/{}/observe",
            session.bridge_state.session_id
        ))
    )
}

fn render_login_body(session: &WorkflowSession) -> String {
    format!(
        r#"<div class="breadcrumbs">Login</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Sign in to continue</h1>
    <p>Use your dispatch credentials to continue to the ticket queue.</p>
    <form action="/workflow/{session_id}/login" method="post">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="off" value="{username}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="off" value="{password}">
      <button id="sign-in" type="submit">Sign in</button>
    </form>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 1</span> Authenticate before opening the queue.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        username = escape_html(&session.login_username),
        password = escape_html(&session.login_password),
        instruction = escape_html(&session.spec.instruction),
    )
}

fn render_queue_body(session: &WorkflowSession) -> String {
    match session.spec.scenario {
        WorkflowScenario::TicketRouting => render_ticket_routing_queue_body(session),
        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
            render_queue_verification_queue_body(session)
        }
        WorkflowScenario::MutationIsolation => render_mutation_isolation_queue_body(session),
        WorkflowScenario::StaleQueueReorder => render_stale_queue_reorder_queue_body(session),
    }
}

fn render_ticket_routing_queue_body(session: &WorkflowSession) -> String {
    let rows = visible_queue_tickets(session)
        .into_iter()
        .map(|ticket| render_queue_row(session, ticket))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Active dispatch queue</h1>
    <p>Open the ticket that matches the task brief, then update the assignment.</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Open <code>{ticket_id}</code> from the queue.</p>
  </aside>
</div>"#,
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        ticket_id = escape_html(&session.spec.ticket_id),
    )
}

fn render_queue_verification_queue_body(session: &WorkflowSession) -> String {
    let visible_tickets = visible_queue_tickets(session);
    let rows = if visible_tickets.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">No tickets matched the current queue search and filter.</td></tr>"
            .to_string()
    } else {
        visible_tickets
            .into_iter()
            .map(|ticket| render_queue_row(session, ticket))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let queue_hint = if session.queue_search.trim().is_empty() {
        "Search is required to reveal the full queue; blank search only shows the first two filtered rows."
    } else if matches!(session.spec.scenario, WorkflowScenario::AuditHistory)
        && session.history_verified
    {
        "Audit history verification completed from typed saved-event state."
    } else if session.queue_verified {
        "Queue verification completed from typed queue state."
    } else {
        "Apply the queue search and filter before opening the target ticket."
    };
    let heading = if matches!(session.spec.scenario, WorkflowScenario::AuditHistory) {
        "Dispatch audit queue"
    } else {
        "Dispatch verification queue"
    };
    let description = if matches!(session.spec.scenario, WorkflowScenario::AuditHistory) {
        "Search and filter the queue to reveal the target ticket while distractors remain visible, then confirm the saved update on the audit history page."
    } else {
        "Search and filter the queue to reveal the target ticket, then confirm the saved update survives navigation back to the queue."
    };
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>{heading}</h1>
    <p>{description}</p>
    <form action="/workflow/{session_id}/queue/filter" method="post">
      <label for="queue-search">Queue search</label>
      <input id="queue-search" name="search" type="text" autocomplete="off" value="{search}">
      <label for="queue-status-filter">Queue status filter</label>
      <select id="queue-status-filter" name="status">
        {status_options}
      </select>
      <button id="apply-filters" type="submit">Apply filters</button>
    </form>
    <p class="muted">{queue_hint}</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Search for <code>{queue_search}</code> and set the queue filter to <code>{queue_filter}</code> before opening <code>{ticket_id}</code>.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        heading = heading,
        description = description,
        search = escape_html(&session.queue_search),
        status_options = render_queue_status_filter_options(&session.queue_status_filter),
        queue_hint = escape_html(queue_hint),
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        queue_search = escape_html(&session.spec.queue_search),
        queue_filter = escape_html(&session.spec.queue_status_filter),
        ticket_id = escape_html(&session.spec.ticket_id),
    )
}

fn render_queue_row(session: &WorkflowSession, ticket: &WorkflowTicketRecord) -> String {
    format!(
        r#"<tr>
  <td><a id="{link_id}" href="/workflow/{session_id}/tickets/{ticket_id}">{ticket_id}</a></td>
  <td>{title}</td>
  <td>{status}</td>
  <td>{assignee}</td>
  <td>{owner}</td>
</tr>"#,
        link_id = ticket_link_id(&ticket.ticket_id),
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket.ticket_id),
        title = escape_html(&ticket.title),
        status = escape_html(&ticket.current_status),
        assignee = escape_html(&display_assignee(&ticket.current_assignee)),
        owner = escape_html(&ticket.suggested_team),
    )
}

fn render_mutation_queue_row(session: &WorkflowSession, ticket: &WorkflowTicketRecord) -> String {
    format!(
        r#"<tr>
  <td><a id="{detail_link_id}" href="/workflow/{session_id}/tickets/{ticket_id}">{ticket_id}</a></td>
  <td>{title}</td>
  <td>{status}</td>
  <td>{assignee}</td>
  <td>{owner}</td>
  <td><a id="{history_link_id}" href="/workflow/{session_id}/tickets/{ticket_id}/history">History</a></td>
</tr>"#,
        detail_link_id = ticket_link_id(&ticket.ticket_id),
        history_link_id = ticket_history_link_id(&ticket.ticket_id),
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket.ticket_id),
        title = escape_html(&ticket.title),
        status = escape_html(&ticket.current_status),
        assignee = escape_html(&display_assignee(&ticket.current_assignee)),
        owner = escape_html(&ticket.suggested_team),
    )
}

fn render_mutation_isolation_queue_body(session: &WorkflowSession) -> String {
    let visible_tickets = visible_queue_tickets(session);
    let rows = if visible_tickets.is_empty() {
        "<tr><td colspan=\"6\" class=\"muted\">No tickets matched the current queue search and filter.</td></tr>"
            .to_string()
    } else {
        visible_tickets
            .into_iter()
            .map(|ticket| render_mutation_queue_row(session, ticket))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let queue_hint = if session.queue_search.trim().is_empty() {
        "Search is required to reveal the ambiguous target and distractor tickets."
    } else if session.queue_verified {
        "Typed queue verification confirmed the target changed and the distractor remained unchanged."
    } else {
        "Keep multiple similar tickets visible, then verify the target changed while the distractor did not."
    };
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Dispatch mutation-isolation queue</h1>
    <p>Keep multiple similar tickets visible, mutate only the requested target, then verify target and distractor outcomes separately from queue and history state.</p>
    <form action="/workflow/{session_id}/queue/filter" method="post">
      <label for="queue-search">Queue search</label>
      <input id="queue-search" name="search" type="text" autocomplete="off" value="{search}">
      <label for="queue-status-filter">Queue status filter</label>
      <select id="queue-status-filter" name="status">
        {status_options}
      </select>
      <button id="apply-filters" type="submit">Apply filters</button>
    </form>
    <p class="muted">{queue_hint}</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th><th>Audit</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Search for <code>{queue_search}</code>, keep the queue filter on <code>{queue_filter}</code>, and leave both <code>{target_ticket}</code> and distractor <code>{distractor_ticket}</code> available for typed verification.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        search = escape_html(&session.queue_search),
        status_options = render_queue_status_filter_options(&session.queue_status_filter),
        queue_hint = escape_html(queue_hint),
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        queue_search = escape_html(&session.spec.queue_search),
        queue_filter = escape_html(&session.spec.queue_status_filter),
        target_ticket = escape_html(&session.spec.ticket_id),
        distractor_ticket = escape_html(&session.spec.distractor_ticket_id),
    )
}

fn render_stale_queue_reorder_queue_body(session: &WorkflowSession) -> String {
    let visible_tickets = visible_queue_tickets(session);
    let rows = if visible_tickets.is_empty() {
        "<tr><td colspan=\"6\" class=\"muted\">No tickets matched the current queue view.</td></tr>"
            .to_string()
    } else {
        visible_tickets
            .into_iter()
            .map(|ticket| render_mutation_queue_row(session, ticket))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let queue_hint = if !session.confirmation_seen {
        "Open the target while the queue still shows the original Ticket ID order."
    } else if !session.queue_view_fresh {
        "This queue view is stale. Reapply the queue controls before trusting the row order or saved state."
    } else if session.queue_verified {
        "Typed queue verification confirmed the target moved above the distractor after refresh while the distractor stayed unchanged."
    } else {
        "Switch the queue sort to Recently Updated, refresh the queue, and verify the target reordered above the distractor."
    };
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Dispatch stale queue reorder</h1>
    <p>Return to the queue after saving, refresh the stale view, then prove the target moved ahead of the distractor in the refreshed queue while the distractor remained unchanged.</p>
    <form action="/workflow/{session_id}/queue/filter" method="post">
      <label for="queue-search">Queue search</label>
      <input id="queue-search" name="search" type="text" autocomplete="off" value="{search}">
      <label for="queue-status-filter">Queue status filter</label>
      <select id="queue-status-filter" name="status">
        {status_options}
      </select>
      <label for="queue-sort">Queue sort</label>
      <select id="queue-sort" name="sort">
        {sort_options}
      </select>
      <button id="apply-filters" type="submit">Apply filters</button>
    </form>
    <p class="muted">{queue_hint}</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th><th>Audit</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Start from the original <code>{queue_sort}</code> order, then after saving switch to <code>{post_confirm_queue_sort}</code> and refresh before accepting the queue as evidence.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        search = escape_html(&session.queue_search),
        status_options = render_queue_status_filter_options(&session.queue_status_filter),
        sort_options = render_queue_sort_options(&session.queue_sort),
        queue_hint = escape_html(queue_hint),
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        queue_sort = escape_html(&session.spec.queue_sort),
        post_confirm_queue_sort = escape_html(&session.spec.post_confirm_queue_sort),
    )
}

fn render_detail_body(session: &WorkflowSession, ticket_id: &str) -> String {
    let ticket = session.tickets.get(ticket_id);
    let ticket_summary = ticket
        .map(|ticket| {
            format!(
                "{} / suggested team: {} / current status: {} / current assignee: {}",
                ticket.title,
                ticket.suggested_team,
                ticket.current_status,
                display_assignee(&ticket.current_assignee)
            )
        })
        .unwrap_or_else(|| "Untracked ticket".to_string());
    let submit_id = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "submit-update",
        WorkflowScenario::QueueVerification
        | WorkflowScenario::AuditHistory
        | WorkflowScenario::MutationIsolation
        | WorkflowScenario::StaleQueueReorder => "review-update",
    };
    let submit_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "Submit update",
        WorkflowScenario::QueueVerification
        | WorkflowScenario::AuditHistory
        | WorkflowScenario::MutationIsolation
        | WorkflowScenario::StaleQueueReorder => "Review update",
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => {
            "Save the requested assignee and note."
        }
        WorkflowScenario::QueueVerification => {
            "Prepare the requested assignee, status, and note before review."
        }
        WorkflowScenario::AuditHistory => {
            "Prepare the requested assignee, status, and note before review, then verify the persisted audit event."
        }
        WorkflowScenario::MutationIsolation => {
            "Prepare the requested assignee, status, and note for the target ticket only. Cancel if the wrong ticket or a stale draft is open."
        }
        WorkflowScenario::StaleQueueReorder => {
            "Prepare the requested assignee, status, and note for the target ticket only. Reopen later if the saved ticket is wrong or the post-save queue proof stays stale."
        }
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Ticket {ticket_id}</div>
<div class="grid two-col">
  <section class="panel">
    <h1 id="ticket-title">Ticket {ticket_id}</h1>
    <p>{summary}</p>
    <form action="/workflow/{session_id}/tickets/{ticket_id}/assign" method="post">
      <label for="assignee">Assign team</label>
      <select id="assignee" name="assignee">
        {options}
      </select>
      <label for="status">Ticket status</label>
      <select id="status" name="status">
        {status_options}
      </select>
      <label for="note">Dispatch note</label>
      <textarea id="note" name="note">{note}</textarea>
      <button id="{submit_id}" type="submit">{submit_text}</button>
    </form>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 3</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(ticket_id),
        summary = escape_html(&ticket_summary),
        options = render_assignee_options(&session.draft_assignee),
        status_options = render_status_options(&session.draft_status),
        note = escape_html(&session.draft_note),
        submit_id = submit_id,
        submit_text = submit_text,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_review_body(session: &WorkflowSession) -> String {
    let ticket_id = session.active_ticket_id.clone();
    let recovery_actions = if matches!(
        session.spec.scenario,
        WorkflowScenario::AuditHistory
            | WorkflowScenario::MutationIsolation
            | WorkflowScenario::StaleQueueReorder
    ) {
        format!(
            r#"
      <form class="inline-form" action="/workflow/{session_id}/review/cancel" method="post">
        <button id="cancel-update" type="submit">Cancel draft</button>
      </form>"#,
            session_id = session.bridge_state.session_id,
        )
    } else {
        String::new()
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::AuditHistory => {
            "Review the draft and confirm it only if the ticket, assignee, status, and note match the request. Cancel the draft if anything is stale or wrong."
        }
        WorkflowScenario::MutationIsolation => {
            "Review the draft and confirm it only if the target ticket, assignee, status, and note match the request. Cancel the draft if the wrong ticket is open or the draft is stale."
        }
        WorkflowScenario::StaleQueueReorder => {
            "Review the draft and confirm it only if the target ticket, assignee, status, and note match the request. Cancel the draft if the wrong ticket is open or the draft is stale."
        }
        WorkflowScenario::TicketRouting | WorkflowScenario::QueueVerification => {
            "Review the draft and confirm it only if the ticket, assignee, status, and note match the request."
        }
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Review draft</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Review queued update</h1>
    <p id="review-ticket">Ticket <strong>{ticket_id}</strong></p>
    <p id="review-assignee">Draft assignee: <strong>{assignee}</strong></p>
    <p id="review-status">Draft status: <strong>{status}</strong></p>
    <p id="review-note">Draft note: {note}</p>
    <div class="inline-actions">
      <form class="inline-form" action="/workflow/{session_id}/review/edit" method="post">
        <button id="edit-update" type="submit">Edit draft</button>
      </form>
      <form class="inline-form" action="/workflow/{session_id}/review/confirm" method="post">
        <button id="confirm-update" type="submit">Confirm update</button>
      </form>
      {recovery_actions}
    </div>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 4</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket_id),
        assignee = escape_html(&session.draft_assignee),
        status = escape_html(&session.draft_status),
        note = escape_html(&session.draft_note),
        recovery_actions = recovery_actions,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_confirmation_body(session: &WorkflowSession) -> String {
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
    let success = match session.spec.scenario {
        WorkflowScenario::TicketRouting => (session.reward - 1.0).abs() < f32::EPSILON,
        WorkflowScenario::QueueVerification => session.queue_verified,
        WorkflowScenario::AuditHistory => session.history_verified,
        WorkflowScenario::MutationIsolation => {
            session.queue_verified
                && session.history_verified
                && session.distractor_history_verified
        }
        WorkflowScenario::StaleQueueReorder => {
            session.queue_verified && session.distractor_history_verified
        }
    };
    let status_class = if success {
        "status-pill success"
    } else {
        "status-pill"
    };
    let status_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting if success => "Saved and verified",
        WorkflowScenario::TicketRouting => "Saved with validation mismatch",
        WorkflowScenario::QueueVerification if success => "Saved and queue-verified",
        WorkflowScenario::QueueVerification => "Saved, queue verification pending",
        WorkflowScenario::AuditHistory if success => "Saved and audit-verified",
        WorkflowScenario::AuditHistory => "Saved, audit verification pending",
        WorkflowScenario::MutationIsolation if success => {
            "Saved and cross-ticket isolation verified"
        }
        WorkflowScenario::MutationIsolation => {
            "Saved, cross-ticket queue/history verification pending"
        }
        WorkflowScenario::StaleQueueReorder if success => "Saved, refreshed, and reorder-verified",
        WorkflowScenario::StaleQueueReorder => {
            "Saved, queue refresh or distractor verification pending"
        }
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "Confirmation page reached.",
        WorkflowScenario::QueueVerification => {
            "Return to the queue and verify the persisted assignee and status."
        }
        WorkflowScenario::AuditHistory => {
            "Open the audit history and verify the persisted update. Reopen the ticket if the saved event is wrong."
        }
        WorkflowScenario::MutationIsolation => {
            "Verify the queue still isolates the target from the distractor, then verify target and distractor audit histories separately. Reopen or cancel if the draft or saved target state is wrong."
        }
        WorkflowScenario::StaleQueueReorder => {
            "Return to the queue, refresh the stale view, switch to Recently Updated, verify the target moved above the distractor, then open distractor audit history and confirm no saved update exists."
        }
    };
    let followup_actions = if matches!(
        session.spec.scenario,
        WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
    ) {
        format!(
            r#"
    <div class="inline-actions">
      <a id="history-link" class="button-link" href="/workflow/{session_id}/tickets/{ticket_id}/history">Open audit history</a>
      <form class="inline-form" action="/workflow/{session_id}/tickets/{ticket_id}/reopen" method="post">
        <button id="reopen-ticket" type="submit">Reopen ticket</button>
      </form>
    </div>"#,
            session_id = session.bridge_state.session_id,
            ticket_id = escape_html(&session.active_ticket_id),
        )
    } else if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder) {
        format!(
            r#"
    <div class="inline-actions">
      <form class="inline-form" action="/workflow/{session_id}/tickets/{ticket_id}/reopen" method="post">
        <button id="reopen-ticket" type="submit">Reopen ticket</button>
      </form>
    </div>"#,
            session_id = session.bridge_state.session_id,
            ticket_id = escape_html(&session.active_ticket_id),
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Confirmation</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Assignment confirmation</h1>
    <p><span id="save-status" class="{status_class}">{status_text}</span></p>
    <p id="assignment-banner">Ticket <strong>{ticket_id}</strong> was routed to <strong>{assignee}</strong>.</p>
    <p id="status-summary">Saved status: {status}</p>
    <p id="note-summary">Saved note: {note}</p>
    {followup_actions}
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 5</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        status_class = status_class,
        status_text = status_text,
        ticket_id = escape_html(&session.active_ticket_id),
        assignee = escape_html(&saved_assignee),
        status = escape_html(&saved_status),
        note = escape_html(&saved_note),
        followup_actions = followup_actions,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_history_body(session: &WorkflowSession, ticket_id: &str) -> String {
    let rows = history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .map(|entry| {
            format!(
                r#"<tr>
  <td>{actor}</td>
  <td>{action}</td>
  <td>{assignee}</td>
  <td>{status}</td>
  <td>{note}</td>
</tr>"#,
                actor = escape_html(&entry.actor),
                action = escape_html(&entry.action),
                assignee = escape_html(&display_assignee(&entry.assignee)),
                status = escape_html(&entry.status),
                note = escape_html(&entry.note),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let body_rows = if rows.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">No persisted audit events are available for this ticket yet.</td></tr>"
            .to_string()
    } else {
        rows
    };
    let audit_status = if session.history_verified {
        "Typed audit verification complete."
    } else if matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        && ticket_id == session.spec.distractor_ticket_id
    {
        "Verify that this distractor history still lacks a saved dispatch update."
    } else if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && ticket_id == session.spec.distractor_ticket_id
    {
        "Verify that the surviving distractor still has no saved dispatch update."
    } else {
        "Verify that the saved dispatch event matches the requested ticket, assignee, status, and note."
    };
    let step_text = if matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        && ticket_id == session.spec.distractor_ticket_id
    {
        format!(
            "Stop only after typed verification confirms ticket <code>{}</code> still has no saved dispatch update. Reopen the target if the saved target state is wrong.",
            escape_html(ticket_id)
        )
    } else if matches!(session.spec.scenario, WorkflowScenario::StaleQueueReorder)
        && ticket_id == session.spec.distractor_ticket_id
    {
        format!(
            "Stop only after typed verification confirms distractor ticket <code>{}</code> still has no saved dispatch update. Reopen the target if the saved target state is wrong.",
            escape_html(ticket_id)
        )
    } else {
        format!(
            "Stop only after this audit history shows the saved event for ticket <code>{}</code>. Reopen the ticket if the saved event is wrong.",
            escape_html(ticket_id)
        )
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / <a id="confirmation-link" href="/workflow/{session_id}/confirmation">Confirmation</a> / Audit history</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Audit history for ticket {ticket_id}</h1>
    <p id="history-status" class="muted">{audit_status}</p>
    <table>
      <thead>
        <tr><th>Actor</th><th>Action</th><th>Assignee</th><th>Status</th><th>Note</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <div class="inline-actions">
      <form class="inline-form" action="/workflow/{session_id}/tickets/{ticket_id}/reopen" method="post">
        <button id="reopen-ticket" type="submit">Reopen ticket</button>
      </form>
    </div>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 5</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(ticket_id),
        audit_status = escape_html(audit_status),
        rows = body_rows,
        instruction = escape_html(&session.spec.instruction),
        step_text = step_text,
    )
}

fn render_assignee_options(selected: &str) -> String {
    [
        "",
        "Facilities",
        "Network Ops",
        "Billing Review",
        "Customer Success",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        format!(
            r#"<option value="{value}"{selected}>{value}</option>"#,
            value = escape_html(option),
            selected = selected_attr
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_status_options(selected: &str) -> String {
    [
        "",
        "New",
        "Awaiting Dispatch",
        "Escalated",
        "Pending Review",
        "Pending Customer Reply",
        "Resolved",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        let label = if option.is_empty() {
            "Select status"
        } else {
            option
        };
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = escape_html(option),
            selected = selected_attr,
            label = escape_html(label),
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_queue_status_filter_options(selected: &str) -> String {
    [
        "",
        "Awaiting Dispatch",
        "Pending Review",
        "Escalated",
        "Pending Customer Reply",
        "Resolved",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        let label = if option.is_empty() {
            "All statuses"
        } else {
            option
        };
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = escape_html(option),
            selected = selected_attr,
            label = escape_html(label),
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_queue_sort_options(selected: &str) -> String {
    ["", "Ticket ID", "Recently Updated"]
        .into_iter()
        .map(|option| {
            let selected_attr = if option == selected { " selected" } else { "" };
            let label = if option.is_empty() {
                "Default queue sort"
            } else {
                option
            };
            format!(
                r#"<option value="{value}"{selected}>{label}</option>"#,
                value = escape_html(option),
                selected = selected_attr,
                label = escape_html(label),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

