fn team_memory_scope_for_summary(
    summary: &SessionSummary,
    preview: &SessionCompactionPreview,
) -> (TeamMemoryScopeKind, String, String) {
    let workspace_root = preview
        .carried_forward_state
        .workspace_root
        .as_deref()
        .or(summary.workspace_root.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(workspace_root) = workspace_root {
        let scope_digest = sha256(workspace_root.as_bytes())
            .map(hex::encode)
            .unwrap_or_else(|_| workspace_root.to_string());
        let scope_label = Path::new(workspace_root)
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("Workspace {}", value))
            .unwrap_or_else(|| "Workspace".to_string());
        return (
            TeamMemoryScopeKind::Workspace,
            format!("workspace:{scope_digest}"),
            scope_label,
        );
    }

    let session_title = title_for_session(summary);
    (
        TeamMemoryScopeKind::Session,
        format!("session:{}", summary.session_id),
        format!("Session {session_title}"),
    )
}

fn normalized_team_memory_actor_component(raw: &str) -> String {
    let mut normalized = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while normalized.contains("--") {
        normalized = normalized.replace("--", "-");
    }
    normalized.trim_matches('-').to_string()
}

fn team_memory_actor_id(actor_label: &str, actor_role: &str) -> String {
    let label = normalized_team_memory_actor_component(actor_label);
    let role = normalized_team_memory_actor_component(actor_role);
    let label = if label.is_empty() {
        "autopilot".to_string()
    } else {
        label
    };
    let role = if role.is_empty() {
        "operator".to_string()
    } else {
        role
    };
    format!("autopilot://team-memory/{label}/{role}")
}

fn trim_token_edge_char(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | ','
            | '.'
            | ';'
            | ':'
            | '!'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
    )
}

fn trim_token_bounds(input: &str, mut start: usize, mut end: usize) -> Option<(usize, usize)> {
    while start < end {
        let ch = input[start..].chars().next()?;
        if trim_token_edge_char(ch) {
            start += ch.len_utf8();
        } else {
            break;
        }
    }
    while start < end {
        let ch = input[..end].chars().next_back()?;
        if trim_token_edge_char(ch) {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    (start < end).then_some((start, end))
}

fn whitespace_token_spans(input: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut token_start = None;
    for (index, ch) in input.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                spans.push((start, index));
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        spans.push((start, input.len()));
    }
    spans
}

fn team_memory_detection_spans(input: &str) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();
    for (raw_start, raw_end) in whitespace_token_spans(input) {
        let Some((start, end)) = trim_token_bounds(input, raw_start, raw_end) else {
            continue;
        };
        let token = &input[start..end];
        if token.is_empty() {
            continue;
        }

        let lower = token.to_ascii_lowercase();
        if let Some(at_index) = token.find('@') {
            let domain = &token[at_index + 1..];
            if at_index > 0 && domain.contains('.') {
                spans.push((start, end, "EMAIL".to_string()));
                continue;
            }
        }

        if token.starts_with("/home/")
            || token.starts_with("/Users/")
            || token.contains("C:\\Users\\")
        {
            spans.push((start, end, "ADDRESS".to_string()));
            continue;
        }

        if lower.starts_with("sk-")
            || lower.starts_with("ghp_")
            || lower.starts_with("tok_")
            || lower.starts_with("xoxb-")
            || lower.starts_with("xoxp-")
        {
            spans.push((start, end, "SECRET_TOKEN".to_string()));
            continue;
        }

        for marker in ["api_key=", "apikey=", "token=", "secret=", "password="] {
            if let Some(offset) = lower.find(marker) {
                let value_start = start + offset + marker.len();
                if value_start < end {
                    let category = if marker.starts_with("api") {
                        "API_KEY"
                    } else {
                        "SECRET_TOKEN"
                    };
                    spans.push((value_start, end, category.to_string()));
                }
            }
        }
    }

    spans.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let mut merged = Vec::new();
    for (start, end, category) in spans {
        if start >= end || end > input.len() {
            continue;
        }
        if let Some((_, last_end, last_category)) = merged.last_mut() {
            if start <= *last_end {
                if end > *last_end {
                    *last_end = end;
                }
                if last_category != &category
                    && (last_category == "SECRET_TOKEN"
                        || last_category == "API_KEY"
                        || category == "SECRET_TOKEN"
                        || category == "API_KEY")
                {
                    *last_category = "SECRET_TOKEN".to_string();
                }
                continue;
            }
        }
        merged.push((start, end, category));
    }
    merged
}

fn team_memory_redacted_fields(map: &ioi_types::app::RedactionMap) -> Vec<String> {
    let mut fields = BTreeSet::new();
    for entry in &map.entries {
        let label = match &entry.redaction_type {
            RedactionType::Pii => "pii".to_string(),
            RedactionType::Secret => "secret".to_string(),
            RedactionType::Custom(custom) => format!("custom:{custom}"),
        };
        fields.insert(label);
    }
    fields.into_iter().collect()
}

fn scrub_team_memory_text(input: &str) -> (String, usize, Vec<String>) {
    let detections = team_memory_detection_spans(input);
    if detections.is_empty() {
        return (input.trim().to_string(), 0, Vec::new());
    }

    match scrub_text(input, &detections) {
        Ok((scrubbed, map)) => (
            scrubbed.trim().to_string(),
            map.entries.len(),
            team_memory_redacted_fields(&map),
        ),
        Err(_) => (
            "<REDACTED:custom>".to_string(),
            1,
            vec!["scrubber_failure".to_string()],
        ),
    }
}

fn shared_team_memory_items(
    preview: &SessionCompactionPreview,
    include_governance_critical: bool,
) -> (Vec<SessionCompactionMemoryItem>, usize, usize, Vec<String>) {
    let mut items = Vec::new();
    let mut omitted_governance_item_count = 0usize;
    let mut redaction_count = 0usize;
    let mut redacted_fields = BTreeSet::new();

    for item in &preview.carried_forward_state.memory_items {
        if item.values.is_empty() || matches!(item.memory_class, SessionMemoryClass::Ephemeral) {
            continue;
        }
        if matches!(item.memory_class, SessionMemoryClass::GovernanceCritical)
            && !include_governance_critical
        {
            omitted_governance_item_count += 1;
            continue;
        }

        let mut next = item.clone();
        next.values = next
            .values
            .iter()
            .filter_map(|value| compaction_excerpt(value, TEAM_MEMORY_SYNC_MAX_ITEM_VALUE_CHARS))
            .take(TEAM_MEMORY_SYNC_MAX_ITEM_VALUES)
            .map(|value| {
                let (scrubbed, count, fields) = scrub_team_memory_text(&value);
                redaction_count += count;
                redacted_fields.extend(fields);
                scrubbed
            })
            .collect();
        if !next.values.is_empty() {
            items.push(next);
        }
    }

    (
        items,
        omitted_governance_item_count,
        redaction_count,
        redacted_fields.into_iter().collect(),
    )
}

fn build_team_memory_summary(
    scope_label: &str,
    preview: &SessionCompactionPreview,
    shared_items: &[SessionCompactionMemoryItem],
    omitted_governance_item_count: usize,
) -> String {
    let mut lines = vec![
        format!("Scope: {scope_label}."),
        preview.summary.clone(),
        format!("Resume anchor: {}.", preview.resume_anchor),
    ];

    if !shared_items.is_empty() {
        let item_summary = shared_items
            .iter()
            .map(|item| format!("{}: {}", item.label, item.values.join(" | ")))
            .collect::<Vec<_>>()
            .join(" || ");
        lines.push(format!("Shared memory items: {item_summary}."));
    }

    if omitted_governance_item_count > 0 {
        lines.push(format!(
            "{omitted_governance_item_count} governance-critical memory item(s) stayed local."
        ));
    }

    lines.join(" ")
}

fn build_team_memory_review_summary(
    actor_label: &str,
    sync_status: &TeamMemorySyncStatus,
    omitted_governance_item_count: usize,
    redaction_count: usize,
) -> String {
    match sync_status {
        TeamMemorySyncStatus::ReviewRequired => format!(
            "Synced by {actor_label} with governance-critical context included. Review before wider promotion."
        ),
        TeamMemorySyncStatus::Redacted if omitted_governance_item_count > 0 => format!(
            "Synced by {actor_label} after local redaction; {omitted_governance_item_count} governance-critical item(s) stayed local."
        ),
        TeamMemorySyncStatus::Redacted => format!(
            "Synced by {actor_label} after local redaction ({redaction_count} redaction(s))."
        ),
        TeamMemorySyncStatus::Synced if omitted_governance_item_count > 0 => format!(
            "Synced by {actor_label}; {omitted_governance_item_count} governance-critical item(s) stayed local."
        ),
        TeamMemorySyncStatus::Synced => {
            format!("Synced by {actor_label} with no additional redaction required.")
        }
    }
}

fn build_team_memory_entry(
    summary: &SessionSummary,
    preview: &SessionCompactionPreview,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: bool,
) -> TeamMemorySyncEntry {
    let actor_label = actor_label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Autopilot".to_string());
    let actor_role = actor_role
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "operator".to_string());
    let actor_id = team_memory_actor_id(&actor_label, &actor_role);
    let (scope_kind, scope_id, scope_label) = team_memory_scope_for_summary(summary, preview);
    let (
        shared_memory_items,
        omitted_governance_item_count,
        item_redaction_count,
        item_redacted_fields,
    ) = shared_team_memory_items(preview, include_governance_critical);

    let raw_summary = build_team_memory_summary(
        &scope_label,
        preview,
        &shared_memory_items,
        omitted_governance_item_count,
    );
    let (summary_text, summary_redaction_count, summary_redacted_fields) =
        scrub_team_memory_text(&raw_summary);
    let (resume_anchor, resume_anchor_redaction_count, resume_anchor_redacted_fields) =
        scrub_team_memory_text(&preview.resume_anchor);
    let (
        pre_compaction_span,
        pre_compaction_span_redaction_count,
        pre_compaction_span_redacted_fields,
    ) = scrub_team_memory_text(&preview.pre_compaction_span);

    let mut redacted_fields = BTreeSet::new();
    redacted_fields.extend(item_redacted_fields);
    redacted_fields.extend(summary_redacted_fields);
    redacted_fields.extend(resume_anchor_redacted_fields);
    redacted_fields.extend(pre_compaction_span_redacted_fields);

    let redaction_count = item_redaction_count
        + summary_redaction_count
        + resume_anchor_redaction_count
        + pre_compaction_span_redaction_count;
    let governance_included = include_governance_critical
        && preview
            .carried_forward_state
            .memory_items
            .iter()
            .any(|item| matches!(item.memory_class, SessionMemoryClass::GovernanceCritical));
    let sync_status = if governance_included {
        TeamMemorySyncStatus::ReviewRequired
    } else if redaction_count > 0 {
        TeamMemorySyncStatus::Redacted
    } else {
        TeamMemorySyncStatus::Synced
    };
    let review_summary = build_team_memory_review_summary(
        &actor_label,
        &sync_status,
        omitted_governance_item_count,
        redaction_count,
    );

    TeamMemorySyncEntry {
        entry_id: Uuid::new_v4().to_string(),
        session_id: summary.session_id.clone(),
        session_title: preview.title.clone(),
        synced_at_ms: crate::kernel::state::now(),
        scope_kind,
        scope_id,
        scope_label,
        actor_id,
        actor_label,
        actor_role,
        sync_status,
        review_summary: compaction_excerpt(&review_summary, 180).unwrap_or(review_summary),
        omitted_governance_item_count,
        resume_anchor: compaction_excerpt(&resume_anchor, 180).unwrap_or(resume_anchor),
        pre_compaction_span: compaction_excerpt(&pre_compaction_span, 180)
            .unwrap_or(pre_compaction_span),
        summary: compaction_excerpt(&summary_text, 640).unwrap_or(summary_text),
        shared_memory_items,
        redaction: TeamMemoryRedactionSummary {
            redaction_count,
            redacted_fields: redacted_fields.into_iter().collect(),
            redaction_version: TEAM_MEMORY_SYNC_REDACTION_VERSION.to_string(),
        },
    }
}

fn build_team_memory_snapshot(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    selected_summary: Option<&SessionSummary>,
) -> TeamMemorySyncSnapshot {
    let stored_entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    let (active_scope_kind, active_scope_id, active_scope_label) = if let Some(summary) =
        selected_summary
    {
        let (local_task, file_context) = load_compaction_context(memory_runtime, summary);
        let preview = build_compaction_preview_from_context(
            summary,
            local_task.as_ref(),
            &file_context,
            &SessionCompactionPolicy::default(),
        );
        let (scope_kind, scope_id, scope_label) = team_memory_scope_for_summary(summary, &preview);
        (Some(scope_kind), Some(scope_id), Some(scope_label))
    } else {
        (None, None, None)
    };

    let entries = if let Some(scope_id) = active_scope_id.as_deref() {
        stored_entries
            .into_iter()
            .filter(|entry| entry.scope_id == scope_id)
            .take(12)
            .collect::<Vec<_>>()
    } else {
        stored_entries.into_iter().take(12).collect::<Vec<_>>()
    };

    let redacted_entry_count = entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::Redacted))
        .count();
    let review_required_count = entries
        .iter()
        .filter(|entry| matches!(entry.sync_status, TeamMemorySyncStatus::ReviewRequired))
        .count();
    let actor_count = entries
        .iter()
        .map(|entry| entry.actor_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let summary = match (active_scope_label.as_deref(), entries.len()) {
        (Some(scope_label), 0) => {
            format!("No team memory entries are synced yet for {scope_label}.")
        }
        (Some(scope_label), count) => format!(
            "{scope_label} currently has {count} synced team-memory entr{} across {actor_count} actor(s).",
            if count == 1 { "y" } else { "ies" }
        ),
        (None, 0) => {
            "No retained team-memory entries exist yet. Sync a retained session to start the shared ledger."
                .to_string()
        }
        (None, count) => format!(
            "Showing {count} recent team-memory entr{} across {actor_count} actor(s).",
            if count == 1 { "y" } else { "ies" }
        ),
    };

    TeamMemorySyncSnapshot {
        generated_at_ms: crate::kernel::state::now(),
        active_session_id: selected_summary.map(|summary| summary.session_id.clone()),
        active_scope_id,
        active_scope_kind,
        active_scope_label,
        entry_count: entries.len(),
        redacted_entry_count,
        review_required_count,
        summary,
        entries,
    }
}

pub fn team_memory_snapshot_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let selected = if sessions.is_empty() {
        None
    } else {
        Some(selected_summary_for_compaction(
            &sessions,
            active_session_id,
            requested_session_id,
        )?)
    };
    Ok(build_team_memory_snapshot(memory_runtime, selected))
}

pub fn sync_team_memory_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: bool,
) -> Result<TeamMemorySyncSnapshot, String> {
    let selected =
        selected_summary_for_compaction(&sessions, active_session_id, requested_session_id)?;
    let (local_task, file_context) = load_compaction_context(memory_runtime, selected);
    let preview = build_compaction_preview_from_context(
        selected,
        local_task.as_ref(),
        &file_context,
        &SessionCompactionPolicy::default(),
    );
    let entry = build_team_memory_entry(
        selected,
        &preview,
        actor_label,
        actor_role,
        include_governance_critical,
    );

    let mut entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    entries.retain(|existing| {
        !(existing.session_id == entry.session_id
            && existing.scope_id == entry.scope_id
            && existing.actor_id == entry.actor_id)
    });
    entries.insert(0, entry);
    if entries.len() > TEAM_MEMORY_SYNC_MAX_ENTRIES {
        entries.truncate(TEAM_MEMORY_SYNC_MAX_ENTRIES);
    }
    orchestrator::save_team_memory_sync_entries(memory_runtime, &entries);
    Ok(build_team_memory_snapshot(memory_runtime, Some(selected)))
}

pub fn forget_team_memory_entry_for_sessions(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    sessions: Vec<SessionSummary>,
    active_session_id: Option<&str>,
    requested_session_id: Option<&str>,
    entry_id: &str,
) -> Result<TeamMemorySyncSnapshot, String> {
    let mut entries = orchestrator::load_team_memory_sync_entries(memory_runtime);
    entries.retain(|entry| entry.entry_id != entry_id.trim());
    orchestrator::save_team_memory_sync_entries(memory_runtime, &entries);

    let selected = if sessions.is_empty() {
        None
    } else {
        Some(selected_summary_for_compaction(
            &sessions,
            active_session_id,
            requested_session_id,
        )?)
    };
    Ok(build_team_memory_snapshot(memory_runtime, selected))
}

#[tauri::command]
pub async fn get_team_memory_snapshot(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    team_memory_snapshot_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
    )
}

#[tauri::command]
pub async fn sync_team_memory(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
    actor_label: Option<String>,
    actor_role: Option<String>,
    include_governance_critical: Option<bool>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    let snapshot = sync_team_memory_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
        actor_label,
        actor_role,
        include_governance_critical.unwrap_or(false),
    )?;
    let _ = app.emit("team-memory-updated", &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn forget_team_memory_entry(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    entry_id: String,
    session_id: Option<String>,
) -> Result<TeamMemorySyncSnapshot, String> {
    let active_session_id = current_task_snapshot(&state)
        .as_ref()
        .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let sessions = refresh_cached_session_history(&state).await;
    let memory_runtime = state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
        .ok_or_else(|| "Memory runtime unavailable for team memory sync.".to_string())?;
    let snapshot = forget_team_memory_entry_for_sessions(
        &memory_runtime,
        sessions,
        active_session_id.as_deref(),
        session_id.as_deref(),
        &entry_id,
    )?;
    let _ = app.emit("team-memory-updated", &snapshot);
    Ok(snapshot)
}
