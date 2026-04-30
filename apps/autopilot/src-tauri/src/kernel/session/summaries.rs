fn title_for_session(summary: &SessionSummary) -> String {
    let trimmed = summary.title.trim();
    if trimmed.is_empty() {
        format!(
            "Session {}",
            &summary.session_id[..summary.session_id.len().min(8)]
        )
    } else {
        trimmed.to_string()
    }
}

fn workspace_label(workspace_root: Option<&str>) -> Option<String> {
    let trimmed = workspace_root?.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.replace('\\', "/");
    normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .last()
        .map(|segment| segment.to_string())
        .or_else(|| Some(normalized))
}

fn unique_session_parts(parts: &[Option<String>]) -> Vec<String> {
    let mut unique = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for part in parts.iter().flatten() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            unique.push(trimmed.to_string());
        }
    }

    unique
}

fn waiting_step(step: &str) -> bool {
    let normalized = step.trim().to_ascii_lowercase();
    normalized.contains("waiting for")
        || normalized.contains("initializing")
        || normalized.contains("routing the request")
        || normalized.contains("sending message")
        || normalized.contains("approval required")
        || normalized.contains("clarification required")
}

fn stable_session(summary: &SessionSummary, active_session_id: Option<&str>) -> bool {
    if active_session_id == Some(summary.session_id.as_str()) {
        return false;
    }

    match summary.phase.as_ref() {
        Some(AgentPhase::Running) | Some(AgentPhase::Gate) => false,
        Some(_) => true,
        None => summary
            .current_step
            .as_deref()
            .map(|step| !waiting_step(step))
            .unwrap_or(true),
    }
}

fn session_preview_detail(summary: &SessionSummary) -> String {
    let parts = unique_session_parts(&[
        summary.phase.as_ref().map(|phase| format!("{phase:?}")),
        summary.current_step.clone(),
        summary.resume_hint.clone(),
        workspace_label(summary.workspace_root.as_deref()),
    ]);

    if parts.is_empty() {
        "Retained session checkpoint.".to_string()
    } else {
        parts.join(" · ")
    }
}
