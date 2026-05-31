use serde_json::Value;

pub fn install_operator_completion_summary(raw_summary: &str) -> Option<String> {
    let json_start = raw_summary.find('{')?;
    let payload: Value = serde_json::from_str(&raw_summary[json_start..]).ok()?;
    payload
        .get("summary")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub fn compose_terminal_chat_reply(summary: &str) -> TerminalReplyComposerOutcome {
    TerminalReplyComposerOutcome {
        output: summary.to_string(),
        applied: false,
        template_id: "model_passthrough",
        validator_passed: true,
        degradation_reason: None,
    }
}

pub fn enrich_command_scope_summary(summary: &str, agent_state: &AgentState) -> String {
    let normalized_summary = normalize_runtime_home_paths(summary);
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    if !command_scope {
        return normalized_summary;
    }

    let mut enriched = normalized_summary;
    let timer_contract_active = requires_timer_notification_contract(agent_state);
    if !timer_contract_active {
        return enriched;
    }
    let run_timestamp_utc = latest_timer_backend_history_entry(agent_state)
        .or_else(|| agent_state.command_history.back())
        .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms));
    let Some(run_timestamp_utc) = run_timestamp_utc else {
        return enriched;
    };
    if timer_contract_active {
        let run_timestamp = parse_utc_rfc3339(&run_timestamp_utc);
        let target_timestamp = extract_structured_field(&enriched, TARGET_UTC_MARKER)
            .as_deref()
            .and_then(parse_utc_rfc3339);
        if target_timestamp
            .zip(run_timestamp)
            .map(|(target, run)| target < run)
            .unwrap_or(true)
        {
            if let Some(derived_target_utc) = derived_target_utc_from_history(agent_state) {
                enriched =
                    upsert_structured_field(&enriched, TARGET_UTC_MARKER, &derived_target_utc);
            }
        }
    }
    if extract_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER).is_none() {
        enriched = upsert_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER, &run_timestamp_utc);
    }
    enriched
}

fn normalize_runtime_home_paths(summary: &str) -> String {
    normalize_runtime_home_paths_with_home(summary, runtime_home_directory().as_deref())
}

fn normalize_runtime_home_paths_with_home(summary: &str, runtime_home_dir: Option<&str>) -> String {
    let Some(runtime_home_dir) = runtime_home_dir else {
        return summary.to_string();
    };
    let runtime_home_dir = runtime_home_dir.trim_end_matches('/').to_string();
    if runtime_home_dir.is_empty() {
        return summary.to_string();
    }

    const RUNTIME_HOME_PLACEHOLDER: &str = "__IOI_RUNTIME_HOME__";
    let mut normalized = summary.replace(&runtime_home_dir, RUNTIME_HOME_PLACEHOLDER);
    normalized = normalized.replace("~/", &format!("{RUNTIME_HOME_PLACEHOLDER}/"));

    // Guard against synthesized "/home/<known-user-dir>/..." paths that should stay
    // scoped under the runtime-owned home root in fixture and sandboxed environments.
    for segment in [
        "Desktop",
        "Documents",
        "Downloads",
        "Music",
        "Pictures",
        "Videos",
        "desktop",
        "documents",
        "downloads",
        "music",
        "pictures",
        "videos",
    ] {
        let escaped_segment = regex::escape(segment);
        // Replace only rooted aliases (start/whitespace/punctuation), never when "/home/<dir>"
        // appears inside an already-correct runtime path like "/tmp/.../home/<dir>".
        let alias_pattern =
            format!(r"(?P<prefix>^|[^\w./-])(?P<alias>/home/{escaped_segment})(?P<suffix>/|$|\s)");
        let alias_re = Regex::new(&alias_pattern).expect("home alias regex should compile");
        normalized = alias_re
            .replace_all(&normalized, |captures: &regex::Captures<'_>| {
                format!(
                    "{}{}/{}{}",
                    &captures["prefix"], RUNTIME_HOME_PLACEHOLDER, segment, &captures["suffix"]
                )
            })
            .into_owned();
    }

    normalized.replace(RUNTIME_HOME_PLACEHOLDER, &runtime_home_dir)
}
