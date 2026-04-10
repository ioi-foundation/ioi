pub fn compose_terminal_chat_reply(summary: &str) -> TerminalReplyComposerOutcome {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let pdf_paths = extract_pdf_paths_for_composer(trimmed);
    if pdf_paths.len() < 2 {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let summary_len = trimmed.chars().count().max(1);
    let path_chars: usize = pdf_paths.iter().map(|path| path.chars().count()).sum();
    if path_chars * 100 < summary_len * 35 {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let run_timestamp = extract_structured_field(trimmed, RUN_TIMESTAMP_UTC_MARKER);
    let target_utc = extract_structured_field(trimmed, TARGET_UTC_MARKER);
    let mechanism = extract_structured_field(trimmed, MECHANISM_MARKER);
    let template_choice = deterministic_template_choice(trimmed);
    let template_id = if template_choice == 0 {
        "markdown_paths"
    } else {
        "markdown_paths_with_count"
    };

    let mut lines = Vec::<String>::new();
    if template_choice == 1 {
        lines.push(format!("Found {} matching PDF files:", pdf_paths.len()));
    } else {
        lines.push("Matching PDF files:".to_string());
    }
    lines.push(String::new());
    for path in &pdf_paths {
        lines.push(format!("- `{}`", path));
    }

    let mut metadata_lines = Vec::<String>::new();
    if let Some(mechanism) = mechanism.as_deref() {
        metadata_lines.push(format!("{} {}", MECHANISM_MARKER, mechanism));
    }
    if let Some(run_timestamp) = run_timestamp.as_deref() {
        metadata_lines.push(format!("{} {}", RUN_TIMESTAMP_UTC_MARKER, run_timestamp));
    }
    if let Some(target_utc) = target_utc.as_deref() {
        metadata_lines.push(format!("{} {}", TARGET_UTC_MARKER, target_utc));
    }
    if !metadata_lines.is_empty() {
        lines.push(String::new());
    }
    lines.extend(metadata_lines);

    let candidate = lines.join("\n").trim().to_string();
    if candidate.is_empty() {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id,
            validator_passed: false,
            fallback_reason: Some("empty_candidate"),
        };
    }

    if !composed_reply_is_valid(
        &candidate,
        &pdf_paths,
        run_timestamp.as_deref(),
        target_utc.as_deref(),
        mechanism.as_deref(),
    ) {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id,
            validator_passed: false,
            fallback_reason: Some("validator_failed"),
        };
    }

    TerminalReplyComposerOutcome {
        output: candidate,
        applied: true,
        template_id,
        validator_passed: true,
        fallback_reason: None,
    }
}

fn deterministic_template_choice(summary: &str) -> u8 {
    sha256(summary.as_bytes())
        .ok()
        .map(|digest| digest.as_ref().first().copied().unwrap_or(0) % 2)
        .unwrap_or(0)
}

fn composed_reply_is_valid(
    candidate: &str,
    pdf_paths: &[String],
    run_timestamp: Option<&str>,
    target_utc: Option<&str>,
    mechanism: Option<&str>,
) -> bool {
    if candidate.trim().is_empty() {
        return false;
    }

    let candidate_paths = extract_pdf_paths_for_composer(candidate);
    if !pdf_paths.iter().all(|path| {
        candidate_paths
            .iter()
            .any(|candidate_path| candidate_path.eq_ignore_ascii_case(path))
    }) {
        return false;
    }

    if let Some(run_timestamp) = run_timestamp {
        if extract_structured_field(candidate, RUN_TIMESTAMP_UTC_MARKER).as_deref()
            != Some(run_timestamp)
        {
            return false;
        }
    }
    if let Some(target_utc) = target_utc {
        if extract_structured_field(candidate, TARGET_UTC_MARKER).as_deref() != Some(target_utc) {
            return false;
        }
    }
    if let Some(mechanism) = mechanism {
        if extract_structured_field(candidate, MECHANISM_MARKER).as_deref() != Some(mechanism) {
            return false;
        }
    }
    true
}

fn extract_pdf_paths_for_composer(summary: &str) -> Vec<String> {
    let lower = summary.to_ascii_lowercase();
    let bytes = summary.as_bytes();
    let mut paths = Vec::<String>::new();
    let mut offset = 0usize;

    while offset < lower.len() {
        let Some(found) = lower[offset..].find(".pdf") else {
            break;
        };
        let end = offset + found + 4;
        let mut start = find_preferred_pdf_path_start(summary, end).unwrap_or(offset + found);
        if start == offset + found {
            while start > 0 {
                if bytes.get(start) == Some(&b'/')
                    && start >= 4
                    && lower[start - 4..start].eq_ignore_ascii_case(".pdf")
                {
                    break;
                }
                let prev = bytes[start - 1] as char;
                if !is_path_token_char(prev) {
                    break;
                }
                start -= 1;
            }
        }
        let candidate = normalize_composer_path(&summary[start..end]);
        if is_valid_composer_pdf_path(&candidate)
            && !paths
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&candidate))
        {
            paths.push(candidate);
        }
        offset = end;
    }

    paths
}

fn find_preferred_pdf_path_start(summary: &str, end: usize) -> Option<usize> {
    let prefix = &summary[..end];
    let mut best: Option<usize> = None;
    for marker in ["/home/", "/Users/", "~/"] {
        for (idx, _) in prefix.match_indices(marker) {
            if !is_path_start_boundary(prefix, idx) {
                continue;
            }
            if best.map(|current| idx > current).unwrap_or(true) {
                best = Some(idx);
            }
        }
    }
    best
}

fn is_path_start_boundary(prefix: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    if prefix[..idx].to_ascii_lowercase().ends_with(".pdf") {
        return true;
    }
    let prev = prefix.as_bytes()[idx - 1] as char;
    prev.is_ascii_whitespace()
        || matches!(prev, '"' | '\'' | '`' | '(' | '[' | '{' | ',' | ';' | ':')
}

fn normalize_composer_path(path: &str) -> String {
    path.trim()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
            )
        })
        .to_string()
}

fn is_valid_composer_pdf_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if !(lower.starts_with('/') || lower.starts_with("~/")) {
        return false;
    }
    lower.ends_with(".pdf")
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
    let run_timestamp_utc = if timer_contract_active {
        latest_timer_backend_history_entry(agent_state)
            .or_else(|| agent_state.command_history.back())
            .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms))
    } else {
        agent_state
            .command_history
            .back()
            .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms))
    };
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
    let Some(runtime_home_dir) = runtime_home_directory() else {
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
