use super::sys_exec::{command_output_indicates_failure, summarize_command_output};
use super::{LaunchAttempt, ToolExecutionResult, ToolExecutor};
use ioi_drivers::terminal::CommandExecutionOptions;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_DISCOVERY_CANDIDATES: usize = 6;
const MAX_PATH_SCAN_ENTRIES_PER_DIR: usize = 512;
const DISCOVERY_SIMILARITY_THRESHOLD: f32 = 0.20;
const MIN_TOKEN_PREFIX_MATCH_CHARS: usize = 4;
const GTK_LAUNCH_DISPATCH_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LaunchIdentityEntry {
    pub(super) identity_id: String,
    pub(super) display_name: String,
    pub(super) desktop_entry_id: Option<String>,
    pub(super) exec_command: Option<String>,
}

#[derive(Clone, Debug)]
struct PlannedLaunchAttempt {
    attempt: LaunchAttempt,
    provenance: Option<String>,
}

pub(super) async fn handle_os_launch_app(
    exec: &ToolExecutor,
    app_name: &str,
) -> ToolExecutionResult {
    let has_gtk_launch = is_command_available("gtk-launch");
    let attempts = if cfg!(target_os = "macos") {
        vec![LaunchAttempt {
            command: "open".to_string(),
            args: vec!["-a".to_string(), app_name.to_string()],
            detach: true,
        }]
    } else if cfg!(target_os = "windows") {
        build_windows_launch_plan(app_name)
    } else {
        build_linux_launch_plan(app_name, has_gtk_launch)
    };

    if attempts.is_empty() {
        return ToolExecutionResult::failure(format!(
            "Failed to launch {}: no launch strategy available",
            app_name
        ));
    }

    let mut seen_attempts = HashSet::new();
    let mut planned_attempts = Vec::new();
    for attempt in attempts {
        seen_attempts.insert(attempt_key(&attempt));
        planned_attempts.push(PlannedLaunchAttempt {
            attempt,
            provenance: None,
        });
    }

    let mut errors = Vec::new();
    let mut attempt_count = 0usize;
    if let Some(success) = run_launch_attempts(
        exec,
        app_name,
        &planned_attempts,
        &mut errors,
        &mut attempt_count,
    )
    .await
    {
        return success;
    }

    let mut discovered_candidates: Vec<String> = Vec::new();
    let discovery = build_discovery_launch_plan(app_name, has_gtk_launch, &seen_attempts);
    if !discovery.candidates.is_empty() {
        discovered_candidates = discovery.candidates.clone();
    }
    if let Some(success) = run_launch_attempts(
        exec,
        app_name,
        &discovery.attempts,
        &mut errors,
        &mut attempt_count,
    )
    .await
    {
        return success;
    }

    let mut base_error = format!(
        "Failed to launch {} after {} attempt(s): {}",
        app_name,
        attempt_count,
        errors.join(" | ")
    );
    let no_installed_target = discovered_candidates.is_empty();
    if !discovered_candidates.is_empty() {
        base_error.push_str(" | discovered candidates: ");
        base_error.push_str(&discovered_candidates.join(", "));
        base_error.push_str(" | RESOLUTION_OUTCOME=CandidatesFailed");
    } else {
        base_error.push_str(
            " | RESOLUTION_OUTCOME=NoInstalledTarget INSTALL_ACTION=PromptInstallOrProvideIdentifier",
        );
    }
    if no_installed_target || launch_errors_indicate_missing_app(&errors) {
        ToolExecutionResult::failure(format!("ERROR_CLASS=ToolUnavailable {}", base_error))
    } else {
        ToolExecutionResult::failure(base_error)
    }
}

async fn run_launch_attempts(
    exec: &ToolExecutor,
    app_name: &str,
    attempts: &[PlannedLaunchAttempt],
    errors: &mut Vec<String>,
    attempt_count: &mut usize,
) -> Option<ToolExecutionResult> {
    for planned in attempts {
        *attempt_count += 1;
        let attempt = &planned.attempt;
        let run_result = if is_dispatch_launcher_attempt(attempt) {
            exec.terminal
                .execute_in_dir_with_options(
                    &attempt.command,
                    &attempt.args,
                    attempt.detach,
                    None,
                    CommandExecutionOptions::default().with_timeout(GTK_LAUNCH_DISPATCH_TIMEOUT),
                )
                .await
        } else {
            exec.terminal
                .execute(&attempt.command, &attempt.args, attempt.detach)
                .await
        };

        match run_result {
            Ok(output) => {
                if launch_attempt_failed(attempt, &output) {
                    errors.push(format!(
                        "{} (non-zero exit: {})",
                        describe_attempt(planned),
                        summarize_command_output(&output)
                    ));
                    continue;
                }
                return Some(ToolExecutionResult::success(format!(
                    "Launched {} via {}",
                    app_name,
                    describe_attempt(planned)
                )));
            }
            Err(e) => {
                let error_text = e.to_string();
                if launch_attempt_timeout_indicates_dispatched(attempt, &error_text) {
                    log::info!(
                        "Launch dispatcher timed out for '{}'; treating as successful dispatch.",
                        describe_attempt(planned)
                    );
                    return Some(ToolExecutionResult::success(format!(
                        "Launched {} via {}",
                        app_name,
                        describe_attempt(planned)
                    )));
                }
                errors.push(format!("{} ({})", describe_attempt(planned), error_text));
            }
        }
    }

    None
}

fn is_dispatch_launcher_attempt(attempt: &LaunchAttempt) -> bool {
    !attempt.detach && attempt.command == "gtk-launch"
}

pub(super) fn launch_attempt_timeout_indicates_dispatched(
    attempt: &LaunchAttempt,
    error_text: &str,
) -> bool {
    is_dispatch_launcher_attempt(attempt)
        && error_text
            .to_ascii_lowercase()
            .contains("command timed out")
}

pub(super) fn quote_powershell_single_quoted_string(value: &str) -> String {
    // Treat CRLF as a single separator to avoid producing double spaces.
    let without_crlf = value.replace("\r\n", " ");
    let sanitized = without_crlf
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect::<String>();
    let trimmed = sanitized.trim();
    format!("'{}'", trimmed.replace('\'', "''"))
}

fn build_windows_launch_plan(app_name: &str) -> Vec<LaunchAttempt> {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Use single-quoted PowerShell string literal with correct escaping of apostrophes.
    let file_path = quote_powershell_single_quoted_string(trimmed);
    let command = format!("Start-Process -FilePath {}", file_path);

    vec![LaunchAttempt {
        command: "powershell".to_string(),
        args: vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            command,
        ],
        detach: true,
    }]
}

pub(super) fn build_linux_launch_plan(app_name: &str, has_gtk_launch: bool) -> Vec<LaunchAttempt> {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut attempts = Vec::new();
    let mut desktop_ids = Vec::new();
    let mut binaries = Vec::new();

    let slug_dash = slugify(trimmed, '-');
    let slug_underscore = slugify(trimmed, '_');
    let trimmed_lower = trimmed.to_lowercase();

    // Candidate IDs for desktop launchers.
    for candidate in [
        trimmed,
        trimmed_lower.as_str(),
        slug_dash.as_str(),
        slug_underscore.as_str(),
    ] {
        if !candidate.is_empty() {
            push_unique(&mut desktop_ids, candidate);
            if !candidate.ends_with(".desktop") {
                push_unique(&mut desktop_ids, format!("{}.desktop", candidate));
            }
        }
    }

    // Candidate binaries for direct spawning.
    if trimmed.contains('/') {
        push_unique(&mut binaries, trimmed);
    }
    for candidate in [
        trimmed_lower.as_str(),
        slug_dash.as_str(),
        slug_underscore.as_str(),
    ] {
        if !candidate.is_empty() && !candidate.contains(' ') {
            push_unique(&mut binaries, candidate);
        }
    }

    if has_gtk_launch {
        for desktop_id in desktop_ids {
            attempts.push(LaunchAttempt {
                command: "gtk-launch".to_string(),
                args: vec![desktop_id],
                // Keep blocking so we can detect launcher failures and fall through.
                detach: false,
            });
        }
    }

    for binary in binaries {
        attempts.push(LaunchAttempt {
            command: binary,
            args: Vec::new(),
            detach: true,
        });
    }

    attempts
}

fn build_discovery_launch_plan(
    app_name: &str,
    has_gtk_launch: bool,
    seen_attempts: &HashSet<String>,
) -> LinuxDiscoveryPlan {
    let entries = discover_launch_identity_entries();
    build_discovery_launch_plan_from_entries(app_name, has_gtk_launch, &entries, seen_attempts)
}

#[derive(Default)]
struct LinuxDiscoveryPlan {
    attempts: Vec<PlannedLaunchAttempt>,
    candidates: Vec<String>,
}

fn build_discovery_launch_plan_from_entries(
    app_name: &str,
    has_gtk_launch: bool,
    entries: &[LaunchIdentityEntry],
    seen_attempts: &HashSet<String>,
) -> LinuxDiscoveryPlan {
    let ranked = rank_launch_identity_entries(app_name, entries, MAX_DISCOVERY_CANDIDATES);
    let mut plan = LinuxDiscoveryPlan::default();
    let mut local_attempt_keys = HashSet::new();
    let query_tag = launch_query_tag(app_name);

    for entry in ranked {
        let descriptor = format!("{} ({})", entry.identity_id, entry.display_name.trim());
        push_unique(&mut plan.candidates, descriptor);

        if has_gtk_launch {
            if let Some(desktop_entry_id) = entry.desktop_entry_id.as_deref() {
                let gtk_attempt = LaunchAttempt {
                    command: "gtk-launch".to_string(),
                    args: vec![desktop_entry_id.to_string()],
                    detach: false,
                };
                push_discovery_attempt(
                    &mut plan.attempts,
                    &mut local_attempt_keys,
                    seen_attempts,
                    gtk_attempt,
                    format!(
                        "query={} discovered:desktop={}",
                        query_tag, desktop_entry_id
                    ),
                );
            }
        }

        if let Some(exec_command) = entry.exec_command.as_deref() {
            let binary_attempt = LaunchAttempt {
                command: exec_command.to_string(),
                args: Vec::new(),
                detach: true,
            };
            push_discovery_attempt(
                &mut plan.attempts,
                &mut local_attempt_keys,
                seen_attempts,
                binary_attempt,
                format!("query={} discovered:exec={}", query_tag, exec_command),
            );
        }
    }

    plan
}

fn launch_query_tag(app_name: &str) -> String {
    let canonical = canonicalize(app_name);
    if canonical.is_empty() {
        "launch-unknown".to_string()
    } else {
        format!("launch-{}", canonical)
    }
}

fn discover_launch_identity_entries() -> Vec<LaunchIdentityEntry> {
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    if cfg!(target_os = "linux") {
        for entry in discover_linux_desktop_entries() {
            if seen.insert(entry.identity_id.clone()) {
                discovered.push(entry);
            }
        }
    }

    for entry in discover_path_executable_entries() {
        if seen.insert(entry.identity_id.clone()) {
            discovered.push(entry);
        }
    }

    discovered
}

fn discover_path_executable_entries() -> Vec<LaunchIdentityEntry> {
    let Some(paths) = env::var_os("PATH") else {
        return Vec::new();
    };

    let mut discovered = Vec::new();
    let mut seen = HashSet::new();
    for dir in env::split_paths(&paths) {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_PATH_SCAN_ENTRIES_PER_DIR) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            let command = normalize_executable_name(file_name);
            if command.is_empty() || command.starts_with('.') {
                continue;
            }
            if !seen.insert(command.clone()) {
                continue;
            }
            discovered.push(LaunchIdentityEntry {
                identity_id: command.clone(),
                display_name: command.clone(),
                desktop_entry_id: None,
                exec_command: Some(command),
            });
        }
    }
    discovered
}

fn normalize_executable_name(file_name: &str) -> String {
    let trimmed = file_name.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if cfg!(target_os = "windows") {
        let lower = trimmed.to_ascii_lowercase();
        for ext in [".exe", ".bat", ".cmd", ".com"] {
            if lower.ends_with(ext) && trimmed.len() > ext.len() {
                return trimmed[..trimmed.len() - ext.len()].to_string();
            }
        }
    }
    trimmed.to_string()
}

fn discover_linux_desktop_entries() -> Vec<LaunchIdentityEntry> {
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();
    for dir in linux_desktop_entry_dirs() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !extension.eq_ignore_ascii_case("desktop") {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let file_name = path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            let Some(parsed) = parse_linux_desktop_entry_content(file_name, &content) else {
                continue;
            };
            if seen.insert(parsed.identity_id.clone()) {
                discovered.push(parsed);
            }
        }
    }
    discovered
}

fn push_discovery_attempt(
    attempts: &mut Vec<PlannedLaunchAttempt>,
    local_attempt_keys: &mut HashSet<String>,
    seen_attempts: &HashSet<String>,
    attempt: LaunchAttempt,
    provenance: String,
) {
    let key = attempt_key(&attempt);
    if seen_attempts.contains(&key) || local_attempt_keys.contains(&key) {
        return;
    }
    local_attempt_keys.insert(key);
    attempts.push(PlannedLaunchAttempt {
        attempt,
        provenance: Some(provenance),
    });
}

fn linux_desktop_entry_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
        push_unique_path(&mut dirs, PathBuf::from(data_home).join("applications"));
    }

    if let Some(home) = env::var_os("HOME") {
        push_unique_path(
            &mut dirs,
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("applications"),
        );
    }

    if let Some(data_dirs) = env::var_os("XDG_DATA_DIRS") {
        for dir in env::split_paths(&data_dirs) {
            push_unique_path(&mut dirs, dir.join("applications"));
        }
    } else {
        push_unique_path(&mut dirs, PathBuf::from("/usr/local/share/applications"));
        push_unique_path(&mut dirs, PathBuf::from("/usr/share/applications"));
    }

    dirs
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

pub(super) fn parse_linux_desktop_entry_content(
    desktop_file_name: &str,
    content: &str,
) -> Option<LaunchIdentityEntry> {
    let desktop_entry_id = desktop_file_name
        .trim()
        .strip_suffix(".desktop")
        .unwrap_or(desktop_file_name)
        .trim()
        .to_string();
    if desktop_entry_id.is_empty() {
        return None;
    }

    let mut in_desktop_entry = false;
    let mut display_name: Option<String> = None;
    let mut exec_command: Option<String> = None;
    let mut hidden = false;
    let mut no_display = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line.eq_ignore_ascii_case("[Desktop Entry]");
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        match key {
            "Name" if display_name.is_none() => {
                if !value.is_empty() {
                    display_name = Some(value.to_string());
                }
            }
            "Exec" if exec_command.is_none() => {
                exec_command = extract_exec_binary(value);
            }
            "Hidden" => {
                hidden = parse_desktop_bool(value);
            }
            "NoDisplay" => {
                no_display = parse_desktop_bool(value);
            }
            _ => {}
        }
    }

    if hidden || no_display {
        return None;
    }

    let display_name = display_name.unwrap_or_else(|| desktop_entry_id.clone());
    Some(LaunchIdentityEntry {
        identity_id: desktop_entry_id.clone(),
        display_name,
        desktop_entry_id: Some(desktop_entry_id),
        exec_command,
    })
}

fn parse_desktop_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(super) fn extract_exec_binary(exec_value: &str) -> Option<String> {
    let tokens = shell_like_tokens(exec_value);
    if tokens.is_empty() {
        return None;
    }

    let mut idx = 0usize;
    if tokens
        .get(idx)
        .map(|token| token == "env" || token.ends_with("/env"))
        .unwrap_or(false)
    {
        idx += 1;
        while idx < tokens.len() {
            let token = tokens[idx].as_str();
            if token.starts_with('-') {
                idx += 1;
                continue;
            }
            if looks_like_env_assignment(token) {
                idx += 1;
                continue;
            }
            break;
        }
    }

    while idx < tokens.len() {
        let token = tokens[idx].trim();
        if token.is_empty() || token.starts_with('%') || looks_like_env_assignment(token) {
            idx += 1;
            continue;
        }
        return Some(token.to_string());
    }

    None
}

fn looks_like_env_assignment(token: &str) -> bool {
    let Some((lhs, rhs)) = token.split_once('=') else {
        return false;
    };
    !lhs.is_empty()
        && !rhs.is_empty()
        && lhs
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_lowercase() || ch == '_')
}

fn shell_like_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                out.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

pub(super) fn rank_launch_identity_entries(
    app_name: &str,
    entries: &[LaunchIdentityEntry],
    limit: usize,
) -> Vec<LaunchIdentityEntry> {
    if limit == 0 {
        return Vec::new();
    }
    let query = normalize_query(app_name);
    if query.canonical.is_empty() && query.tokens.is_empty() {
        return Vec::new();
    }

    let mut scored: Vec<(LaunchIdentityEntry, f32)> = entries
        .iter()
        .cloned()
        .filter_map(|entry| {
            let score = entry_similarity(&query, &entry);
            if score >= DISCOVERY_SIMILARITY_THRESHOLD && entry_has_token_alignment(&query, &entry)
            {
                Some((entry, score))
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|(a_entry, a_score), (b_entry, b_score)| {
        b_score
            .partial_cmp(a_score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a_entry.identity_id.cmp(&b_entry.identity_id))
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(entry, _)| entry)
        .collect()
}

struct NormalizedQuery {
    canonical: String,
    tokens: HashSet<String>,
}

fn normalize_query(value: &str) -> NormalizedQuery {
    NormalizedQuery {
        canonical: canonicalize(value),
        tokens: tokenize(value).into_iter().collect(),
    }
}

fn canonicalize(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn tokenize(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn entry_similarity(query: &NormalizedQuery, entry: &LaunchIdentityEntry) -> f32 {
    let mut best = field_similarity(query, &entry.identity_id);
    best = best.max(field_similarity(query, &entry.display_name));
    if let Some(desktop_entry_id) = entry.desktop_entry_id.as_deref() {
        best = best.max(field_similarity(query, desktop_entry_id));
    }
    if let Some(exec) = entry.exec_command.as_deref() {
        best = best.max(field_similarity(query, exec));
    }
    best
}

fn entry_has_token_alignment(query: &NormalizedQuery, entry: &LaunchIdentityEntry) -> bool {
    if query.tokens.is_empty() {
        return false;
    }

    if tokens_align(&query.tokens, &tokenize(&entry.identity_id)) {
        return true;
    }
    if tokens_align(&query.tokens, &tokenize(&entry.display_name)) {
        return true;
    }
    if let Some(desktop_entry_id) = entry.desktop_entry_id.as_deref() {
        if tokens_align(&query.tokens, &tokenize(desktop_entry_id)) {
            return true;
        }
    }
    if let Some(exec) = entry.exec_command.as_deref() {
        if tokens_align(&query.tokens, &tokenize(exec)) {
            return true;
        }
    }
    false
}

fn tokens_align(query_tokens: &HashSet<String>, candidate_tokens: &[String]) -> bool {
    if query_tokens.is_empty() || candidate_tokens.is_empty() {
        return false;
    }
    for query_token in query_tokens {
        for candidate_token in candidate_tokens {
            if query_token == candidate_token {
                return true;
            }
            if common_prefix_len(query_token, candidate_token) >= MIN_TOKEN_PREFIX_MATCH_CHARS {
                return true;
            }
        }
    }
    false
}

fn common_prefix_len(a: &str, b: &str) -> usize {
    a.chars()
        .zip(b.chars())
        .take_while(|(left, right)| left == right)
        .count()
}

fn field_similarity(query: &NormalizedQuery, candidate: &str) -> f32 {
    let candidate_canonical = canonicalize(candidate);
    if candidate_canonical.is_empty() {
        return 0.0;
    }
    if query.canonical == candidate_canonical {
        return 1.0;
    }

    let mut token_overlap = 0.0f32;
    let candidate_tokens: HashSet<String> = tokenize(candidate).into_iter().collect();
    if !query.tokens.is_empty() && !candidate_tokens.is_empty() {
        let intersection = query.tokens.intersection(&candidate_tokens).count() as f32;
        let union = query.tokens.union(&candidate_tokens).count() as f32;
        if union > 0.0 {
            token_overlap = intersection / union;
        }
    }

    let dice = dice_coefficient(&query.canonical, &candidate_canonical);
    (token_overlap + dice) / 2.0
}

fn dice_coefficient(a: &str, b: &str) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    if a == b {
        return 1.0;
    }
    if a.len() < 2 || b.len() < 2 {
        return if a == b { 1.0 } else { 0.0 };
    }

    let a_bigrams = bigrams(a);
    let b_bigrams = bigrams(b);
    if a_bigrams.is_empty() || b_bigrams.is_empty() {
        return 0.0;
    }
    let overlap = a_bigrams.intersection(&b_bigrams).count() as f32;
    (2.0 * overlap) / ((a_bigrams.len() + b_bigrams.len()) as f32)
}

fn bigrams(value: &str) -> HashSet<(char, char)> {
    let chars: Vec<char> = value.chars().collect();
    let mut out = HashSet::new();
    for window in chars.windows(2) {
        if let [left, right] = window {
            out.insert((*left, *right));
        }
    }
    out
}

fn push_unique(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if value.is_empty() {
        return;
    }
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn slugify(input: &str, separator: char) -> String {
    input
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(&separator.to_string())
}

fn is_command_available(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }

    if command.contains('/') {
        return Path::new(command).is_file();
    }

    let Some(paths) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&paths).any(|path_dir| path_dir.join(command).is_file())
}

fn format_attempt(attempt: &LaunchAttempt) -> String {
    if attempt.args.is_empty() {
        attempt.command.clone()
    } else {
        format!("{} {}", attempt.command, attempt.args.join(" "))
    }
}

fn describe_attempt(attempt: &PlannedLaunchAttempt) -> String {
    let base = format_attempt(&attempt.attempt);
    if let Some(provenance) = attempt.provenance.as_deref() {
        format!("{} [{}]", base, provenance)
    } else {
        base
    }
}

fn attempt_key(attempt: &LaunchAttempt) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        attempt.command,
        if attempt.detach { "1" } else { "0" },
        attempt.args.join("\u{1f}")
    )
}

pub(super) fn launch_attempt_failed(attempt: &LaunchAttempt, output: &str) -> bool {
    // Detached launches only confirm process spawn. For blocking launches, a
    // non-zero exit is surfaced by TerminalDriver as "Command failed: ...".
    !attempt.detach && command_output_indicates_failure(output)
}

pub(super) fn launch_errors_indicate_missing_app(errors: &[String]) -> bool {
    if errors.is_empty() {
        return false;
    }

    errors.iter().any(|error| {
        let msg = error.to_ascii_lowercase();
        msg.contains("no such file")
            || msg.contains("not found")
            || msg.contains("failed to spawn")
            || msg.contains("unable to locate")
            || msg.contains("cannot find")
            || (msg.contains("gtk-launch") && msg.contains("non-zero exit"))
    })
}
