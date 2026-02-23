use ioi_types::app::agentic::{AgentTool, ResolvedIntentState};
use std::path::Path;

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";

pub fn is_command_probe_intent(resolved_intent: Option<&ResolvedIntentState>) -> bool {
    resolved_intent
        .map(|resolved| resolved.intent_id == "command.probe")
        .unwrap_or(false)
}

pub fn is_system_clock_read_intent(resolved_intent: Option<&ResolvedIntentState>) -> bool {
    resolved_intent
        .map(|resolved| resolved.intent_id == "system.clock.read")
        .unwrap_or(false)
}

fn is_utc_iso_timestamp(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    matches!(
        (bytes[4], bytes[7], bytes[10], bytes[13], bytes[16], bytes[19]),
        (b'-', b'-', b'T', b':', b':', b'Z')
    ) && bytes[0..4].iter().all(|b| b.is_ascii_digit())
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
        && bytes[11..13].iter().all(|b| b.is_ascii_digit())
        && bytes[14..16].iter().all(|b| b.is_ascii_digit())
        && bytes[17..19].iter().all(|b| b.is_ascii_digit())
}

fn extract_utc_iso_timestamp(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|token| {
        let candidate = token.trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | ':' | 'T' | 'Z'))
        });
        if is_utc_iso_timestamp(candidate) {
            Some(candidate.to_string())
        } else {
            None
        }
    })
}

fn extract_command_history_clock_line(output: &str) -> Option<String> {
    let marker_idx = output.find(COMMAND_HISTORY_PREFIX)?;
    let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
    let (payload, tail) = match suffix.find('\n') {
        Some(idx) => (&suffix[..idx], &suffix[idx + 1..]),
        None => (suffix, ""),
    };
    let payload = payload.trim();

    if !payload.is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(stdout) = value.get("stdout").and_then(|v| v.as_str()) {
                if let Some(line) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
                    return Some(line.to_string());
                }
            }
        }
    }

    tail.lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with(COMMAND_HISTORY_PREFIX)
                && !line.to_ascii_lowercase().starts_with("exit status:")
        })
        .map(|line| line.to_string())
}

pub fn summarize_system_clock_output(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(line) = extract_command_history_clock_line(trimmed) {
        if let Some(ts) = extract_utc_iso_timestamp(&line) {
            return Some(format!("Current UTC time: {}", ts));
        }
        return Some(format!("Current UTC time: {}", line));
    }

    if let Some(ts) = extract_utc_iso_timestamp(trimmed) {
        return Some(format!("Current UTC time: {}", ts));
    }

    let line = trimmed.lines().map(str::trim).find(|line| {
        !line.is_empty()
            && !line.starts_with(COMMAND_HISTORY_PREFIX)
            && !line.to_ascii_lowercase().starts_with("exit status:")
    })?;
    Some(format!("Current UTC time: {}", line))
}

fn cleaned_probe_token(token: &str) -> String {
    token
        .trim_matches(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '+' | ':' | '='))
        })
        .to_string()
}

fn scan_for_flagged_subject(text: &str, head: &str, flag: &str) -> Option<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }

    for i in 0..(tokens.len() - 2) {
        let t0 = cleaned_probe_token(tokens[i]);
        if !t0.eq_ignore_ascii_case(head) {
            continue;
        }

        let t1 = cleaned_probe_token(tokens[i + 1]);
        if !t1.eq_ignore_ascii_case(flag) {
            continue;
        }

        let subject = cleaned_probe_token(tokens[i + 2]);
        if subject.is_empty() {
            continue;
        }
        return Some(subject);
    }

    None
}

fn scan_for_which_subject(text: &str) -> Option<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }

    for i in 0..(tokens.len() - 1) {
        let t0 = cleaned_probe_token(tokens[i]);
        if !t0.eq_ignore_ascii_case("which") {
            continue;
        }
        let subject = cleaned_probe_token(tokens[i + 1]);
        if subject.is_empty() {
            continue;
        }
        return Some(subject);
    }

    None
}

fn is_shell_binary(command: &str) -> bool {
    let first = command.trim().split_whitespace().next().unwrap_or("");
    let basename = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(first);
    matches!(basename, "sh" | "bash" | "zsh" | "dash")
}

fn extract_shell_script_arg(command: &str, args: &[String]) -> Option<String> {
    if !is_shell_binary(command) {
        return None;
    }
    let idx = args.iter().position(|arg| arg == "-c")?;
    args.get(idx + 1).cloned()
}

fn extract_probed_subject(tool: &AgentTool) -> Option<String> {
    let (command, args) = match tool {
        AgentTool::SysExec { command, args, .. } => (command, args),
        AgentTool::SysExecSession { command, args, .. } => (command, args),
        _ => return None,
    };

    // Prefer the shell script argument when available (sh -c "<script>").
    let mut haystacks: Vec<String> = Vec::new();
    if let Some(script) = extract_shell_script_arg(command, args) {
        haystacks.push(script);
    }
    haystacks.push(command.clone());
    haystacks.extend(args.iter().cloned());

    for text in haystacks {
        if let Some(subject) = scan_for_flagged_subject(&text, "command", "-v") {
            return Some(subject);
        }
        if let Some(subject) = scan_for_which_subject(&text) {
            return Some(subject);
        }
    }

    None
}

fn extract_found_path(output: &str) -> Option<(String, usize)> {
    for (idx, line) in output.lines().enumerate() {
        let trimmed = line.trim();
        let Some((_, rest)) = trimmed.split_once("FOUND:") else {
            continue;
        };
        let path = rest.trim();
        if path.is_empty() {
            continue;
        }
        return Some((path.to_string(), idx));
    }
    None
}

fn basename_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .filter(|name| !name.trim().is_empty())
}

fn extract_version_hint(output: &str, found_line_idx: Option<usize>) -> Option<String> {
    let start_idx = found_line_idx.map(|idx| idx + 1).unwrap_or(0);
    for line in output.lines().skip(start_idx) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("not_found_in_path") {
            continue;
        }
        if trimmed.to_ascii_lowercase().starts_with("exit ") {
            continue;
        }
        if trimmed.to_ascii_lowercase().starts_with("found:") {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

pub fn summarize_command_probe_output(tool: &AgentTool, output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    let not_found = trimmed.contains("NOT_FOUND_IN_PATH") || trimmed.contains("not_found_in_path");
    let found = extract_found_path(trimmed);
    if !not_found && found.is_none() {
        return None;
    }

    let (found_path, found_line_idx) = match found {
        Some((path, idx)) => (Some(path), Some(idx)),
        None => (None, None),
    };

    let subject =
        extract_probed_subject(tool).or_else(|| found_path.as_deref().and_then(basename_from_path));

    if not_found {
        let name = subject.unwrap_or_else(|| "The command".to_string());
        return Some(format!(
            "{} is not installed (it's not found in PATH on this machine).",
            name
        ));
    }

    let name = subject.unwrap_or_else(|| "The command".to_string());
    let mut suffix = String::new();
    if let Some(path) = found_path.as_deref() {
        suffix.push_str(&format!(" (found in PATH at {}).", path));
    } else {
        suffix.push_str(" (found in PATH).");
    }

    if let Some(version) = extract_version_hint(trimmed, found_line_idx) {
        return Some(format!(
            "{} is installed{} Version: {}",
            name, suffix, version
        ));
    }

    Some(format!("{} is installed{}", name, suffix))
}

#[cfg(test)]
mod tests {
    use super::{
        is_command_probe_intent, is_system_clock_read_intent, summarize_command_probe_output,
        summarize_system_clock_output,
    };
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};

    #[test]
    fn detects_command_probe_intent() {
        let resolved = ResolvedIntentState {
            intent_id: "command.probe".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.9,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v2".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        };
        assert!(is_command_probe_intent(Some(&resolved)));
        let mut other = resolved.clone();
        other.intent_id = "command.exec".to_string();
        assert!(!is_command_probe_intent(Some(&other)));
        assert!(!is_command_probe_intent(None));
    }

    #[test]
    fn detects_system_clock_read_intent() {
        let resolved = ResolvedIntentState {
            intent_id: "system.clock.read".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.9,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v2".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        };
        assert!(is_system_clock_read_intent(Some(&resolved)));
    }

    #[test]
    fn summarizes_system_clock_output() {
        let summary = summarize_system_clock_output("2026-02-23T01:23:45Z\n")
            .expect("should produce summary");
        assert!(summary.contains("Current UTC time: 2026-02-23T01:23:45Z"));
    }

    #[test]
    fn summarizes_system_clock_output_from_command_history_prefix() {
        let summary = summarize_system_clock_output(
            "COMMAND_HISTORY:{\"command\":\"date -u +%Y-%m-%dT%H:%M:%SZ\",\"exit_code\":0,\"stdout\":\"2026-02-23T13:36:27Z\",\"stderr\":\"\",\"timestamp_ms\":1771853787127,\"step_index\":0}\n2026-02-23T13:36:27Z\n",
        )
        .expect("should produce summary");
        assert_eq!(summary, "Current UTC time: 2026-02-23T13:36:27Z");
    }

    #[test]
    fn summarizes_system_clock_output_from_embedded_command_history_timestamp() {
        let summary = summarize_system_clock_output(
            "Current UTC time: COMMAND_HISTORY:{\"stdout\":\"2026-02-23T13:36:27Z\"}",
        )
        .expect("should produce summary");
        assert_eq!(summary, "Current UTC time: 2026-02-23T13:36:27Z");
    }

    #[test]
    fn summarizes_not_found_probe() {
        let tool = ioi_types::app::agentic::AgentTool::SysExec {
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; else echo \"NOT_FOUND_IN_PATH\"; fi".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        let summary = summarize_command_probe_output(&tool, "NOT_FOUND_IN_PATH")
            .expect("should produce summary");
        assert!(summary.contains("gimp is not installed"));
    }

    #[test]
    fn summarizes_not_found_probe_for_exec_session() {
        let tool = ioi_types::app::agentic::AgentTool::SysExecSession {
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; else echo \"NOT_FOUND_IN_PATH\"; fi".to_string(),
            ],
            stdin: None,
        };
        let summary = summarize_command_probe_output(&tool, "NOT_FOUND_IN_PATH")
            .expect("should produce summary");
        assert!(summary.contains("gimp is not installed"));
    }

    #[test]
    fn summarizes_found_probe() {
        let tool = ioi_types::app::agentic::AgentTool::SysExec {
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; gimp --version; fi".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        let output = "FOUND: /usr/bin/gimp\nGIMP 2.10.34";
        let summary =
            summarize_command_probe_output(&tool, output).expect("should produce summary");
        assert!(summary.contains("gimp is installed"));
        assert!(summary.contains("/usr/bin/gimp"));
        assert!(summary.contains("Version:"));
    }
}
