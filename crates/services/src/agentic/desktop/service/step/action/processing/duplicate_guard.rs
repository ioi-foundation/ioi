use crate::agentic::desktop::service::step::action::command_contract::{
    format_utc_rfc3339, parse_sleep_seconds, render_command_preview, target_utc_from_run_and_sleep,
};
use crate::agentic::desktop::types::CommandExecution;
use ioi_types::app::agentic::AgentTool;
use std::collections::VecDeque;

pub(super) fn duplicate_command_execution_summary(tool: &AgentTool) -> String {
    let _ = tool;
    "Duplicate command action was blocked because it was already executed in this run. Select a new action, verify postconditions, or finalize with evidence."
        .to_string()
}

pub(super) fn find_matching_command_history_entry<'a>(
    tool: &AgentTool,
    history: &'a VecDeque<CommandExecution>,
) -> Option<&'a CommandExecution> {
    let command_preview = match tool {
        AgentTool::SysExec { command, args, .. } => render_command_preview(command, args),
        AgentTool::SysExecSession { command, args, .. } => render_command_preview(command, args),
        _ => return None,
    };

    history
        .iter()
        .rev()
        .find(|entry| entry.exit_code == 0 && commands_equivalent(&command_preview, &entry.command))
}

pub(super) fn duplicate_command_completion_summary(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    let (sleep_seconds, executed_command) = match tool {
        AgentTool::SysExec {
            command,
            args,
            detach,
            ..
        } => {
            if !*detach {
                return None;
            }
            let command_preview = render_command_preview(command, args);
            let sleep_seconds = parse_sleep_seconds(&command_preview)?;
            (sleep_seconds, command_preview)
        }
        _ => return None,
    };
    let entry = history_entry?;
    if entry.exit_code != 0 {
        return None;
    }
    let run_timestamp_utc = format_utc_rfc3339(entry.timestamp_ms)?;
    let target_utc = target_utc_from_run_and_sleep(entry.timestamp_ms, sleep_seconds)?;
    let mechanism = if let Some(pid) = extract_background_pid(&entry.stdout) {
        format!(
            "Detached sys__exec command '{}' launched as background process (PID: {}).",
            executed_command, pid
        )
    } else {
        format!(
            "Detached sys__exec command '{}' launched as background process.",
            executed_command
        )
    };
    Some(format!(
        "Timer scheduled.\nMechanism: {}\nRun timestamp (UTC): {}\nTarget UTC: {}",
        mechanism, run_timestamp_utc, target_utc
    ))
}

pub(super) fn duplicate_command_cached_success_summary(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    let command_preview = match tool {
        AgentTool::SysExec {
            command,
            args,
            detach,
            ..
        } => {
            if *detach {
                return None;
            }
            render_command_preview(command, args)
        }
        AgentTool::SysExecSession { command, args, .. } => render_command_preview(command, args),
        _ => return None,
    };

    let entry = history_entry?;
    if entry.exit_code != 0 {
        return None;
    }

    // Reuse only read/probe commands to avoid masking side-effecting workflows.
    if !is_safe_read_probe_command(&command_preview) {
        return None;
    }

    if !commands_equivalent(&command_preview, &entry.command) {
        return None;
    }

    let run_timestamp_utc = format_utc_rfc3339(entry.timestamp_ms)?;
    let stdout = entry.stdout.trim();
    let stderr = entry.stderr.trim();
    let mut summary = format!(
        "Reused prior successful command result for '{}'.\nRun timestamp (UTC): {}",
        command_preview, run_timestamp_utc
    );
    if !stdout.is_empty() {
        summary.push_str(&format!("\nStdout: {}", stdout));
    }
    if !stderr.is_empty() {
        summary.push_str(&format!("\nStderr: {}", stderr));
    }
    Some(summary)
}

pub(super) fn duplicate_command_cached_completion_summary(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    // Reuse eligibility checks from cached-success path.
    let _ = duplicate_command_cached_success_summary(tool, history_entry)?;
    let entry = history_entry?;
    if normalize_command_binary(&entry.command).as_deref() == Some("find")
        && is_safe_find_probe_command(entry.command.trim())
    {
        let stdout = entry.stdout.trim();
        if !stdout.is_empty() {
            return Some(stdout.to_string());
        }
    }
    preferred_cached_completion_line(&entry.stdout)
        .or_else(|| preferred_cached_completion_line(&entry.stderr))
        .or_else(|| duplicate_command_cached_success_summary(tool, Some(entry)))
}

fn preferred_cached_completion_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.to_string())
}

fn commands_equivalent(left: &str, right: &str) -> bool {
    normalize_command_string(left) == normalize_command_string(right)
}

fn normalize_command_string(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_command_binary(command_preview: &str) -> Option<String> {
    let trimmed = command_preview.trim();
    if trimmed.is_empty() {
        return None;
    }
    let binary = trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| ch == '\'' || ch == '"' || ch == '`')
        .to_ascii_lowercase();
    if binary.is_empty() {
        None
    } else {
        Some(binary)
    }
}

fn is_safe_read_probe_command(command_preview: &str) -> bool {
    let trimmed = command_preview.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Reject obvious side-effect operators/chaining.
    if trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
        || trimmed.contains('|')
        || trimmed.contains('>')
        || trimmed.contains('<')
    {
        return false;
    }

    let Some(binary) = normalize_command_binary(trimmed) else {
        return false;
    };

    matches!(
        binary.as_str(),
        "date"
            | "echo"
            | "printf"
            | "pwd"
            | "whoami"
            | "uname"
            | "id"
            | "hostname"
            | "which"
            | "command"
            | "ls"
            | "env"
    )
        || (binary == "find" && is_safe_find_probe_command(trimmed))
}

fn is_safe_find_probe_command(command_preview: &str) -> bool {
    let disallowed_tokens = [
        "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf",
        "-fls",
    ];

    command_preview
        .split_whitespace()
        .map(|token| token.to_ascii_lowercase())
        .all(|token| !disallowed_tokens.contains(&token.as_str()))
}

fn extract_background_pid(stdout: &str) -> Option<String> {
    let marker_idx = stdout.find("PID:")?;
    let suffix = &stdout[marker_idx + "PID:".len()..];
    let pid: String = suffix
        .chars()
        .skip_while(|c| c.is_ascii_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if pid.is_empty() {
        None
    } else {
        Some(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        duplicate_command_cached_completion_summary, duplicate_command_cached_success_summary,
        duplicate_command_completion_summary, find_matching_command_history_entry,
    };
    use crate::agentic::desktop::types::CommandExecution;
    use ioi_types::app::agentic::AgentTool;
    use std::collections::VecDeque;

    #[test]
    fn duplicate_detached_timer_terminalizes() {
        let tool = AgentTool::SysExec {
            command: "sleep".to_string(),
            args: vec![
                "900".to_string(),
                "&&".to_string(),
                "notify-send".to_string(),
                "Timer".to_string(),
            ],
            stdin: None,
            detach: true,
        };
        let history = CommandExecution {
            command: "sleep 900 && notify-send Timer".to_string(),
            exit_code: 0,
            stdout: "Launched background process '/bin/bash' (PID: 1234)".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 0,
        };
        let summary = duplicate_command_completion_summary(&tool, Some(&history))
            .expect("detached timer should terminalize");
        assert!(summary.contains("Timer scheduled."));
        assert!(summary.contains("Target UTC:"));
    }

    #[test]
    fn duplicate_safe_probe_reuses_prior_success() {
        let tool = AgentTool::SysExec {
            command: "date".to_string(),
            args: vec!["+%Y-%m-%dT%H:%M:%SZ".to_string()],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "date +%Y-%m-%dT%H:%M:%SZ".to_string(),
            exit_code: 0,
            stdout: "2026-02-25T06:13:00Z".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 1,
        };
        let summary = duplicate_command_cached_success_summary(&tool, Some(&history))
            .expect("safe probe command should reuse cached success");
        assert!(summary.contains("Reused prior successful command result"));
        assert!(summary.contains("Stdout: 2026-02-25T06:13:00Z"));
    }

    #[test]
    fn duplicate_safe_probe_completion_prefers_stdout_line() {
        let tool = AgentTool::SysExec {
            command: "echo".to_string(),
            args: vec!["$((247 * 38))".to_string()],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "echo $((247 * 38))".to_string(),
            exit_code: 0,
            stdout: "9386\n".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 1,
        };
        let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
            .expect("completion summary should be derived from cached stdout");
        assert_eq!(summary, "9386");
    }

    #[test]
    fn matching_history_entry_finds_equivalent_command() {
        let tool = AgentTool::SysExec {
            command: "date".to_string(),
            args: vec!["-u".to_string()],
            stdin: None,
            detach: false,
        };
        let history = VecDeque::from(vec![
            CommandExecution {
                command: "sleep 900 && notify-send Timer".to_string(),
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timestamp_ms: 1_772_000_000_000,
                step_index: 0,
            },
            CommandExecution {
                command: "date -u".to_string(),
                exit_code: 0,
                stdout: "Wed Feb 25 07:13:57 UTC 2026".to_string(),
                stderr: String::new(),
                timestamp_ms: 1_772_000_001_000,
                step_index: 1,
            },
        ]);
        let matched = find_matching_command_history_entry(&tool, &history)
            .expect("expected to find matching date -u history entry");
        assert_eq!(matched.command, "date -u");
    }

    #[test]
    fn duplicate_find_probe_reuses_prior_success() {
        let tool = AgentTool::SysExec {
            command: "find".to_string(),
            args: vec![
                "/home/user".to_string(),
                "-type".to_string(),
                "f".to_string(),
                "-name".to_string(),
                "*.pdf".to_string(),
                "-mtime".to_string(),
                "-7".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "find /home/user -type f -name *.pdf -mtime -7".to_string(),
            exit_code: 0,
            stdout: "/home/user/report.pdf".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 1,
        };
        let summary = duplicate_command_cached_success_summary(&tool, Some(&history))
            .expect("safe find probe command should reuse cached success");
        assert!(summary.contains("Reused prior successful command result"));
        assert!(summary.contains("Stdout: /home/user/report.pdf"));
    }

    #[test]
    fn duplicate_find_with_delete_is_not_reused() {
        let tool = AgentTool::SysExec {
            command: "find".to_string(),
            args: vec![
                "/home/user".to_string(),
                "-type".to_string(),
                "f".to_string(),
                "-name".to_string(),
                "*.pdf".to_string(),
                "-delete".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "find /home/user -type f -name *.pdf -delete".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 1,
        };
        assert!(duplicate_command_cached_success_summary(&tool, Some(&history)).is_none());
    }

    #[test]
    fn duplicate_find_completion_returns_full_stdout() {
        let tool = AgentTool::SysExec {
            command: "find".to_string(),
            args: vec![
                "/home/user".to_string(),
                "-type".to_string(),
                "f".to_string(),
                "-name".to_string(),
                "*.pdf".to_string(),
                "-mtime".to_string(),
                "-7".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "find /home/user -type f -name *.pdf -mtime -7".to_string(),
            exit_code: 0,
            stdout: "/home/user/a.pdf\n/home/user/b.pdf\n".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 1,
        };
        let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
            .expect("safe find completion should use full stdout");
        assert_eq!(summary, "/home/user/a.pdf\n/home/user/b.pdf");
    }
}
