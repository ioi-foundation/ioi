use crate::agentic::desktop::service::step::action::command_contract::{
    format_utc_rfc3339, parse_sleep_seconds, render_command_preview, target_utc_from_run_and_sleep,
};
use crate::agentic::desktop::types::CommandExecution;
use ioi_types::app::agentic::AgentTool;

pub(super) fn duplicate_command_execution_summary(tool: &AgentTool) -> String {
    let _ = tool;
    "Duplicate command action was blocked because it was already executed in this run. Select a new action, verify postconditions, or finalize with evidence."
        .to_string()
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
