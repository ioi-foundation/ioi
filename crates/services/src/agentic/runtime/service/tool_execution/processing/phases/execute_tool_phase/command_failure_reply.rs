use super::*;

fn compact_shell_command_for_reply(command: &str) -> Option<String> {
    let compact = command.split_whitespace().collect::<Vec<_>>().join(" ");
    let compact = compact.trim().replace('`', "'");
    if compact.is_empty() {
        return None;
    }

    const MAX_REPLY_COMMAND_CHARS: usize = 120;
    if compact.chars().count() <= MAX_REPLY_COMMAND_CHARS {
        return Some(compact);
    }

    let mut truncated = compact
        .chars()
        .take(MAX_REPLY_COMMAND_CHARS.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    Some(truncated)
}

pub(super) fn governed_shell_failure_terminal_reply(
    tool: &AgentTool,
    error: &str,
) -> Option<String> {
    let command = compact_shell_command_for_reply(&sys_exec_command_preview(tool)?)?;
    let lower = error.to_ascii_lowercase();

    if lower.contains("error_class=timeoutorhang")
        || lower.contains("foreground sleep command would block")
    {
        return Some(format!(
            "The governed shell blocked {command} as a foreground timeout/hang risk. The command was not left running."
        ));
    }

    if lower.contains("error_class=policyblocked") || lower.contains("blocked by policy") {
        return Some(format!(
            "The governed shell blocked {command} by policy. The command was not run."
        ));
    }

    if lower.contains("error_class=permissionorapprovalrequired")
        || lower.contains("requires approval")
        || lower.contains("approval is required")
    {
        return Some(format!(
            "The governed shell did not run {command} because approval is required."
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys_exec_tool(command: &str, args: Vec<&str>) -> AgentTool {
        AgentTool::SysExec {
            command: command.to_string(),
            args: args.into_iter().map(str::to_string).collect(),
            stdin: None,
            wait_ms_before_async: Some(50),
            detach: false,
        }
    }

    #[test]
    fn reports_timeout_without_error_class() {
        let tool = sys_exec_tool("sleep", vec!["900"]);
        let reply = governed_shell_failure_terminal_reply(
            &tool,
            "ERROR_CLASS=TimeoutOrHang Foreground sleep command would block for 900 second(s).",
        )
        .expect("timeout/hang shell failures should be terminal reply ready");

        assert!(reply.contains("sleep 900"), "{reply}");
        assert!(reply.contains("timeout/hang"), "{reply}");
        assert!(reply.contains("blocked"), "{reply}");
        assert!(!reply.contains("ERROR_CLASS"), "{reply}");
        assert!(!reply.contains("receipt"), "{reply}");
        assert!(!reply.contains("trace"), "{reply}");
    }

    #[test]
    fn reports_policy_denial_without_raw_error() {
        let tool = sys_exec_tool("bash", vec!["-lc", "touch /tmp/nope"]);
        let reply = governed_shell_failure_terminal_reply(
            &tool,
            "ERROR_CLASS=PolicyBlocked shell command blocked by policy",
        )
        .expect("policy shell failures should be terminal reply ready");

        assert!(reply.contains("bash -lc touch /tmp/nope"), "{reply}");
        assert!(reply.contains("blocked"), "{reply}");
        assert!(reply.contains("policy"), "{reply}");
        assert!(!reply.contains("ERROR_CLASS"), "{reply}");
    }
}
