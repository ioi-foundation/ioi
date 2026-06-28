use super::*;

pub(super) fn record_policy_blocked_workspace_read_observation(
    agent_state: &mut AgentState,
    tool: &AgentTool,
    step_index: u32,
    error: &str,
) {
    let Some((tool_name, path)) = workspace_read_policy_tool(tool) else {
        return;
    };
    let Some(policy) = policy_blocked_workspace_read_policy(error) else {
        return;
    };
    let path = path.trim();
    if path.is_empty() {
        return;
    }

    let evidence =
        format!("step={step_index};tool={tool_name};path={path};status=blocked;policy={policy}");
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        evidence.clone(),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read",
        evidence.clone(),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "file_context",
        evidence,
    );
}

pub(super) fn governed_file_policy_failure_observation(
    tool: &AgentTool,
    error: &str,
) -> Option<String> {
    let (tool_name, _) = workspace_read_policy_tool(tool)?;
    let product_tool_label = workspace_read_policy_product_label(tool_name);
    let lower = error.to_ascii_lowercase();

    if lower.contains("symlink paths must be resolved")
        || lower.contains("symlink target is outside workspace authority")
    {
        return Some(format!(
            "The {product_tool_label} was blocked: the symlink would escape outside workspace authority. The target was not read."
        ));
    }

    if lower.contains("filesystem path is outside workspace authority")
        || lower.contains("outside the workspace boundary")
        || lower.contains("outside workspace boundary")
        || lower.contains("outside workspace authority")
    {
        return Some(format!(
            "The {product_tool_label} was blocked: the path is outside workspace authority. The target was not read."
        ));
    }

    if lower.contains("only regular files are allowed") {
        return Some(format!(
            "The {product_tool_label} was blocked: only regular workspace files may be read. The target was not read."
        ));
    }

    None
}

fn workspace_read_policy_product_label(tool_name: &str) -> &'static str {
    match tool_name {
        "file__read" => "governed file read",
        "file__view" => "governed file view",
        "file__info" => "governed file info",
        _ => "governed file tool",
    }
}

fn workspace_read_policy_tool(tool: &AgentTool) -> Option<(&'static str, &str)> {
    match tool {
        AgentTool::FsRead { path } => Some(("file__read", path.as_str())),
        AgentTool::FsView { path, .. } => Some(("file__view", path.as_str())),
        AgentTool::FsStat { path } => Some(("file__info", path.as_str())),
        _ => None,
    }
}

fn policy_blocked_workspace_read_policy(error: &str) -> Option<&'static str> {
    let lower = error.to_ascii_lowercase();
    if lower.contains("filesystem path is outside workspace authority")
        || lower.contains("outside the workspace boundary")
        || lower.contains("outside workspace boundary")
        || lower.contains("outside workspace authority")
    {
        return Some("workspace_filesystem_boundary");
    }
    if lower.contains("symlink paths must be resolved")
        || lower.contains("symlink target is outside workspace authority")
    {
        return Some("workspace_symlink_boundary");
    }
    if lower.contains("only regular files are allowed") {
        return Some("workspace_special_file_boundary");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_workspace_read_policy_denials() {
        assert_eq!(
            policy_blocked_workspace_read_policy(
                "ERROR_CLASS=PolicyBlocked Refusing to read .hypervisor-stage73-outside-link: symlink paths must be resolved by an explicit, governed workflow."
            ),
            Some("workspace_symlink_boundary")
        );
        assert_eq!(
            policy_blocked_workspace_read_policy(
                "Invalid transaction: Blocked by Policy: filesystem path is outside workspace authority."
            ),
            Some("workspace_filesystem_boundary")
        );
        assert_eq!(policy_blocked_workspace_read_policy("model timeout"), None);
    }

    #[test]
    fn file_policy_observation_is_product_safe() {
        let tool = AgentTool::FsRead {
            path: ".hypervisor-stage73-outside-link".to_string(),
        };
        let observation = governed_file_policy_failure_observation(
            &tool,
            "ERROR_CLASS=PolicyBlocked Refusing to read .hypervisor-stage73-outside-link: symlink paths must be resolved by an explicit, governed workflow. stage73-symlink-canary-should-not-leak",
        )
        .expect("symlink boundary denial should be observable");

        assert!(observation.contains("governed file read"), "{observation}");
        assert!(observation.contains("blocked"), "{observation}");
        assert!(observation.contains("symlink"), "{observation}");
        assert!(observation.contains("outside workspace"), "{observation}");
        assert!(!observation.contains("file__read"), "{observation}");
        assert!(
            !observation.contains(".hypervisor-stage73"),
            "{observation}"
        );
        assert!(
            !observation.contains("stage73-symlink-canary"),
            "{observation}"
        );
        assert!(!observation.contains("ERROR_CLASS"), "{observation}");
    }
}
