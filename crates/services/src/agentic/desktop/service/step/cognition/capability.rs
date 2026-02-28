use crate::agentic::desktop::service::step::signals::{
    is_mail_connector_tool_name, is_mailbox_connector_intent,
};
use ioi_types::app::agentic::{IntentScopeProfile, LlmToolDefinition};

pub(super) fn preflight_missing_capability(
    scope: IntentScopeProfile,
    is_browser_active: bool,
    tools: &[LlmToolDefinition],
) -> Option<(String, String)> {
    // Browser windows have their own tool surface; avoid false escalations here.
    if is_browser_active {
        return None;
    }

    let has_tool = |name: &str| tools.iter().any(|t| t.name == name);

    let requires_ui_interaction = matches!(scope, IntentScopeProfile::UiInteraction);
    let requires_browser_interaction = matches!(scope, IntentScopeProfile::WebResearch);
    let requires_command_execution = matches!(scope, IntentScopeProfile::CommandExecution);
    let requires_workspace_ops = matches!(scope, IntentScopeProfile::WorkspaceOps);

    let has_browser_tooling = has_tool("web__search")
        || has_tool("web__read")
        || has_tool("browser__navigate")
        || has_tool("browser__snapshot")
        || has_tool("browser__click")
        || has_tool("browser__click_element");

    let can_click =
        has_tool("computer") || has_tool("gui__click_element") || has_tool("gui__click");
    let can_type = has_tool("computer") || has_tool("gui__type");

    let has_command_tool = has_tool("sys__exec") || has_tool("sys__exec_session");
    let has_install_package_tool = has_tool("sys__install_package");
    let has_filesystem_tooling = tools.iter().any(|t| t.name.starts_with("filesystem__"));

    if requires_browser_interaction && !has_browser_tooling {
        return Some((
            "browser__navigate".to_string(),
            "Resolver selected web_research scope but browser tooling is unavailable.".to_string(),
        ));
    }

    if requires_ui_interaction && !can_click {
        return Some((
            "gui__click_element".to_string(),
            "Resolver selected ui_interaction scope but no click-capable tool is available."
                .to_string(),
        ));
    }

    if requires_ui_interaction && !can_type {
        return Some((
            "gui__type".to_string(),
            "Resolver selected ui_interaction scope but no typing-capable tool is available."
                .to_string(),
        ));
    }

    if requires_command_execution && !has_command_tool && !has_install_package_tool {
        return Some((
            "sys__exec".to_string(),
            "Resolver selected command_execution scope but neither sys__exec nor sys__exec_session is available."
                .to_string(),
        ));
    }

    if requires_workspace_ops && !has_filesystem_tooling {
        return Some((
            "filesystem__read_file".to_string(),
            "Resolver selected workspace_ops scope but filesystem tooling is unavailable."
                .to_string(),
        ));
    }

    None
}

fn mailbox_connector_tool_names(tools: &[LlmToolDefinition]) -> Vec<String> {
    let mut names = tools
        .iter()
        .filter(|tool| is_mail_connector_tool_name(&tool.name))
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

pub(super) fn mailbox_connector_instruction(
    goal: &str,
    tools: &[LlmToolDefinition],
) -> Option<String> {
    if !is_mailbox_connector_intent(goal) {
        return None;
    }

    let names = mailbox_connector_tool_names(tools);
    if names.is_empty() {
        return Some(
            "18. MAILBOX CONNECTOR RULE: This request is mailbox-local. Do NOT use `web__search`, `web__read`, `browser__*`, or `memory__search` as a substitute. Use `chat__reply` to state mailbox-access limitation and provide actionable connector next steps with an absolute UTC timestamp and at least one citation line.".to_string(),
        );
    }

    Some(format!(
        "18. MAILBOX CONNECTOR RULE: This request is mailbox-local. Use mailbox connector tooling first: {}. Do NOT use `web__search`, `web__read`, or `browser__*` unless the user explicitly asks for public-web context.",
        names.join(", ")
    ))
}
