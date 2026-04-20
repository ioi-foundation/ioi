use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::automation::{
    artifact_path_for, install_monitor_request, render_installation_summary,
    resolve_automation_root_path, CreateMonitorRequest, AUTOMATION_ROOT_ENV_VAR,
};

pub(crate) fn handle_automation_create_monitor_tool(
    workspace_path: Option<&str>,
    title: Option<String>,
    description: Option<String>,
    keywords: Vec<String>,
    interval_seconds: Option<u64>,
    source_prompt: Option<String>,
) -> ActionExecutionOutcome {
    let Some(root_dir) = resolve_automation_root_path(workspace_path) else {
        return no_visual(
            false,
            None,
            Some(format!(
                "ERROR_CLASS=ToolUnavailable Missing automation runtime root. Set {} before calling monitor__create.",
                AUTOMATION_ROOT_ENV_VAR
            )),
        );
    };

    let request = CreateMonitorRequest {
        title,
        description,
        keywords,
        interval_seconds,
        source_prompt,
    };

    match install_monitor_request(&root_dir, request, "automation.create_monitor") {
        Ok(summary) => {
            let artifact_path = artifact_path_for(&root_dir, &summary.workflow_id);
            let output = format!(
                "{}\nArtifact path: {}",
                render_installation_summary(&summary),
                artifact_path.display()
            );
            no_visual(true, Some(output), None)
        }
        Err(error) => no_visual(false, None, Some(error)),
    }
}

#[cfg(test)]
#[path = "automation/tests.rs"]
mod tests;
