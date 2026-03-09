use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::automation::{
    artifact_path_for, automation_root_path_from_env, install_monitor_request,
    render_installation_summary, CreateMonitorRequest, AUTOMATION_ROOT_ENV_VAR,
};

pub(crate) fn handle_automation_create_monitor_tool(
    title: Option<String>,
    description: Option<String>,
    keywords: Vec<String>,
    interval_seconds: Option<u64>,
    source_prompt: Option<String>,
) -> ActionExecutionOutcome {
    let Some(root_dir) = automation_root_path_from_env() else {
        return no_visual(
            false,
            None,
            Some(format!(
                "ERROR_CLASS=ToolUnavailable Missing automation runtime root. Set {} before calling automation__create_monitor.",
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
mod tests {
    use super::handle_automation_create_monitor_tool;
    use crate::agentic::automation::{
        artifact_path_for, registry_path_for, state_path_for, AUTOMATION_ROOT_ENV_VAR,
    };

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ioi-automation-handler-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        ))
    }

    #[test]
    fn automation_handler_fails_when_root_env_is_missing() {
        let previous = std::env::var(AUTOMATION_ROOT_ENV_VAR).ok();
        std::env::remove_var(AUTOMATION_ROOT_ENV_VAR);

        let (success, output, error, _) = handle_automation_create_monitor_tool(
            None,
            None,
            vec!["web4".to_string()],
            Some(300),
            Some("Monitor Hacker News for Web4".to_string()),
        );
        assert!(!success);
        assert!(output.is_none());
        assert!(error
            .as_deref()
            .unwrap_or_default()
            .contains("ERROR_CLASS=ToolUnavailable"));

        if let Some(value) = previous {
            std::env::set_var(AUTOMATION_ROOT_ENV_VAR, value);
        }
    }

    #[test]
    fn automation_handler_installs_monitor_artifacts() {
        let root = temp_root();
        let previous = std::env::var(AUTOMATION_ROOT_ENV_VAR).ok();
        std::env::set_var(AUTOMATION_ROOT_ENV_VAR, &root);

        let (success, output, error, _) = handle_automation_create_monitor_tool(
            None,
            None,
            vec!["web4".to_string()],
            Some(300),
            Some("Monitor Hacker News for Web4".to_string()),
        );

        assert!(success);
        assert!(error.is_none());
        let output = output.expect("automation install summary");
        assert!(output.contains("Scheduled workflow:"));
        assert!(registry_path_for(&root).exists());

        let workflow_id_line = output
            .lines()
            .find(|line| line.starts_with("Workflow ID: "))
            .expect("workflow id line");
        let workflow_id = workflow_id_line
            .trim_start_matches("Workflow ID: ")
            .trim()
            .to_string();
        assert!(artifact_path_for(&root, &workflow_id).exists());
        assert!(state_path_for(&root, &workflow_id).exists());

        let _ = std::fs::remove_dir_all(&root);
        if let Some(value) = previous {
            std::env::set_var(AUTOMATION_ROOT_ENV_VAR, value);
        } else {
            std::env::remove_var(AUTOMATION_ROOT_ENV_VAR);
        }
    }
}
