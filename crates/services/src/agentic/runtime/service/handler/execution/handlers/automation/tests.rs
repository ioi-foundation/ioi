use super::handle_automation_create_monitor_tool;
use crate::agentic::automation::{
    artifact_path_for, registry_path_for, root_path_for, state_path_for, AUTOMATION_ROOT_ENV_VAR,
};
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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
    let _guard = env_lock().lock().expect("env lock");
    let previous = std::env::var(AUTOMATION_ROOT_ENV_VAR).ok();
    std::env::remove_var(AUTOMATION_ROOT_ENV_VAR);

    let (success, output, error, _) = handle_automation_create_monitor_tool(
        None,
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
    let _guard = env_lock().lock().expect("env lock");
    let root = temp_root();
    let previous = std::env::var(AUTOMATION_ROOT_ENV_VAR).ok();
    std::env::set_var(AUTOMATION_ROOT_ENV_VAR, &root);

    let (success, output, error, _) = handle_automation_create_monitor_tool(
        None,
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

#[test]
fn automation_handler_uses_workspace_root_when_env_is_missing() {
    let _guard = env_lock().lock().expect("env lock");
    let workspace_root = temp_root();
    let automation_root = root_path_for(&workspace_root);
    let previous = std::env::var(AUTOMATION_ROOT_ENV_VAR).ok();
    std::env::remove_var(AUTOMATION_ROOT_ENV_VAR);

    let workspace = workspace_root.to_string_lossy().to_string();
    let (success, output, error, _) = handle_automation_create_monitor_tool(
        Some(&workspace),
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
    assert!(registry_path_for(&automation_root).exists());

    let workflow_id_line = output
        .lines()
        .find(|line| line.starts_with("Workflow ID: "))
        .expect("workflow id line");
    let workflow_id = workflow_id_line
        .trim_start_matches("Workflow ID: ")
        .trim()
        .to_string();
    assert!(artifact_path_for(&automation_root, &workflow_id).exists());
    assert!(state_path_for(&automation_root, &workflow_id).exists());

    let _ = std::fs::remove_dir_all(&workspace_root);
    if let Some(value) = previous {
        std::env::set_var(AUTOMATION_ROOT_ENV_VAR, value);
    } else {
        std::env::remove_var(AUTOMATION_ROOT_ENV_VAR);
    }
}
