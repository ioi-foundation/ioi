use super::handle_automation_create_monitor_tool_with_root;
use crate::agentic::automation::{
    artifact_path_for, registry_path_for, root_path_for, state_path_for,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root() -> std::path::PathBuf {
    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ioi-automation-handler-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        counter
    ))
}

#[test]
fn automation_handler_fails_when_root_env_is_missing() {
    let (success, output, error, _) = handle_automation_create_monitor_tool_with_root(
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
}

#[test]
fn automation_handler_installs_monitor_artifacts() {
    let root = temp_root();

    let (success, output, error, _) = handle_automation_create_monitor_tool_with_root(
        Some(root.clone()),
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
}

#[test]
fn automation_handler_uses_workspace_root_when_env_is_missing() {
    let workspace_root = temp_root();
    let automation_root = root_path_for(&workspace_root);

    let (success, output, error, _) = handle_automation_create_monitor_tool_with_root(
        Some(automation_root.clone()),
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
}
