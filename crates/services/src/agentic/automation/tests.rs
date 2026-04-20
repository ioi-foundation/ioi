use super::*;

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ioi-automation-test-{}-{}",
        std::process::id(),
        now()
    ))
}

#[test]
fn compile_monitor_request_normalizes_keywords_and_shape() {
    let artifact = compile_monitor_request(
        CreateMonitorRequest {
            title: None,
            description: None,
            keywords: vec![
                "Web4".to_string(),
                " post-quantum cryptography ".to_string(),
                "web4".to_string(),
            ],
            interval_seconds: Some(30),
            source_prompt: Some("Monitor Hacker News for Web4".to_string()),
        },
        "automation.create_monitor",
    )
    .expect("compile monitor request");

    assert_eq!(
        artifact.monitor.predicate.keywords,
        vec!["post-quantum cryptography".to_string(), "web4".to_string()]
    );
    assert_eq!(artifact.trigger.every_seconds, 60);
    assert_eq!(artifact.monitor.source.url, HACKER_NEWS_FRONT_PAGE_URL);
    assert_eq!(
        artifact.provenance.authoring_tool,
        "automation.create_monitor"
    );
}

#[test]
fn install_monitor_request_writes_registry_artifact_state_and_receipt() {
    let root = temp_root();
    let summary = install_monitor_request(
        &root,
        CreateMonitorRequest {
            title: None,
            description: None,
            keywords: vec!["web4".to_string()],
            interval_seconds: Some(300),
            source_prompt: Some("Monitor Hacker News for Web4".to_string()),
        },
        "automation.create_monitor",
    )
    .expect("install monitor request");

    assert!(registry_path_for(&root).exists());
    assert!(artifact_path_for(&root, &summary.workflow_id).exists());
    assert!(state_path_for(&root, &summary.workflow_id).exists());
    assert!(receipt_dir_for(&root, &summary.workflow_id)
        .join("install.json")
        .exists());

    let _ = fs::remove_dir_all(root);
}
