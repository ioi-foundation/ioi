use super::*;
use crate::models::AppState;
use crate::open_or_create_memory_runtime;
use crate::orchestrator::load_assistant_notifications;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{test::mock_app, Manager, Runtime};

fn test_fixture_html() -> &'static str {
    r#"
        <html>
          <body>
            <span class="titleline"><a href="https://example.com/web4">Web4 Arrives</a></span>
            <span class="titleline"><a href="item?id=123">Ask HN: post-quantum cryptography</a></span>
          </body>
        </html>
    "#
}

fn write_fixture_file(dir: &Path) -> PathBuf {
    let fixture_path = dir.join("hacker-news-fixture.html");
    std::fs::write(&fixture_path, test_fixture_html()).expect("write fixture");
    fixture_path
}

fn test_data_dir(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ioi-workflow-test-{}-{}", label, Uuid::new_v4()));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("clear old test dir");
    }
    std::fs::create_dir_all(&root).expect("create test dir");
    root
}

fn build_fixture_artifact_for_test(
    fixture_path: &Path,
    workflow_id: &str,
    title: &str,
    trigger: WorkflowTrigger,
) -> WorkflowArtifact {
    let mut artifact = compile_monitor_request(CreateMonitorRequest {
        title: Some(title.to_string()),
        description: Some("Fixture-backed workflow test".to_string()),
        keywords: vec!["web4".to_string(), "post-quantum cryptography".to_string()],
        interval_seconds: Some(120),
        source_prompt: Some("workflow test".to_string()),
    })
    .expect("artifact");
    artifact.workflow_id = workflow_id.to_string();
    artifact.title = title.to_string();
    artifact.trigger = trigger;
    artifact.monitor.source.source_type = HACKER_NEWS_FIXTURE_SOURCE_KIND.to_string();
    artifact.monitor.source.url = Url::from_file_path(fixture_path)
        .expect("fixture file url")
        .to_string();
    artifact.policy.network_allowlist = vec!["local_fixture".to_string()];
    artifact.graph = monitor_graph_for_keywords(
        &artifact.monitor.predicate.keywords,
        &artifact.trigger,
        &artifact.monitor.source.url,
    );
    artifact
}

async fn wait_for_workflow_run<R: Runtime + 'static>(
    manager: &WorkflowManager<R>,
    workflow_id: &str,
    expected_run_count: u64,
    timeout: Duration,
) -> InstalledWorkflowDetail {
    let started_at = Instant::now();
    loop {
        let detail = manager
            .get_workflow(workflow_id)
            .await
            .expect("read workflow")
            .expect("workflow detail");
        if detail.summary.run_count >= expected_run_count {
            return detail;
        }
        assert!(
            started_at.elapsed() < timeout,
            "timed out waiting for workflow '{}' to reach run_count {}",
            workflow_id,
            expected_run_count
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn compile_monitor_request_normalizes_keywords_and_shape() {
    let artifact = compile_monitor_request(CreateMonitorRequest {
        title: None,
        description: None,
        keywords: vec![
            "Web4".to_string(),
            " post-quantum cryptography ".to_string(),
            "web4".to_string(),
        ],
        interval_seconds: Some(30),
        source_prompt: Some("Monitor Hacker News".to_string()),
    })
    .expect("artifact");

    assert_eq!(artifact.spec_version, AUTOMATION_SPEC_VERSION);
    assert_eq!(
        artifact.monitor.predicate.keywords,
        vec!["post-quantum cryptography".to_string(), "web4".to_string()]
    );
    assert_eq!(artifact.trigger.every_seconds, 60);
    assert_eq!(artifact.monitor.source.url, HACKER_NEWS_FRONT_PAGE_URL);
}

#[test]
fn extract_hacker_news_titles_reads_expected_anchors() {
    let html = r#"
        <html>
          <body>
            <span class="titleline"><a href="https://example.com/a">Web4 Arrives</a></span>
            <span class="titleline"><a href="item?id=123">Ask HN: post-quantum cryptography</a></span>
          </body>
        </html>
    "#;
    let headlines = extract_hacker_news_titles(html).expect("headlines");
    assert_eq!(headlines.len(), 2);
    assert_eq!(headlines[0].title, "Web4 Arrives");
    assert_eq!(
        headlines[1].href,
        "https://news.ycombinator.com/item?id=123"
    );
}

#[test]
fn dedupe_seen_keys_keeps_unique_recent_values() {
    let mut seen_keys = vec![
        "one".to_string(),
        "two".to_string(),
        "one".to_string(),
        "three".to_string(),
    ];
    dedupe_seen_keys(&mut seen_keys);
    assert_eq!(
        seen_keys,
        vec!["one".to_string(), "two".to_string(), "three".to_string()]
    );
}

#[test]
fn project_projection_uses_workflow_metadata() {
    let artifact = compile_monitor_request(CreateMonitorRequest {
        title: Some("HN Monitor".to_string()),
        description: Some("Testing".to_string()),
        keywords: vec!["web4".to_string()],
        interval_seconds: Some(300),
        source_prompt: None,
    })
    .expect("artifact");
    let project = project_from_artifact(&artifact);
    assert_eq!(project.version, "1.0.0");
    assert_eq!(project.nodes.len(), 6);
    assert_eq!(project.global_config["meta"]["name"], "HN Monitor");
}

#[tokio::test]
async fn workflow_manager_supports_remote_and_wait_until_fixture_triggers() {
    let data_dir = test_data_dir("temporal");
    let fixture_path = write_fixture_file(&data_dir);
    let app = mock_app();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&data_dir).expect("memory"));
    let mut app_state = AppState::default();
    app_state.memory_runtime = Some(memory_runtime.clone());
    app.manage(Mutex::new(app_state));

    let manager = WorkflowManager::new(app.handle().clone(), root_path_for(&data_dir));
    manager.bootstrap().await.expect("bootstrap");

    let remote_summary = manager
        .install_workflow(
            build_fixture_artifact_for_test(
                &fixture_path,
                "test_remote_monitor",
                "Test remote monitor",
                WorkflowTrigger {
                    trigger_type: WORKFLOW_TRIGGER_REMOTE.to_string(),
                    every_seconds: 0,
                    remote_trigger_id: Some("tests.workflow.remote".to_string()),
                    wait_until_ms: None,
                },
            ),
            Some("workflow.tests.remote"),
        )
        .await
        .expect("install remote");
    assert_eq!(remote_summary.trigger_kind, WORKFLOW_TRIGGER_REMOTE);
    assert_eq!(
        remote_summary.remote_trigger_id.as_deref(),
        Some("tests.workflow.remote")
    );
    assert_eq!(remote_summary.next_run_at_ms, None);

    let remote_receipt = manager
        .trigger_workflow_remote(
            &remote_summary.workflow_id,
            Some("workflow-test-remote-trigger-1".to_string()),
            Some(json!({"source":"test","event":"remote"})),
        )
        .await
        .expect("trigger remote");
    assert_eq!(remote_receipt.trigger_kind, WORKFLOW_TRIGGER_REMOTE);
    assert_eq!(remote_receipt.status, "success");
    assert_eq!(
        remote_receipt.idempotency_key.as_deref(),
        Some("workflow-test-remote-trigger-1")
    );

    let remote_detail = wait_for_workflow_run(
        &manager,
        &remote_summary.workflow_id,
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(remote_detail.summary.status, WorkflowStatus::Active);
    assert_eq!(
        remote_detail.summary.trigger_label,
        "Remote trigger tests.workflow.remote"
    );
    assert_eq!(
        remote_detail.recent_receipts.first().and_then(|receipt| {
            receipt.observation["remotePayload"]["event"]
                .as_str()
                .map(str::to_string)
        }),
        Some("remote".to_string())
    );

    let wait_until_at = now().saturating_add(250);
    let wait_summary = manager
        .install_workflow(
            build_fixture_artifact_for_test(
                &fixture_path,
                "test_wait_until_monitor",
                "Test wait-until monitor",
                WorkflowTrigger {
                    trigger_type: WORKFLOW_TRIGGER_WAIT_UNTIL.to_string(),
                    every_seconds: 0,
                    remote_trigger_id: None,
                    wait_until_ms: Some(wait_until_at),
                },
            ),
            Some("workflow.tests.wait_until"),
        )
        .await
        .expect("install wait until");
    assert_eq!(wait_summary.trigger_kind, WORKFLOW_TRIGGER_WAIT_UNTIL);
    assert_eq!(wait_summary.wait_until_ms, Some(wait_until_at));
    assert_eq!(wait_summary.next_run_at_ms, Some(wait_until_at));

    let wait_detail = wait_for_workflow_run(
        &manager,
        &wait_summary.workflow_id,
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(wait_detail.summary.status, WorkflowStatus::Paused);
    assert_eq!(wait_detail.summary.next_run_at_ms, None);
    assert_eq!(
        wait_detail
            .recent_receipts
            .first()
            .map(|receipt| receipt.workflow_status.clone()),
        Some(WorkflowStatus::Paused)
    );

    let notification_titles = load_assistant_notifications(&memory_runtime)
        .into_iter()
        .map(|record| record.title)
        .collect::<Vec<_>>();
    assert!(
        notification_titles
            .iter()
            .any(|title| title.contains("Web4 Arrives")),
        "expected workflow notifications to include the fixture match"
    );

    std::fs::remove_dir_all(&data_dir).expect("remove test data dir");
}
