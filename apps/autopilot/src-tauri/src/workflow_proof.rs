use crate::kernel::workflows::{
    compile_monitor_request, monitor_graph_for_keywords, root_path_for, CreateMonitorRequest,
    InstalledWorkflowDetail, WorkflowArtifact, WorkflowManager, WorkflowTrigger,
};
use crate::models::AppState;
use crate::open_or_create_memory_runtime;
use crate::orchestrator::load_assistant_notifications;
use serde::Serialize;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{test::mock_app, Manager, Runtime};
use url::Url;

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn cli_data_dir() -> Result<PathBuf, String> {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = env_text("HOME").ok_or_else(|| "HOME is not set.".to_string())?;
    Ok(PathBuf::from(home)
        .join(".local/share/ai.ioi.autopilot")
        .join("workflow-proof"))
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn required_flag(args: &mut Vec<String>, flag: &str) -> Result<String, String> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Err(format!("Missing required flag '{}'.", flag));
    };
    if index + 1 >= args.len() {
        return Err(format!("Missing value for flag '{}'.", flag));
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Ok(value)
}

fn optional_flag_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    if index + 1 >= args.len() {
        return Err(format!("Missing value for flag '{}'.", flag));
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Ok(Some(value))
}

fn file_url(path: &Path) -> Result<String, String> {
    let canonical_path = path.canonicalize().map_err(|error| {
        format!(
            "Failed to canonicalize workflow proof fixture '{}': {}",
            path.display(),
            error
        )
    })?;
    Url::from_file_path(&canonical_path)
        .map(|url| url.to_string())
        .map_err(|_| {
            format!(
                "Failed to build file URL for '{}'.",
                canonical_path.display()
            )
        })
}

fn build_fixture_artifact(
    fixture_path: &Path,
    workflow_id: &str,
    title: &str,
    description: &str,
    trigger: WorkflowTrigger,
) -> Result<WorkflowArtifact, String> {
    let mut artifact = compile_monitor_request(CreateMonitorRequest {
        title: Some(title.to_string()),
        description: Some(description.to_string()),
        keywords: vec!["web4".to_string(), "post-quantum cryptography".to_string()],
        interval_seconds: Some(120),
        source_prompt: Some("Workflow proof".to_string()),
    })?;
    artifact.workflow_id = workflow_id.to_string();
    artifact.title = title.to_string();
    artifact.description = description.to_string();
    artifact.trigger = trigger;
    artifact.monitor.source.source_type = "hacker_news_front_page_fixture".to_string();
    artifact.monitor.source.url = file_url(fixture_path)?;
    artifact.policy.network_allowlist = vec!["local_fixture".to_string()];
    artifact.graph = monitor_graph_for_keywords(
        &artifact.monitor.predicate.keywords,
        &artifact.trigger,
        &artifact.monitor.source.url,
    );
    Ok(artifact)
}

async fn wait_for_run<R: Runtime + 'static>(
    manager: &WorkflowManager<R>,
    workflow_id: &str,
    expected_run_count: u64,
    timeout_ms: u64,
) -> Result<InstalledWorkflowDetail, String> {
    let started_at = std::time::Instant::now();
    loop {
        let detail = manager
            .get_workflow(workflow_id)
            .await?
            .ok_or_else(|| format!("Workflow '{}' disappeared during proof.", workflow_id))?;
        if detail.summary.run_count >= expected_run_count {
            return Ok(detail);
        }
        if started_at.elapsed().as_millis() as u64 >= timeout_ms {
            return Err(format!(
                "Timed out waiting for workflow '{}' to reach run_count {}.",
                workflow_id, expected_run_count
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowProofSlice {
    summary: crate::kernel::workflows::InstalledWorkflowSummary,
    receipt_count: usize,
    latest_receipt: Option<crate::kernel::workflows::WorkflowRunReceipt>,
    project_node_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowProofOutput {
    fixture_path: String,
    data_dir: String,
    workflow_root: String,
    notification_count: usize,
    notification_titles: Vec<String>,
    interval: WorkflowProofSlice,
    remote: WorkflowProofSlice,
    wait_until: WorkflowProofSlice,
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    println!("{text}");
    Ok(())
}

async fn run_proof(fixture_path: PathBuf, data_dir: PathBuf, wait_ms: u64) -> Result<(), String> {
    if !fixture_path.exists() {
        return Err(format!(
            "Workflow proof fixture '{}' does not exist.",
            fixture_path.display()
        ));
    }
    if data_dir.exists() {
        fs::remove_dir_all(&data_dir).map_err(|error| {
            format!(
                "Failed to clear workflow proof data dir '{}': {}",
                data_dir.display(),
                error
            )
        })?;
    }
    fs::create_dir_all(&data_dir).map_err(|error| {
        format!(
            "Failed to create workflow proof data dir '{}': {}",
            data_dir.display(),
            error
        )
    })?;

    let app = mock_app();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&data_dir)?);
    let mut app_state = AppState::default();
    app_state.memory_runtime = Some(memory_runtime.clone());
    app.manage(Mutex::new(app_state));

    let workflow_root = root_path_for(&data_dir);
    let manager = WorkflowManager::new(app.handle().clone(), workflow_root.clone());
    manager.bootstrap().await?;

    let interval_summary = manager
        .install_workflow(
            build_fixture_artifact(
                &fixture_path,
                "proof_interval_monitor",
                "Proof interval monitor",
                "Proof interval workflow backed by a local Hacker News fixture.",
                WorkflowTrigger {
                    trigger_type: "interval".to_string(),
                    every_seconds: 60,
                    remote_trigger_id: None,
                    wait_until_ms: None,
                },
            )?,
            Some("workflow_proof.interval"),
        )
        .await?;
    let interval_detail = wait_for_run(&manager, &interval_summary.workflow_id, 1, 5_000).await?;
    let interval_project = manager
        .export_project(&interval_summary.workflow_id)
        .await?;
    let _ = manager
        .pause_workflow(&interval_summary.workflow_id)
        .await?;
    let interval_final = manager
        .get_workflow(&interval_summary.workflow_id)
        .await?
        .ok_or_else(|| "Interval workflow detail disappeared.".to_string())?;

    let remote_summary = manager
        .install_workflow(
            build_fixture_artifact(
                &fixture_path,
                "proof_remote_monitor",
                "Proof remote monitor",
                "Proof remote-trigger workflow backed by a local Hacker News fixture.",
                WorkflowTrigger {
                    trigger_type: "remote".to_string(),
                    every_seconds: 0,
                    remote_trigger_id: Some("proof.remote.monitor".to_string()),
                    wait_until_ms: None,
                },
            )?,
            Some("workflow_proof.remote"),
        )
        .await?;
    let _ = manager
        .trigger_workflow_remote(
            &remote_summary.workflow_id,
            Some("workflow-proof-remote-trigger-1".to_string()),
            Some(json!({
                "source": "workflow-proof",
                "event": "remote-trigger",
            })),
        )
        .await?;
    let remote_detail = wait_for_run(&manager, &remote_summary.workflow_id, 1, 5_000).await?;
    let remote_project = manager.export_project(&remote_summary.workflow_id).await?;

    let wait_until_summary = manager
        .install_workflow(
            build_fixture_artifact(
                &fixture_path,
                "proof_wait_until_monitor",
                "Proof durable wait monitor",
                "Proof durable-wait workflow backed by a local Hacker News fixture.",
                WorkflowTrigger {
                    trigger_type: "wait_until".to_string(),
                    every_seconds: 0,
                    remote_trigger_id: None,
                    wait_until_ms: Some(crate::kernel::state::now().saturating_add(wait_ms)),
                },
            )?,
            Some("workflow_proof.wait_until"),
        )
        .await?;
    let wait_until_detail = wait_for_run(
        &manager,
        &wait_until_summary.workflow_id,
        1,
        wait_ms + 5_000,
    )
    .await?;
    let wait_until_project = manager
        .export_project(&wait_until_summary.workflow_id)
        .await?;

    let notifications = load_assistant_notifications(&memory_runtime);
    print_json(&WorkflowProofOutput {
        fixture_path: slash_path(&fixture_path),
        data_dir: slash_path(&data_dir),
        workflow_root: slash_path(&workflow_root),
        notification_count: notifications.len(),
        notification_titles: notifications
            .iter()
            .map(|item| item.title.clone())
            .collect::<Vec<_>>(),
        interval: WorkflowProofSlice {
            summary: interval_final.summary,
            receipt_count: interval_detail.recent_receipts.len(),
            latest_receipt: interval_detail.recent_receipts.first().cloned(),
            project_node_count: interval_project.nodes.len(),
        },
        remote: WorkflowProofSlice {
            summary: remote_detail.summary,
            receipt_count: remote_detail.recent_receipts.len(),
            latest_receipt: remote_detail.recent_receipts.first().cloned(),
            project_node_count: remote_project.nodes.len(),
        },
        wait_until: WorkflowProofSlice {
            summary: wait_until_detail.summary,
            receipt_count: wait_until_detail.recent_receipts.len(),
            latest_receipt: wait_until_detail.recent_receipts.first().cloned(),
            project_node_count: wait_until_project.nodes.len(),
        },
    })
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().cloned().ok_or_else(|| {
        "Usage: autopilot_workflow_proof prove --fixture <path> [--data-dir <path>] [--wait-ms <ms>]"
            .to_string()
    })?;
    args.remove(0);
    if command != "prove" {
        return Err(format!(
            "Unknown command '{}'. Usage: autopilot_workflow_proof prove --fixture <path> [--data-dir <path>] [--wait-ms <ms>]",
            command
        ));
    }

    let fixture_path = PathBuf::from(required_flag(&mut args, "--fixture")?);
    let data_dir = optional_flag_value(&mut args, "--data-dir")?
        .map(PathBuf::from)
        .unwrap_or(cli_data_dir()?);
    let wait_ms = optional_flag_value(&mut args, "--wait-ms")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("Invalid value for '--wait-ms': {}", error))
        })
        .transpose()?
        .unwrap_or(250);
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("Failed to start proof runtime: {}", error))?;
    runtime.block_on(run_proof(fixture_path, data_dir, wait_ms))
}
