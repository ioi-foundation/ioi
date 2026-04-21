use crate::kernel::events::{build_event, register_artifact, register_event};
use crate::kernel::state::update_task_state;
use crate::models::{
    AppState, Artifact, ArtifactRef, ArtifactType, BuildArtifactSession, ChatArtifactSession,
    EventStatus, EventType, ChatArtifactLifecycleState, ChatArtifactManifestVerification,
    ChatArtifactMaterializationContract, ChatArtifactVerificationStatus, ChatBuildReceipt,
};
use ioi_api::runtime_harness::{ArtifactOperatorPhase, ArtifactOperatorRunStatus};
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use super::{
    apply_chat_authoritative_status, build_session_to_renderer_session,
    create_receipt_report_artifact, lifecycle_state_label, now_iso, refresh_pipeline_steps,
    update_chat_session_from_build_session, verified_reply_from_manifest, BUILD_LENSES_IN_PROGRESS,
    BUILD_LENSES_READY,
};

static PREVIEW_PROCESS_REGISTRY: Lazy<Mutex<HashMap<String, ChatPreviewProcess>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct ChatPreviewProcess {
    child: Child,
}

struct CommandExecutionResult {
    command: String,
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    duration_ms: u64,
}

pub(super) fn spawn_build_supervisor(
    app: AppHandle,
    chat_session: ChatArtifactSession,
    build_session: BuildArtifactSession,
) {
    tauri::async_runtime::spawn(async move {
        let app_for_thread = app.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            run_build_supervisor_blocking(&app_for_thread, chat_session, build_session)
        })
        .await;

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                update_task_state(&app, |task| {
                    if let Some(build_session) = task.build_session.as_mut() {
                        build_session.build_status = "failed".to_string();
                        build_session.verification_status = "failed".to_string();
                        build_session.last_failure_summary = Some(error.clone());
                        build_session.current_worker_execution.execution_state =
                            "failed_terminal".to_string();
                    }
                    let build_session_snapshot = task.build_session.clone();
                    if let Some(chat_session) = task.chat_session.as_mut() {
                        chat_session.lifecycle_state = ChatArtifactLifecycleState::Failed;
                        chat_session.status =
                            lifecycle_state_label(ChatArtifactLifecycleState::Failed).to_string();
                        chat_session.artifact_manifest.verification =
                            ChatArtifactManifestVerification {
                                status: ChatArtifactVerificationStatus::Failed,
                                lifecycle_state: ChatArtifactLifecycleState::Failed,
                                summary: error.clone(),
                                production_provenance: chat_session
                                    .materialization
                                    .production_provenance
                                    .clone(),
                                acceptance_provenance: chat_session
                                    .materialization
                                    .acceptance_provenance
                                    .clone(),
                                failure: chat_session.materialization.failure.clone(),
                            };
                        chat_session.verified_reply = verified_reply_from_manifest(
                            &chat_session.title,
                            &chat_session.artifact_manifest,
                        );
                        refresh_pipeline_steps(chat_session, build_session_snapshot.as_ref());
                        chat_session.updated_at = now_iso();
                    }
                    task.current_step = format!("Chat build supervisor failed: {}", error);
                });
            }
            Err(join_error) => {
                update_task_state(&app, |task| {
                    task.current_step =
                        format!("Chat build supervisor join failure: {}", join_error);
                });
            }
        }
    });
}

pub(super) fn run_build_supervisor_for_proof(
    chat_session: &mut ChatArtifactSession,
    build_session: &mut BuildArtifactSession,
) -> Result<(), String> {
    let workspace_root = PathBuf::from(&build_session.workspace_root);

    chat_session.lifecycle_state = ChatArtifactLifecycleState::Implementing;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Implementing).to_string();
    build_session.build_status = "installing".to_string();
    build_session.current_worker_execution.execution_state = "validating".to_string();
    update_workspace_verification_step(&mut chat_session.materialization, "install", "running");

    let install_result = run_command_capture(
        &workspace_root,
        npm_binary(),
        &["install", "--no-audit", "--no-fund"],
    )?;
    record_command_receipt_for_proof(
        chat_session,
        build_session,
        "install",
        "Install dependencies",
        &install_result,
        None,
    );

    if !install_result.success {
        build_session.retry_count += 1;
        let retry_result = run_command_capture(
            &workspace_root,
            npm_binary(),
            &["install", "--no-audit", "--no-fund"],
        )?;
        record_command_receipt_for_proof(
            chat_session,
            build_session,
            "install",
            "Retry dependency install",
            &retry_result,
            Some("network_or_registry".to_string()),
        );
        if !retry_result.success {
            mark_build_failed_for_proof(
                chat_session,
                build_session,
                "Install failed after a bounded retry.".to_string(),
            );
            return Ok(());
        }
    }

    build_session.build_status = "validating".to_string();
    update_workspace_verification_step(&mut chat_session.materialization, "install", "success");
    update_workspace_verification_step(&mut chat_session.materialization, "validation", "running");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Implementing;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Implementing).to_string();

    let build_result = run_command_capture(&workspace_root, npm_binary(), &["run", "build"])?;
    record_command_receipt_for_proof(
        chat_session,
        build_session,
        "validation",
        "Validate build",
        &build_result,
        None,
    );

    if !build_result.success {
        mark_build_failed_for_proof(
            chat_session,
            build_session,
            build_result
                .stderr
                .trim()
                .lines()
                .next()
                .filter(|line| !line.is_empty())
                .unwrap_or("Build validation failed.")
                .to_string(),
        );
        return Ok(());
    }

    update_workspace_verification_step(&mut chat_session.materialization, "validation", "success");
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "running");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Verifying;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Verifying).to_string();
    build_session.current_worker_execution.execution_state = "validating".to_string();
    build_session.build_status = "preview-starting".to_string();

    let preview_outcome = start_preview_process(&build_session.session_id, &workspace_root)?;
    append_proof_receipt(build_session, preview_outcome.receipt.clone());

    if !preview_outcome.success {
        build_session.retry_count += 1;
        let retry_preview = start_preview_process(&build_session.session_id, &workspace_root)?;
        append_proof_receipt(build_session, retry_preview.receipt.clone());
        if !retry_preview.success {
            mark_build_failed_for_proof(
                chat_session,
                build_session,
                "Preview verification failed after a bounded restart.".to_string(),
            );
            return Ok(());
        }
    }

    kill_preview_process(&build_session.session_id);
    build_session.preview_url = None;
    build_session.preview_process_id = None;
    build_session.current_lens = "preview".to_string();
    build_session.available_lenses = BUILD_LENSES_READY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.ready_lenses = BUILD_LENSES_READY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.build_status = "preview-ready".to_string();
    build_session.verification_status = "passed".to_string();
    build_session.current_worker_execution.execution_state = "complete".to_string();
    if let Some(preview_intent) = chat_session.materialization.preview_intent.as_mut() {
        preview_intent.status = "ready".to_string();
        preview_intent.url = None;
    }
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "success");
    update_chat_session_from_build_session(chat_session, Some(build_session));
    chat_session.updated_at = now_iso();

    Ok(())
}

fn run_build_supervisor_blocking(
    app: &AppHandle,
    mut chat_session: ChatArtifactSession,
    mut build_session: BuildArtifactSession,
) -> Result<(), String> {
    let thread_id = chat_session.thread_id.clone();
    let artifact_title = chat_session.title.clone();
    let workspace_root = PathBuf::from(&build_session.workspace_root);
    sync_task_sessions(
        app,
        &chat_session,
        Some(&build_session),
        "Chat is installing dependencies...".to_string(),
    );

    chat_session.lifecycle_state = ChatArtifactLifecycleState::Implementing;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Implementing).to_string();
    build_session.build_status = "installing".to_string();
    build_session.current_worker_execution.execution_state = "validating".to_string();
    update_workspace_verification_step(&mut chat_session.materialization, "install", "running");
    sync_task_sessions(
        app,
        &chat_session,
        Some(&build_session),
        "Installing dependencies".to_string(),
    );

    let install_result = run_command_capture(
        &workspace_root,
        npm_binary(),
        &["install", "--no-audit", "--no-fund"],
    )?;
    record_command_receipt(
        app,
        &thread_id,
        &artifact_title,
        &mut chat_session,
        &mut build_session,
        "install",
        "Install dependencies",
        &install_result,
        None,
    );

    if !install_result.success {
        build_session.retry_count += 1;
        let retry_result = run_command_capture(
            &workspace_root,
            npm_binary(),
            &["install", "--no-audit", "--no-fund"],
        )?;
        record_command_receipt(
            app,
            &thread_id,
            &artifact_title,
            &mut chat_session,
            &mut build_session,
            "install",
            "Retry dependency install",
            &retry_result,
            Some("network_or_registry".to_string()),
        );
        if !retry_result.success {
            mark_build_failed(
                app,
                &mut chat_session,
                &mut build_session,
                "Install failed after a bounded retry.".to_string(),
            );
            return Ok(());
        }
    }

    build_session.build_status = "validating".to_string();
    update_workspace_verification_step(&mut chat_session.materialization, "install", "success");
    update_workspace_verification_step(&mut chat_session.materialization, "validation", "running");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Implementing;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Implementing).to_string();
    sync_task_sessions(
        app,
        &chat_session,
        Some(&build_session),
        "Validating the Chat artifact build".to_string(),
    );

    let build_result = run_command_capture(&workspace_root, npm_binary(), &["run", "build"])?;
    record_command_receipt(
        app,
        &thread_id,
        &artifact_title,
        &mut chat_session,
        &mut build_session,
        "validation",
        "Validate build",
        &build_result,
        None,
    );

    if !build_result.success {
        mark_build_failed(
            app,
            &mut chat_session,
            &mut build_session,
            build_result
                .stderr
                .trim()
                .lines()
                .next()
                .filter(|line| !line.is_empty())
                .unwrap_or("Build validation failed.")
                .to_string(),
        );
        return Ok(());
    }

    update_workspace_verification_step(&mut chat_session.materialization, "validation", "success");
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "running");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Verifying;
    chat_session.status =
        lifecycle_state_label(ChatArtifactLifecycleState::Verifying).to_string();
    build_session.current_worker_execution.execution_state = "validating".to_string();
    build_session.build_status = "preview-starting".to_string();
    sync_task_sessions(
        app,
        &chat_session,
        Some(&build_session),
        "Launching preview".to_string(),
    );

    let preview_outcome = start_preview_process(&build_session.session_id, &workspace_root)?;
    let preview_receipt = preview_outcome.receipt.clone();
    append_receipt_artifact(
        app,
        &thread_id,
        &artifact_title,
        &mut build_session,
        preview_receipt,
    );

    if !preview_outcome.success {
        build_session.retry_count += 1;
        let retry_preview = start_preview_process(&build_session.session_id, &workspace_root)?;
        append_receipt_artifact(
            app,
            &thread_id,
            &artifact_title,
            &mut build_session,
            retry_preview.receipt.clone(),
        );
        if !retry_preview.success {
            mark_build_failed(
                app,
                &mut chat_session,
                &mut build_session,
                "Preview verification failed after a bounded restart.".to_string(),
            );
            return Ok(());
        }
        build_session.preview_url = retry_preview.preview_url.clone();
        build_session.preview_process_id = retry_preview.preview_process_id;
    } else {
        build_session.preview_url = preview_outcome.preview_url.clone();
        build_session.preview_process_id = preview_outcome.preview_process_id;
    }

    build_session.current_lens = "preview".to_string();
    build_session.available_lenses = BUILD_LENSES_READY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.ready_lenses = BUILD_LENSES_READY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.build_status = "preview-ready".to_string();
    build_session.verification_status = "passed".to_string();
    build_session.current_worker_execution.execution_state = "complete".to_string();
    chat_session.current_lens = "preview".to_string();
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Ready;
    chat_session.status = lifecycle_state_label(ChatArtifactLifecycleState::Ready).to_string();
    chat_session.available_lenses = BUILD_LENSES_READY
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    chat_session.updated_at = now_iso();
    if let Some(preview_intent) = chat_session.materialization.preview_intent.as_mut() {
        preview_intent.status = "ready".to_string();
        preview_intent.url = build_session.preview_url.clone();
    }
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "success");
    sync_task_sessions(
        app,
        &chat_session,
        Some(&build_session),
        "Preview verified and ready".to_string(),
    );

    let final_event = build_event(
        &chat_session.thread_id,
        build_session.receipts.len() as u32,
        EventType::Receipt,
        "Chat workspace renderer verified".to_string(),
        json!({
            "renderer_session_id": build_session.session_id,
            "preview_url": build_session.preview_url,
            "scaffold_recipe_id": build_session.scaffold_recipe_id,
        }),
        serde_json::to_value(&build_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        Vec::new(),
        None,
        Vec::new(),
        Some(0),
    );
    register_event(app, final_event);

    Ok(())
}

struct PreviewOutcome {
    success: bool,
    preview_url: Option<String>,
    preview_process_id: Option<u32>,
    receipt: ChatBuildReceipt,
}

#[derive(Debug, Clone)]
pub(super) struct PreviewLaunchCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub display: String,
}

fn start_preview_process(
    session_id: &str,
    workspace_root: &Path,
) -> Result<PreviewOutcome, String> {
    kill_preview_process(session_id);

    let preview_port = pick_open_port()?;
    let preview_url = format!("http://127.0.0.1:{preview_port}");
    let log_dir = workspace_root.join(".chat");
    fs::create_dir_all(&log_dir).map_err(|error| {
        format!(
            "Failed to create preview log dir '{}': {}",
            log_dir.display(),
            error
        )
    })?;
    let log_path = log_dir.join("preview.log");
    let log_file = File::create(&log_path).map_err(|error| {
        format!(
            "Failed to create preview log '{}': {}",
            log_path.display(),
            error
        )
    })?;

    let started_at = now_iso();
    let start = Instant::now();
    let preview_command = preview_launch_command(workspace_root, preview_port);
    let child = Command::new(&preview_command.program)
        .current_dir(workspace_root)
        .args(&preview_command.args)
        .stdout(Stdio::from(
            log_file.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log_file))
        .spawn()
        .map_err(|error| format!("Failed to launch preview process: {}", error))?;

    let process_id = child.id();
    PREVIEW_PROCESS_REGISTRY
        .lock()
        .map_err(|_| "Failed to lock preview registry".to_string())?
        .insert(session_id.to_string(), ChatPreviewProcess { child });

    let success = poll_preview_health(&preview_url, Duration::from_secs(24));
    if !success {
        kill_preview_process(session_id);
    }

    let summary = if success {
        format!("Preview verified at {}.", preview_url)
    } else {
        format!(
            "Preview failed to respond at {}. {}",
            preview_url,
            read_log_excerpt(&log_path)
                .unwrap_or_else(|| "No preview log output was captured.".to_string())
        )
    };

    Ok(PreviewOutcome {
        success,
        preview_url: if success {
            Some(preview_url.clone())
        } else {
            None
        },
        preview_process_id: if success { Some(process_id) } else { None },
        receipt: ChatBuildReceipt {
            receipt_id: Uuid::new_v4().to_string(),
            kind: "preview".to_string(),
            title: if success {
                "Preview verified".to_string()
            } else {
                "Preview failed".to_string()
            },
            status: if success {
                "success".to_string()
            } else {
                "failure".to_string()
            },
            summary,
            started_at,
            finished_at: Some(now_iso()),
            artifact_ids: Vec::new(),
            command: Some(preview_command.display),
            exit_code: Some(if success { 0 } else { 1 }),
            duration_ms: Some(start.elapsed().as_millis() as u64),
            failure_class: if success {
                None
            } else {
                Some("preview_unreachable".to_string())
            },
            replay_classification: Some(if success {
                "replay_safe".to_string()
            } else {
                "retry_required".to_string()
            }),
        },
    })
}

pub(super) fn preview_launch_command(
    workspace_root: &Path,
    preview_port: u16,
) -> PreviewLaunchCommand {
    let shared_args = vec![
        "preview".to_string(),
        "--host".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        preview_port.to_string(),
    ];
    let vite_js = workspace_root
        .join("node_modules")
        .join("vite")
        .join("bin")
        .join("vite.js");
    if vite_js.exists() {
        return PreviewLaunchCommand {
            program: PathBuf::from("node"),
            args: std::iter::once(vite_js.display().to_string())
                .chain(shared_args.clone())
                .collect(),
            display: format!("node {} {}", vite_js.display(), shared_args.join(" ")),
        };
    }

    let local_vite = workspace_root
        .join("node_modules")
        .join(".bin")
        .join(if cfg!(windows) { "vite.cmd" } else { "vite" });
    if local_vite.exists() {
        return PreviewLaunchCommand {
            program: local_vite.clone(),
            args: shared_args.clone(),
            display: format!("{} {}", local_vite.display(), shared_args.join(" ")),
        };
    }

    let args = vec![
        "run".to_string(),
        "preview".to_string(),
        "--".to_string(),
        "--host".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        preview_port.to_string(),
    ];
    PreviewLaunchCommand {
        program: PathBuf::from(npm_binary()),
        args: args.clone(),
        display: format!("{} {}", npm_binary(), args.join(" ")),
    }
}

fn append_receipt_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    build_session: &mut BuildArtifactSession,
    mut receipt: ChatBuildReceipt,
) {
    if let Some(artifact) = create_receipt_report_artifact(app, thread_id, title, &receipt) {
        receipt.artifact_ids.push(artifact.artifact_id.clone());
        register_artifact(app, artifact);
    }
    build_session.receipts.push(receipt.clone());
    let event = build_event(
        thread_id,
        build_session.receipts.len() as u32,
        EventType::Receipt,
        receipt.title.clone(),
        json!({
            "kind": receipt.kind,
            "status": receipt.status,
        }),
        serde_json::to_value(&receipt).unwrap_or_else(|_| json!({})),
        if receipt.status == "success" {
            EventStatus::Success
        } else {
            EventStatus::Failure
        },
        receipt
            .artifact_ids
            .iter()
            .map(|artifact_id| ArtifactRef {
                artifact_id: artifact_id.clone(),
                artifact_type: ArtifactType::Report,
            })
            .collect(),
        None,
        Vec::new(),
        receipt.duration_ms,
    );
    register_event(app, event);
}

fn append_proof_receipt(build_session: &mut BuildArtifactSession, receipt: ChatBuildReceipt) {
    build_session.receipts.push(receipt);
}

fn record_command_receipt(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    chat_session: &mut ChatArtifactSession,
    build_session: &mut BuildArtifactSession,
    receipt_kind: &str,
    receipt_title: &str,
    result: &CommandExecutionResult,
    failure_class: Option<String>,
) {
    let status = if result.success { "success" } else { "failure" };
    if receipt_kind == "validation" {
        update_workspace_verification_step(
            &mut chat_session.materialization,
            "validation",
            if result.success { "success" } else { "failure" },
        );
    }
    let summary = if result.success {
        format!(
            "{} completed successfully in {} ms.",
            receipt_title, result.duration_ms
        )
    } else {
        format!(
            "{} failed with exit code {:?}. {}",
            receipt_title,
            result.exit_code,
            summarize_failure_output(&result.stderr, &result.stdout)
        )
    };

    let mut receipt = ChatBuildReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        kind: receipt_kind.to_string(),
        title: receipt_title.to_string(),
        status: status.to_string(),
        summary,
        started_at: now_iso(),
        finished_at: Some(now_iso()),
        artifact_ids: Vec::new(),
        command: Some(result.command.clone()),
        exit_code: result.exit_code,
        duration_ms: Some(result.duration_ms),
        failure_class,
        replay_classification: Some(if result.success {
            "replay_safe".to_string()
        } else {
            "retry_required".to_string()
        }),
    };

    if let Some(log_artifact) = create_log_artifact_for_command(
        app,
        thread_id,
        receipt_title,
        &result.stdout,
        &result.stderr,
    ) {
        receipt.artifact_ids.push(log_artifact.artifact_id.clone());
        register_artifact(app, log_artifact);
    }

    append_receipt_artifact(app, thread_id, title, build_session, receipt);
}

fn record_command_receipt_for_proof(
    chat_session: &mut ChatArtifactSession,
    build_session: &mut BuildArtifactSession,
    receipt_kind: &str,
    receipt_title: &str,
    result: &CommandExecutionResult,
    failure_class: Option<String>,
) {
    let status = if result.success { "success" } else { "failure" };
    if receipt_kind == "validation" {
        update_workspace_verification_step(
            &mut chat_session.materialization,
            "validation",
            if result.success { "success" } else { "failure" },
        );
    }
    let summary = if result.success {
        format!(
            "{} completed successfully in {} ms.",
            receipt_title, result.duration_ms
        )
    } else {
        format!(
            "{} failed with exit code {:?}. {}",
            receipt_title,
            result.exit_code,
            summarize_failure_output(&result.stderr, &result.stdout)
        )
    };

    append_proof_receipt(
        build_session,
        ChatBuildReceipt {
            receipt_id: Uuid::new_v4().to_string(),
            kind: receipt_kind.to_string(),
            title: receipt_title.to_string(),
            status: status.to_string(),
            summary,
            started_at: now_iso(),
            finished_at: Some(now_iso()),
            artifact_ids: Vec::new(),
            command: Some(result.command.clone()),
            exit_code: result.exit_code,
            duration_ms: Some(result.duration_ms),
            failure_class,
            replay_classification: Some(if result.success {
                "replay_safe".to_string()
            } else {
                "retry_required".to_string()
            }),
        },
    );
}

fn create_log_artifact_for_command(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    stdout: &str,
    stderr: &str,
) -> Option<Artifact> {
    let output = [stdout.trim(), stderr.trim()]
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n\n");
    if output.trim().is_empty() {
        return None;
    }
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.memory_runtime.clone())?;
    Some(crate::kernel::artifacts::create_log_artifact(
        &memory_runtime,
        thread_id,
        &format!("{} log", title),
        "Chat supervised command output",
        &output,
        json!({
            "surface": "chat",
            "receipt_title": title,
        }),
    ))
}

fn mark_build_failed(
    app: &AppHandle,
    chat_session: &mut ChatArtifactSession,
    build_session: &mut BuildArtifactSession,
    summary: String,
) {
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Failed;
    chat_session.status = lifecycle_state_label(ChatArtifactLifecycleState::Failed).to_string();
    chat_session.current_lens = "code".to_string();
    chat_session.updated_at = now_iso();
    if let Some(preview_intent) = chat_session.materialization.preview_intent.as_mut() {
        preview_intent.status = "failed".to_string();
        preview_intent.url = None;
    }
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "failure");
    build_session.build_status = "failed".to_string();
    build_session.verification_status = "failed".to_string();
    build_session.current_lens = "code".to_string();
    build_session.available_lenses = BUILD_LENSES_IN_PROGRESS
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.ready_lenses = vec!["code".to_string()];
    build_session.last_failure_summary = Some(summary.clone());
    build_session.current_worker_execution.execution_state = "failed_retryable".to_string();
    build_session.current_worker_execution.last_summary = Some(summary.clone());
    sync_task_sessions(app, chat_session, Some(build_session), summary);
}

fn mark_build_failed_for_proof(
    chat_session: &mut ChatArtifactSession,
    build_session: &mut BuildArtifactSession,
    summary: String,
) {
    kill_preview_process(&build_session.session_id);
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Failed;
    chat_session.status = lifecycle_state_label(ChatArtifactLifecycleState::Failed).to_string();
    chat_session.current_lens = "code".to_string();
    chat_session.updated_at = now_iso();
    if let Some(preview_intent) = chat_session.materialization.preview_intent.as_mut() {
        preview_intent.status = "failed".to_string();
        preview_intent.url = None;
    }
    update_workspace_verification_step(&mut chat_session.materialization, "preview", "failure");
    build_session.build_status = "failed".to_string();
    build_session.verification_status = "failed".to_string();
    build_session.preview_url = None;
    build_session.preview_process_id = None;
    build_session.current_lens = "code".to_string();
    build_session.available_lenses = BUILD_LENSES_IN_PROGRESS
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    build_session.ready_lenses = vec!["code".to_string()];
    build_session.last_failure_summary = Some(summary);
    build_session.current_worker_execution.execution_state = "failed_retryable".to_string();
    build_session.current_worker_execution.last_summary =
        build_session.last_failure_summary.clone();
    update_chat_session_from_build_session(chat_session, Some(build_session));
}

fn sync_task_sessions(
    app: &AppHandle,
    chat_session: &ChatArtifactSession,
    build_session: Option<&BuildArtifactSession>,
    current_step: String,
) {
    let mut chat_session = chat_session.clone();
    let build_session = build_session.cloned();
    update_chat_session_from_build_session(&mut chat_session, build_session.as_ref());
    let renderer_session = build_session
        .as_ref()
        .map(build_session_to_renderer_session);
    update_task_state(app, move |task| {
        if task
            .chat_session
            .as_ref()
            .is_some_and(|existing| existing.session_id == chat_session.session_id)
            || task.chat_session.is_none()
        {
            task.chat_session = Some(chat_session.clone());
            task.renderer_session = renderer_session.clone();
            task.build_session = build_session.clone();
            apply_chat_authoritative_status(task, Some(current_step.clone()));
        }
    });
}

fn update_workspace_verification_step(
    contract: &mut ChatArtifactMaterializationContract,
    step_id: &str,
    status: &str,
) {
    update_operator_step_for_workspace_verification(contract, step_id, status);
}

fn update_operator_step_for_workspace_verification(
    contract: &mut ChatArtifactMaterializationContract,
    step_id: &str,
    status: &str,
) {
    let (operator_step_id, label) = match step_id {
        "scaffold" => ("workspace_scaffold", "Scaffold workspace"),
        "install" => ("workspace_install", "Install dependencies"),
        "validation" => ("workspace_validation", "Validate build"),
        "preview" => ("workspace_preview", "Verify preview"),
        _ => return,
    };
    let normalized = status.trim().to_ascii_lowercase();
    let operator_status = match normalized.as_str() {
        "running" | "active" => ArtifactOperatorRunStatus::Active,
        "success" | "complete" | "completed" => ArtifactOperatorRunStatus::Complete,
        "failure" | "failed" | "blocked" => ArtifactOperatorRunStatus::Blocked,
        _ => ArtifactOperatorRunStatus::Pending,
    };
    let detail = match operator_status {
        ArtifactOperatorRunStatus::Active => format!("{label} is in progress."),
        ArtifactOperatorRunStatus::Complete => format!("{label} completed."),
        ArtifactOperatorRunStatus::Blocked => format!("{label} failed."),
        _ => format!("{label} is pending."),
    };
    if let Some(step) = contract
        .operator_steps
        .iter_mut()
        .find(|step| step.step_id == operator_step_id)
    {
        step.status = operator_status;
        step.detail = detail;
        if matches!(
            operator_status,
            ArtifactOperatorRunStatus::Complete | ArtifactOperatorRunStatus::Blocked
        ) {
            step.finished_at_ms = Some(step.finished_at_ms.unwrap_or(0));
        }
        return;
    }

    contract
        .operator_steps
        .push(ioi_api::runtime_harness::ArtifactOperatorStep {
            step_id: operator_step_id.to_string(),
            origin_prompt_event_id: String::new(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "workspace_build".to_string(),
            status: operator_status,
            label: label.to_string(),
            detail,
            started_at_ms: 0,
            finished_at_ms: None,
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        });
}

fn run_command_capture(
    root: &Path,
    program: &str,
    args: &[&str],
) -> Result<CommandExecutionResult, String> {
    let start = Instant::now();
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| {
            format!(
                "Failed to run '{}': {}",
                format_command(program, args),
                error
            )
        })?;

    Ok(CommandExecutionResult {
        command: format_command(program, args),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

fn summarize_failure_output(stderr: &str, stdout: &str) -> String {
    let source = if !stderr.trim().is_empty() {
        stderr
    } else {
        stdout
    };
    source
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| "No failure summary was captured.".to_string())
}

fn format_command(program: &str, args: &[&str]) -> String {
    std::iter::once(program.to_string())
        .chain(args.iter().map(|value| (*value).to_string()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn npm_binary() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "npm.cmd"
    }

    #[cfg(not(target_os = "windows"))]
    {
        "npm"
    }
}

fn poll_preview_health(url: &str, timeout: Duration) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build();
    let Ok(client) = client else {
        return false;
    };

    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(response) = client.get(url).send() {
            if response.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(350));
    }
    false
}

fn pick_open_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Failed to allocate preview port: {}", error))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("Failed to read preview port: {}", error))
}

pub(super) fn kill_preview_process(session_id: &str) {
    if let Ok(mut registry) = PREVIEW_PROCESS_REGISTRY.lock() {
        if let Some(mut process) = registry.remove(session_id) {
            let _ = process.child.kill();
            let _ = process.child.wait();
        }
    }
}

fn read_log_excerpt(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let mut excerpt = raw.lines().rev().take(8).collect::<Vec<_>>();
    excerpt.reverse();
    let compact = excerpt.join(" ").trim().to_string();
    if compact.is_empty() {
        None
    } else {
        Some(compact)
    }
}
