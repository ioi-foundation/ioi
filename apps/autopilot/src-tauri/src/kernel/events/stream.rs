use super::clarification::build_clarification_request_with_inference;
use super::emission::{
    build_event, create_macro_artifacts_for_action, emit_browser_navigate, emit_browser_snapshot,
    emit_code_search, emit_command_run, emit_command_stream, emit_file_edit, emit_receipt_digest,
    emit_test_run, register_artifact, register_event,
};
use super::support::{
    clarification_preset_for_tool, detect_clarification_preset, event_status_from_agent_status,
    event_type_for_tool, is_hard_terminal_task, is_identity_resolution_kind,
    is_install_package_tool, is_sudo_password_required_install,
    is_waiting_for_identity_clarification_step, thread_id_from_session, ClarificationPreset,
    CLARIFICATION_WAIT_STEP, WAIT_FOR_CLARIFICATION_PROMPT,
};
use crate::kernel::artifacts as artifact_store;
use crate::kernel::state::get_rpc_client;
use crate::kernel::state::update_task_state;
use crate::kernel::thresholds;
use crate::models::{
    AgentPhase, AppState, ArtifactRef, ArtifactType, ChatMessage, CredentialRequest, EventStatus,
    EventType, GateInfo, GhostInputEvent, PiiReviewInfo, Receipt, SwarmAgent,
};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::chain_event::Event as ChainEventEnum;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::SubscribeEventsRequest;
use ioi_pii::validate_review_request_compat;
use ioi_types::app::agentic::PiiReviewRequest;
use ioi_types::codec;
use serde_json::json;
use std::sync::Mutex;
use tauri::{Emitter, Manager};

async fn fetch_pii_review_info(
    app: &tauri::AppHandle,
    request_hash_hex: &str,
) -> Option<PiiReviewInfo> {
    let hash_bytes = hex::decode(request_hash_hex).ok()?;
    if hash_bytes.len() != 32 {
        return None;
    }
    let mut decision_hash = [0u8; 32];
    decision_hash.copy_from_slice(&hash_bytes);

    let state_handle = app.state::<Mutex<AppState>>();
    let mut client = get_rpc_client(&state_handle).await.ok()?;
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let key = [
        ns_prefix.as_slice(),
        b"pii::review::request::",
        &decision_hash,
    ]
    .concat();
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .ok()?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return None;
    }
    let request: PiiReviewRequest = codec::from_bytes_canonical(&resp.value).ok()?;
    if validate_review_request_compat(&request).is_err() {
        return None;
    }
    Some(PiiReviewInfo {
        decision_hash: hex::encode(request.decision_hash),
        target_label: request.summary.target_label,
        span_summary: request.summary.span_summary,
        class_counts: request.summary.class_counts,
        severity_counts: request.summary.severity_counts,
        stage2_prompt: request.summary.stage2_prompt,
        deadline_ms: request.deadline_ms,
        target_id: Some(request.material.target),
    })
}

pub async fn monitor_kernel_events(app: tauri::AppHandle) {
    loop {
        let mut client = loop {
            match PublicApiClient::connect("http://127.0.0.1:9000").await {
                Ok(c) => {
                    println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                    break c;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };

        let request = tonic::Request::new(SubscribeEventsRequest {});

        let mut stream = match client.subscribe_events(request).await {
            Ok(s) => s.into_inner(),
            Err(e) => {
                eprintln!(
                    "[Autopilot] Failed to subscribe to events (retrying in 2s): {}",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        let state_handle = app.state::<Mutex<AppState>>();

        println!("[Autopilot] Event Stream Active ✅");

        while let Ok(Some(event_msg)) = stream.message().await {
            if let Some(event_enum) = event_msg.event {
                match event_enum {
                    ChainEventEnum::Thought(thought) => {
                        update_task_state(&app, |t| {
                            if let Some(agent) =
                                t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id)
                            {
                                if let Some(existing) = &agent.current_thought {
                                    agent.current_thought =
                                        Some(format!("{}{}", existing, thought.content));
                                } else {
                                    agent.current_thought = Some(thought.content.clone());
                                }
                                if agent.status != "paused" && agent.status != "requisition" {
                                    agent.status = "running".to_string();
                                }
                            } else {
                                if t.current_step == "Initializing..."
                                    || t.current_step.starts_with("Executed")
                                {
                                    t.current_step = thought.content.clone();
                                } else {
                                    t.current_step.push_str(&thought.content);
                                }
                            }

                            if t.phase != AgentPhase::Complete
                                && t.phase != AgentPhase::Failed
                                && t.phase != AgentPhase::Gate
                            {
                                t.phase = AgentPhase::Running;
                            }

                            t.progress += 1;
                            if !thought.visual_hash.is_empty() {
                                t.visual_hash = Some(thought.visual_hash.clone());
                            }
                            if !thought.session_id.is_empty() {
                                t.session_id = Some(thought.session_id.clone());
                            }
                        });

                        if thought.is_final {
                            let thread_id = thread_id_from_session(&app, &thought.session_id);
                            let event = build_event(
                                &thread_id,
                                0,
                                EventType::InfoNote,
                                "Captured reasoning step".to_string(),
                                json!({
                                    "session_id": thought.session_id,
                                    "visual_hash": thought.visual_hash,
                                    "token_count": thought.content.chars().count(),
                                }),
                                json!({
                                    "content": thresholds::trim_for_expanded_view(&thought.content),
                                }),
                                EventStatus::Success,
                                Vec::new(),
                                None,
                                Vec::new(),
                                None,
                            );
                            register_event(&app, event);
                        }
                    }
                    ChainEventEnum::ActionResult(res) => {
                        let password_required =
                            is_sudo_password_required_install(&res.tool_name, &res.output);
                        let clarification_preset =
                            if res.agent_status.eq_ignore_ascii_case("paused") {
                                detect_clarification_preset(&res.tool_name, &res.output)
                            } else {
                                None
                            };
                        let clarification_required = clarification_preset.is_some();
                        let clarification_request = if clarification_required {
                            let preset =
                                clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &res.tool_name,
                                    &res.output,
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
                        let already_processed = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    task.processed_steps.contains(&dedup_key)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if already_processed {
                            continue;
                        }
                        let suppress_terminal_action_result = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    is_hard_terminal_task(task)
                                        && !password_required
                                        && !clarification_required
                                        && !res.agent_status.eq_ignore_ascii_case("completed")
                                        && !res.agent_status.eq_ignore_ascii_case("failed")
                                        && !res.tool_name.eq_ignore_ascii_case("agent__complete")
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if suppress_terminal_action_result {
                            continue;
                        }

                        update_task_state(&app, |t| {
                            let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                            if t.processed_steps.contains(&dedup_key) {
                                return;
                            }
                            t.processed_steps.insert(dedup_key);

                            t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                            if !res.session_id.is_empty() {
                                t.session_id = Some(res.session_id.clone());
                            }

                            if let Some(agent) =
                                t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                            {
                                agent.artifacts_produced += 1;
                            }

                            let waiting_for_sudo = t
                                .credential_request
                                .as_ref()
                                .map(|req| req.kind == "sudo_password")
                                .unwrap_or(false)
                                || t.current_step
                                    .eq_ignore_ascii_case("Waiting for sudo password");
                            let waiting_for_clarification = t
                                .clarification_request
                                .as_ref()
                                .map(|req| is_identity_resolution_kind(&req.kind))
                                .unwrap_or(false)
                                || is_waiting_for_identity_clarification_step(&t.current_step);

                            if password_required {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt: "A one-time sudo password is required to continue the install."
                                        .to_string(),
                                    one_time: true,
                                });
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                let prompt_msg =
                                    "System: Install requires sudo password. Enter password to retry."
                                        .to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                return;
                            }

                            if clarification_required {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = clarification_request.clone();
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                let prompt_msg = WAIT_FOR_CLARIFICATION_PROMPT.to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                return;
                            }

                            // Keep password prompt stable even if later receipts/actions arrive
                            // before user submits credentials.
                            let terminal_status = res.agent_status.eq_ignore_ascii_case("failed")
                                || res.agent_status.eq_ignore_ascii_case("completed");
                            let keep_waiting_for_sudo = waiting_for_sudo
                                && !terminal_status
                                && is_install_package_tool(&res.tool_name)
                                && password_required;
                            if keep_waiting_for_sudo {
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                return;
                            }

                            let keep_waiting_for_clarification = waiting_for_clarification
                                && !terminal_status
                                && clarification_required;
                            if keep_waiting_for_clarification {
                                if !res.output.trim().is_empty() {
                                    let tool_msg =
                                        format!("Tool Output ({}): {}", res.tool_name, res.output);
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                return;
                            }

                            t.credential_request = None;
                            t.clarification_request = None;

                            match res.agent_status.as_str() {
                                "Completed" => {
                                    t.phase = AgentPhase::Complete;
                                    t.current_step = "Task completed".to_string();
                                    t.gate_info = None;
                                    t.pending_request_hash = None;
                                    t.credential_request = None;
                                    t.clarification_request = None;

                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "completed".to_string();
                                    }

                                    t.receipt = Some(Receipt {
                                        duration: "Done".to_string(),
                                        actions: t.progress,
                                        cost: Some("$0.00".to_string()),
                                    });

                                    let msg = format!("Task Completed: {}", res.output);
                                    if t.history.last().map(|m| m.text != msg).unwrap_or(true) {
                                        t.history.push(ChatMessage {
                                            role: "system".into(),
                                            text: msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }
                                "Failed" => {
                                    t.phase = AgentPhase::Failed;
                                    t.gate_info = None;
                                    t.pending_request_hash = None;
                                    t.credential_request = None;
                                    t.clarification_request = None;
                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "failed".to_string();
                                    }

                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!("Task Failed: {}", res.output),
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                                "Paused" => {
                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == res.session_id)
                                    {
                                        agent.status = "paused".to_string();
                                    }
                                }
                                _ => {
                                    if t.phase != AgentPhase::Gate {
                                        t.phase = AgentPhase::Running;
                                    }
                                }
                            }

                            if res.tool_name == "chat::reply" || res.tool_name == "chat__reply" {
                                if res.agent_status == "Paused" {
                                    t.phase = AgentPhase::Complete;
                                    t.current_step = "Ready for input".to_string();
                                }

                                let duplicate = t
                                    .history
                                    .last()
                                    .map(|m| m.text == res.output)
                                    .unwrap_or(false);
                                if !duplicate {
                                    t.history.push(ChatMessage {
                                        role: "agent".to_string(),
                                        text: res.output.clone(),
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            } else if res.tool_name == "system::refusal" {
                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("⚠️ Agent Paused: {}", res.output),
                                    timestamp: crate::kernel::state::now(),
                                });
                            } else if res.agent_status == "Running"
                                && res.tool_name != "agent__complete"
                            {
                                t.history.push(ChatMessage {
                                    role: "tool".to_string(),
                                    text: format!(
                                        "Tool Output ({}): {}",
                                        res.tool_name, res.output
                                    ),
                                    timestamp: crate::kernel::state::now(),
                                });
                            }
                        });

                        let thread_id = thread_id_from_session(&app, &res.session_id);
                        let kind = event_type_for_tool(&res.tool_name);
                        let status = event_status_from_agent_status(&res.agent_status);
                        let artifact_refs = create_macro_artifacts_for_action(
                            &app,
                            &thread_id,
                            &kind,
                            &res.tool_name,
                            &res.output,
                        );

                        let event = match kind {
                            EventType::CodeSearch => emit_code_search(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::FileEdit => emit_file_edit(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::BrowserNavigate => emit_browser_navigate(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::BrowserSnapshot => emit_browser_snapshot(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            EventType::TestRun => emit_test_run(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                            _ => emit_command_run(
                                &thread_id,
                                res.step_index,
                                &res.tool_name,
                                &res.output,
                                status,
                                artifact_refs,
                                Vec::new(),
                            ),
                        };
                        register_event(&app, event);
                    }
                    ChainEventEnum::ProcessActivity(activity) => {
                        let thread_id = thread_id_from_session(&app, &activity.session_id);
                        let exit_code = if activity.has_exit_code {
                            Some(activity.exit_code)
                        } else {
                            None
                        };
                        let stream_password_required = activity.is_final
                            && is_sudo_password_required_install(
                                &activity.tool_name,
                                &activity.chunk,
                            );
                        let stream_clarification_preset = if activity.is_final {
                            detect_clarification_preset(&activity.tool_name, &activity.chunk)
                        } else {
                            None
                        };
                        let stream_clarification_required = stream_clarification_preset.is_some();
                        let stream_clarification_request = if stream_clarification_required {
                            let preset = stream_clarification_preset
                                .unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &activity.tool_name,
                                    &activity.chunk,
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        update_task_state(&app, |t| {
                            if !activity.session_id.is_empty() {
                                t.session_id = Some(activity.session_id.clone());
                            }
                            if matches!(t.phase, AgentPhase::Idle | AgentPhase::Running) {
                                t.phase = AgentPhase::Running;
                            }
                            t.current_step =
                                format!("Streaming {} ({})", activity.tool_name, activity.channel);
                        });

                        if stream_password_required {
                            update_task_state(&app, |t| {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt:
                                        "A one-time sudo password is required to continue the install."
                                            .to_string(),
                                    one_time: true,
                                });

                                if !activity.chunk.trim().is_empty() {
                                    let tool_msg = format!(
                                        "Tool Output ({}): {}",
                                        activity.tool_name, activity.chunk
                                    );
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }

                                let prompt_msg =
                                    "System: Install requires sudo password. Enter password to retry."
                                        .to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            });
                        } else if stream_clarification_required {
                            update_task_state(&app, |t| {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = stream_clarification_request.clone();

                                if !activity.chunk.trim().is_empty() {
                                    let tool_msg = format!(
                                        "Tool Output ({}): {}",
                                        activity.tool_name, activity.chunk
                                    );
                                    if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true)
                                    {
                                        t.history.push(ChatMessage {
                                            role: "tool".to_string(),
                                            text: tool_msg,
                                            timestamp: crate::kernel::state::now(),
                                        });
                                    }
                                }

                                let prompt_msg = WAIT_FOR_CLARIFICATION_PROMPT.to_string();
                                if t.history
                                    .last()
                                    .map(|m| m.text != prompt_msg)
                                    .unwrap_or(true)
                                {
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: prompt_msg,
                                        timestamp: crate::kernel::state::now(),
                                    });
                                }
                            });
                        }

                        let event = emit_command_stream(
                            &thread_id,
                            activity.step_index,
                            &activity.tool_name,
                            &activity.stream_id,
                            &activity.channel,
                            &activity.chunk,
                            activity.seq,
                            activity.is_final,
                            exit_code,
                            &activity.command_preview,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::RoutingReceipt(receipt) => {
                        let receipt_is_install_tool = is_install_package_tool(&receipt.tool_name);
                        let receipt_is_identity_lookup_tool =
                            clarification_preset_for_tool(&receipt.tool_name).is_some();
                        let receipt_waiting_for_sudo = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                s.agent_status
                                    .to_ascii_lowercase()
                                    .contains("waiting for sudo password")
                                    || s.verification_checks.iter().any(|check| {
                                        check.eq_ignore_ascii_case("awaiting_sudo_password=true")
                                    })
                            })
                            .unwrap_or(false)
                            || (receipt_is_install_tool
                                && (receipt
                                    .resolution_action
                                    .eq_ignore_ascii_case("wait_for_sudo_password")
                                    || receipt
                                        .escalation_path
                                        .eq_ignore_ascii_case("wait_for_sudo_password")));
                        let receipt_waiting_for_clarification = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                s.verification_checks.iter().any(|check| {
                                    check.eq_ignore_ascii_case("awaiting_clarification=true")
                                })
                            })
                            .unwrap_or(false)
                            || (receipt_is_identity_lookup_tool
                                && (receipt
                                    .resolution_action
                                    .eq_ignore_ascii_case("wait_for_clarification")
                                    || receipt
                                        .escalation_path
                                        .eq_ignore_ascii_case("wait_for_clarification")));
                        let receipt_dedup_key = format!(
                            "receipt:{}:{}:{}:{}:{}:{}",
                            receipt.step_index,
                            receipt.tool_name,
                            receipt.policy_decision,
                            receipt.incident_stage,
                            receipt.gate_state,
                            receipt.resolution_action
                        );
                        let already_processed_receipt = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    task.processed_steps.contains(&receipt_dedup_key)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if already_processed_receipt {
                            continue;
                        }
                        let suppress_terminal_receipt = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    is_hard_terminal_task(task)
                                        && !receipt_waiting_for_sudo
                                        && !receipt_waiting_for_clarification
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if suppress_terminal_receipt {
                            continue;
                        }
                        let receipt_clarification_request = if receipt_waiting_for_clarification {
                            let preset = clarification_preset_for_tool(&receipt.tool_name)
                                .unwrap_or(ClarificationPreset::IdentityLookup);
                            Some(
                                build_clarification_request_with_inference(
                                    &app,
                                    preset,
                                    &receipt.tool_name,
                                    "",
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                        let failure_class = if receipt.failure_class_name.is_empty() {
                            None
                        } else {
                            Some(receipt.failure_class_name.as_str())
                        };

                        let verification = receipt
                            .post_state
                            .as_ref()
                            .map(|s| {
                                if s.verification_checks.is_empty() {
                                    "none".to_string()
                                } else {
                                    s.verification_checks.join(", ")
                                }
                            })
                            .unwrap_or_else(|| "none".to_string());

                        let mut summary = format!(
                            "RoutingReceipt(step={}, tier={}, tool={}, decision={}, stop={}, policy_hash={})",
                            receipt.step_index,
                            receipt
                                .pre_state
                                .as_ref()
                                .map(|s| s.tier.as_str())
                                .unwrap_or("unknown"),
                            receipt.tool_name,
                            receipt.policy_decision,
                            receipt.stop_condition_hit,
                            receipt.policy_binding_hash
                        );

                        if let Some(class) = failure_class {
                            summary.push_str(&format!(", failure_class={}", class));
                        }
                        if !receipt.intent_class.is_empty() {
                            summary.push_str(&format!(", intent_class={}", receipt.intent_class));
                        }
                        if !receipt.incident_id.is_empty() {
                            summary.push_str(&format!(", incident_id={}", receipt.incident_id));
                        }
                        if !receipt.incident_stage.is_empty() {
                            summary
                                .push_str(&format!(", incident_stage={}", receipt.incident_stage));
                        }
                        if !receipt.strategy_name.is_empty() {
                            summary.push_str(&format!(", strategy_name={}", receipt.strategy_name));
                        }
                        if !receipt.strategy_node.is_empty() {
                            summary.push_str(&format!(", strategy_node={}", receipt.strategy_node));
                        }
                        if !receipt.gate_state.is_empty() {
                            summary.push_str(&format!(", gate_state={}", receipt.gate_state));
                        }
                        if !receipt.resolution_action.is_empty() {
                            summary.push_str(&format!(
                                ", resolution_action={}",
                                receipt.resolution_action
                            ));
                        }
                        if !receipt.escalation_path.is_empty() {
                            summary.push_str(&format!(", escalation={}", receipt.escalation_path));
                        }
                        if !receipt.scs_lineage_ptr.is_empty() {
                            summary.push_str(&format!(", lineage={}", receipt.scs_lineage_ptr));
                        }
                        if !receipt.mutation_receipt_ptr.is_empty() {
                            summary.push_str(&format!(
                                ", mutation_receipt={}",
                                receipt.mutation_receipt_ptr
                            ));
                        }
                        summary.push_str(&format!(", verify=[{}]", verification));

                        update_task_state(&app, |t| {
                            if t.processed_steps.contains(&receipt_dedup_key) {
                                return;
                            }
                            t.processed_steps.insert(receipt_dedup_key.clone());

                            if !receipt.session_id.is_empty() {
                                t.session_id = Some(receipt.session_id.clone());
                            }

                            let waiting_for_sudo = t
                                .credential_request
                                .as_ref()
                                .map(|req| req.kind == "sudo_password")
                                .unwrap_or(false)
                                || t.current_step
                                    .eq_ignore_ascii_case("Waiting for sudo password");
                            let waiting_for_clarification = t
                                .clarification_request
                                .as_ref()
                                .map(|req| is_identity_resolution_kind(&req.kind))
                                .unwrap_or(false)
                                || is_waiting_for_identity_clarification_step(&t.current_step);
                            let mut effective_waiting_for_sudo = waiting_for_sudo;
                            let mut effective_waiting_for_clarification = waiting_for_clarification;

                            if waiting_for_sudo && !receipt_waiting_for_sudo {
                                t.credential_request = None;
                                effective_waiting_for_sudo = false;
                            }

                            if waiting_for_clarification && !receipt_waiting_for_clarification {
                                t.clarification_request = None;
                                effective_waiting_for_clarification = false;
                            }

                            if receipt_waiting_for_sudo {
                                t.phase = AgentPhase::Complete;
                                t.current_step = "Waiting for sudo password".to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.clarification_request = None;
                                t.credential_request = Some(CredentialRequest {
                                    kind: "sudo_password".to_string(),
                                    prompt:
                                        "A one-time sudo password is required to continue the install."
                                            .to_string(),
                                    one_time: true,
                                });
                            }

                            if receipt_waiting_for_clarification {
                                t.phase = AgentPhase::Complete;
                                t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                                t.gate_info = None;
                                t.pending_request_hash = None;
                                t.credential_request = None;
                                t.clarification_request = receipt_clarification_request.clone();
                            }

                            if receipt
                                .policy_decision
                                .eq_ignore_ascii_case("require_approval")
                                && !effective_waiting_for_sudo
                                && !receipt_waiting_for_sudo
                                && !effective_waiting_for_clarification
                                && !receipt_waiting_for_clarification
                            {
                                t.phase = AgentPhase::Gate;
                                if t.gate_info.is_none() {
                                    t.gate_info = Some(GateInfo {
                                        title: "Restricted Action Intercepted".to_string(),
                                        description: format!(
                                            "The agent is attempting to execute: {}",
                                            receipt.tool_name
                                        ),
                                        risk: "high".to_string(),
                                        deadline_ms: None,
                                        pii: None,
                                    });
                                }
                            }

                            if !receipt_waiting_for_sudo && !receipt_waiting_for_clarification {
                                t.current_step = format!(
                                    "Routing: {} ({})",
                                    receipt.tool_name, receipt.policy_decision
                                );
                            }
                            t.history.push(ChatMessage {
                                role: "system".to_string(),
                                text: summary.clone(),
                                timestamp: crate::kernel::state::now(),
                            });
                        });

                        let thread_id = thread_id_from_session(&app, &receipt.session_id);
                        let receipt_id =
                            format!("{}:{}:{}", thread_id, receipt.step_index, receipt.tool_name);

                        let report_ref = {
                            let scs = {
                                let state = app.state::<Mutex<AppState>>();
                                state.lock().ok().and_then(|s| s.studio_scs.clone())
                            };
                            if let Some(scs) = scs {
                                let report_payload = json!({
                                    "receipt_id": receipt_id,
                                    "session_id": receipt.session_id,
                                    "step_index": receipt.step_index,
                                    "tool_name": receipt.tool_name,
                                    "decision": receipt.policy_decision,
                                    "intent_class": receipt.intent_class,
                                    "incident_id": receipt.incident_id,
                                    "incident_stage": receipt.incident_stage,
                                    "strategy_name": receipt.strategy_name,
                                    "strategy_node": receipt.strategy_node,
                                    "gate_state": receipt.gate_state,
                                    "resolution_action": receipt.resolution_action,
                                    "failure_class_name": receipt.failure_class_name,
                                    "summary": summary,
                                    "artifacts": receipt.artifacts,
                                    "policy_binding_hash": receipt.policy_binding_hash,
                                    "verification": receipt.post_state.as_ref().map(|v| v.verification_checks.clone()).unwrap_or_default(),
                                });
                                let report = artifact_store::create_report_artifact(
                                    &scs,
                                    &thread_id,
                                    &format!("Receipt {}", receipt.step_index),
                                    "Routing policy decision receipt",
                                    &report_payload,
                                );
                                let report_ref = ArtifactRef {
                                    artifact_id: report.artifact_id.clone(),
                                    artifact_type: ArtifactType::Report,
                                };
                                register_artifact(&app, report);
                                Some(report_ref)
                            } else {
                                None
                            }
                        };

                        let event = emit_receipt_digest(
                            &thread_id,
                            receipt.step_index,
                            receipt_id,
                            &receipt.tool_name,
                            receipt
                                .pre_state
                                .as_ref()
                                .map(|s| s.tier.clone())
                                .unwrap_or_else(|| "unknown".to_string())
                                .as_str(),
                            &receipt.policy_decision,
                            &receipt.intent_class,
                            &receipt.incident_stage,
                            &receipt.strategy_node,
                            &receipt.gate_state,
                            &receipt.resolution_action,
                            &summary,
                            report_ref,
                            Vec::new(),
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Ghost(input) => {
                        let payload = GhostInputEvent {
                            device: input.device.clone(),
                            description: input.description.clone(),
                        };
                        let _ = app.emit("ghost-input", &payload);
                        update_task_state(&app, |t| {
                            if matches!(t.phase, AgentPhase::Running) {
                                t.current_step = format!("User Input: {}", input.description);
                                t.history.push(ChatMessage {
                                    role: "user".to_string(),
                                    text: format!("[Ghost] {}", input.description),
                                    timestamp: crate::kernel::state::now(),
                                });
                            }
                        });

                        let thread_id = thread_id_from_session(&app, "");
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            "Captured ghost input".to_string(),
                            json!({
                                "device": input.device,
                                "description": input.description,
                            }),
                            json!({}),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Action(action) => {
                        if action.verdict == "PII_REVIEW_REQUESTED" {
                            let pii_info = fetch_pii_review_info(&app, &action.reason).await;
                            if let Some(pii) = pii_info {
                                update_task_state(&app, |t| {
                                    t.gate_info = Some(GateInfo {
                                        title: "PII Review".to_string(),
                                        description: "Sensitive content was detected before egress. Review and choose a deterministic action.".to_string(),
                                        risk: "high".to_string(),
                                        deadline_ms: Some(pii.deadline_ms),
                                        pii: Some(pii.clone()),
                                    });
                                    t.pending_request_hash = Some(action.reason.clone());
                                    if !action.session_id.is_empty() {
                                        t.session_id = Some(action.session_id.clone());
                                    }
                                });
                            }
                            continue;
                        }

                        if action.verdict == "REQUIRE_APPROVAL" {
                            let pii_info = fetch_pii_review_info(&app, &action.reason).await;
                            let (waiting_for_sudo, waiting_for_clarification, hard_terminal_task) = {
                                if let Ok(guard) = state_handle.lock() {
                                    if let Some(task) = &guard.current_task {
                                        let waiting_for_sudo = task
                                            .credential_request
                                            .as_ref()
                                            .map(|req| req.kind == "sudo_password")
                                            .unwrap_or(false)
                                            || task
                                                .current_step
                                                .eq_ignore_ascii_case("Waiting for sudo password");
                                        let waiting_for_clarification = task
                                            .clarification_request
                                            .as_ref()
                                            .map(|req| is_identity_resolution_kind(&req.kind))
                                            .unwrap_or(false)
                                            || is_waiting_for_identity_clarification_step(
                                                &task.current_step,
                                            );
                                        (
                                            waiting_for_sudo,
                                            waiting_for_clarification,
                                            is_hard_terminal_task(task),
                                        )
                                    } else {
                                        (false, false, false)
                                    }
                                } else {
                                    (false, false, false)
                                }
                            };
                            let action_is_install = is_install_package_tool(&action.target);
                            let action_is_identity_lookup_tool =
                                clarification_preset_for_tool(&action.target).is_some();
                            let suppress_gate_for_wait = (waiting_for_sudo && action_is_install)
                                || (waiting_for_clarification && action_is_identity_lookup_tool);

                            let already_gating = {
                                if let Ok(guard) = state_handle.lock() {
                                    if let Some(task) = &guard.current_task {
                                        task.phase == AgentPhase::Gate
                                            && task.pending_request_hash.as_deref()
                                                == Some(action.reason.as_str())
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            };

                            if !already_gating && !suppress_gate_for_wait && !hard_terminal_task {
                                println!("[Autopilot] Policy Gate Triggered for {}", action.target);

                                update_task_state(&app, |t| {
                                    t.phase = AgentPhase::Gate;
                                    t.current_step = "Policy Gate: Approval Required".to_string();
                                    // Gate takes precedence over credential/clarification prompts.
                                    t.credential_request = None;
                                    t.clarification_request = None;

                                    t.gate_info = Some(if let Some(pii) = pii_info.clone() {
                                        GateInfo {
                                            title: "PII Review".to_string(),
                                            description:
                                                "Sensitive content was detected before egress. Choose transform, deny, or scoped exception."
                                                    .to_string(),
                                            risk: "high".to_string(),
                                            deadline_ms: Some(pii.deadline_ms),
                                            pii: Some(pii),
                                        }
                                    } else {
                                        GateInfo {
                                            title: "Restricted Action Intercepted".to_string(),
                                            description: format!(
                                                "The agent is attempting to execute: {}",
                                                action.target
                                            ),
                                            risk: "high".to_string(),
                                            deadline_ms: None,
                                            pii: None,
                                        }
                                    });

                                    t.pending_request_hash = Some(action.reason.clone());

                                    if !action.session_id.is_empty() {
                                        t.session_id = Some(action.session_id.clone());
                                    }

                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!(
                                            "🛑 Policy Gate triggered for action: {}",
                                            action.target
                                        ),
                                        timestamp: crate::kernel::state::now(),
                                    });

                                    if let Some(agent) =
                                        t.swarm_tree.iter_mut().find(|a| a.id == action.session_id)
                                    {
                                        agent.status = "paused".to_string();
                                    }
                                });

                                let thread_id = thread_id_from_session(&app, &action.session_id);
                                let event = build_event(
                                    &thread_id,
                                    0,
                                    EventType::Warning,
                                    "Approval required".to_string(),
                                    json!({
                                        "target": action.target,
                                        "verdict": action.verdict,
                                        "request_hash": action.reason,
                                    }),
                                    json!({
                                        "message": "Policy gate triggered",
                                    }),
                                    EventStatus::Partial,
                                    Vec::new(),
                                    None,
                                    Vec::new(),
                                    None,
                                );
                                register_event(&app, event);

                                if let Some(w) = app.get_webview_window("studio") {
                                    if w.is_visible().unwrap_or(false) {
                                        let _ = w.set_focus();
                                    }
                                }
                            }
                        } else if action.verdict == "BLOCK" {
                            update_task_state(&app, |t| {
                                t.current_step = format!("⛔ Action Blocked: {}", action.target);
                                t.phase = AgentPhase::Failed;

                                if let Some(agent) =
                                    t.swarm_tree.iter_mut().find(|a| a.id == action.session_id)
                                {
                                    agent.status = "failed".to_string();
                                }

                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("⛔ Blocked action: {}", action.target),
                                    timestamp: crate::kernel::state::now(),
                                });
                            });

                            let thread_id = thread_id_from_session(&app, &action.session_id);
                            let event = build_event(
                                &thread_id,
                                0,
                                EventType::Error,
                                "Action blocked".to_string(),
                                json!({
                                    "target": action.target,
                                    "verdict": action.verdict,
                                }),
                                json!({}),
                                EventStatus::Failure,
                                Vec::new(),
                                None,
                                Vec::new(),
                                None,
                            );
                            register_event(&app, event);
                        }
                    }
                    ChainEventEnum::Spawn(spawn) => {
                        update_task_state(&app, |t| {
                            let agent = SwarmAgent {
                                id: spawn.new_session_id.clone(),
                                parent_id: if spawn.parent_session_id.is_empty() {
                                    None
                                } else {
                                    Some(spawn.parent_session_id.clone())
                                },
                                name: spawn.name.clone(),
                                role: spawn.role.clone(),
                                status: "running".to_string(),
                                budget_used: 0.0,
                                budget_cap: spawn.budget as f64,
                                current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
                                artifacts_produced: 0,
                                estimated_cost: 0.0,
                                policy_hash: "".to_string(),
                            };

                            if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
                                t.swarm_tree[pos] = agent;
                            } else {
                                t.swarm_tree.push(agent);
                            }
                        });

                        let thread_id = thread_id_from_session(&app, &spawn.parent_session_id);
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            format!("Spawned agent {}", spawn.name),
                            json!({
                                "agent_id": spawn.new_session_id,
                                "role": spawn.role,
                                "budget": spawn.budget,
                            }),
                            json!({
                                "goal": spawn.goal,
                            }),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::System(update) => {
                        update_task_state(&app, |t| {
                            t.history.push(ChatMessage {
                                role: "system".to_string(),
                                text: format!("⚙️ {}: {}", update.component, update.status),
                                timestamp: crate::kernel::state::now(),
                            });
                        });

                        let thread_id = thread_id_from_session(&app, "");
                        let event = build_event(
                            &thread_id,
                            0,
                            EventType::InfoNote,
                            format!("System update: {}", update.component),
                            json!({
                                "component": update.component,
                                "status": update.status,
                            }),
                            json!({}),
                            EventStatus::Success,
                            Vec::new(),
                            None,
                            Vec::new(),
                            None,
                        );
                        register_event(&app, event);
                    }
                    ChainEventEnum::Block(block) => {
                        #[cfg(debug_assertions)]
                        println!(
                            "[Autopilot] Block #{} committed (Tx: {})",
                            block.height, block.tx_count
                        );
                    }
                }
            }
        }

        eprintln!("[Autopilot] Event Stream Disconnected. Attempting reconnection...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
