use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{
    create_macro_artifacts_for_action, emit_browser_navigate, emit_browser_snapshot,
    emit_code_search, emit_command_run, emit_file_edit, emit_test_run, register_event,
};
use crate::kernel::events::support::{
    bind_task_session, clarification_prompt_for_preset, clarification_wait_step_for_preset,
    detect_clarification_preset, event_status_from_agent_status, event_type_for_tool,
    explicit_clarification_preset_for_tool, is_hard_terminal_task, is_identity_resolution_kind,
    is_software_install_tool, is_sudo_password_required_install,
    is_waiting_for_identity_clarification_step, thread_id_from_session, ClarificationPreset,
};
use crate::kernel::notifications;
use crate::kernel::state::update_task_state;
use crate::models::AppState;
use crate::models::{AgentPhase, ChatMessage, CredentialRequest, EventType, Receipt};
use ioi_ipc::public::AgentActionResult;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};

const MAX_COMPLETION_MESSAGE_CHARS: usize = 1200;
const CHAT_COMPOSER_FOCUS_REQUESTED_EVENT: &str = "chat-composer-focus-requested";

fn is_chat_reply_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("chat::reply") || tool_name.eq_ignore_ascii_case("chat__reply")
}

fn is_planner_execute_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("planner::execute")
        || tool_name.eq_ignore_ascii_case("planner__execute")
}

fn is_browser_surface_tool(tool_name: &str) -> bool {
    let normalized = tool_name.to_ascii_lowercase();
    normalized == "browser__navigate"
        || normalized == "browser::navigate"
        || normalized == "browser__snapshot"
        || normalized == "browser::snapshot"
        || normalized == "browser__inspect"
        || normalized == "browser::inspect"
}

fn should_refocus_chat_after_action_result(tool_name: &str, agent_status: &str) -> bool {
    is_browser_surface_tool(tool_name)
        && (agent_status.eq_ignore_ascii_case("completed")
            || agent_status.eq_ignore_ascii_case("failed"))
}

fn should_release_browser_after_action_result(
    tool_name: &str,
    agent_status: &str,
    task_has_browser_surface_event: bool,
) -> bool {
    agent_status.eq_ignore_ascii_case("completed")
        && (is_browser_surface_tool(tool_name) || task_has_browser_surface_event)
}

fn task_has_browser_surface_event(task: &crate::models::AgentTask) -> bool {
    task.events.iter().any(|event| {
        matches!(
            event.event_type,
            EventType::BrowserNavigate | EventType::BrowserSnapshot
        )
    })
}

fn should_append_completed_tool_message_from_action_result(
    task_requires_chat_primary_execution: bool,
    task_has_chat_outcome: bool,
    tool_name: &str,
) -> bool {
    !task_requires_chat_primary_execution
        && !task_has_chat_outcome
        && !is_chat_reply_tool(tool_name)
}

fn truncate_message_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut end = text.len();
    for (count, (idx, _)) in text.char_indices().enumerate() {
        if count == max_chars {
            end = idx;
            break;
        }
    }
    format!("{}…", text[..end].trim_end())
}

fn agent_message_exists_after_latest_user(history: &[ChatMessage], text: &str) -> bool {
    history
        .iter()
        .rev()
        .take_while(|message| message.role != "user")
        .any(|message| message.role == "agent" && message.text == text)
}

fn completion_message_for_history(tool_name: &str, output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    if is_software_install_tool(tool_name) {
        if let Some(summary) = install_output_summary(trimmed) {
            return Some(truncate_message_chars(
                &summary,
                MAX_COMPLETION_MESSAGE_CHARS,
            ));
        }
    }

    let candidate = if is_planner_execute_tool(tool_name) {
        if let Some(idx) = trimmed.find("Scheduled workflow:") {
            trimmed[idx..].trim()
        } else if let Some(idx) = trimmed.find("COMMAND_HISTORY:") {
            let head = trimmed[..idx].trim();
            if head.is_empty() {
                trimmed
            } else {
                head
            }
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    Some(truncate_message_chars(
        candidate,
        MAX_COMPLETION_MESSAGE_CHARS,
    ))
}

fn install_json_payload(output: &str) -> Option<Value> {
    let trimmed = output.trim();
    let json = first_json_object_slice(trimmed)?;
    serde_json::from_str(json).ok()
}

fn first_json_object_slice(value: &str) -> Option<&str> {
    let start = value.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in value[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return Some(&value[start..end]);
                }
            }
            _ => {}
        }
    }
    None
}

fn install_output_summary(output: &str) -> Option<String> {
    install_json_payload(output).and_then(|value| {
        value
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn install_current_step(tool_name: &str, output: &str) -> Option<String> {
    if !is_software_install_tool(tool_name) {
        return None;
    }
    install_output_summary(output).or_else(|| Some("Software install event received".to_string()))
}

fn install_failure_summary(tool_name: &str, output: &str) -> Option<String> {
    if !is_software_install_tool(tool_name) {
        return None;
    }
    install_output_summary(output).map(|summary| format!("Install blocked: {summary}"))
}

fn failure_message_for_history(tool_name: &str, output: &str) -> String {
    install_failure_summary(tool_name, output).unwrap_or_else(|| {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            "Task failed.".to_string()
        } else {
            format!("Task failed: {trimmed}")
        }
    })
}

fn automation_artifact_path_from_output(output: &str) -> Option<PathBuf> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Artifact path: ")
            .map(|value| PathBuf::from(value.trim()))
    })
}

fn should_preserve_existing_operator_gate(
    task: &crate::models::AgentTask,
    result_agent_status: &str,
) -> bool {
    matches!(task.phase, AgentPhase::Gate)
        && (task.gate_info.is_some() || task.pending_request_hash.is_some())
        && !result_agent_status.eq_ignore_ascii_case("failed")
}

pub(super) async fn handle_action_result(app: &tauri::AppHandle, res: AgentActionResult) {
    let password_required = is_sudo_password_required_install(&res.tool_name, &res.output);
    let thread_id = thread_id_from_session(&app, &res.session_id);
    let clarification_preset = detect_clarification_preset(&res.tool_name, &res.output)
        .or_else(|| explicit_clarification_preset_for_tool(&res.tool_name));
    let clarification_required = clarification_preset.is_some();
    let effective_clarification_preset =
        clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
    let clarification_wait_step =
        clarification_wait_step_for_preset(effective_clarification_preset);
    let clarification_prompt = clarification_prompt_for_preset(effective_clarification_preset);
    let clarification_request = if clarification_required {
        let clarification_kind = match effective_clarification_preset {
            ClarificationPreset::IdentityLookup => "identity_lookup",
            ClarificationPreset::InstallLookup => "install_lookup",
            ClarificationPreset::LaunchLookup => "launch_lookup",
            ClarificationPreset::IntentClarification => "intent_clarification",
        };
        notifications::record_clarification_intervention(
            app,
            &thread_id,
            &res.session_id,
            clarification_kind,
            clarification_prompt,
        );
        Some(
            build_clarification_request_with_inference(
                &app,
                effective_clarification_preset,
                &res.tool_name,
                &res.output,
            )
            .await,
        )
    } else {
        None
    };
    if password_required {
        notifications::record_credential_intervention(
            app,
            &thread_id,
            &res.session_id,
            "sudo_password",
            "A one-time sudo password is required to continue the install.",
        );
    }

    let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
    let already_processed = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(|task| task.processed_steps.contains(&dedup_key))
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if already_processed {
        return;
    }

    let suppress_terminal_action_result = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(|task| {
                    is_hard_terminal_task(task)
                        && !password_required
                        && !clarification_required
                        && !res.agent_status.eq_ignore_ascii_case("completed")
                        && !res.agent_status.eq_ignore_ascii_case("failed")
                        && !res.tool_name.eq_ignore_ascii_case("agent__complete")
                })
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if suppress_terminal_action_result {
        return;
    }

    let mut accepted_for_processing = false;
    update_task_state(app, |t| {
        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
        if t.processed_steps.contains(&dedup_key) {
            return;
        }
        t.processed_steps.insert(dedup_key);
        accepted_for_processing = true;

        t.current_step = install_current_step(&res.tool_name, &res.output)
            .unwrap_or_else(|| format!("Executed {}: {}", res.tool_name, res.output));
        bind_task_session(t, &res.session_id);

        if let Some(agent) = t
            .work_graph_tree
            .iter_mut()
            .find(|a| a.id == res.session_id)
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
            t.phase = AgentPhase::Running;
            t.current_step = "Waiting for sudo password".to_string();
            t.gate_info = None;
            t.pending_request_hash = None;
            t.credential_request = Some(CredentialRequest {
                kind: "sudo_password".to_string(),
                prompt: "A one-time sudo password is required to continue the install.".to_string(),
                one_time: true,
            });
            t.clarification_request = None;

            if !res.output.trim().is_empty() {
                let tool_msg = format!("Tool Output ({}): {}", res.tool_name, res.output);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                    t.history.push(ChatMessage {
                        role: "tool".to_string(),
                        text: tool_msg,
                        timestamp: crate::kernel::state::now(),
                    });
                }
            }
            let prompt_msg =
                "System: Install requires sudo password. Enter password to retry.".to_string();
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
            t.phase = AgentPhase::Running;
            t.current_step = clarification_wait_step.to_string();
            t.gate_info = None;
            t.pending_request_hash = None;
            t.credential_request = None;
            t.clarification_request = clarification_request.clone();

            if !res.output.trim().is_empty() {
                let tool_msg = format!("Tool Output ({}): {}", res.tool_name, res.output);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                    t.history.push(ChatMessage {
                        role: "tool".to_string(),
                        text: tool_msg,
                        timestamp: crate::kernel::state::now(),
                    });
                }
            }
            let prompt_msg = clarification_prompt.to_string();
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

        let terminal_status = res.agent_status.eq_ignore_ascii_case("failed")
            || res.agent_status.eq_ignore_ascii_case("completed");
        let keep_waiting_for_sudo = waiting_for_sudo
            && !terminal_status
            && is_software_install_tool(&res.tool_name)
            && password_required;
        if keep_waiting_for_sudo {
            if !res.output.trim().is_empty() {
                let tool_msg = format!("Tool Output ({}): {}", res.tool_name, res.output);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
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
            && (clarification_required
                || explicit_clarification_preset_for_tool(&res.tool_name).is_some());
        if keep_waiting_for_clarification {
            if !res.output.trim().is_empty() {
                let tool_msg = format!("Tool Output ({}): {}", res.tool_name, res.output);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
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
        if should_preserve_existing_operator_gate(t, &res.agent_status) {
            if !res.output.trim().is_empty() {
                let tool_msg = format!("Tool Output ({}): {}", res.tool_name, res.output);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                    t.history.push(ChatMessage {
                        role: "tool".to_string(),
                        text: tool_msg,
                        timestamp: crate::kernel::state::now(),
                    });
                }
            }
            return;
        }
        if t.phase == AgentPhase::Gate && !res.agent_status.eq_ignore_ascii_case("paused") {
            t.gate_info = None;
            t.pending_request_hash = None;
            t.phase = AgentPhase::Running;
        }

        match res.agent_status.as_str() {
            "Completed" => {
                t.phase = AgentPhase::Complete;
                t.current_step = "Task completed".to_string();
                t.gate_info = None;
                t.pending_request_hash = None;
                t.credential_request = None;
                t.clarification_request = None;

                if let Some(agent) = t
                    .work_graph_tree
                    .iter_mut()
                    .find(|a| a.id == res.session_id)
                {
                    agent.status = "completed".to_string();
                }

                t.receipt = Some(Receipt {
                    duration: "Done".to_string(),
                    actions: t.progress,
                    cost: Some("$0.00".to_string()),
                });

                let task_requires_chat_primary_execution =
                    crate::kernel::chat::task_requires_chat_primary_execution(t);
                if should_append_completed_tool_message_from_action_result(
                    task_requires_chat_primary_execution,
                    t.chat_outcome.is_some(),
                    &res.tool_name,
                ) {
                    if let Some(msg) = completion_message_for_history(&res.tool_name, &res.output) {
                        if !agent_message_exists_after_latest_user(&t.history, &msg) {
                            t.history.push(ChatMessage {
                                role: "agent".to_string(),
                                text: msg,
                                timestamp: crate::kernel::state::now(),
                            });
                        }
                    }
                }
            }
            "Failed" => {
                t.phase = AgentPhase::Failed;
                t.gate_info = None;
                t.pending_request_hash = None;
                t.credential_request = None;
                t.clarification_request = None;
                let chat_failure_summary =
                    if crate::kernel::chat::task_requires_chat_primary_execution(t) {
                        crate::kernel::chat::verified_reply_summary_for_task(t)
                    } else {
                        None
                    };

                if let Some(agent) = t
                    .work_graph_tree
                    .iter_mut()
                    .find(|a| a.id == res.session_id)
                {
                    agent.status = "failed".to_string();
                }

                // Keep terminal failures visible in the primary conversation stream.
                let agent_failure = chat_failure_summary
                    .clone()
                    .unwrap_or_else(|| failure_message_for_history(&res.tool_name, &res.output));
                if !t
                    .history
                    .iter()
                    .rev()
                    .take(8)
                    .any(|entry| entry.role == "system" && entry.text == agent_failure)
                {
                    t.history.push(ChatMessage {
                        role: "system".to_string(),
                        text: agent_failure.clone(),
                        timestamp: crate::kernel::state::now(),
                    });
                }
                t.current_step = agent_failure.clone();
                if !agent_message_exists_after_latest_user(&t.history, &agent_failure) {
                    t.history.push(ChatMessage {
                        role: "agent".to_string(),
                        text: agent_failure,
                        timestamp: crate::kernel::state::now(),
                    });
                }
            }
            "Paused" => {
                if let Some(agent) = t
                    .work_graph_tree
                    .iter_mut()
                    .find(|a| a.id == res.session_id)
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

        if is_chat_reply_tool(&res.tool_name) {
            if res.agent_status != "Failed" {
                t.phase = AgentPhase::Complete;
                t.current_step = "Ready for input".to_string();
            }

            let reply_text = if crate::kernel::chat::task_requires_chat_primary_execution(t) {
                crate::kernel::chat::verified_reply_summary_for_task(t)
                    .unwrap_or_else(|| res.output.clone())
            } else {
                res.output.clone()
            };
            if !agent_message_exists_after_latest_user(&t.history, &reply_text) {
                t.history.push(ChatMessage {
                    role: "agent".to_string(),
                    text: reply_text,
                    timestamp: crate::kernel::state::now(),
                });
            }
        } else if res.tool_name == "system::refusal" {
            t.history.push(ChatMessage {
                role: "system".to_string(),
                text: format!("⚠️ Agent Paused: {}", res.output),
                timestamp: crate::kernel::state::now(),
            });
        } else if res.agent_status == "Running" && res.tool_name != "agent__complete" {
            t.history.push(ChatMessage {
                role: "tool".to_string(),
                text: format!("Tool Output ({}): {}", res.tool_name, res.output),
                timestamp: crate::kernel::state::now(),
            });
        }
    });
    if !accepted_for_processing {
        return;
    }

    if res.tool_name.eq_ignore_ascii_case("monitor__create") && !res.has_error_class {
        let manager: State<crate::kernel::workflows::WorkflowManager> = app.state();
        if let Some(artifact_path) = automation_artifact_path_from_output(&res.output) {
            if let Err(error) = manager
                .import_workflow_from_artifact_path(&artifact_path)
                .await
            {
                eprintln!(
                    "[Autopilot] Failed to import workflow artifact after automation install: {}",
                    error
                );
            }
        } else if res.output.contains("Scheduled workflow:") {
            if let Err(error) = manager.sync_from_disk().await {
                eprintln!(
                    "[Autopilot] Failed to sync workflow manager after automation install: {}",
                    error
                );
            }
        }
    }

    let kind = event_type_for_tool(&res.tool_name);
    let status = event_status_from_agent_status(&res.agent_status);
    let artifact_refs =
        create_macro_artifacts_for_action(&app, &thread_id, &kind, &res.tool_name, &res.output);
    let chat_completion = {
        let state_handle = app.state::<Mutex<AppState>>();
        let completion = match state_handle.lock() {
            Ok(guard) => guard.current_task.as_ref().and_then(|task| {
                if !crate::kernel::chat::task_requires_chat_primary_execution(task) {
                    return None;
                }
                crate::kernel::chat::verified_reply_summary_for_task(task).map(|summary| {
                    (
                        crate::kernel::chat::verified_reply_title_for_task(task)
                            .unwrap_or_else(|| "Chat outcome verified".to_string()),
                        summary,
                    )
                })
            }),
            Err(_) => None,
        };
        completion
    };

    if res.agent_status.eq_ignore_ascii_case("completed") {
        let (title, summary) = chat_completion.unwrap_or_else(|| {
            (
                "Workflow completed".to_string(),
                completion_message_for_history(&res.tool_name, &res.output)
                    .unwrap_or_else(|| "Task completed successfully.".to_string()),
            )
        });
        notifications::record_valuable_completion(
            app,
            &thread_id,
            &res.session_id,
            &title,
            &summary,
            artifact_refs.clone(),
        );
    }

    let mut event = match kind {
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
    if let Some(payload) = install_json_payload(&res.output) {
        if let Some(details) = event.details.as_object_mut() {
            details.insert("install_payload".to_string(), payload.clone());
            if let Some(install_event) = payload.get("install_event").cloned() {
                details.insert("install_event".to_string(), install_event);
            }
            if let Some(receipt) = payload.get("install_final_receipt").cloned() {
                details.insert("install_final_receipt".to_string(), receipt);
            }
        }
    }
    register_event(&app, event);

    let has_browser_surface_event = {
        let state_handle = app.state::<Mutex<AppState>>();
        state_handle
            .lock()
            .ok()
            .and_then(|guard| {
                guard
                    .current_task
                    .as_ref()
                    .map(task_has_browser_surface_event)
            })
            .unwrap_or(false)
    };

    if should_release_browser_after_action_result(
        &res.tool_name,
        &res.agent_status,
        has_browser_surface_event,
    ) {
        crate::execution::release_browser_session().await;
    }

    if should_refocus_chat_after_action_result(&res.tool_name, &res.agent_status) {
        let window = app.get_webview_window("chat").or_else(|| {
            app.get_webview_window("chat-session")
                .filter(|candidate| candidate.is_visible().unwrap_or(false))
        });
        if let Some(window) = window {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
            let _ = window.emit(
                CHAT_COMPOSER_FOCUS_REQUESTED_EVENT,
                json!({
                    "source": "terminal_action_result",
                    "tool_name": res.tool_name,
                    "agent_status": res.agent_status,
                }),
            );
        }
    }
}

#[cfg(test)]
#[path = "action_result/tests.rs"]
mod tests;
