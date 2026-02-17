use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{
    create_macro_artifacts_for_action, emit_browser_navigate, emit_browser_snapshot,
    emit_code_search, emit_command_run, emit_file_edit, emit_test_run, register_event,
};
use crate::kernel::events::support::{
    detect_clarification_preset, event_status_from_agent_status, event_type_for_tool,
    is_hard_terminal_task, is_identity_resolution_kind, is_install_package_tool,
    is_sudo_password_required_install, is_waiting_for_identity_clarification_step,
    thread_id_from_session, ClarificationPreset, CLARIFICATION_WAIT_STEP,
    WAIT_FOR_CLARIFICATION_PROMPT,
};
use crate::kernel::state::update_task_state;
use crate::models::AppState;
use crate::models::{AgentPhase, ChatMessage, CredentialRequest, EventType, Receipt};
use ioi_ipc::public::chain_event::AgentActionResult;
use serde_json::json;
use std::sync::Mutex;

pub(super) async fn handle_action_result(app: &tauri::AppHandle, res: AgentActionResult) {
    let password_required = is_sudo_password_required_install(&res.tool_name, &res.output);
    let clarification_preset = if res.agent_status.eq_ignore_ascii_case("paused") {
        detect_clarification_preset(&res.tool_name, &res.output)
    } else {
        None
    };
    let clarification_required = clarification_preset.is_some();
    let clarification_request = if clarification_required {
        let preset = clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
        Some(
            build_clarification_request_with_inference(&app, preset, &res.tool_name, &res.output)
                .await,
        )
    } else {
        None
    };

    let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
    let already_processed = {
        let state_handle = app.state::<Mutex<AppState>>();
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
        return;
    }

    let suppress_terminal_action_result = {
        let state_handle = app.state::<Mutex<AppState>>();
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
        return;
    }

    update_task_state(app, |t| {
        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);
        if t.processed_steps.contains(&dedup_key) {
            return;
        }
        t.processed_steps.insert(dedup_key);

        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
        if !res.session_id.is_empty() {
            t.session_id = Some(res.session_id.clone());
        }

        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
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
            t.phase = AgentPhase::Complete;
            t.current_step = CLARIFICATION_WAIT_STEP.to_string();
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

        let terminal_status = res.agent_status.eq_ignore_ascii_case("failed")
            || res.agent_status.eq_ignore_ascii_case("completed");
        let keep_waiting_for_sudo = waiting_for_sudo
            && !terminal_status
            && is_install_package_tool(&res.tool_name)
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

        let keep_waiting_for_clarification =
            waiting_for_clarification && !terminal_status && clarification_required;
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

        match res.agent_status.as_str() {
            "Completed" => {
                t.phase = AgentPhase::Complete;
                t.current_step = "Task completed".to_string();
                t.gate_info = None;
                t.pending_request_hash = None;
                t.credential_request = None;
                t.clarification_request = None;

                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
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

                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                    agent.status = "failed".to_string();
                }

                t.history.push(ChatMessage {
                    role: "system".to_string(),
                    text: format!("Task Failed: {}", res.output),
                    timestamp: crate::kernel::state::now(),
                });
            }
            "Paused" => {
                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
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
        } else if res.agent_status == "Running" && res.tool_name != "agent__complete" {
            t.history.push(ChatMessage {
                role: "tool".to_string(),
                text: format!("Tool Output ({}): {}", res.tool_name, res.output),
                timestamp: crate::kernel::state::now(),
            });
        }
    });

    let thread_id = thread_id_from_session(&app, &res.session_id);
    let kind = event_type_for_tool(&res.tool_name);
    let status = event_status_from_agent_status(&res.agent_status);
    let artifact_refs =
        create_macro_artifacts_for_action(&app, &thread_id, &kind, &res.tool_name, &res.output);

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
