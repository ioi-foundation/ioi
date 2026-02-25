use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{
    create_macro_artifacts_for_action, emit_browser_navigate, emit_browser_snapshot,
    emit_code_search, emit_command_run, emit_file_edit, emit_test_run, register_event,
};
use crate::kernel::events::support::{
    bind_task_session, clarification_prompt_for_preset, clarification_wait_step_for_preset,
    detect_clarification_preset, event_status_from_agent_status, event_type_for_tool,
    is_hard_terminal_task, is_identity_resolution_kind, is_install_package_tool,
    is_sudo_password_required_install, is_waiting_for_identity_clarification_step,
    thread_id_from_session, ClarificationPreset,
};
use crate::kernel::state::update_task_state;
use crate::models::AppState;
use crate::models::{AgentPhase, ChatMessage, CredentialRequest, EventType, Receipt};
use ioi_ipc::public::AgentActionResult;
use std::sync::Mutex;
use tauri::Manager;

const MAX_COMPLETION_MESSAGE_CHARS: usize = 1200;

fn is_chat_reply_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("chat::reply") || tool_name.eq_ignore_ascii_case("chat__reply")
}

fn is_planner_execute_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("planner::execute")
        || tool_name.eq_ignore_ascii_case("planner__execute")
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

fn completion_message_for_history(tool_name: &str, output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
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

pub(super) async fn handle_action_result(app: &tauri::AppHandle, res: AgentActionResult) {
    let password_required = is_sudo_password_required_install(&res.tool_name, &res.output);
    let clarification_preset = if res.agent_status.eq_ignore_ascii_case("paused") {
        detect_clarification_preset(&res.tool_name, &res.output)
    } else {
        None
    };
    let clarification_required = clarification_preset.is_some();
    let effective_clarification_preset =
        clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
    let clarification_wait_step =
        clarification_wait_step_for_preset(effective_clarification_preset);
    let clarification_prompt = clarification_prompt_for_preset(effective_clarification_preset);
    let clarification_request = if clarification_required {
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

        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
        bind_task_session(t, &res.session_id);

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

                if !is_chat_reply_tool(&res.tool_name) {
                    if let Some(msg) = completion_message_for_history(&res.tool_name, &res.output) {
                        let duplicate = t
                            .history
                            .iter()
                            .rev()
                            .take(8)
                            .any(|m| m.role == "agent" && m.text == msg);
                        if !duplicate {
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

        if is_chat_reply_tool(&res.tool_name) {
            if res.agent_status != "Failed" {
                t.phase = AgentPhase::Complete;
                t.current_step = "Ready for input".to_string();
            }

            let duplicate = t
                .history
                .iter()
                .rev()
                .take(8)
                .any(|m| m.role == "agent" && m.text == res.output);
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
    if !accepted_for_processing {
        return;
    }

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

#[cfg(test)]
mod tests {
    use super::{
        completion_message_for_history, is_chat_reply_tool, is_planner_execute_tool,
        truncate_message_chars,
    };

    #[test]
    fn chat_reply_tool_detection_is_case_insensitive() {
        assert!(is_chat_reply_tool("chat__reply"));
        assert!(is_chat_reply_tool("CHAT::REPLY"));
        assert!(!is_chat_reply_tool("planner::execute"));
    }

    #[test]
    fn planner_completion_prefers_scheduled_workflow_summary() {
        let output = "Route: route.linux.systemd_run.notify_send. Strategy: Selected Linux scheduler route. COMMAND_HISTORY:{\"command\":\"systemd-run --user --on-active=900s\"}\nStderr:\nRunning timer as unit: ioi-timer-1.timer\nWill run service as unit: ioi-timer-1.service\nScheduled workflow: set a timer for 15 minutes. Target UTC: 2026-02-24T03:47:26Z.";
        let message = completion_message_for_history("planner::execute", output).expect("message");
        assert!(message.starts_with("Scheduled workflow:"));
        assert!(message.contains("Target UTC: 2026-02-24T03:47:26Z."));
        assert!(!message.contains("COMMAND_HISTORY:"));
    }

    #[test]
    fn planner_completion_falls_back_to_route_without_command_history_blob() {
        let output = "Route: route.local.timer. Strategy: fallback route. COMMAND_HISTORY:{\"command\":\"foo\"}";
        let message = completion_message_for_history("planner::execute", output).expect("message");
        assert_eq!(
            message,
            "Route: route.local.timer. Strategy: fallback route."
        );
        assert!(is_planner_execute_tool("planner::execute"));
    }

    #[test]
    fn completion_message_is_truncated_for_very_long_output() {
        let long = "a".repeat(5000);
        let message =
            completion_message_for_history("sys__exec", &long).expect("message should exist");
        assert!(message.len() < long.len());
        assert!(message.ends_with('…'));
        assert_eq!(message, truncate_message_chars(&long, 1200));
    }

    #[test]
    fn empty_completion_output_yields_none() {
        assert!(completion_message_for_history("planner::execute", "   ").is_none());
    }
}
