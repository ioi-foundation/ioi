use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{emit_command_stream, register_event};
use crate::kernel::events::support::{
    detect_clarification_preset, is_sudo_password_required_install, thread_id_from_session,
    ClarificationPreset, CLARIFICATION_WAIT_STEP, WAIT_FOR_CLARIFICATION_PROMPT,
};
use crate::kernel::state::update_task_state;
use crate::models::CredentialRequest;
use ioi_ipc::public::workload_activity::Kind as WorkloadActivityKind;
use ioi_ipc::public::WorkloadActivity;

pub(super) async fn handle_workload_activity(app: &tauri::AppHandle, activity: WorkloadActivity) {
    let WorkloadActivity {
        session_id,
        step_index,
        workload_id,
        kind,
        ..
    } = activity;
    let thread_id = thread_id_from_session(&app, &session_id);

    match kind {
        Some(WorkloadActivityKind::Stdio(stdio)) => {
            // WorkloadActivity stdio payload no longer includes tool_name/command_preview.
            // Use workload_id as stable correlation key for stream rendering.
            let tool_name = if workload_id.is_empty() {
                "workload".to_string()
            } else {
                workload_id.clone()
            };
            let stream_id = if workload_id.is_empty() {
                format!("step-{}", step_index)
            } else {
                workload_id.clone()
            };
            let channel = if stdio.stream.is_empty() {
                "status".to_string()
            } else {
                stdio.stream.clone()
            };
            let exit_code = if stdio.has_exit_code {
                Some(stdio.exit_code)
            } else {
                None
            };
            let stream_password_required =
                stdio.is_final && is_sudo_password_required_install(&tool_name, &stdio.chunk);
            let stream_clarification_preset = if stdio.is_final {
                detect_clarification_preset(&tool_name, &stdio.chunk)
            } else {
                None
            };
            let stream_clarification_required = stream_clarification_preset.is_some();
            let stream_clarification_request = if stream_clarification_required {
                let preset =
                    stream_clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
                Some(
                    build_clarification_request_with_inference(
                        &app,
                        preset,
                        &tool_name,
                        &stdio.chunk,
                    )
                    .await,
                )
            } else {
                None
            };

            update_task_state(app, |t| {
                if !session_id.is_empty() {
                    t.session_id = Some(session_id.clone());
                }
                if matches!(
                    t.phase,
                    crate::models::AgentPhase::Idle | crate::models::AgentPhase::Running
                ) {
                    t.phase = crate::models::AgentPhase::Running;
                }
                t.current_step = format!("Streaming {} ({})", tool_name, channel);
            });

            if stream_password_required {
                update_task_state(app, |t| {
                    t.phase = crate::models::AgentPhase::Complete;
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

                    if !stdio.chunk.trim().is_empty() {
                        let tool_msg = format!("Tool Output ({}): {}", tool_name, stdio.chunk);
                        if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                            t.history.push(crate::models::ChatMessage {
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
                        t.history.push(crate::models::ChatMessage {
                            role: "system".to_string(),
                            text: prompt_msg,
                            timestamp: crate::kernel::state::now(),
                        });
                    }
                });
            } else if stream_clarification_required {
                update_task_state(app, |t| {
                    t.phase = crate::models::AgentPhase::Complete;
                    t.current_step = CLARIFICATION_WAIT_STEP.to_string();
                    t.gate_info = None;
                    t.pending_request_hash = None;
                    t.credential_request = None;
                    t.clarification_request = stream_clarification_request.clone();

                    if !stdio.chunk.trim().is_empty() {
                        let tool_msg = format!("Tool Output ({}): {}", tool_name, stdio.chunk);
                        if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                            t.history.push(crate::models::ChatMessage {
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
                        t.history.push(crate::models::ChatMessage {
                            role: "system".to_string(),
                            text: prompt_msg,
                            timestamp: crate::kernel::state::now(),
                        });
                    }
                });
            }

            let event = emit_command_stream(
                &thread_id,
                step_index,
                &tool_name,
                &stream_id,
                &channel,
                &stdio.chunk,
                stdio.seq,
                stdio.is_final,
                exit_code,
                "",
            );
            register_event(&app, event);
        }
        Some(WorkloadActivityKind::Lifecycle(lifecycle)) => {
            let display = if workload_id.is_empty() {
                "workload".to_string()
            } else {
                workload_id
            };
            update_task_state(app, |t| {
                if !session_id.is_empty() {
                    t.session_id = Some(session_id.clone());
                }
                if matches!(
                    t.phase,
                    crate::models::AgentPhase::Idle | crate::models::AgentPhase::Running
                ) {
                    t.phase = crate::models::AgentPhase::Running;
                }
                t.current_step = format!("Workload {} {}", display, lifecycle.phase);
            });
        }
        None => {}
    }
}
