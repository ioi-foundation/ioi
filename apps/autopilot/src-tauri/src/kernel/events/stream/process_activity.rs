use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{emit_command_stream, register_event};
use crate::kernel::events::support::{
    detect_clarification_preset, is_sudo_password_required_install,
    thread_id_from_session, ClarificationPreset, WAIT_FOR_CLARIFICATION_PROMPT,
    CLARIFICATION_WAIT_STEP,
};
use crate::kernel::state::update_task_state;
use crate::models::CredentialRequest;
use ioi_ipc::public::chain_event::ProcessActivity;

pub(super) async fn handle_process_activity(app: &tauri::AppHandle, activity: ProcessActivity) {
    let thread_id = thread_id_from_session(&app, &activity.session_id);
    let exit_code = if activity.has_exit_code {
        Some(activity.exit_code)
    } else {
        None
    };
    let stream_password_required =
        activity.is_final && is_sudo_password_required_install(&activity.tool_name, &activity.chunk);
    let stream_clarification_preset = if activity.is_final {
        detect_clarification_preset(&activity.tool_name, &activity.chunk)
    } else {
        None
    };
    let stream_clarification_required = stream_clarification_preset.is_some();
    let stream_clarification_request = if stream_clarification_required {
        let preset = stream_clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
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

    update_task_state(app, |t| {
        if !activity.session_id.is_empty() {
            t.session_id = Some(activity.session_id.clone());
        }
        if matches!(t.phase, crate::models::AgentPhase::Idle | crate::models::AgentPhase::Running) {
            t.phase = crate::models::AgentPhase::Running;
        }
        t.current_step = format!("Streaming {} ({})", activity.tool_name, activity.channel);
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

            if !activity.chunk.trim().is_empty() {
                let tool_msg =
                    format!("Tool Output ({}): {}", activity.tool_name, activity.chunk);
                if t.history.last().map(|m| m.text != tool_msg).unwrap_or(true) {
                    t.history.push(crate::models::ChatMessage {
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

            if !activity.chunk.trim().is_empty() {
                let tool_msg =
                    format!("Tool Output ({}): {}", activity.tool_name, activity.chunk);
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
