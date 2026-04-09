use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{emit_command_stream, register_event};
use crate::kernel::events::support::{
    bind_task_session, clarification_prompt_for_preset, clarification_wait_step_for_preset,
    detect_clarification_preset, explicit_clarification_preset_for_tool, is_hard_terminal_task,
    is_identity_resolution_kind, is_sudo_password_required_install,
    is_waiting_for_identity_clarification_step, thread_id_from_session, ClarificationPreset,
};
use crate::kernel::notifications;
use crate::kernel::state::update_task_state;
use crate::models::AppState;
use crate::models::CredentialRequest;
use ioi_ipc::public::workload_activity::Kind as WorkloadActivityKind;
use ioi_ipc::public::WorkloadActivity;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::Manager;

const STREAM_COALESCE_MAX_CHARS: usize = 1200;
const STREAM_COALESCE_MAX_LINES: usize = 8;
const STREAM_PROGRESS_MAX_CHARS: usize = 140;

#[derive(Debug, Clone, Default)]
struct StreamBuffer {
    chunk: String,
    seq: u64,
}

static STREAM_BUFFERS: Lazy<Mutex<HashMap<String, StreamBuffer>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn stream_buffer_key(thread_id: &str, step_index: u32, stream_id: &str, channel: &str) -> String {
    format!("{}:{}:{}:{}", thread_id, step_index, stream_id, channel)
}

fn should_flush_stream_buffer(buffer: &str) -> bool {
    if buffer.chars().count() >= STREAM_COALESCE_MAX_CHARS {
        return true;
    }
    buffer
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        >= STREAM_COALESCE_MAX_LINES
}

fn stream_progress_excerpt(chunk: &str) -> Option<String> {
    let line = chunk
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_else(|| chunk.trim());
    if line.is_empty() {
        return None;
    }
    let mut clipped = line
        .chars()
        .take(STREAM_PROGRESS_MAX_CHARS)
        .collect::<String>();
    if line.chars().count() > STREAM_PROGRESS_MAX_CHARS {
        clipped.push_str("...");
    }
    Some(clipped)
}

fn emit_coalesced_stream_event(
    app: &tauri::AppHandle,
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    stream_id: &str,
    channel: &str,
    chunk: &str,
    seq: u64,
    is_final: bool,
    exit_code: Option<i32>,
) {
    let key = stream_buffer_key(thread_id, step_index, stream_id, channel);
    let mut emit_payload: Option<(String, u64)> = None;

    if let Ok(mut buffers) = STREAM_BUFFERS.lock() {
        let buffer = buffers.entry(key.clone()).or_default();
        if !chunk.is_empty() {
            buffer.chunk.push_str(chunk);
        }
        buffer.seq = seq;

        if is_final || should_flush_stream_buffer(&buffer.chunk) {
            emit_payload = Some((std::mem::take(&mut buffer.chunk), buffer.seq));
            if is_final {
                buffers.remove(&key);
            }
        }
    } else {
        emit_payload = Some((chunk.to_string(), seq));
    }

    if let Some((merged_chunk, merged_seq)) = emit_payload {
        if merged_chunk.is_empty() && !is_final {
            return;
        }
        let event = emit_command_stream(
            thread_id,
            step_index,
            tool_name,
            stream_id,
            channel,
            &merged_chunk,
            merged_seq,
            is_final,
            exit_code,
            "",
        );
        register_event(app, event);
    }
}

fn flush_stream_buffers_for_workload(
    app: &tauri::AppHandle,
    thread_id: &str,
    step_index: u32,
    tool_name: &str,
    stream_id: &str,
    exit_code: Option<i32>,
) {
    let prefix = format!("{}:{}:{}:", thread_id, step_index, stream_id);
    let mut pending = Vec::<(String, StreamBuffer)>::new();
    if let Ok(mut buffers) = STREAM_BUFFERS.lock() {
        let keys: Vec<String> = buffers
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        for key in keys {
            if let Some(buffer) = buffers.remove(&key) {
                pending.push((key, buffer));
            }
        }
    }
    for (key, buffer) in pending {
        let channel = key.rsplit(':').next().unwrap_or("status");
        if buffer.chunk.trim().is_empty() {
            continue;
        }
        let event = emit_command_stream(
            thread_id,
            step_index,
            tool_name,
            stream_id,
            channel,
            &buffer.chunk,
            buffer.seq,
            true,
            exit_code,
            "",
        );
        register_event(app, event);
    }
}

pub(super) async fn handle_workload_activity(app: &tauri::AppHandle, activity: WorkloadActivity) {
    let WorkloadActivity {
        session_id,
        step_index,
        workload_id,
        kind,
        ..
    } = activity;
    let thread_id = thread_id_from_session(&app, &session_id);

    let suppress_terminal_activity = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(is_hard_terminal_task)
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if suppress_terminal_activity {
        return;
    }

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
                    .or_else(|| explicit_clarification_preset_for_tool(&tool_name))
            } else {
                None
            };
            let stream_clarification_required = stream_clarification_preset.is_some();
            let effective_stream_clarification_preset =
                stream_clarification_preset.unwrap_or(ClarificationPreset::IdentityLookup);
            let stream_clarification_wait_step =
                clarification_wait_step_for_preset(effective_stream_clarification_preset);
            let stream_clarification_prompt =
                clarification_prompt_for_preset(effective_stream_clarification_preset);
            let stream_clarification_request = if stream_clarification_required {
                Some(
                    build_clarification_request_with_inference(
                        &app,
                        effective_stream_clarification_preset,
                        &tool_name,
                        &stdio.chunk,
                    )
                    .await,
                )
            } else {
                None
            };

            update_task_state(app, |t| {
                bind_task_session(t, &session_id);
                if matches!(
                    t.phase,
                    crate::models::AgentPhase::Idle | crate::models::AgentPhase::Running
                ) {
                    t.phase = crate::models::AgentPhase::Running;
                }
                let already_waiting_for_password = t
                    .credential_request
                    .as_ref()
                    .map(|req| req.kind == "sudo_password")
                    .unwrap_or(false)
                    || t.current_step
                        .eq_ignore_ascii_case("Waiting for sudo password");
                let already_waiting_for_clarification = t
                    .clarification_request
                    .as_ref()
                    .map(|req| is_identity_resolution_kind(&req.kind))
                    .unwrap_or(false)
                    || is_waiting_for_identity_clarification_step(&t.current_step);
                if !stream_password_required
                    && !stream_clarification_required
                    && !already_waiting_for_password
                    && !already_waiting_for_clarification
                {
                    t.credential_request = None;
                    t.clarification_request = None;
                }
                let progress = stream_progress_excerpt(&stdio.chunk);
                t.current_step = match progress {
                    Some(progress) => {
                        format!("Streaming {} ({}) • {}", tool_name, channel, progress)
                    }
                    None => format!("Streaming {} ({})", tool_name, channel),
                };
            });

            if stream_password_required {
                notifications::record_credential_intervention(
                    app,
                    &thread_id,
                    &session_id,
                    "sudo_password",
                    "A one-time sudo password is required to continue the install.",
                );
                update_task_state(app, |t| {
                    t.phase = crate::models::AgentPhase::Running;
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
                let clarification_kind = match effective_stream_clarification_preset {
                    ClarificationPreset::IdentityLookup => "identity_lookup",
                    ClarificationPreset::InstallLookup => "install_lookup",
                    ClarificationPreset::LaunchLookup => "launch_lookup",
                    ClarificationPreset::IntentClarification => "intent_clarification",
                };
                notifications::record_clarification_intervention(
                    app,
                    &thread_id,
                    &session_id,
                    clarification_kind,
                    stream_clarification_prompt,
                );
                update_task_state(app, |t| {
                    t.phase = crate::models::AgentPhase::Running;
                    t.current_step = stream_clarification_wait_step.to_string();
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

                    let prompt_msg = stream_clarification_prompt.to_string();
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

            emit_coalesced_stream_event(
                &app,
                &thread_id,
                step_index,
                &tool_name,
                &stream_id,
                &channel,
                &stdio.chunk,
                stdio.seq,
                stdio.is_final,
                exit_code,
            );
        }
        Some(WorkloadActivityKind::Lifecycle(lifecycle)) => {
            let display = if workload_id.is_empty() {
                "workload".to_string()
            } else {
                workload_id
            };
            let stream_id = if display == "workload" {
                format!("step-{}", step_index)
            } else {
                display.clone()
            };
            let exit_code = if lifecycle.has_exit_code {
                Some(lifecycle.exit_code)
            } else {
                None
            };
            flush_stream_buffers_for_workload(
                app, &thread_id, step_index, &display, &stream_id, exit_code,
            );
            update_task_state(app, |t| {
                bind_task_session(t, &session_id);
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

#[cfg(test)]
mod tests {
    use super::{should_flush_stream_buffer, stream_progress_excerpt};

    #[test]
    fn stream_progress_excerpt_prefers_last_non_empty_line() {
        let excerpt = stream_progress_excerpt("line one\n\nline two\n")
            .expect("expected stream progress excerpt");
        assert_eq!(excerpt, "line two");
    }

    #[test]
    fn stream_progress_excerpt_truncates_long_lines() {
        let long_line = "a".repeat(200);
        let excerpt =
            stream_progress_excerpt(&long_line).expect("expected stream progress excerpt");
        assert!(excerpt.ends_with("..."));
        assert!(excerpt.len() < long_line.len());
    }

    #[test]
    fn stream_buffer_flushes_on_line_threshold() {
        let mut payload = String::new();
        for idx in 0..8 {
            payload.push_str(&format!("line-{}\n", idx));
        }
        assert!(should_flush_stream_buffer(&payload));
    }
}
