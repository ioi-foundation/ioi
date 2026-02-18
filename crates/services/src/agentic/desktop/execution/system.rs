// Path: crates/services/src/agentic/desktop/execution/system.rs

use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::types::CommandExecution;
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::terminal::{CommandExecutionOptions, ProcessStreamChunk, ProcessStreamObserver};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    KernelEvent, WorkloadActivityEvent, WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt,
    WorkloadReceiptEvent,
};
use serde_json;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct LaunchAttempt {
    command: String,
    args: Vec<String>,
    detach: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SysExecInvocation {
    command: String,
    args: Vec<String>,
    shell_wrapped: bool,
}

const INSTALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const SYS_EXEC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const SYS_EXEC_EXTENDED_TIMEOUT: Duration = Duration::from_secs(600);
const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";
const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER: &str = "[REDACTED_PII]";
const WORKLOAD_RECEIPT_MAX_ARG_LEN: usize = 512;

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn compute_workload_id(
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    command_preview: &str,
) -> String {
    let seed = format!(
        "{}:{}:{}:{}",
        hex::encode(session_id),
        step_index,
        tool_name,
        command_preview
    );
    sha256(seed.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| format!("{}:{}:{}", hex::encode(session_id), step_index, tool_name))
}

fn extract_error_class(error: Option<&str>) -> Option<String> {
    let msg = error?;
    let marker = "ERROR_CLASS=";
    let start = msg.find(marker)?;
    let token = msg[start + marker.len()..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn is_sensitive_key_for_receipt(raw: &str) -> bool {
    let key = raw
        .trim_start_matches('-')
        .trim_matches(|c: char| c == '"' || c == '\'');
    let lower = key.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("passphrase")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("apikey")
        || lower.contains("access_token")
        || lower.contains("access-token")
        || lower.contains("client_secret")
        || lower.contains("client-secret")
        || lower.contains("authorization")
        || lower.contains("bearer")
        || lower == "user"
        || lower == "username"
        || lower == "auth"
}

fn is_sensitive_flag_for_receipt(raw: &str) -> bool {
    matches!(
        raw,
        "--password"
            | "--passwd"
            | "--passphrase"
            | "--token"
            | "--access-token"
            | "--access_token"
            | "--api-key"
            | "--apikey"
            | "--client-secret"
            | "--client_secret"
            | "--secret"
            | "--authorization"
            | "--auth"
            | "--bearer"
            | "--private-key"
            | "--private_key"
            | "--user"
            | "-u"
            | "--data"
            | "--data-raw"
            | "--data-binary"
            | "--form"
            | "-d"
            | "-F"
    )
}

fn redact_authorization_header_value(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let Some(bearer_start) = lower.find("bearer") else {
        return raw.to_string();
    };
    let after_bearer = &raw[bearer_start + "bearer".len()..];
    let mut iter = after_bearer.char_indices();
    let Some((space_idx, _)) = iter.find(|(_, ch)| !ch.is_whitespace()) else {
        return raw.to_string();
    };
    let token_start = bearer_start + "bearer".len() + space_idx;
    format!(
        "{}{}",
        &raw[..token_start],
        WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER
    )
}

fn looks_like_jwt(arg: &str) -> bool {
    let mut parts = arg.split('.');
    let (Some(a), Some(b), Some(c), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let min_segment = 10;
    if a.len() < min_segment || b.len() < min_segment || c.len() < min_segment {
        return false;
    }
    let allowed = |ch: char| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '=';
    a.chars().all(allowed) && b.chars().all(allowed) && c.chars().all(allowed)
}

fn looks_like_known_secret_token(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.contains("sk_live_")
        || lower.contains("sk_test_")
        || lower.contains("sk-proj-")
        || (arg.starts_with("AKIA")
            && arg.len() == 20
            && arg.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn looks_like_long_token(arg: &str) -> bool {
    if arg.len() < 48 || arg.len() > 256 {
        return false;
    }
    if arg.starts_with('-') {
        return false;
    }
    if arg.contains('/') || arg.contains('\\') {
        return false;
    }

    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '=' | '+' | '/')
    };
    arg.chars().all(allowed)
}

fn redact_args_for_receipt(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    let mut header_next = false;

    for arg in args {
        if redact_next {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            redact_next = false;
            continue;
        }
        if header_next {
            let lower = arg.to_ascii_lowercase();
            if lower.contains("authorization:") && lower.contains("bearer") {
                out.push(redact_authorization_header_value(arg));
            } else {
                out.push(arg.to_string());
            }
            header_next = false;
            continue;
        }

        let trimmed = arg.trim();
        if trimmed.is_empty() {
            out.push(String::new());
            continue;
        }

        if trimmed == "--header" || trimmed == "-H" {
            out.push(trimmed.to_string());
            header_next = true;
            continue;
        }

        if is_sensitive_flag_for_receipt(trimmed) {
            out.push(trimmed.to_string());
            redact_next = true;
            continue;
        }

        if trimmed.len() > WORKLOAD_RECEIPT_MAX_ARG_LEN {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            continue;
        }

        if looks_like_known_secret_token(trimmed)
            || looks_like_jwt(trimmed)
            || looks_like_long_token(trimmed)
        {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            continue;
        }

        if let Some((left, right)) = trimmed.split_once('=') {
            if !right.is_empty() && is_sensitive_key_for_receipt(left) {
                out.push(format!(
                    "{}={}",
                    left,
                    WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER
                ));
                continue;
            }
        }

        out.push(trimmed.to_string());
    }

    out
}

async fn scrub_workload_text_field_for_receipt(exec: &ToolExecutor, input: &str) -> String {
    let Some(scrubber) = exec.pii_scrubber.as_ref() else {
        return input.to_string();
    };
    match scrubber.scrub(input).await {
        Ok((scrubbed, _)) => scrubbed,
        Err(_) => WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string(),
    }
}

async fn scrub_workload_args_for_receipt(exec: &ToolExecutor, args: &[String]) -> Vec<String> {
    let redacted = redact_args_for_receipt(args);
    let Some(scrubber) = exec.pii_scrubber.as_ref() else {
        return redacted;
    };

    let mut out = Vec::with_capacity(redacted.len());
    for arg in redacted {
        if arg.is_empty() {
            out.push(arg);
            continue;
        }
        match scrubber.scrub(arg.as_str()).await {
            Ok((scrubbed, _)) => out.push(scrubbed),
            Err(_) => out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string()),
        }
    }
    out
}

fn emit_workload_activity(
    tx: &tokio::sync::broadcast::Sender<KernelEvent>,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    kind: WorkloadActivityKind,
) {
    let _ = tx.send(KernelEvent::WorkloadActivity(WorkloadActivityEvent {
        session_id,
        step_index,
        workload_id,
        timestamp_ms: unix_timestamp_ms_now(),
        kind,
    }));
}

fn emit_workload_receipt(
    tx: &tokio::sync::broadcast::Sender<KernelEvent>,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    receipt: WorkloadReceipt,
) {
    let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
        session_id,
        step_index,
        workload_id,
        timestamp_ms: unix_timestamp_ms_now(),
        receipt,
    }));
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    cwd: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    match tool {
        AgentTool::SysExec {
            command,
            args,
            stdin,
            detach,
        } => {
            let resolved_cwd = match resolve_working_directory(cwd) {
                Ok(path) => path,
                Err(error) => return ToolExecutionResult::failure(error),
            };
            let invocation = match resolve_sys_exec_invocation(&command, &args) {
                Ok(invocation) => invocation,
                Err(error) => return ToolExecutionResult::failure(error),
            };
            let raw_command_preview = command_preview(&command, &args);
            let timeout = resolve_sys_exec_timeout(&invocation.command, &invocation.args, detach);
            let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
            let receipt_command =
                scrub_workload_text_field_for_receipt(exec, invocation.command.as_str()).await;
            let receipt_args =
                scrub_workload_args_for_receipt(exec, invocation.args.as_slice()).await;
            let receipt_cwd =
                scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
            let receipt_preview = command_preview(&receipt_command, &receipt_args);
            let workload_id =
                compute_workload_id(session_id, step_index, "sys__exec", &receipt_preview);
            let observer = if detach {
                None
            } else {
                process_stream_observer(
                    exec,
                    session_id,
                    step_index,
                    "sys__exec",
                    workload_id.clone(),
                    raw_command_preview.clone(),
                )
            };
            if let Some(tx) = exec.event_sender.as_ref() {
                emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: "started".to_string(),
                        exit_code: None,
                    },
                );
            }
            let options = CommandExecutionOptions::default()
                .with_timeout(timeout)
                .with_stdin_data(normalize_stdin_data(stdin))
                .with_stream_observer(observer);

            let result = match exec
                .terminal
                .execute_in_dir_with_options(
                    &invocation.command,
                    &invocation.args,
                    detach,
                    Some(&resolved_cwd),
                    options,
                )
                .await
            {
                Ok(out) => {
                    let command_failed = command_output_indicates_failure(&out);
                    let mut result = if command_failed {
                        let mut failure = sys_exec_failure_result(&command, &out);
                        // Preserve raw output so command-history metadata can be derived without SCS reads.
                        failure.history_entry = Some(out);
                        failure
                    } else {
                        ToolExecutionResult::success(out)
                    };
                    append_sys_exec_command_history(
                        &mut result,
                        &raw_command_preview,
                        step_index,
                        if command_failed { 1 } else { 0 },
                    );
                    result
                }
                Err(e) => {
                    let error = e.to_string();
                    let mut result = sys_exec_failure_result(&command, &error);
                    // Preserve raw output so command-history metadata can be derived without SCS reads.
                    result.history_entry = Some(error);
                    append_sys_exec_command_history(&mut result, &raw_command_preview, step_index, 1);
                    result
                }
            };

            if let Some(tx) = exec.event_sender.as_ref() {
                let exit_code = result
                    .history_entry
                    .as_deref()
                    .and_then(extract_exit_code)
                    .or_else(|| result.error.as_deref().and_then(extract_exit_code));
                let phase = if detach {
                    "detached"
                } else if result.success {
                    "completed"
                } else {
                    "failed"
                };
                emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: phase.to_string(),
                        exit_code,
                    },
                );
                emit_workload_receipt(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadReceipt::Exec(WorkloadExecReceipt {
                        tool_name: "sys__exec".to_string(),
                        command: receipt_command,
                        args: receipt_args,
                        cwd: receipt_cwd,
                        detach,
                        timeout_ms: timeout.as_millis() as u64,
                        success: result.success,
                        exit_code,
                        error_class: extract_error_class(result.error.as_deref()),
                        command_preview: receipt_preview,
                    }),
                );
            }

            result
        }

        AgentTool::SysExecSession {
            command,
            args,
            stdin,
        } => {
            let resolved_cwd = match resolve_working_directory(cwd) {
                Ok(path) => path,
                Err(error) => return ToolExecutionResult::failure(error),
            };

            let trimmed = command.trim();
            if trimmed.is_empty() {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=ToolUnavailable sys__exec_session requires a non-empty command."
                        .to_string(),
                );
            }

            let raw_command_preview = command_preview(&command, &args);
            let timeout = resolve_sys_exec_timeout(trimmed, &args, false);
            let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
            let receipt_command = scrub_workload_text_field_for_receipt(exec, trimmed).await;
            let receipt_args = scrub_workload_args_for_receipt(exec, &args).await;
            let receipt_cwd =
                scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
            let receipt_preview = command_preview(&receipt_command, &receipt_args);
            let workload_id = compute_workload_id(
                session_id,
                step_index,
                "sys__exec_session",
                &receipt_preview,
            );
            let observer = process_stream_observer(
                exec,
                session_id,
                step_index,
                "sys__exec_session",
                workload_id.clone(),
                raw_command_preview.clone(),
            );
            let options = CommandExecutionOptions::default()
                .with_timeout(timeout)
                .with_stdin_data(normalize_stdin_data(stdin))
                .with_stream_observer(observer);

            let session_key = hex::encode(session_id);

            if let Some(tx) = exec.event_sender.as_ref() {
                emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: "started".to_string(),
                        exit_code: None,
                    },
                );
            }

            let result = match exec
                .terminal
                .execute_session_in_dir_with_options(
                    &session_key,
                    trimmed,
                    &args,
                    Some(&resolved_cwd),
                    options,
                )
                .await
            {
                Ok(out) => {
                    let command_failed = command_output_indicates_failure(&out);
                    let mut result = if command_failed {
                        let mut failure = sys_exec_failure_result(&command, &out);
                        failure.history_entry = Some(out);
                        failure
                    } else {
                        ToolExecutionResult::success(out)
                    };
                    append_sys_exec_command_history(
                        &mut result,
                        &raw_command_preview,
                        step_index,
                        if command_failed { 1 } else { 0 },
                    );
                    result
                }
                Err(e) => {
                    let error = e.to_string();
                    let mut result = sys_exec_failure_result(&command, &error);
                    result.history_entry = Some(error);
                    append_sys_exec_command_history(&mut result, &raw_command_preview, step_index, 1);
                    result
                }
            };

            if let Some(tx) = exec.event_sender.as_ref() {
                let exit_code = result
                    .history_entry
                    .as_deref()
                    .and_then(extract_exit_code)
                    .or_else(|| result.error.as_deref().and_then(extract_exit_code));
                let phase = if result.success { "completed" } else { "failed" };
                emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: phase.to_string(),
                        exit_code,
                    },
                );
                emit_workload_receipt(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadReceipt::Exec(WorkloadExecReceipt {
                        tool_name: "sys__exec_session".to_string(),
                        command: receipt_command,
                        args: receipt_args,
                        cwd: receipt_cwd,
                        detach: false,
                        timeout_ms: timeout.as_millis() as u64,
                        success: result.success,
                        exit_code,
                        error_class: extract_error_class(result.error.as_deref()),
                        command_preview: receipt_preview,
                    }),
                );
            }

            result
        }

        AgentTool::SysExecSessionReset {} => {
            let session_key = hex::encode(session_id);
            match exec.terminal.reset_session(&session_key).await {
                Ok(()) => ToolExecutionResult::success("Reset persistent shell session."),
                Err(e) => ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=UnexpectedState Failed to reset persistent shell session: {}",
                    e
                )),
            }
        }

        AgentTool::SysChangeDir { path } => match resolve_target_directory(cwd, &path) {
            Ok(path) => ToolExecutionResult::success(path.to_string_lossy().to_string()),
            Err(error) => ToolExecutionResult::failure(error),
        },

        AgentTool::SysInstallPackage { package, manager } => {
            handle_install_package(
                exec,
                cwd,
                &package,
                manager.as_deref(),
                session_id,
                step_index,
            )
            .await
        }

        AgentTool::OsLaunchApp { app_name } => {
            let attempts = if cfg!(target_os = "macos") {
                vec![LaunchAttempt {
                    command: "open".to_string(),
                    args: vec!["-a".to_string(), app_name.clone()],
                    detach: true,
                }]
            } else if cfg!(target_os = "windows") {
                build_windows_launch_plan(&app_name)
            } else {
                build_linux_launch_plan(&app_name, is_command_available("gtk-launch"))
            };

            if attempts.is_empty() {
                return ToolExecutionResult::failure(format!(
                    "Failed to launch {}: no launch strategy available",
                    app_name
                ));
            }

            let mut errors = Vec::new();
            for attempt in &attempts {
                match exec
                    .terminal
                    .execute(&attempt.command, &attempt.args, attempt.detach)
                    .await
                {
                    Ok(output) => {
                        if launch_attempt_failed(attempt, &output) {
                            errors.push(format!(
                                "{} (non-zero exit: {})",
                                format_attempt(attempt),
                                summarize_command_output(&output)
                            ));
                            continue;
                        }
                        return ToolExecutionResult::success(format!(
                            "Launched {} via {}",
                            app_name,
                            format_attempt(attempt)
                        ));
                    }
                    Err(e) => errors.push(format!("{} ({})", format_attempt(attempt), e)),
                }
            }

            let base_error = format!(
                "Failed to launch {} after {} attempt(s): {}",
                app_name,
                attempts.len(),
                errors.join(" | ")
            );
            if launch_errors_indicate_missing_app(&errors) {
                ToolExecutionResult::failure(format!("ERROR_CLASS=ToolUnavailable {}", base_error))
            } else {
                ToolExecutionResult::failure(base_error)
            }
        }

        _ => ToolExecutionResult::failure("Unsupported System action"),
    }
}

fn command_preview(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    let joined = args.join(" ");
    let preview = format!("{} {}", command, joined);
    let mut chars = preview.chars();
    let preview_truncated: String = chars.by_ref().take(220).collect();
    if chars.next().is_some() {
        format!("{}...", preview_truncated)
    } else {
        preview
    }
}

fn append_sys_exec_command_history(
    result: &mut ToolExecutionResult,
    command: &str,
    step_index: u32,
    fallback_exit_code: i32,
) {
    let Some(mut output) = result.history_entry.take() else {
        return;
    };
    if output.trim().is_empty() {
        result.history_entry = Some(output);
        return;
    }

    let exit_code = extract_exit_code(&output).unwrap_or(fallback_exit_code);
    let (stdout, stderr) = parse_terminal_output(&output);
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis() as u64)
        .unwrap_or(0);

    let payload = CommandExecution {
        command: command.to_string(),
        exit_code,
        stdout,
        stderr,
        timestamp_ms,
        step_index,
    };

    if let Ok(metadata) = serde_json::to_string(&payload) {
        let prefixed = format!("{}{}", COMMAND_HISTORY_PREFIX, metadata);
        output.insert_str(0, "\n");
        output.insert_str(0, &prefixed);
    }
    result.history_entry = Some(output);
}

fn extract_exit_code(output: &str) -> Option<i32> {
    output.lines().find_map(|line| {
        line.split_once("exit status:").and_then(|(_, status)| {
            status
                .split_whitespace()
                .next()
                .and_then(|raw_status| raw_status.parse::<i32>().ok())
        })
    })
}

fn parse_terminal_output(output: &str) -> (String, String) {
    if let Some((stdout, stderr)) = output.split_once("Stderr:") {
        (stdout.trim().to_string(), stderr.trim().to_string())
    } else {
        (output.trim().to_string(), String::new())
    }
}

fn normalize_stdin_data(stdin: Option<String>) -> Option<Vec<u8>> {
    stdin
        .map(|value| value.into_bytes())
        .filter(|bytes| !bytes.is_empty())
}

fn resolve_sys_exec_invocation(
    command: &str,
    args: &[String],
) -> Result<SysExecInvocation, String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("ERROR_CLASS=ToolUnavailable sys__exec requires a non-empty command.".into());
    }

    if should_shell_wrap_sys_exec(trimmed) {
        let shell_command = if cfg!(target_os = "windows") {
            build_cmd_wrapped_command_line(trimmed, args)
        } else {
            build_shell_wrapped_command_line(trimmed, args)
        };
        return Ok(wrap_sys_exec_with_shell(&shell_command));
    }

    if !args.is_empty() {
        let inline_tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if inline_tokens.len() > 1 && should_merge_inline_sys_exec_tokens(inline_tokens[0]) {
            let mut merged_args: Vec<String> = inline_tokens[1..]
                .iter()
                .map(|token| (*token).to_string())
                .collect();
            merged_args.extend(args.iter().cloned());
            return Ok(SysExecInvocation {
                command: inline_tokens[0].to_string(),
                args: merged_args,
                shell_wrapped: false,
            });
        }

        return Ok(SysExecInvocation {
            command: trimmed.to_string(),
            args: args.to_vec(),
            shell_wrapped: false,
        });
    }

    let mut tokens = trimmed.split_whitespace();
    let binary = tokens.next().ok_or_else(|| {
        "ERROR_CLASS=ToolUnavailable sys__exec requires a non-empty command.".to_string()
    })?;

    Ok(SysExecInvocation {
        command: binary.to_string(),
        args: tokens.map(|token| token.to_string()).collect(),
        shell_wrapped: false,
    })
}

fn should_merge_inline_sys_exec_tokens(first_token: &str) -> bool {
    // Heuristic: allow "git show" + explicit args, but do not break paths with spaces such as:
    // "C:\Program Files\Git\bin\git.exe" + ["status"].
    //
    // If callers truly want inline shell parsing, they should include a shell token (e.g. "&&")
    // or explicit quoting, which routes through `should_shell_wrap_sys_exec`.
    let token = first_token.trim();
    if token.is_empty() {
        return false;
    }

    // Path-like tokens (unix path, windows path, or drive-prefixed) should be preserved verbatim.
    !(token.contains('/') || token.contains('\\') || token.contains(':'))
}

fn should_shell_wrap_sys_exec(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return false;
    }

    if starts_with_shell_builtin(trimmed) || starts_with_env_assignment_prefix(trimmed) {
        return true;
    }

    let shell_tokens = ["&&", "||", "|", ";", ">", "<", "$(", "`", "\n", "\r"];
    if shell_tokens
        .iter()
        .any(|token| !token.is_empty() && trimmed.contains(token))
    {
        return true;
    }

    trimmed.contains('"')
        || trimmed.contains('\'')
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('{')
        || trimmed.contains('}')
}

fn starts_with_shell_builtin(command: &str) -> bool {
    let Some(first_token) = command.split_whitespace().next() else {
        return false;
    };

    let token = first_token.to_ascii_lowercase();
    matches!(
        token.as_str(),
        "." | "cd" | "source" | "export" | "unset" | "alias" | "unalias" | "pushd" | "popd"
    )
}

fn starts_with_env_assignment_prefix(command: &str) -> bool {
    if cfg!(target_os = "windows") {
        return false;
    }

    let mut saw_assignment = false;
    for token in command.split_whitespace() {
        if is_env_assignment_token(token) {
            saw_assignment = true;
            continue;
        }
        break;
    }

    saw_assignment
}

fn is_env_assignment_token(token: &str) -> bool {
    let Some((name, _value)) = token.split_once('=') else {
        return false;
    };

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn build_shell_wrapped_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }

    let mut out = String::from(command);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_shell_argument(arg));
    }
    out
}

fn quote_shell_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@'))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

fn resolve_windows_comspec_path() -> String {
    env::var("COMSPEC")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .filter(|value| Path::new(value).is_file())
        .unwrap_or_else(|| "cmd.exe".to_string())
}

fn build_cmd_wrapped_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        // Allow compound commands ("echo hi", "dir && echo ok") to behave like unix shell wrapping.
        // The caller can include quotes in `command` when needed (for paths with spaces).
        return command.to_string();
    }

    let mut out = String::from(command);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_cmd_argument(arg));
    }
    out
}

fn quote_cmd_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }

    let safe = arg.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '_' | '-' | '.' | '\\' | '/' | ':' | '@' | '+' | '=')
    });
    if safe {
        return arg.to_string();
    }

    // Minimal quoting: wrap in double quotes and escape embedded quotes for cmd parsing.
    let escaped = arg.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn wrap_sys_exec_with_shell(command: &str) -> SysExecInvocation {
    if cfg!(target_os = "windows") {
        let comspec = resolve_windows_comspec_path();
        return SysExecInvocation {
            command: comspec,
            // Prefer cmd.exe for shell-wrapped execution to avoid PowerShell version skew
            // (e.g. Windows PowerShell 5.1 lacks `&&`).
            args: vec![
                "/Q".to_string(),
                "/D".to_string(),
                "/C".to_string(),
                command.to_string(),
            ],
            shell_wrapped: true,
        };
    }

    let shell = env::var("SHELL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .filter(|value| Path::new(value).is_file())
        .unwrap_or_else(|| "/bin/sh".to_string());

    SysExecInvocation {
        command: shell,
        args: vec!["-lc".to_string(), command.to_string()],
        shell_wrapped: true,
    }
}

fn resolve_sys_exec_timeout(command: &str, args: &[String], detach: bool) -> Duration {
    if detach {
        return SYS_EXEC_DEFAULT_TIMEOUT;
    }

    let command_lc = command.trim().to_ascii_lowercase();
    if command_lc.is_empty() {
        return SYS_EXEC_DEFAULT_TIMEOUT;
    }

    if is_extended_timeout_command(command_lc.as_str())
        || args
            .iter()
            .any(|arg| is_extended_timeout_arg(arg.trim().to_ascii_lowercase().as_str()))
    {
        return SYS_EXEC_EXTENDED_TIMEOUT;
    }

    SYS_EXEC_DEFAULT_TIMEOUT
}

fn is_extended_timeout_command(command: &str) -> bool {
    matches!(
        command,
        "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "pwsh"
            | "powershell"
            | "cmd"
            | "cmd.exe"
            | "cargo"
            | "npm"
            | "pnpm"
            | "yarn"
            | "python"
            | "python3"
            | "node"
            | "go"
            | "gradle"
            | "mvn"
            | "make"
            | "cmake"
            | "docker"
            | "podman"
    )
}

fn is_extended_timeout_arg(arg: &str) -> bool {
    matches!(
        arg,
        "build"
            | "check"
            | "test"
            | "bench"
            | "run"
            | "install"
            | "update"
            | "upgrade"
            | "compile"
            | "clippy"
            | "watch"
            | "serve"
            | "dev"
            | "clone"
            | "fetch"
            | "pull"
    )
}

fn process_stream_observer(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    workload_id: String,
    command_preview: String,
) -> Option<ProcessStreamObserver> {
    let tx = exec.event_sender.clone()?;
    let tool_name = tool_name.to_string();
    let stream_id = workload_id.clone();

    Some(Arc::new(move |chunk: ProcessStreamChunk| {
        let channel = chunk.channel.as_str().to_string();
        let chunk_payload = chunk.chunk;
        let _ = tx.send(KernelEvent::ProcessActivity {
            session_id,
            step_index,
            tool_name: tool_name.clone(),
            stream_id: stream_id.clone(),
            channel: channel.clone(),
            chunk: chunk_payload.clone(),
            seq: chunk.seq,
            is_final: chunk.is_final,
            exit_code: chunk.exit_code,
            command_preview: command_preview.clone(),
        });
        emit_workload_activity(
            &tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Stdio {
                stream: channel,
                chunk: chunk_payload,
                seq: chunk.seq,
                is_final: chunk.is_final,
                exit_code: chunk.exit_code,
            },
        );
    }))
}

async fn handle_install_package(
    exec: &ToolExecutor,
    cwd: &str,
    package: &str,
    manager: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    let resolved_cwd = match resolve_working_directory(cwd) {
        Ok(path) => path,
        Err(error) => return ToolExecutionResult::failure(error),
    };

    let trimmed = package.trim();
    if trimmed.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=MissingDependency Package name cannot be empty.".to_string(),
        );
    }

    let manager = normalize_install_manager(manager);
    let mut stdin_data: Option<Vec<u8>> = None;
    let mut used_runtime_password = false;
    let (command, mut args): (&str, Vec<String>) = match manager.as_str() {
        "apt-get" => (
            "sudo",
            vec![
                "-n".to_string(),
                "apt-get".to_string(),
                "install".to_string(),
                "-y".to_string(),
                trimmed.to_string(),
            ],
        ),
        "brew" => ("brew", vec!["install".to_string(), trimmed.to_string()]),
        "pip" => (
            "python",
            vec![
                "-m".to_string(),
                "pip".to_string(),
                "install".to_string(),
                trimmed.to_string(),
            ],
        ),
        "npm" => (
            "npm",
            vec!["install".to_string(), "-g".to_string(), trimmed.to_string()],
        ),
        "pnpm" => (
            "pnpm",
            vec!["add".to_string(), "-g".to_string(), trimmed.to_string()],
        ),
        "cargo" => ("cargo", vec!["install".to_string(), trimmed.to_string()]),
        "winget" => (
            "winget",
            vec![
                "install".to_string(),
                "--id".to_string(),
                trimmed.to_string(),
                "--silent".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
        ),
        "choco" => (
            "choco",
            vec!["install".to_string(), trimmed.to_string(), "-y".to_string()],
        ),
        "yum" => (
            "sudo",
            vec![
                "-n".to_string(),
                "yum".to_string(),
                "install".to_string(),
                "-y".to_string(),
                trimmed.to_string(),
            ],
        ),
        "dnf" => (
            "sudo",
            vec![
                "-n".to_string(),
                "dnf".to_string(),
                "install".to_string(),
                "-y".to_string(),
                trimmed.to_string(),
            ],
        ),
        _ => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=ToolUnavailable Unsupported package manager '{}'.",
                manager
            ));
        }
    };

    if matches!(manager.as_str(), "apt-get" | "yum" | "dnf") {
        let session_id_hex = hex::encode(session_id);
        if let Some(secret) =
            runtime_secret::take_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD)
        {
            used_runtime_password = true;
            args = vec![
                "-S".to_string(),
                "-k".to_string(),
                manager.clone(),
                "install".to_string(),
                "-y".to_string(),
                trimmed.to_string(),
            ];
            stdin_data = Some(format!("{}\n", secret).into_bytes());
        }
    }

    let cmd_preview = command_preview(command, &args);
    let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
    let receipt_command = scrub_workload_text_field_for_receipt(exec, command).await;
    let receipt_args = scrub_workload_args_for_receipt(exec, &args).await;
    let receipt_cwd =
        scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
    let receipt_preview = command_preview(&receipt_command, &receipt_args);
    let workload_id =
        compute_workload_id(session_id, step_index, "sys__install_package", &receipt_preview);
    if let Some(tx) = exec.event_sender.as_ref() {
        emit_workload_activity(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Lifecycle {
                phase: "started".to_string(),
                exit_code: None,
            },
        );
    }

    let options = CommandExecutionOptions::default()
        .with_timeout(INSTALL_COMMAND_TIMEOUT)
        .with_stdin_data(stdin_data)
        .with_stream_observer(process_stream_observer(
            exec,
            session_id,
            step_index,
            "sys__install_package",
            workload_id.clone(),
            cmd_preview.clone(),
        ));

    let result = match exec
        .terminal
        .execute_in_dir_with_options(command, &args, false, Some(&resolved_cwd), options)
        .await
    {
        Ok(output) => {
            if command_output_indicates_failure(&output) {
                let class = classify_install_failure(output.as_str(), command, &manager);
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS={} Failed to install '{}' via '{}': {}",
                    class,
                    trimmed,
                    manager,
                    summarize_install_failure_output(&output)
                ))
            } else {
                let mode_note = if used_runtime_password {
                    "sudo-password"
                } else {
                    command
                };
                ToolExecutionResult::success(format!(
                    "Installed '{}' via '{}' ({})",
                    trimmed, manager, mode_note
                ))
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let class = classify_install_failure(msg.as_str(), command, &manager);
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS={} Failed to install '{}' via '{}': {}",
                class, trimmed, manager, msg
            ))
        }
    };

    if let Some(tx) = exec.event_sender.as_ref() {
        let exit_code = result
            .history_entry
            .as_deref()
            .and_then(extract_exit_code)
            .or_else(|| result.error.as_deref().and_then(extract_exit_code));
        let phase = if result.success { "completed" } else { "failed" };
        emit_workload_activity(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Lifecycle {
                phase: phase.to_string(),
                exit_code,
            },
        );
        emit_workload_receipt(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "sys__install_package".to_string(),
                command: receipt_command,
                args: receipt_args,
                cwd: receipt_cwd,
                detach: false,
                timeout_ms: INSTALL_COMMAND_TIMEOUT.as_millis() as u64,
                success: result.success,
                exit_code,
                error_class: extract_error_class(result.error.as_deref()),
                command_preview: receipt_preview,
            }),
        );
    }

    result
}

fn default_install_manager() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew"
    } else if cfg!(target_os = "windows") {
        "winget"
    } else {
        "apt-get"
    }
}

fn normalize_install_manager(raw: Option<&str>) -> String {
    let manager = raw
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| default_install_manager().to_string());
    match manager.as_str() {
        "apt" | "apt-get" => "apt-get".to_string(),
        "brew" => "brew".to_string(),
        "pip" | "pip3" => "pip".to_string(),
        "npm" => "npm".to_string(),
        "pnpm" => "pnpm".to_string(),
        "cargo" => "cargo".to_string(),
        "winget" => "winget".to_string(),
        "choco" | "chocolatey" => "choco".to_string(),
        "yum" => "yum".to_string(),
        "dnf" => "dnf".to_string(),
        _ => manager,
    }
}

fn classify_install_failure(error: &str, command: &str, manager: &str) -> &'static str {
    let msg = error.to_ascii_lowercase();

    if msg.contains("timed out") || msg.contains("timeout") {
        return "TimeoutOrHang";
    }

    // Prefer deterministic package lookup failures over incidental sudo text.
    // Some environments can surface both in a single stderr stream.
    if is_install_package_lookup_error(error) {
        return "MissingDependency";
    }

    if is_sudo_password_required_install_error(error) || msg.contains("permission denied") {
        return "PermissionOrApprovalRequired";
    }

    if msg.contains("no such file")
        || msg.contains("not found")
        || msg.contains("failed to spawn")
        || msg.contains("command not found")
    {
        if msg.contains(command) || msg.contains(manager) {
            return "ToolUnavailable";
        }
    }

    "UnexpectedState"
}

pub(crate) fn is_install_package_lookup_error(error: &str) -> bool {
    let msg = error.to_ascii_lowercase();
    msg.contains("unable to locate package")
        || msg.contains("no package")
        || msg.contains("could not find")
        || msg.contains("has no installation candidate")
        || msg.contains("no match for argument")
        || msg.contains("cannot find a package")
}

pub(crate) fn is_sudo_password_required_install_error(error: &str) -> bool {
    if is_install_package_lookup_error(error) {
        return false;
    }
    let msg = error.to_ascii_lowercase();
    msg.contains("sudo:")
        || msg.contains("a password is required")
        || msg.contains("not in the sudoers")
        || msg.contains("requires elevated privileges")
        || msg.contains("incorrect password")
        || msg.contains("sorry, try again")
        || msg.contains("error_class=permissionorapprovalrequired")
}

fn resolve_home_directory() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }

    if let Some(user_profile) = env::var_os("USERPROFILE") {
        if !user_profile.is_empty() {
            return Ok(PathBuf::from(user_profile));
        }
    }

    if let (Some(home_drive), Some(home_path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        if !home_drive.is_empty() && !home_path.is_empty() {
            let mut combined = PathBuf::from(home_drive);
            combined.push(home_path);
            return Ok(combined);
        }
    }

    Err("Home directory is not configured (HOME/USERPROFILE).".to_string())
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        return resolve_home_directory();
    }

    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Ok(resolve_home_directory()?.join(remainder));
    }

    Ok(PathBuf::from(path))
}

fn resolve_working_directory(cwd: &str) -> Result<PathBuf, String> {
    let normalized = cwd.trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        expand_tilde_path(normalized)?
    };

    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        env::current_dir()
            .map_err(|e| format!("Failed to resolve current directory: {}", e))?
            .join(candidate)
    };

    if !absolute.exists() {
        return Err(format!(
            "Working directory '{}' does not exist.",
            absolute.display()
        ));
    }

    if !absolute.is_dir() {
        return Err(format!(
            "Working directory '{}' is not a directory.",
            absolute.display()
        ));
    }

    Ok(absolute)
}

fn resolve_target_directory(current_cwd: &str, requested_path: &str) -> Result<PathBuf, String> {
    let trimmed = requested_path.trim();
    if trimmed.is_empty() {
        return Err("Target path cannot be empty.".to_string());
    }

    let requested = expand_tilde_path(trimmed)?;
    let candidate = if requested.is_absolute() {
        requested
    } else {
        resolve_working_directory(current_cwd)?.join(requested)
    };

    let canonical = std::fs::canonicalize(&candidate).map_err(|e| {
        format!(
            "Failed to resolve directory '{}': {}",
            candidate.display(),
            e
        )
    })?;

    if !canonical.is_dir() {
        return Err(format!("'{}' is not a directory.", canonical.display()));
    }

    Ok(canonical)
}

fn quote_powershell_single_quoted_string(value: &str) -> String {
    // Treat CRLF as a single separator to avoid producing double spaces.
    let without_crlf = value.replace("\r\n", " ");
    let sanitized = without_crlf
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect::<String>();
    let trimmed = sanitized.trim();
    format!("'{}'", trimmed.replace('\'', "''"))
}

fn build_windows_launch_plan(app_name: &str) -> Vec<LaunchAttempt> {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Use single-quoted PowerShell string literal with correct escaping of apostrophes.
    let file_path = quote_powershell_single_quoted_string(trimmed);
    let command = format!("Start-Process -FilePath {}", file_path);

    vec![LaunchAttempt {
        command: "powershell".to_string(),
        args: vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            command,
        ],
        detach: true,
    }]
}

fn build_linux_launch_plan(app_name: &str, has_gtk_launch: bool) -> Vec<LaunchAttempt> {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut attempts = Vec::new();
    let mut desktop_ids = Vec::new();
    let mut binaries = Vec::new();

    let slug_dash = slugify(trimmed, '-');
    let slug_underscore = slugify(trimmed, '_');
    let trimmed_lower = trimmed.to_lowercase();

    // Candidate IDs for desktop launchers.
    for candidate in [
        trimmed,
        trimmed_lower.as_str(),
        slug_dash.as_str(),
        slug_underscore.as_str(),
    ] {
        if !candidate.is_empty() {
            push_unique(&mut desktop_ids, candidate);
            if !candidate.ends_with(".desktop") {
                push_unique(&mut desktop_ids, format!("{}.desktop", candidate));
            }
        }
    }

    // Candidate binaries for direct spawning.
    if trimmed.contains('/') {
        push_unique(&mut binaries, trimmed);
    }
    for candidate in [
        trimmed_lower.as_str(),
        slug_dash.as_str(),
        slug_underscore.as_str(),
    ] {
        if !candidate.is_empty() && !candidate.contains(' ') {
            push_unique(&mut binaries, candidate);
        }
    }

    if has_gtk_launch {
        for desktop_id in desktop_ids {
            attempts.push(LaunchAttempt {
                command: "gtk-launch".to_string(),
                args: vec![desktop_id],
                // Keep blocking so we can detect launcher failures and fall through.
                detach: false,
            });
        }
    }

    for binary in binaries {
        attempts.push(LaunchAttempt {
            command: binary,
            args: Vec::new(),
            detach: true,
        });
    }

    attempts
}

fn push_unique(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if value.is_empty() {
        return;
    }
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn slugify(input: &str, separator: char) -> String {
    input
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(&separator.to_string())
}

fn is_command_available(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }

    if command.contains('/') {
        return Path::new(command).is_file();
    }

    let Some(paths) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&paths).any(|path_dir| path_dir.join(command).is_file())
}

fn format_attempt(attempt: &LaunchAttempt) -> String {
    if attempt.args.is_empty() {
        attempt.command.clone()
    } else {
        format!("{} {}", attempt.command, attempt.args.join(" "))
    }
}

fn launch_attempt_failed(attempt: &LaunchAttempt, output: &str) -> bool {
    // Detached launches only confirm process spawn. For blocking launches, a
    // non-zero exit is surfaced by TerminalDriver as "Command failed: ...".
    !attempt.detach && command_output_indicates_failure(output)
}

fn command_output_indicates_failure(output: &str) -> bool {
    output
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("command failed:")
}

fn classify_sys_exec_failure(error: &str, command: &str) -> &'static str {
    let msg = error.to_ascii_lowercase();
    let command_lc = command
        .split_whitespace()
        .next()
        .map(|token| token.trim_matches(|ch| ch == '"' || ch == '\''))
        .unwrap_or(command)
        .to_ascii_lowercase();

    if msg.contains("timed out") || msg.contains("timeout") {
        return "TimeoutOrHang";
    }

    if msg.contains("permission denied")
        || msg.contains("a password is required")
        || msg.contains("not in the sudoers")
        || msg.contains("requires elevated privileges")
        || msg.contains("operation not permitted")
        || msg.contains("error_class=permissionorapprovalrequired")
        || (command_lc == "sudo" && msg.contains("sudo:"))
    {
        return "PermissionOrApprovalRequired";
    }

    if msg.contains("command not found")
        || msg.contains("is not recognized as an internal or external command")
        || msg.contains("not recognized as the name of a cmdlet")
    {
        return "ToolUnavailable";
    }

    if msg.contains("failed to spawn")
        || msg.contains("no such file")
        || msg.contains("command not found")
        || msg.contains("not found")
    {
        if !command_lc.is_empty() && (msg.contains(&command_lc) || msg.contains("executable")) {
            return "ToolUnavailable";
        }
    }

    "UnexpectedState"
}

fn summarize_sys_exec_failure_output(output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return "unknown error".to_string();
    }
    let stderr_or_full = trimmed
        .split_once("Stderr:")
        .map(|(_, stderr)| stderr.trim())
        .unwrap_or(trimmed);
    let compact = stderr_or_full
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return "unknown error".to_string();
    }
    let max_chars = 480;
    let compact_chars = compact.chars().count();
    if compact_chars > max_chars {
        let truncated = compact.chars().take(max_chars).collect::<String>();
        format!("{}...", truncated)
    } else {
        compact
    }
}

fn sys_exec_failure_result(command: &str, error: &str) -> ToolExecutionResult {
    let class = classify_sys_exec_failure(error, command);
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS={} sys__exec '{}' failed: {}",
        class,
        command,
        summarize_sys_exec_failure_output(error)
    ))
}

fn summarize_command_output(output: &str) -> String {
    output
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .unwrap_or("unknown error")
        .to_string()
}

fn summarize_install_failure_output(output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return "unknown error".to_string();
    }
    let stderr_or_full = trimmed
        .split_once("Stderr:")
        .map(|(_, stderr)| stderr.trim())
        .unwrap_or(trimmed);
    let compact = stderr_or_full
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return summarize_command_output(trimmed);
    }
    let max_chars = 480;
    let compact_chars = compact.chars().count();
    if compact_chars > max_chars {
        let truncated = compact.chars().take(max_chars).collect::<String>();
        format!("{}...", truncated)
    } else {
        compact
    }
}

fn launch_errors_indicate_missing_app(errors: &[String]) -> bool {
    if errors.is_empty() {
        return false;
    }

    errors.iter().any(|error| {
        let msg = error.to_ascii_lowercase();
        msg.contains("no such file")
            || msg.contains("not found")
            || msg.contains("failed to spawn")
            || msg.contains("unable to locate")
            || msg.contains("cannot find")
            || (msg.contains("gtk-launch") && msg.contains("non-zero exit"))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        append_sys_exec_command_history, build_linux_launch_plan, classify_install_failure,
        classify_sys_exec_failure, command_output_indicates_failure, extract_exit_code,
        launch_attempt_failed, launch_errors_indicate_missing_app, normalize_stdin_data,
        parse_terminal_output, quote_powershell_single_quoted_string, resolve_home_directory,
        resolve_sys_exec_invocation,
        resolve_sys_exec_timeout, resolve_target_directory, resolve_working_directory,
        summarize_sys_exec_failure_output, sys_exec_failure_result, CommandExecution,
        LaunchAttempt, ToolExecutionResult, COMMAND_HISTORY_PREFIX, SYS_EXEC_DEFAULT_TIMEOUT,
        SYS_EXEC_EXTENDED_TIMEOUT, WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER, redact_args_for_receipt,
    };

    #[test]
    fn powershell_single_quoted_string_escapes_apostrophes() {
        assert_eq!(
            quote_powershell_single_quoted_string("O'Reilly"),
            "'O''Reilly'"
        );
    }

    #[test]
    fn powershell_single_quoted_string_strips_newlines() {
        assert_eq!(quote_powershell_single_quoted_string("a\r\nb"), "'a b'");
    }

    #[test]
    fn sys_exec_timeout_defaults_for_simple_commands() {
        let timeout = resolve_sys_exec_timeout("ls", &["-la".to_string()], false);
        assert_eq!(timeout, SYS_EXEC_DEFAULT_TIMEOUT);
    }

    #[test]
    fn sys_exec_timeout_extends_for_shell_wrappers() {
        let timeout = resolve_sys_exec_timeout(
            "bash",
            &["-lc".to_string(), "cargo test".to_string()],
            false,
        );
        assert_eq!(timeout, SYS_EXEC_EXTENDED_TIMEOUT);
    }

    #[test]
    fn sys_exec_timeout_extends_for_build_subcommands() {
        let timeout = resolve_sys_exec_timeout("git", &["clone".to_string()], false);
        assert_eq!(timeout, SYS_EXEC_EXTENDED_TIMEOUT);
    }

    #[test]
    fn sys_exec_invocation_preserves_explicit_args() {
        let args = vec!["status".to_string(), "--short".to_string()];
        let invocation =
            resolve_sys_exec_invocation("git", &args).expect("invocation should normalize");

        assert_eq!(invocation.command, "git");
        assert_eq!(invocation.args, args);
        assert!(!invocation.shell_wrapped);
    }

    #[test]
    fn sys_exec_invocation_merges_inline_tokens_with_explicit_args() {
        let args = vec!["HEAD~1".to_string()];
        let invocation = resolve_sys_exec_invocation("git show", &args)
            .expect("inline command tokens should merge with explicit args");

        assert_eq!(invocation.command, "git");
        assert_eq!(
            invocation.args,
            vec!["show".to_string(), "HEAD~1".to_string()]
        );
        assert!(!invocation.shell_wrapped);
    }

    #[test]
    fn sys_exec_invocation_preserves_windows_style_paths_with_spaces_when_args_present() {
        let command = r"C:\Program Files\Git\bin\git.exe";
        let args = vec!["--version".to_string()];
        let invocation = resolve_sys_exec_invocation(command, &args)
            .expect("paths with spaces should not be split into inline tokens");

        assert_eq!(invocation.command, command);
        assert_eq!(invocation.args, args);
        assert!(!invocation.shell_wrapped);
    }

    #[test]
    fn sys_exec_invocation_splits_plain_command_string() {
        let invocation = resolve_sys_exec_invocation("git status --short", &[])
            .expect("plain command string should split");

        assert_eq!(invocation.command, "git");
        assert_eq!(
            invocation.args,
            vec!["status".to_string(), "--short".to_string()]
        );
        assert!(!invocation.shell_wrapped);
    }

    #[test]
    fn sys_exec_invocation_shell_wraps_pipeline_syntax() {
        let invocation = resolve_sys_exec_invocation("cat Cargo.toml | head -n 1", &[])
            .expect("pipeline syntax should wrap via shell");

        assert!(invocation.shell_wrapped);
        if cfg!(target_os = "windows") {
            assert!(invocation
                .command
                .to_ascii_lowercase()
                .ends_with("cmd.exe"));
            assert!(invocation.args.iter().any(|arg| arg == "/C"));
        } else {
            assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
        }
    }

    #[test]
    fn sys_exec_invocation_shell_wraps_builtins_with_explicit_args() {
        let args = vec!["/tmp/my project".to_string()];
        let invocation =
            resolve_sys_exec_invocation("cd", &args).expect("shell builtins should wrap");

        assert!(invocation.shell_wrapped);
        if cfg!(target_os = "windows") {
            assert!(invocation
                .command
                .to_ascii_lowercase()
                .ends_with("cmd.exe"));
            assert!(invocation.args.iter().any(|arg| arg == "/C"));
        } else {
            assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
            let command_line = invocation
                .args
                .get(1)
                .expect("shell command should be passed as second arg");
            assert!(command_line.contains("cd"));
            assert!(command_line.contains("'/tmp/my project'"));
        }
    }

    #[test]
    fn sys_exec_invocation_shell_wraps_env_assignment_prefix() {
        let invocation = resolve_sys_exec_invocation("FOO=bar npm run test", &[])
            .expect("env-prefix commands should wrap via shell");

        if cfg!(target_os = "windows") {
            assert!(!invocation.shell_wrapped);
            assert_eq!(invocation.command, "FOO=bar");
        } else {
            assert!(invocation.shell_wrapped);
            assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
            assert_eq!(
                invocation.args.get(1),
                Some(&"FOO=bar npm run test".to_string())
            );
        }
    }

    #[test]
    fn linux_plan_prefers_gtk_launch_when_available() {
        let plan = build_linux_launch_plan("Google Chrome", true);
        assert!(!plan.is_empty());
        assert_eq!(plan[0].command, "gtk-launch");
        assert!(plan
            .iter()
            .any(|a| a.command == "gtk-launch" && a.args.iter().any(|arg| arg == "google-chrome")));
    }

    #[test]
    fn linux_plan_includes_generic_binary_fallbacks() {
        let plan = build_linux_launch_plan("Google Chrome", false);
        let commands: Vec<&str> = plan.iter().map(|a| a.command.as_str()).collect();
        assert!(commands.contains(&"google-chrome"));
        assert!(commands.contains(&"google_chrome"));
    }

    #[test]
    fn detects_terminal_non_zero_output_banner() {
        assert!(command_output_indicates_failure(
            "Command failed: exit status: 1\nStderr: launch failed"
        ));
        assert!(!command_output_indicates_failure(
            "Launched background process 'code' (PID: 1234)"
        ));
    }

    #[test]
    fn blocking_launch_attempt_treats_non_zero_output_as_failure() {
        let blocking = LaunchAttempt {
            command: "gtk-launch".to_string(),
            args: vec!["calculator".to_string()],
            detach: false,
        };
        assert!(launch_attempt_failed(
            &blocking,
            "Command failed: exit status: 1\nStderr: not found"
        ));
    }

    #[test]
    fn detached_launch_attempt_does_not_parse_banner_as_failure() {
        let detached = LaunchAttempt {
            command: "calculator".to_string(),
            args: vec![],
            detach: true,
        };
        assert!(!launch_attempt_failed(
            &detached,
            "Command failed: exit status: 1\nStderr: not found"
        ));
    }

    #[test]
    fn classify_missing_app_errors_as_tool_unavailable() {
        let errors = vec![
            "gnome-calculator (No such file or directory)".to_string(),
            "gtk-launch gnome-calculator (non-zero exit: Command failed: exit status: 1)"
                .to_string(),
        ];
        assert!(launch_errors_indicate_missing_app(&errors));
    }

    #[test]
    fn do_not_classify_generic_runtime_errors_as_missing_app() {
        let errors = vec!["google-chrome (Command timed out after 5 seconds)".to_string()];
        assert!(!launch_errors_indicate_missing_app(&errors));
    }

    #[test]
    fn classify_mixed_sudo_and_package_lookup_as_missing_dependency() {
        let mixed = "[sudo] password for user: sudo: a password is required\nE: Unable to locate package calculator";
        assert_eq!(
            classify_install_failure(mixed, "sudo", "apt-get"),
            "MissingDependency"
        );
    }

    #[test]
    fn classify_password_required_as_permission_error() {
        let password = "sudo: a password is required";
        assert_eq!(
            classify_install_failure(password, "sudo", "apt-get"),
            "PermissionOrApprovalRequired"
        );
    }

    #[test]
    fn classify_sys_exec_not_found_as_tool_unavailable() {
        let err = "Command failed: exit status: 127\nStderr: bash: fooctl: command not found";
        assert_eq!(classify_sys_exec_failure(err, "fooctl"), "ToolUnavailable");
    }

    #[test]
    fn classify_sys_exec_not_found_with_compound_command_as_tool_unavailable() {
        let err = "Command failed: exit status: 127\nStderr: bash: fooctl: command not found";
        assert_eq!(
            classify_sys_exec_failure(err, "fooctl --version"),
            "ToolUnavailable"
        );
    }

    #[test]
    fn classify_sys_exec_timeout_as_timeout_or_hang() {
        let err = "Command timed out after 5 seconds.";
        assert_eq!(classify_sys_exec_failure(err, "sleep"), "TimeoutOrHang");
    }

    #[test]
    fn summarize_sys_exec_failure_prefers_stderr_payload() {
        let err = "Command failed: exit status: 1\nStderr: permission denied";
        assert_eq!(summarize_sys_exec_failure_output(err), "permission denied");
    }

    #[test]
    fn sys_exec_failure_result_emits_error_class_prefix() {
        let result = sys_exec_failure_result(
            "fooctl",
            "Command failed: exit status: 127\nStderr: fooctl: command not found",
        );
        assert!(!result.success);
        assert!(result.history_entry.is_none());
        let err = result.error.expect("error payload must exist");
        assert!(err.starts_with("ERROR_CLASS=ToolUnavailable"));
    }

    #[test]
    fn append_sys_exec_command_history_uses_exit_code_prefix_and_split_output() {
        let mut result = ToolExecutionResult::failure("command output");
        let output = "Command failed: exit status: 127\nStderr: boom\n";
        result.history_entry = Some(output.to_string());
        append_sys_exec_command_history(&mut result, "fooctl --version", 42, 9);
        assert!(result.history_entry.is_some());
        let entry = result.history_entry.as_deref().unwrap_or("");
        assert!(entry.starts_with(COMMAND_HISTORY_PREFIX));
        let payload = &entry[COMMAND_HISTORY_PREFIX.len()..];
        let json_payload = payload.lines().next().unwrap_or("").trim();
        let parsed = match serde_json::from_str::<CommandExecution>(json_payload) {
            Ok(value) => value,
            Err(error) => panic!("history json should parse: {}", error),
        };
        assert_eq!(parsed.command, "fooctl --version");
        assert_eq!(parsed.exit_code, 127);
        assert_eq!(parsed.stderr, "boom");
        assert_eq!(parsed.step_index, 42);
    }

    #[test]
    fn append_sys_exec_command_history_falls_back_to_provided_exit_code_when_missing() {
        let mut result = ToolExecutionResult::failure("command output");
        let output = "Command output without a numeric exit status line";
        result.history_entry = Some(output.to_string());
        append_sys_exec_command_history(&mut result, "echo hi", 7, 9);
        let entry = result.history_entry.as_deref().unwrap_or("");
        let payload = &entry[COMMAND_HISTORY_PREFIX.len()..];
        let json_payload = payload.lines().next().unwrap_or("").trim();
        let parsed = match serde_json::from_str::<CommandExecution>(json_payload) {
            Ok(value) => value,
            Err(error) => panic!("history json should parse: {}", error),
        };
        assert_eq!(parsed.exit_code, 9);
        assert_eq!(parsed.command, "echo hi");
    }

    #[test]
    fn extract_exit_code_parses_terminal_exit_status() {
        let output = "Command failed: exit status: 127\nStderr: boom";
        assert_eq!(extract_exit_code(output), Some(127));
    }

    #[test]
    fn parse_terminal_output_splits_stdout_and_stderr() {
        let output = "line one\nline two\nStderr: boom on stderr";
        let (stdout, stderr) = parse_terminal_output(output);
        assert_eq!(stdout, "line one\nline two");
        assert_eq!(stderr, "boom on stderr");
    }

    #[test]
    fn resolve_working_directory_expands_tilde_home() {
        let home = resolve_home_directory().expect("home directory should resolve");
        let resolved =
            resolve_working_directory("~").expect("tilde working directory should resolve");
        assert_eq!(resolved, home);
    }

    #[test]
    fn resolve_target_directory_expands_tilde_path() {
        let expected =
            std::fs::canonicalize(resolve_home_directory().expect("home directory should resolve"))
                .expect("canonical home path should resolve");
        let resolved =
            resolve_target_directory(".", "~").expect("tilde target directory should resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn normalize_stdin_data_preserves_non_empty_payload() {
        let stdin = normalize_stdin_data(Some("line1\nline2".to_string()));
        assert_eq!(stdin, Some(b"line1\nline2".to_vec()));
    }

    #[test]
    fn normalize_stdin_data_drops_empty_payload() {
        assert!(normalize_stdin_data(Some(String::new())).is_none());
        assert!(normalize_stdin_data(None).is_none());
    }

    #[test]
    fn workload_receipt_arg_redaction_redacts_sensitive_values() {
        let args = vec![
            "--password".to_string(),
            "super-secret".to_string(),
            "--token=abc123".to_string(),
            "--user=user:pass".to_string(),
            "ok".to_string(),
            "API_KEY=hunter2".to_string(),
            "--header".to_string(),
            "Authorization: Bearer jwt.jwt.jwt".to_string(),
        ];

        let redacted = redact_args_for_receipt(&args);
        assert_eq!(redacted.len(), args.len());
        assert_eq!(redacted[0], "--password");
        assert_eq!(
            redacted[1],
            WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string()
        );
        assert_eq!(
            redacted[2],
            format!("--token={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            redacted[3],
            format!("--user={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
        );
        assert_eq!(redacted[4], "ok");
        assert_eq!(
            redacted[5],
            format!("API_KEY={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            redacted[7],
            format!("Authorization: Bearer {}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
        );
    }
}
