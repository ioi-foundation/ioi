use super::paths::resolve_working_directory;
use super::receipt::{scrub_workload_args_for_receipt, scrub_workload_text_field_for_receipt};
use super::{
    compute_workload_id, emit_workload_activity, emit_workload_receipt, extract_error_class,
    SysExecInvocation, ToolExecutionResult, ToolExecutor,
};
use crate::agentic::desktop::types::CommandExecution;
use ioi_drivers::terminal::{CommandExecutionOptions, ProcessStreamChunk, ProcessStreamObserver};
use ioi_types::app::{WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt};
use std::env;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
pub(super) const SYS_EXEC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub(super) const SYS_EXEC_EXTENDED_TIMEOUT: Duration = Duration::from_secs(600);

pub(super) async fn handle_sys_exec(
    exec: &ToolExecutor,
    command: &str,
    args: &[String],
    stdin: Option<String>,
    detach: bool,
    cwd: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    let resolved_cwd = match resolve_working_directory(cwd) {
        Ok(path) => path,
        Err(error) => return ToolExecutionResult::failure(error),
    };
    let invocation = match resolve_sys_exec_invocation(command, args) {
        Ok(invocation) => invocation,
        Err(error) => return ToolExecutionResult::failure(error),
    };
    let raw_command_preview = command_preview(command, args);
    let timeout = resolve_sys_exec_timeout(&invocation.command, &invocation.args, detach);
    let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
    let receipt_command =
        scrub_workload_text_field_for_receipt(exec, invocation.command.as_str()).await;
    let receipt_args = scrub_workload_args_for_receipt(exec, invocation.args.as_slice()).await;
    let receipt_cwd =
        scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
    let receipt_preview = command_preview(&receipt_command, &receipt_args);
    let workload_id = compute_workload_id(session_id, step_index, "sys__exec", &receipt_preview);
    let observer = if detach {
        None
    } else {
        process_stream_observer(exec, session_id, step_index, workload_id.clone())
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
                let mut failure = sys_exec_failure_result(command, &out);
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
            let mut result = sys_exec_failure_result(command, &error);
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

pub(super) async fn handle_sys_exec_session(
    exec: &ToolExecutor,
    command: &str,
    args: &[String],
    stdin: Option<String>,
    cwd: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
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

    let raw_command_preview = command_preview(command, args);
    let timeout = resolve_sys_exec_timeout(trimmed, args, false);
    let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
    let receipt_command = scrub_workload_text_field_for_receipt(exec, trimmed).await;
    let receipt_args = scrub_workload_args_for_receipt(exec, args).await;
    let receipt_cwd =
        scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
    let receipt_preview = command_preview(&receipt_command, &receipt_args);
    let workload_id = compute_workload_id(
        session_id,
        step_index,
        "sys__exec_session",
        &receipt_preview,
    );
    let observer = process_stream_observer(exec, session_id, step_index, workload_id.clone());
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
            args,
            Some(&resolved_cwd),
            options,
        )
        .await
    {
        Ok(out) => {
            let command_failed = command_output_indicates_failure(&out);
            let mut result = if command_failed {
                let mut failure = sys_exec_failure_result(command, &out);
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
            let mut result = sys_exec_failure_result(command, &error);
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
        let phase = if result.success {
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

pub(super) async fn handle_sys_exec_session_reset(
    exec: &ToolExecutor,
    cwd: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    let command_preview = "sys__exec_session_reset".to_string();
    let workload_id = compute_workload_id(
        session_id,
        step_index,
        "sys__exec_session_reset",
        &command_preview,
    );

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

    let session_key = hex::encode(session_id);
    let result = match exec.terminal.reset_session(&session_key).await {
        Ok(()) => ToolExecutionResult::success("Reset persistent shell session."),
        Err(e) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=UnexpectedState Failed to reset persistent shell session: {}",
            e
        )),
    };

    if let Some(tx) = exec.event_sender.as_ref() {
        let phase = if result.success {
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
                exit_code: None,
            },
        );

        let cwd_for_receipt = if cwd.trim().is_empty() {
            "."
        } else {
            cwd.trim()
        };
        let receipt_cwd = scrub_workload_text_field_for_receipt(exec, cwd_for_receipt).await;

        emit_workload_receipt(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "sys__exec_session_reset".to_string(),
                command: "sys__exec_session_reset".to_string(),
                args: Vec::new(),
                cwd: receipt_cwd,
                detach: false,
                timeout_ms: 0,
                success: result.success,
                exit_code: None,
                error_class: extract_error_class(result.error.as_deref()),
                command_preview,
            }),
        );
    }

    result
}

pub(super) fn command_preview(command: &str, args: &[String]) -> String {
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

pub(super) fn append_sys_exec_command_history(
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

pub(super) fn extract_exit_code(output: &str) -> Option<i32> {
    output.lines().find_map(|line| {
        line.split_once("exit status:").and_then(|(_, status)| {
            status
                .split_whitespace()
                .next()
                .and_then(|raw_status| raw_status.parse::<i32>().ok())
        })
    })
}

pub(super) fn parse_terminal_output(output: &str) -> (String, String) {
    if let Some((stdout, stderr)) = output.split_once("Stderr:") {
        (stdout.trim().to_string(), stderr.trim().to_string())
    } else {
        (output.trim().to_string(), String::new())
    }
}

pub(super) fn normalize_stdin_data(stdin: Option<String>) -> Option<Vec<u8>> {
    stdin
        .map(|value| value.into_bytes())
        .filter(|bytes| !bytes.is_empty())
}

pub(super) fn resolve_sys_exec_invocation(
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

pub(super) fn resolve_sys_exec_timeout(command: &str, args: &[String], detach: bool) -> Duration {
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

pub(super) fn process_stream_observer(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
) -> Option<ProcessStreamObserver> {
    let tx = exec.event_sender.clone()?;

    Some(Arc::new(move |chunk: ProcessStreamChunk| {
        emit_workload_activity(
            &tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Stdio {
                stream: chunk.channel.as_str().to_string(),
                chunk: chunk.chunk,
                seq: chunk.seq,
                is_final: chunk.is_final,
                exit_code: chunk.exit_code,
            },
        );
    }))
}

pub(super) fn command_output_indicates_failure(output: &str) -> bool {
    output
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("command failed:")
}

pub(super) fn classify_sys_exec_failure(error: &str, command: &str) -> &'static str {
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

pub(super) fn summarize_sys_exec_failure_output(output: &str) -> String {
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

pub(super) fn sys_exec_failure_result(command: &str, error: &str) -> ToolExecutionResult {
    let class = classify_sys_exec_failure(error, command);
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS={} sys__exec '{}' failed: {}",
        class,
        command,
        summarize_sys_exec_failure_output(error)
    ))
}

pub(super) fn summarize_command_output(output: &str) -> String {
    output
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .unwrap_or("unknown error")
        .to_string()
}
