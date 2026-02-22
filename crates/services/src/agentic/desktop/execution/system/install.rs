use super::paths::resolve_working_directory;
use super::receipt::{scrub_workload_args_for_receipt, scrub_workload_text_field_for_receipt};
use super::sys_exec::{
    command_output_indicates_failure, command_preview, extract_exit_code, process_stream_observer,
    summarize_command_output,
};
use super::{
    compute_workload_id, emit_workload_activity, emit_workload_receipt, extract_error_class,
    ToolExecutionResult, ToolExecutor,
};
use crate::agentic::desktop::runtime_secret;
use ioi_drivers::terminal::CommandExecutionOptions;
use ioi_types::app::{WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt};
use std::time::Duration;

const INSTALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

pub(super) async fn handle_install_package(
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

    let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
    let receipt_command = scrub_workload_text_field_for_receipt(exec, command).await;
    let receipt_args = scrub_workload_args_for_receipt(exec, &args).await;
    let receipt_cwd =
        scrub_workload_text_field_for_receipt(exec, resolved_cwd_string.as_str()).await;
    let receipt_preview = command_preview(&receipt_command, &receipt_args);
    let workload_id = compute_workload_id(
        session_id,
        step_index,
        "sys__install_package",
        &receipt_preview,
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

    let options = CommandExecutionOptions::default()
        .with_timeout(INSTALL_COMMAND_TIMEOUT)
        .with_stdin_data(stdin_data)
        .with_stream_observer(process_stream_observer(
            exec,
            session_id,
            step_index,
            workload_id.clone(),
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

pub(super) fn classify_install_failure(error: &str, command: &str, manager: &str) -> &'static str {
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
