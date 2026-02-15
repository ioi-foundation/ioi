// Path: crates/services/src/agentic/desktop/execution/system.rs

use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::runtime_secret;
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::terminal::{CommandExecutionOptions, ProcessStreamChunk, ProcessStreamObserver};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::KernelEvent;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
struct LaunchAttempt {
    command: String,
    args: Vec<String>,
    detach: bool,
}

const INSTALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

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
            detach,
        } => {
            let resolved_cwd = match resolve_working_directory(cwd) {
                Ok(path) => path,
                Err(error) => return ToolExecutionResult::failure(error),
            };
            let command_preview = command_preview(&command, &args);
            let observer = if detach {
                None
            } else {
                process_stream_observer(
                    exec,
                    session_id,
                    step_index,
                    "sys__exec",
                    command_preview.clone(),
                )
            };
            let options = CommandExecutionOptions::default().with_stream_observer(observer);

            match exec
                .terminal
                .execute_in_dir_with_options(&command, &args, detach, Some(&resolved_cwd), options)
                .await
            {
                Ok(out) => ToolExecutionResult::success(out),
                Err(e) => ToolExecutionResult::failure(e.to_string()),
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
                vec![LaunchAttempt {
                    // Powershell Start-Process for better app resolution.
                    command: "powershell".to_string(),
                    args: vec![
                        "-Command".to_string(),
                        format!("Start-Process '{}'", app_name),
                    ],
                    detach: true,
                }]
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
    if preview.len() > 220 {
        format!("{}...", &preview[..220])
    } else {
        preview
    }
}

fn process_stream_observer(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    command_preview: String,
) -> Option<ProcessStreamObserver> {
    let tx = exec.event_sender.clone()?;
    let tool_name = tool_name.to_string();
    let stream_seed = format!(
        "{}:{}:{}:{}",
        hex::encode(session_id),
        step_index,
        tool_name,
        command_preview
    );
    let stream_id = sha256(stream_seed.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| format!("{}:{}:{}", hex::encode(session_id), step_index, tool_name));

    Some(Arc::new(move |chunk: ProcessStreamChunk| {
        let _ = tx.send(KernelEvent::ProcessActivity {
            session_id,
            step_index,
            tool_name: tool_name.clone(),
            stream_id: stream_id.clone(),
            channel: chunk.channel.as_str().to_string(),
            chunk: chunk.chunk,
            seq: chunk.seq,
            is_final: chunk.is_final,
            exit_code: chunk.exit_code,
            command_preview: command_preview.clone(),
        });
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
    let options = CommandExecutionOptions::default()
        .with_timeout(INSTALL_COMMAND_TIMEOUT)
        .with_stdin_data(stdin_data)
        .with_stream_observer(process_stream_observer(
            exec,
            session_id,
            step_index,
            "sys__install_package",
            cmd_preview,
        ));

    match exec
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
    }
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

fn resolve_working_directory(cwd: &str) -> Result<PathBuf, String> {
    let normalized = cwd.trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(normalized)
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

    let requested = PathBuf::from(trimmed);
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
        build_linux_launch_plan, classify_install_failure, command_output_indicates_failure,
        launch_attempt_failed, launch_errors_indicate_missing_app, LaunchAttempt,
    };

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
}
