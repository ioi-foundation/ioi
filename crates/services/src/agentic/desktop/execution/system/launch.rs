use super::sys_exec::{command_output_indicates_failure, summarize_command_output};
use super::{LaunchAttempt, ToolExecutionResult, ToolExecutor};
use std::env;
use std::path::Path;

pub(super) async fn handle_os_launch_app(
    exec: &ToolExecutor,
    app_name: &str,
) -> ToolExecutionResult {
    let attempts = if cfg!(target_os = "macos") {
        vec![LaunchAttempt {
            command: "open".to_string(),
            args: vec!["-a".to_string(), app_name.to_string()],
            detach: true,
        }]
    } else if cfg!(target_os = "windows") {
        build_windows_launch_plan(app_name)
    } else {
        build_linux_launch_plan(app_name, is_command_available("gtk-launch"))
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

pub(super) fn quote_powershell_single_quoted_string(value: &str) -> String {
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

pub(super) fn build_linux_launch_plan(app_name: &str, has_gtk_launch: bool) -> Vec<LaunchAttempt> {
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

pub(super) fn launch_attempt_failed(attempt: &LaunchAttempt, output: &str) -> bool {
    // Detached launches only confirm process spawn. For blocking launches, a
    // non-zero exit is surfaced by TerminalDriver as "Command failed: ...".
    !attempt.detach && command_output_indicates_failure(output)
}

pub(super) fn launch_errors_indicate_missing_app(errors: &[String]) -> bool {
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
