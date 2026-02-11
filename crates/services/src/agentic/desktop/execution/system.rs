// Path: crates/services/src/agentic/desktop/execution/system.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use std::env;
use std::path::Path;

#[derive(Clone, Debug)]
struct LaunchAttempt {
    command: String,
    args: Vec<String>,
    detach: bool,
}

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::SysExec {
            command,
            args,
            detach,
        } => match exec.terminal.execute(&command, &args, detach).await {
            Ok(out) => ToolExecutionResult::success(out),
            Err(e) => ToolExecutionResult::failure(e.to_string()),
        },

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
                    Ok(_) => return ToolExecutionResult::success(format!("Launched {}", app_name)),
                    Err(e) => errors.push(format!("{} ({})", format_attempt(attempt), e)),
                }
            }

            ToolExecutionResult::failure(format!(
                "Failed to launch {} after {} attempt(s): {}",
                app_name,
                attempts.len(),
                errors.join(" | ")
            ))
        }

        _ => ToolExecutionResult::failure("Unsupported System action"),
    }
}

fn build_linux_launch_plan(app_name: &str, has_gtk_launch: bool) -> Vec<LaunchAttempt> {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut attempts = Vec::new();
    let mut desktop_ids = Vec::new();
    let mut binaries = Vec::new();

    let app_lower = trimmed.to_lowercase();

    // Existing targeted mappings.
    if app_lower.contains("calculator") {
        push_unique(&mut desktop_ids, "gnome-calculator");
        push_unique(&mut binaries, "gnome-calculator");
    }
    if app_lower.contains("code") {
        push_unique(&mut desktop_ids, "code");
        push_unique(&mut binaries, "code");
    }

    // Browser aliases for common Linux installations.
    if app_lower.contains("browser")
        || app_lower.contains("chrome")
        || app_lower.contains("chromium")
        || app_lower.contains("brave")
    {
        for candidate in [
            "google-chrome",
            "google-chrome-stable",
            "chrome",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "firefox",
        ] {
            push_unique(&mut desktop_ids, candidate);
            push_unique(&mut binaries, candidate);
        }
    } else if app_lower.contains("firefox") {
        push_unique(&mut desktop_ids, "firefox");
        push_unique(&mut binaries, "firefox");
    }

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
    for candidate in [
        trimmed,
        trimmed_lower.as_str(),
        slug_dash.as_str(),
        slug_underscore.as_str(),
    ] {
        if !candidate.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::build_linux_launch_plan;

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
    fn linux_plan_includes_browser_binary_fallbacks() {
        let plan = build_linux_launch_plan("Google Chrome", false);
        let commands: Vec<&str> = plan.iter().map(|a| a.command.as_str()).collect();
        assert!(commands.contains(&"google-chrome"));
        assert!(commands.contains(&"google-chrome-stable"));
        assert!(commands.contains(&"chromium"));
        assert!(commands.contains(&"brave-browser"));
    }
}
