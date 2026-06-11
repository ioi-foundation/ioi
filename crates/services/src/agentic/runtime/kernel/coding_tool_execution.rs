use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolExecutionError {
    code: &'static str,
    message: String,
}

impl CodingToolExecutionError {
    pub fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedCommand {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_command_with_timeout(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    env_overrides: &[(String, String)],
) -> Result<CapturedCommand, CodingToolExecutionError> {
    let command_env = safe_subprocess_env(env_overrides);
    let mut child = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(command_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            CodingToolExecutionError::new("diagnostic_command_spawn_failed", error.to_string())
        })?;
    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    loop {
        match child.try_wait().map_err(|error| {
            CodingToolExecutionError::new("diagnostic_command_wait_failed", error.to_string())
        })? {
            Some(_) => break,
            None if started.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    let output = child.wait_with_output().map_err(|error| {
        CodingToolExecutionError::new("diagnostic_command_output_failed", error.to_string())
    })?;
    Ok(CapturedCommand {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: if timed_out {
            124
        } else {
            output.status.code().unwrap_or(1)
        },
        timed_out,
    })
}

pub fn run_git_read_only(
    root: &Path,
    args: &[String],
) -> Result<CommandOutput, CodingToolExecutionError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| CodingToolExecutionError::new("git_spawn_failed", error.to_string()))?;
    Ok(CommandOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn safe_subprocess_env(overrides: &[(String, String)]) -> Vec<(String, String)> {
    let mut env_values = env::vars()
        .filter(|(key, _)| env_key_allowed(key) && !key.starts_with("NODE_TEST"))
        .collect::<Vec<_>>();
    for (key, value) in overrides {
        if env_key_allowed(key) && !key.starts_with("NODE_TEST") {
            env_values.retain(|(existing_key, _)| existing_key != key);
            env_values.push((key.clone(), value.clone()));
        }
    }
    env_values
}

pub fn env_key_allowed(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    if !chars.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        return false;
    }
    !is_sensitive_env_key(key)
}

pub fn is_sensitive_env_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "session",
        "vault",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("privatekey")
        || lower.contains("private_key")
        || lower.contains("private-key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_env_keys_are_filtered_from_subprocesses() {
        assert!(!env_key_allowed("OPENAI_API_KEY"));
        assert!(!env_key_allowed("SESSION_TOKEN"));
        assert!(!env_key_allowed("vault_ref"));
        assert!(env_key_allowed("PATH"));
        assert!(env_key_allowed("_IOI_TEST"));
    }

    #[test]
    fn bounded_command_reports_timeout() {
        let run = run_command_with_timeout(
            "sh",
            &["-c".to_string(), "sleep 2; echo late".to_string()],
            Path::new("."),
            10,
            &[],
        )
        .expect("command should spawn");

        assert!(run.timed_out);
        assert_eq!(run.exit_code, 124);
    }
}
