use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time;

use super::session::ShellSession;
use super::stream::{combine_success_output, read_stream};
use super::types::{CommandExecutionOptions, ProcessStreamChannel, ProcessStreamChunk};

#[derive(Clone)]
pub struct TerminalDriver {
    sessions: Arc<Mutex<HashMap<String, Arc<ShellSession>>>>,
}

impl TerminalDriver {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Executes a command.
    /// If `detach` is true, it spawns the process and returns immediately (for GUI apps).
    /// If `detach` is false, it waits using default timeout options.
    pub async fn execute(&self, command: &str, args: &[String], detach: bool) -> Result<String> {
        self.execute_in_dir(command, args, detach, None).await
    }

    /// Executes a command with an optional working directory override.
    pub async fn execute_in_dir(
        &self,
        command: &str,
        args: &[String],
        detach: bool,
        cwd: Option<&Path>,
    ) -> Result<String> {
        self.execute_in_dir_with_options(
            command,
            args,
            detach,
            cwd,
            CommandExecutionOptions::default(),
        )
        .await
    }

    pub async fn execute_in_dir_with_options(
        &self,
        command: &str,
        args: &[String],
        detach: bool,
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<String> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }

        if detach {
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
            cmd.stdin(Stdio::null());

            #[cfg(unix)]
            {
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::setsid() == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }

            let child = cmd
                .spawn()
                .map_err(|e| anyhow!("Failed to spawn detached command '{}': {}", command, e))?;
            let pid = child.id().unwrap_or_default();
            return Ok(format!(
                "Launched background process '{}' (PID: {})",
                command, pid
            ));
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if options.stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn command '{}': {}", command, e))?;

        if let Some(stdin_data) = options.stdin_data.clone() {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("Failed to capture stdin for '{}'", command))?;
            stdin.write_all(&stdin_data).await?;
            stdin.flush().await?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stdout for '{}'", command))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stderr for '{}'", command))?;

        let observer = options.stream_observer.clone();
        let seq = Arc::new(AtomicU64::new(0));
        let stdout_task = tokio::spawn(read_stream(
            stdout,
            ProcessStreamChannel::Stdout,
            seq.clone(),
            observer.clone(),
        ));
        let stderr_task = tokio::spawn(read_stream(
            stderr,
            ProcessStreamChannel::Stderr,
            seq.clone(),
            observer.clone(),
        ));

        let mut timed_out = false;
        let status = match time::timeout(options.timeout, child.wait()).await {
            Ok(wait_result) => wait_result?,
            Err(_) => {
                timed_out = true;
                let _ = child.kill().await;
                child.wait().await?
            }
        };

        let stdout_bytes = stdout_task
            .await
            .map_err(|e| anyhow!("stdout reader join failed: {}", e))??;
        let stderr_bytes = stderr_task
            .await
            .map_err(|e| anyhow!("stderr reader join failed: {}", e))??;

        if let Some(cb) = observer {
            let final_seq = seq.fetch_add(1, Ordering::Relaxed);
            (cb)(ProcessStreamChunk {
                channel: ProcessStreamChannel::Status,
                chunk: String::new(),
                seq: final_seq,
                is_final: true,
                exit_code: status.code(),
            });
        }

        if timed_out {
            return Err(anyhow!(
                "Command timed out after {} seconds.",
                options.timeout.as_secs()
            ));
        }

        let stdout_text = String::from_utf8_lossy(&stdout_bytes).to_string();
        let stderr_text = String::from_utf8_lossy(&stderr_bytes).to_string();

        if status.success() {
            Ok(combine_success_output(&stdout_text, &stderr_text))
        } else {
            Ok(format!(
                "Command failed: {}\nStderr: {}",
                status, stderr_text
            ))
        }
    }

    /// Executes a command inside a persistent shell session keyed by `session_key`.
    ///
    /// The session is lazily created and reused for subsequent calls. On internal failures
    /// (timeout, transport error, missing markers), the session is reset to avoid wedged state.
    pub async fn execute_session_in_dir_with_options(
        &self,
        session_key: &str,
        command: &str,
        args: &[String],
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<String> {
        let key = session_key.trim();
        if key.is_empty() {
            return Err(anyhow!("Session key cannot be empty."));
        }

        let session = self.get_or_create_session(key, cwd).await?;
        match ShellSession::exec(&session, command, args, cwd, options).await {
            Ok(out) => Ok(out),
            Err(e) => {
                let _ = self.reset_session(key).await;
                Err(e)
            }
        }
    }

    /// Kills and removes a persistent shell session.
    pub async fn reset_session(&self, session_key: &str) -> Result<()> {
        let key = session_key.trim();
        if key.is_empty() {
            return Err(anyhow!("Session key cannot be empty."));
        }

        let session = { self.sessions.lock().await.remove(key) };
        if let Some(session) = session {
            session.terminate().await?;
        }
        Ok(())
    }

    async fn get_or_create_session(
        &self,
        session_key: &str,
        cwd: Option<&Path>,
    ) -> Result<Arc<ShellSession>> {
        if let Some(existing) = { self.sessions.lock().await.get(session_key).cloned() } {
            return Ok(existing);
        }

        let created = Arc::new(ShellSession::spawn(cwd).await?);
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get(session_key).cloned() {
            drop(sessions);
            created.terminate().await?;
            return Ok(existing);
        }
        sessions.insert(session_key.to_string(), created.clone());
        Ok(created)
    }
}
