// Path: crates/drivers/src/terminal/mod.rs

use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time;

#[derive(Clone, Debug)]
pub enum ProcessStreamChannel {
    Stdout,
    Stderr,
    Status,
}

impl ProcessStreamChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessStreamChunk {
    pub channel: ProcessStreamChannel,
    pub chunk: String,
    pub seq: u64,
    pub is_final: bool,
    pub exit_code: Option<i32>,
}

pub type ProcessStreamObserver = Arc<dyn Fn(ProcessStreamChunk) + Send + Sync>;

#[derive(Clone)]
pub struct CommandExecutionOptions {
    pub timeout: Duration,
    pub stream_observer: Option<ProcessStreamObserver>,
    pub stdin_data: Option<Vec<u8>>,
}

impl Default for CommandExecutionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            stream_observer: None,
            stdin_data: None,
        }
    }
}

impl CommandExecutionOptions {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_stream_observer(mut self, stream_observer: Option<ProcessStreamObserver>) -> Self {
        self.stream_observer = stream_observer;
        self
    }

    pub fn with_stdin_data(mut self, stdin_data: Option<Vec<u8>>) -> Self {
        self.stdin_data = stdin_data;
        self
    }
}

pub struct TerminalDriver;

impl TerminalDriver {
    pub fn new() -> Self {
        Self
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
}

async fn read_stream<R: AsyncRead + Unpin>(
    mut reader: R,
    channel: ProcessStreamChannel,
    seq: Arc<AtomicU64>,
    observer: Option<ProcessStreamObserver>,
) -> Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let mut out = Vec::<u8>::new();
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
        if let Some(cb) = observer.as_ref() {
            let seq_value = seq.fetch_add(1, Ordering::Relaxed);
            (cb)(ProcessStreamChunk {
                channel: channel.clone(),
                chunk: String::from_utf8_lossy(&buf[..read]).to_string(),
                seq: seq_value,
                is_final: false,
                exit_code: None,
            });
        }
    }
    Ok(out)
}

fn combine_success_output(stdout_text: &str, stderr_text: &str) -> String {
    let stdout = stdout_text.trim_end_matches('\n');
    let stderr = stderr_text.trim_end_matches('\n');

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_string(),
        (true, false) => format!("Stderr:\n{}", stderr),
        (false, false) => format!("Stdout:\n{}\nStderr:\n{}", stdout, stderr),
    }
}

#[cfg(test)]
mod tests {
    use super::combine_success_output;

    #[test]
    fn combine_success_output_keeps_stdout_when_stderr_empty() {
        let output = combine_success_output("hello world\n", "");
        assert_eq!(output, "hello world");
    }

    #[test]
    fn combine_success_output_surfaces_stderr_when_stdout_empty() {
        let output = combine_success_output("", "warning: fallback path used\n");
        assert_eq!(output, "Stderr:\nwarning: fallback path used");
    }

    #[test]
    fn combine_success_output_labels_mixed_streams() {
        let output = combine_success_output("ready\n", "warning: cache miss\n");
        assert_eq!(output, "Stdout:\nready\nStderr:\nwarning: cache miss");
    }
}
