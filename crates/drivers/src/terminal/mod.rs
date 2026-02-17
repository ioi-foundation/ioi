// Path: crates/drivers/src/terminal/mod.rs

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
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
        match session.exec(command, args, cwd, options).await {
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

struct ShellSession {
    exec_lock: Mutex<()>,
    child: Mutex<tokio::process::Child>,
    stdin: Mutex<tokio::process::ChildStdin>,
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
    next_marker: AtomicU64,
}

impl ShellSession {
    async fn spawn(cwd: Option<&Path>) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = cwd;
            return Err(anyhow!(
                "Persistent shell sessions are not supported on this platform."
            ));
        }

        #[cfg(unix)]
        {
            let shell = resolve_shell_path();
            let mut cmd = Command::new(shell);
            cmd.arg("-s");
            if let Some(dir) = cwd {
                cmd.current_dir(dir);
            }

            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            // We'll redirect stderr to stdout inside the shell (`exec 2>&1`) to avoid needing
            // dual-stream parsing and deadlocks when stderr isn't drained.
            cmd.stderr(Stdio::null());

            let mut child = cmd
                .spawn()
                .map_err(|e| anyhow!("Failed to spawn persistent shell session: {}", e))?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("Failed to capture session stdin"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Failed to capture session stdout"))?;

            let session = Self {
                exec_lock: Mutex::new(()),
                child: Mutex::new(child),
                stdin: Mutex::new(stdin),
                stdout: Mutex::new(BufReader::new(stdout)),
                next_marker: AtomicU64::new(1),
            };

            // Redirect all stderr from commands in this session into stdout for consistent capture.
            {
                let mut stdin = session.stdin.lock().await;
                stdin.write_all(b"exec 2>&1\n").await?;
                stdin.flush().await?;
            }

            Ok(session)
        }
    }

    async fn terminate(&self) -> Result<()> {
        let _guard = self.exec_lock.lock().await;
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        Ok(())
    }

    async fn exec(
        &self,
        command: &str,
        args: &[String],
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<String> {
        #[cfg(not(unix))]
        {
            let _ = (command, args, cwd, options);
            return Err(anyhow!(
                "Persistent shell sessions are not supported on this platform."
            ));
        }

        #[cfg(unix)]
        {
            let _guard = self.exec_lock.lock().await;

            // If the shell died, fail fast so the caller can reset.
            {
                let mut child = self.child.lock().await;
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(anyhow!("Shell session terminated ({}).", status));
                }
            }

            let trimmed = command.trim();
            if trimmed.is_empty() {
                return Err(anyhow!("Command cannot be empty."));
            }

            let marker_id = self.next_marker.fetch_add(1, Ordering::Relaxed);
            let done_marker = format!("__IOI_DONE:{}__", marker_id);
            let rc_prefix = format!("__IOI_RC:{}__:", marker_id);

            let cmd_line = build_shell_command_line(trimmed, args);
            let script = build_session_script(
                cwd,
                &cmd_line,
                options.stdin_data.as_deref(),
                &rc_prefix,
                &done_marker,
                marker_id,
            )?;

            let observer = options.stream_observer.clone();
            let seq = Arc::new(AtomicU64::new(0));

            // Write the script and read until the completion marker is observed.
            let mut timed_out = false;
            let run = async {
                {
                    let mut stdin = self.stdin.lock().await;
                    stdin.write_all(script.as_bytes()).await?;
                    stdin.flush().await?;
                }

                let mut stdout = self.stdout.lock().await;
                let mut output = String::new();
                let mut exit_code: Option<i32> = None;

                loop {
                    let mut line = String::new();
                    let read = stdout.read_line(&mut line).await?;
                    if read == 0 {
                        return Err(anyhow!(
                            "Shell session ended before emitting completion marker."
                        ));
                    }

                    let trimmed_line = line.trim_end_matches(['\n', '\r']);
                    if trimmed_line == done_marker {
                        break;
                    }

                    if let Some(rest) = trimmed_line.strip_prefix(&rc_prefix) {
                        exit_code = rest.trim().parse::<i32>().ok();
                        continue;
                    }

                    // Forward output to observers, preserving read order as seq.
                    if let Some(cb) = observer.as_ref() {
                        let seq_value = seq.fetch_add(1, Ordering::Relaxed);
                        (cb)(ProcessStreamChunk {
                            channel: ProcessStreamChannel::Stdout,
                            chunk: line.clone(),
                            seq: seq_value,
                            is_final: false,
                            exit_code: None,
                        });
                    }

                    output.push_str(&line);
                }

                let code = exit_code.ok_or_else(|| anyhow!("Missing exit code marker."))?;
                Ok((output, code))
            };

            let (output, exit_code) = match time::timeout(options.timeout, run).await {
                Ok(res) => res?,
                Err(_) => {
                    timed_out = true;
                    // Kill the session; it's unsafe to keep using a potentially wedged shell.
                    drop(_guard);
                    self.terminate().await?;
                    (String::new(), -1)
                }
            };

            if let Some(cb) = observer.as_ref() {
                let final_seq = seq.fetch_add(1, Ordering::Relaxed);
                (cb)(ProcessStreamChunk {
                    channel: ProcessStreamChannel::Status,
                    chunk: String::new(),
                    seq: final_seq,
                    is_final: true,
                    exit_code: if timed_out { None } else { Some(exit_code) },
                });
            }

            if timed_out {
                return Err(anyhow!(
                    "Command timed out after {} seconds.",
                    options.timeout.as_secs()
                ));
            }

            let output_text = output.trim_end_matches(['\n', '\r']).to_string();
            if exit_code == 0 {
                Ok(output_text)
            } else {
                Ok(format!(
                    "Command failed: exit status: {}\nStderr: {}",
                    exit_code, output_text
                ))
            }
        }
    }
}

#[cfg(unix)]
fn resolve_shell_path() -> String {
    env::var("SHELL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .filter(|value| Path::new(value).is_file())
        .unwrap_or_else(|| "/bin/sh".to_string())
}

#[cfg(unix)]
fn build_shell_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    let mut out = String::from(command);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_sh_argument(arg));
    }
    out
}

#[cfg(unix)]
fn quote_sh_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    if arg.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@' | '+')
    }) {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

#[cfg(unix)]
fn build_session_script(
    cwd: Option<&Path>,
    cmd_line: &str,
    stdin_data: Option<&[u8]>,
    rc_prefix: &str,
    done_marker: &str,
    marker_id: u64,
) -> Result<String> {
    let mut script = String::new();
    script.push_str("ioi_rc=0\n");

    if let Some(dir) = cwd {
        let dir_str = dir.to_string_lossy().to_string();
        script.push_str(&format!("if ! cd {}; then\n", quote_sh_argument(&dir_str)));
        script.push_str("  ioi_rc=$?\n");
        script.push_str("else\n");
    }

    if let Some(bytes) = stdin_data {
        let data = String::from_utf8_lossy(bytes).to_string();
        let delimiter = choose_heredoc_delimiter(marker_id, &data);
        script.push_str(&format!("  {cmd_line} <<'{delimiter}'\n"));
        script.push_str(&data);
        if !data.ends_with('\n') {
            script.push('\n');
        }
        script.push_str(&format!("{delimiter}\n"));
        script.push_str("  ioi_rc=$?\n");
    } else {
        script.push_str(&format!("  {cmd_line}\n"));
        script.push_str("  ioi_rc=$?\n");
    }

    if cwd.is_some() {
        script.push_str("fi\n");
    }

    script.push_str(&format!("echo \"{rc_prefix}$ioi_rc\"\n"));
    script.push_str(&format!("echo \"{done_marker}\"\n"));
    Ok(script)
}

#[cfg(unix)]
fn choose_heredoc_delimiter(marker_id: u64, data: &str) -> String {
    // Ensure the delimiter cannot occur in the payload to avoid premature heredoc termination.
    for attempt in 0..10u32 {
        let candidate = format!("__IOI_STDIN_{}_{}__", marker_id, attempt);
        if !data.contains(&candidate) {
            return candidate;
        }
    }
    "__IOI_STDIN_FALLBACK__".to_string()
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
    use super::{combine_success_output, CommandExecutionOptions, TerminalDriver};
    use std::time::Duration;

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

    #[cfg(unix)]
    #[tokio::test]
    async fn session_exec_preserves_shell_state_across_calls() {
        let driver = TerminalDriver::new();
        let key = "test-session";

        let out = driver
            .execute_session_in_dir_with_options(
                key,
                "export",
                &["IOI_SESSION_TEST=ok".to_string()],
                None,
                CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
            )
            .await
            .expect("export should succeed");
        assert!(out.trim().is_empty());

        let out = driver
            .execute_session_in_dir_with_options(
                key,
                "echo $IOI_SESSION_TEST",
                &[],
                None,
                CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
            )
            .await
            .expect("echo should succeed");
        assert_eq!(out.trim(), "ok");

        let _ = driver.reset_session(key).await;
    }
}
