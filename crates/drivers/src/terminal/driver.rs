use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncWriteExt;
use tokio::process::{ChildStdin, Command};
use tokio::sync::{Mutex, Notify};
use tokio::time;

use super::session::ShellSession;
use super::stream::{combine_success_output, read_stream};
use super::types::{
    CommandExecutionOptions, CommandLaunchResult, ProcessStreamChannel, ProcessStreamChunk,
    ProcessStreamObserver, RetainedCommandSnapshot,
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const POST_KILL_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const POST_EXIT_STREAM_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);
const RETAINED_OUTPUT_TAIL_MAX_BYTES: usize = 64 * 1024;

#[cfg(unix)]
type SessionStdinBridgeHandle = Arc<StdMutex<Option<std::fs::File>>>;

async fn join_stream_task_with_drain_timeout(
    mut task: tokio::task::JoinHandle<Result<Vec<u8>>>,
    channel: &str,
    command: &str,
) -> Result<Vec<u8>> {
    match time::timeout(POST_EXIT_STREAM_DRAIN_TIMEOUT, &mut task).await {
        Ok(join_result) => {
            join_result.map_err(|e| anyhow!("{} reader join failed: {}", channel, e))?
        }
        Err(_) => {
            task.abort();
            log::warn!(
                "Timed out draining {} stream for '{}' after {:?}; continuing with partial output.",
                channel,
                command,
                POST_EXIT_STREAM_DRAIN_TIMEOUT
            );
            Ok(Vec::new())
        }
    }
}

fn unix_timestamp_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn append_output_tail(output_tail: &mut String, chunk: &str) -> bool {
    output_tail.push_str(chunk);
    if output_tail.len() <= RETAINED_OUTPUT_TAIL_MAX_BYTES {
        return false;
    }

    let overflow = output_tail.len() - RETAINED_OUTPUT_TAIL_MAX_BYTES;
    let mut drain_until = overflow;
    while drain_until < output_tail.len() && !output_tail.is_char_boundary(drain_until) {
        drain_until += 1;
    }
    output_tail.drain(..drain_until.min(output_tail.len()));
    true
}

#[cfg(unix)]
fn create_retained_session_stdin_bridge(
    command_id: &str,
) -> Result<(PathBuf, SessionStdinBridgeHandle)> {
    let path = std::env::temp_dir().join(format!(
        "ioi-session-stdin-{}-{}",
        std::process::id(),
        command_id.trim()
    ));
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes().to_vec())
        .map_err(|_| anyhow!("Failed to encode stdin bridge path."))?;
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EEXIST)) {
            return Err(anyhow!(
                "Failed to create retained session stdin bridge '{}': {}",
                path.display(),
                error
            ));
        }
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| {
            anyhow!(
                "Failed to open retained session stdin bridge '{}': {}",
                path.display(),
                error
            )
        })?;
    Ok((path, Arc::new(StdMutex::new(Some(file)))))
}

#[cfg(unix)]
async fn write_session_stdin_bridge(handle: &SessionStdinBridgeHandle, input: &[u8]) -> Result<()> {
    if input.is_empty() {
        return Ok(());
    }

    let payload = input.to_vec();
    let bridge = Arc::clone(handle);
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write as _;

        let mut guard = bridge
            .lock()
            .map_err(|_| anyhow!("Session stdin bridge mutex poisoned"))?;
        let file = guard
            .as_mut()
            .ok_or_else(|| anyhow!("Session stdin bridge is no longer available."))?;
        file.write_all(&payload)?;
        file.flush()?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("Session stdin bridge write join failed: {}", e))??;

    Ok(())
}

#[derive(Clone)]
enum RetainedCommandControl {
    Process {
        pid: u32,
        stdin: Arc<Mutex<Option<ChildStdin>>>,
    },
    Session {
        session: Arc<ShellSession>,
        #[cfg(unix)]
        stdin_bridge: Option<SessionStdinBridgeHandle>,
    },
}

struct RetainedCommandState {
    snapshot: RetainedCommandSnapshot,
    final_output: Option<String>,
    final_error: Option<String>,
}

#[derive(Clone)]
struct RetainedCommandHandle {
    state: Arc<StdMutex<RetainedCommandState>>,
    control: RetainedCommandControl,
    completion: Arc<Notify>,
}

#[derive(Clone)]
pub struct TerminalDriver {
    sessions: Arc<Mutex<HashMap<String, Arc<ShellSession>>>>,
    retained_commands: Arc<Mutex<HashMap<String, Arc<RetainedCommandHandle>>>>,
    next_retained_command: Arc<AtomicU64>,
}

impl TerminalDriver {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            retained_commands: Arc::new(Mutex::new(HashMap::new())),
            next_retained_command: Arc::new(AtomicU64::new(1)),
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
                match time::timeout(POST_KILL_WAIT_TIMEOUT, child.wait()).await {
                    Ok(wait_result) => wait_result?,
                    Err(_) => {
                        stdout_task.abort();
                        stderr_task.abort();
                        if let Some(cb) = observer.as_ref() {
                            let final_seq = seq.fetch_add(1, Ordering::Relaxed);
                            (cb)(ProcessStreamChunk {
                                channel: ProcessStreamChannel::Status,
                                chunk: String::new(),
                                seq: final_seq,
                                is_final: true,
                                exit_code: None,
                            });
                        }
                        return Err(anyhow!(
                            "Command timed out after {} seconds and could not be terminated within {} seconds.",
                            options.timeout.as_secs(),
                            POST_KILL_WAIT_TIMEOUT.as_secs()
                        ));
                    }
                }
            }
        };

        if timed_out {
            stdout_task.abort();
            stderr_task.abort();
            if let Some(cb) = observer.as_ref() {
                let final_seq = seq.fetch_add(1, Ordering::Relaxed);
                (cb)(ProcessStreamChunk {
                    channel: ProcessStreamChannel::Status,
                    chunk: String::new(),
                    seq: final_seq,
                    is_final: true,
                    exit_code: None,
                });
            }
            return Err(anyhow!(
                "Command timed out after {} seconds.",
                options.timeout.as_secs()
            ));
        }

        let stdout_bytes =
            join_stream_task_with_drain_timeout(stdout_task, "stdout", command).await?;
        let stderr_bytes =
            join_stream_task_with_drain_timeout(stderr_task, "stderr", command).await?;

        if let Some(cb) = observer.as_ref() {
            let final_seq = seq.fetch_add(1, Ordering::Relaxed);
            (cb)(ProcessStreamChunk {
                channel: ProcessStreamChannel::Status,
                chunk: String::new(),
                seq: final_seq,
                is_final: true,
                exit_code: status.code(),
            });
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

    pub async fn execute_in_dir_with_async_boundary(
        &self,
        command_id: Option<String>,
        command: &str,
        args: &[String],
        detach: bool,
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<CommandLaunchResult> {
        if detach {
            return self
                .execute_in_dir_with_options(command, args, detach, cwd, options)
                .await
                .map(CommandLaunchResult::Completed);
        }

        let wait_before_async = options.wait_before_async.unwrap_or_default();
        let retained_command_id = command_id.unwrap_or_else(|| self.generate_retained_command_id());
        let cwd_label = cwd.map(|path| path.to_string_lossy().to_string());
        let state = RetainedCommandState {
            snapshot: RetainedCommandSnapshot {
                command_id: retained_command_id.clone(),
                terminal_id: None,
                command: command.to_string(),
                args: args.to_vec(),
                cwd: cwd_label,
                created_at_ms: unix_timestamp_ms_now(),
                completed_at_ms: None,
                exit_code: None,
                running: true,
                output_tail: String::new(),
                output_truncated: false,
            },
            final_output: None,
            final_error: None,
        };
        let state = Arc::new(StdMutex::new(state));
        let completion = Arc::new(Notify::new());

        let mut cmd = Command::new(command);
        cmd.args(args);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn command '{}': {}", command, e))?;

        if let Some(stdin_data) = options.stdin_data.as_ref() {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(stdin_data).await?;
                stdin.flush().await?;
            }
        }

        let pid = child.id().unwrap_or_default();
        let stdin = Arc::new(Mutex::new(child.stdin.take()));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stdout for '{}'", command))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stderr for '{}'", command))?;

        let handle = Arc::new(RetainedCommandHandle {
            state: state.clone(),
            control: RetainedCommandControl::Process {
                pid,
                stdin: stdin.clone(),
            },
            completion: completion.clone(),
        });
        self.retained_commands
            .lock()
            .await
            .insert(retained_command_id.clone(), handle);

        let observer = build_retained_observer(state.clone(), options.stream_observer.clone());
        let command_label = command.to_string();
        tokio::spawn(async move {
            run_retained_process(
                command_label,
                options.timeout,
                child,
                stdout,
                stderr,
                stdin,
                observer,
                state,
                completion,
            )
            .await;
        });

        self.finalize_command_launch(&retained_command_id, wait_before_async)
            .await
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

    pub async fn execute_session_in_dir_with_async_boundary(
        &self,
        command_id: Option<String>,
        session_key: &str,
        command: &str,
        args: &[String],
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<CommandLaunchResult> {
        let key = session_key.trim();
        if key.is_empty() {
            return Err(anyhow!("Session key cannot be empty."));
        }

        let session = self.get_or_create_session(key, cwd).await?;
        let mut options = options;
        let wait_before_async = options.wait_before_async.unwrap_or_default();
        let retained_command_id = command_id.unwrap_or_else(|| self.generate_retained_command_id());
        #[cfg(unix)]
        let (stdin_bridge_path, stdin_bridge_handle) =
            create_retained_session_stdin_bridge(&retained_command_id)?;
        #[cfg(unix)]
        {
            options.stdin_bridge_path = Some(stdin_bridge_path.clone());
        }
        let state = Arc::new(StdMutex::new(RetainedCommandState {
            snapshot: RetainedCommandSnapshot {
                command_id: retained_command_id.clone(),
                terminal_id: Some(key.to_string()),
                command: command.to_string(),
                args: args.to_vec(),
                cwd: cwd.map(|path| path.to_string_lossy().to_string()),
                created_at_ms: unix_timestamp_ms_now(),
                completed_at_ms: None,
                exit_code: None,
                running: true,
                output_tail: String::new(),
                output_truncated: false,
            },
            final_output: None,
            final_error: None,
        }));
        let completion = Arc::new(Notify::new());
        let handle = Arc::new(RetainedCommandHandle {
            state: state.clone(),
            control: RetainedCommandControl::Session {
                session: session.clone(),
                #[cfg(unix)]
                stdin_bridge: Some(stdin_bridge_handle.clone()),
            },
            completion: completion.clone(),
        });
        self.retained_commands
            .lock()
            .await
            .insert(retained_command_id.clone(), handle);

        let command_label = command.to_string();
        let args_owned = args.to_vec();
        let cwd_owned = cwd.map(|path| path.to_path_buf());
        #[cfg(unix)]
        let initial_stdin_data = options.stdin_data.clone();
        tokio::spawn(async move {
            run_retained_session_command(
                session,
                command_label,
                args_owned,
                cwd_owned,
                options,
                state,
                completion,
                #[cfg(unix)]
                Some(stdin_bridge_path),
                #[cfg(unix)]
                Some(stdin_bridge_handle),
                #[cfg(unix)]
                initial_stdin_data,
            )
            .await;
        });

        self.finalize_command_launch(&retained_command_id, wait_before_async)
            .await
    }

    pub async fn retained_command_status(
        &self,
        command_id: &str,
    ) -> Result<RetainedCommandSnapshot> {
        let handle = self.retained_command(command_id).await?;
        snapshot_from_state(&handle.state)
    }

    pub async fn retained_command_input(
        &self,
        command_id: &str,
        input: &[u8],
    ) -> Result<RetainedCommandSnapshot> {
        if input.is_empty() {
            return self.retained_command_status(command_id).await;
        }

        let handle = self.retained_command(command_id).await?;
        if !snapshot_from_state(&handle.state)?.running {
            return Err(anyhow!("Command '{}' is no longer running.", command_id));
        }

        match &handle.control {
            RetainedCommandControl::Process { stdin, .. } => {
                let mut guard = stdin.lock().await;
                let stdin = guard
                    .as_mut()
                    .ok_or_else(|| anyhow!("Command '{}' no longer accepts stdin.", command_id))?;
                stdin.write_all(input).await?;
                stdin.flush().await?;
            }
            RetainedCommandControl::Session {
                session,
                #[cfg(unix)]
                stdin_bridge,
            } => {
                #[cfg(unix)]
                if let Some(stdin_bridge) = stdin_bridge.as_ref() {
                    write_session_stdin_bridge(stdin_bridge, input).await?;
                } else {
                    session.send_input(input).await?;
                }
                #[cfg(not(unix))]
                session.send_input(input).await?;
            }
        }

        self.retained_command_status(command_id).await
    }

    pub async fn retained_command_terminate(
        &self,
        command_id: &str,
    ) -> Result<RetainedCommandSnapshot> {
        let handle = self.retained_command(command_id).await?;
        if !snapshot_from_state(&handle.state)?.running {
            return self.retained_command_status(command_id).await;
        }

        match &handle.control {
            RetainedCommandControl::Process { pid, .. } => terminate_pid(*pid).await?,
            RetainedCommandControl::Session {
                session,
                #[cfg(unix)]
                    stdin_bridge: _,
            } => {
                session.interrupt_current_command().await?;
            }
        }

        self.retained_command_status(command_id).await
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

    async fn finalize_command_launch(
        &self,
        command_id: &str,
        wait_before_async: std::time::Duration,
    ) -> Result<CommandLaunchResult> {
        let Some(handle) = self.retained_commands.lock().await.get(command_id).cloned() else {
            return Err(anyhow!(
                "Retained command '{}' disappeared before launch finished.",
                command_id
            ));
        };

        if wait_before_async.is_zero() {
            return self
                .retained_command_status(command_id)
                .await
                .map(CommandLaunchResult::Retained);
        }

        if snapshot_from_state(&handle.state)?.running {
            match time::timeout(wait_before_async, handle.completion.notified()).await {
                Ok(_) => {}
                Err(_) => {
                    return self
                        .retained_command_status(command_id)
                        .await
                        .map(CommandLaunchResult::Retained)
                }
            }
        }

        let handle = self
            .retained_commands
            .lock()
            .await
            .remove(command_id)
            .ok_or_else(|| {
                anyhow!(
                    "Retained command '{}' disappeared before fast completion could be read.",
                    command_id
                )
            })?;
        let state = handle
            .state
            .lock()
            .map_err(|_| anyhow!("Retained command state mutex poisoned"))?;
        if let Some(error) = state.final_error.clone() {
            Err(anyhow!(error))
        } else {
            Ok(CommandLaunchResult::Completed(
                state.final_output.clone().unwrap_or_default(),
            ))
        }
    }

    async fn retained_command(&self, command_id: &str) -> Result<Arc<RetainedCommandHandle>> {
        let normalized = command_id.trim();
        if normalized.is_empty() {
            return Err(anyhow!("Command ID cannot be empty."));
        }
        self.retained_commands
            .lock()
            .await
            .get(normalized)
            .cloned()
            .ok_or_else(|| anyhow!("Unknown retained command '{}'.", normalized))
    }

    fn generate_retained_command_id(&self) -> String {
        let next = self.next_retained_command.fetch_add(1, Ordering::Relaxed);
        format!("cmd-{}", next)
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

fn snapshot_from_state(
    state: &Arc<StdMutex<RetainedCommandState>>,
) -> Result<RetainedCommandSnapshot> {
    state
        .lock()
        .map(|guard| guard.snapshot.clone())
        .map_err(|_| anyhow!("Retained command state mutex poisoned"))
}

fn build_retained_observer(
    state: Arc<StdMutex<RetainedCommandState>>,
    forward: Option<ProcessStreamObserver>,
) -> Option<ProcessStreamObserver> {
    Some(Arc::new(move |chunk: ProcessStreamChunk| {
        if matches!(
            chunk.channel,
            ProcessStreamChannel::Stdout | ProcessStreamChannel::Stderr
        ) && !chunk.chunk.is_empty()
        {
            if let Ok(mut guard) = state.lock() {
                if append_output_tail(&mut guard.snapshot.output_tail, &chunk.chunk) {
                    guard.snapshot.output_truncated = true;
                }
            }
        }
        if let Some(cb) = forward.as_ref() {
            (cb)(chunk);
        }
    }))
}

async fn run_retained_process(
    command: String,
    timeout: std::time::Duration,
    mut child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    observer: Option<ProcessStreamObserver>,
    state: Arc<StdMutex<RetainedCommandState>>,
    completion: Arc<Notify>,
) {
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

    let finish =
        |final_output: Option<String>, final_error: Option<String>, exit_code: Option<i32>| {
            if let Ok(mut guard) = state.lock() {
                guard.snapshot.running = false;
                guard.snapshot.completed_at_ms = Some(unix_timestamp_ms_now());
                guard.snapshot.exit_code = exit_code;
                guard.final_output = final_output;
                guard.final_error = final_error;
            }
            completion.notify_waiters();
        };

    let mut timed_out = false;
    let status = match time::timeout(timeout, child.wait()).await {
        Ok(wait_result) => match wait_result {
            Ok(status) => status,
            Err(error) => {
                let _ = stdin.lock().await.take();
                finish(None, Some(error.to_string()), None);
                return;
            }
        },
        Err(_) => {
            timed_out = true;
            let _ = child.kill().await;
            match time::timeout(POST_KILL_WAIT_TIMEOUT, child.wait()).await {
                Ok(wait_result) => match wait_result {
                    Ok(status) => status,
                    Err(error) => {
                        let _ = stdin.lock().await.take();
                        stdout_task.abort();
                        stderr_task.abort();
                        if let Some(cb) = observer.as_ref() {
                            let final_seq = seq.fetch_add(1, Ordering::Relaxed);
                            (cb)(ProcessStreamChunk {
                                channel: ProcessStreamChannel::Status,
                                chunk: String::new(),
                                seq: final_seq,
                                is_final: true,
                                exit_code: None,
                            });
                        }
                        finish(None, Some(error.to_string()), None);
                        return;
                    }
                },
                Err(_) => {
                    let _ = stdin.lock().await.take();
                    stdout_task.abort();
                    stderr_task.abort();
                    if let Some(cb) = observer.as_ref() {
                        let final_seq = seq.fetch_add(1, Ordering::Relaxed);
                        (cb)(ProcessStreamChunk {
                            channel: ProcessStreamChannel::Status,
                            chunk: String::new(),
                            seq: final_seq,
                            is_final: true,
                            exit_code: None,
                        });
                    }
                    finish(
                        None,
                        Some(format!(
                            "Command timed out after {} seconds and could not be terminated within {} seconds.",
                            timeout.as_secs(),
                            POST_KILL_WAIT_TIMEOUT.as_secs()
                        )),
                        None,
                    );
                    return;
                }
            }
        }
    };

    if timed_out {
        stdout_task.abort();
        stderr_task.abort();
        if let Some(cb) = observer.as_ref() {
            let final_seq = seq.fetch_add(1, Ordering::Relaxed);
            (cb)(ProcessStreamChunk {
                channel: ProcessStreamChannel::Status,
                chunk: String::new(),
                seq: final_seq,
                is_final: true,
                exit_code: None,
            });
        }
        let _ = stdin.lock().await.take();
        finish(
            None,
            Some(format!(
                "Command timed out after {} seconds.",
                timeout.as_secs()
            )),
            None,
        );
        return;
    }

    let stdout_bytes =
        match join_stream_task_with_drain_timeout(stdout_task, "stdout", &command).await {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = stdin.lock().await.take();
                finish(None, Some(error.to_string()), status.code());
                return;
            }
        };
    let stderr_bytes =
        match join_stream_task_with_drain_timeout(stderr_task, "stderr", &command).await {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = stdin.lock().await.take();
                finish(None, Some(error.to_string()), status.code());
                return;
            }
        };

    if let Some(cb) = observer.as_ref() {
        let final_seq = seq.fetch_add(1, Ordering::Relaxed);
        (cb)(ProcessStreamChunk {
            channel: ProcessStreamChannel::Status,
            chunk: String::new(),
            seq: final_seq,
            is_final: true,
            exit_code: status.code(),
        });
    }

    let _ = stdin.lock().await.take();
    let stdout_text = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).to_string();
    let output = if status.success() {
        combine_success_output(&stdout_text, &stderr_text)
    } else {
        format!("Command failed: {}\nStderr: {}", status, stderr_text)
    };
    finish(Some(output), None, status.code());
}

async fn run_retained_session_command(
    session: Arc<ShellSession>,
    command: String,
    args: Vec<String>,
    cwd: Option<std::path::PathBuf>,
    options: CommandExecutionOptions,
    state: Arc<StdMutex<RetainedCommandState>>,
    completion: Arc<Notify>,
    #[cfg(unix)] stdin_bridge_path: Option<PathBuf>,
    #[cfg(unix)] stdin_bridge: Option<SessionStdinBridgeHandle>,
    #[cfg(unix)] initial_stdin_data: Option<Vec<u8>>,
) {
    #[cfg(unix)]
    if let (Some(stdin_bridge), Some(initial_stdin_data)) =
        (stdin_bridge.clone(), initial_stdin_data.clone())
    {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = write_session_stdin_bridge(&stdin_bridge, &initial_stdin_data).await;
        });
    }

    let result = ShellSession::exec(
        &session,
        &command,
        &args,
        cwd.as_deref(),
        CommandExecutionOptions {
            wait_before_async: None,
            ..options
        },
    )
    .await;

    #[cfg(unix)]
    {
        if let Some(stdin_bridge) = stdin_bridge.as_ref() {
            if let Ok(mut guard) = stdin_bridge.lock() {
                *guard = None;
            }
        }
        if let Some(path) = stdin_bridge_path.as_ref() {
            let _ = std::fs::remove_file(path);
        }
    }

    if let Ok(mut guard) = state.lock() {
        guard.snapshot.running = false;
        guard.snapshot.completed_at_ms = Some(unix_timestamp_ms_now());
        match result {
            Ok(output) => {
                guard.snapshot.exit_code = if output.starts_with("Command failed: exit status:") {
                    output.lines().find_map(|line| {
                        line.split_once("exit status:")
                            .and_then(|(_, value)| value.trim().parse::<i32>().ok())
                    })
                } else {
                    Some(0)
                };
                if append_output_tail(&mut guard.snapshot.output_tail, &output) {
                    guard.snapshot.output_truncated = true;
                }
                guard.final_output = Some(output);
                guard.final_error = None;
            }
            Err(error) => {
                guard.snapshot.exit_code = None;
                guard.final_output = None;
                guard.final_error = Some(error.to_string());
            }
        }
    }
    completion.notify_waiters();
}

async fn terminate_pid(pid: u32) -> Result<()> {
    if pid == 0 {
        return Err(anyhow!("Cannot terminate a process without a PID."));
    }

    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if rc == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH)) {
            return Ok(());
        }
        return Err(anyhow!("Failed to terminate PID {}: {}", pid, error));
    }

    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args([
                "/PID".to_string(),
                pid.to_string(),
                "/T".to_string(),
                "/F".to_string(),
            ])
            .status()
            .await
            .map_err(|error| anyhow!("Failed to spawn taskkill for PID {}: {}", pid, error))?;
        if status.success() {
            return Ok(());
        }
        return Err(anyhow!(
            "taskkill failed for PID {} with status {}",
            pid,
            status
        ));
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "Process termination is unsupported on this platform."
    ))
}
