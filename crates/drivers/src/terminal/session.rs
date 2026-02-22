use anyhow::{anyhow, Result};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time;

#[cfg(unix)]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
#[cfg(unix)]
use std::io::{BufReader as StdBufReader, Read as StdRead, Write as StdWrite};

#[cfg(windows)]
use std::process::Stdio;
#[cfg(windows)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::process::Command;

#[cfg(windows)]
use super::scripts::{build_cmd_command_line, build_session_script_windows, resolve_comspec_path};
#[cfg(unix)]
use super::scripts::{build_session_script, build_shell_command_line, resolve_shell_path};
use super::types::{
    CommandExecutionOptions, ProcessStreamChannel, ProcessStreamChunk, ProcessStreamObserver,
};

pub(crate) struct ShellSession {
    exec_lock: Mutex<()>,
    next_marker: AtomicU64,

    // Unix: PTY-backed session so TTY-gated CLIs work in `sys__exec_session`.
    #[cfg(unix)]
    child: std::sync::Mutex<Box<dyn portable_pty::Child + Send>>,
    #[cfg(unix)]
    stdin: std::sync::Mutex<Box<dyn StdWrite + Send>>,
    #[cfg(unix)]
    stdout: std::sync::Mutex<StdBufReader<Box<dyn StdRead + Send>>>,

    // Windows: keep existing pipe-based cmd.exe session.
    #[cfg(windows)]
    child: Mutex<tokio::process::Child>,
    #[cfg(windows)]
    stdin: Mutex<tokio::process::ChildStdin>,
    #[cfg(windows)]
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
}

impl ShellSession {
    pub(crate) async fn spawn(cwd: Option<&Path>) -> Result<Self> {
        #[cfg(unix)]
        {
            let shell = resolve_shell_path();
            let pty_system = native_pty_system();

            let pair = pty_system
                .openpty(PtySize {
                    rows: 24,
                    cols: 120,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| anyhow!("Failed to open pty: {}", e))?;

            let mut cmd = CommandBuilder::new(shell);
            // Avoid user rc files that may emit prompts or alter shell semantics; we want a
            // deterministic session transport.
            cmd.arg("--noprofile");
            cmd.arg("--norc");
            cmd.arg("-s");
            cmd.env("TERM", "dumb");
            cmd.env("PS1", "");
            cmd.env("PROMPT_COMMAND", "");
            if let Some(dir) = cwd {
                cmd.cwd(dir.as_os_str());
            }

            let child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|e| anyhow!("Failed to spawn PTY shell session: {}", e))?;

            let reader = pair
                .master
                .try_clone_reader()
                .map_err(|e| anyhow!("Failed to clone PTY reader: {}", e))?;
            let writer = pair
                .master
                .take_writer()
                .map_err(|e| anyhow!("Failed to take PTY writer: {}", e))?;

            Ok(Self {
                exec_lock: Mutex::new(()),
                next_marker: AtomicU64::new(1),
                child: std::sync::Mutex::new(child),
                stdin: std::sync::Mutex::new(writer),
                stdout: std::sync::Mutex::new(StdBufReader::new(reader)),
            })
        }

        #[cfg(windows)]
        {
            let comspec = resolve_comspec_path();
            let mut cmd = Command::new(comspec);
            cmd.arg("/Q");
            cmd.arg("/D");
            if let Some(dir) = cwd {
                cmd.current_dir(dir);
            }

            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            // We'll redirect stderr to stdout inside the command line (`2>&1`) to avoid needing
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
                next_marker: AtomicU64::new(1),
                child: Mutex::new(child),
                stdin: Mutex::new(stdin),
                stdout: Mutex::new(BufReader::new(stdout)),
            };

            // Suppress prompt/echo for deterministic output parsing.
            {
                let mut stdin = session.stdin.lock().await;
                stdin.write_all(b"@echo off\r\n").await?;
                stdin.write_all(b"set PROMPT=\r\n").await?;
                stdin.flush().await?;
            }

            Ok(session)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = cwd;
            Err(anyhow!(
                "Persistent shell sessions are not supported on this platform."
            ))
        }
    }

    pub(crate) async fn terminate(self: &Arc<Self>) -> Result<()> {
        let _guard = self.exec_lock.lock().await;

        #[cfg(unix)]
        {
            let session = Arc::clone(self);
            let _ = tokio::task::spawn_blocking(move || {
                let mut child = session
                    .child
                    .lock()
                    .map_err(|_| anyhow!("PTY child mutex poisoned"))?;
                let _ = child.kill();
                let _ = child.wait();
                Ok::<(), anyhow::Error>(())
            })
            .await
            .map_err(|e| anyhow!("PTY terminate join failed: {}", e))??;
            return Ok(());
        }

        #[cfg(windows)]
        {
            let mut child = self.child.lock().await;
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Ok(());
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    pub(crate) async fn exec(
        self: &Arc<Self>,
        command: &str,
        args: &[String],
        cwd: Option<&Path>,
        options: CommandExecutionOptions,
    ) -> Result<String> {
        #[cfg(unix)]
        {
            let _guard = self.exec_lock.lock().await;

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
            let observer_worker = observer.clone();
            let seq_worker = Arc::clone(&seq);

            let mut timed_out = false;
            let session = Arc::clone(self);
            let run = tokio::task::spawn_blocking(move || -> Result<(String, i32)> {
                let script = script;
                let sent_lines: std::collections::HashSet<String> = script
                    .lines()
                    .map(|line| line.trim_end_matches('\r').to_string())
                    .collect();

                {
                    let mut stdin = session
                        .stdin
                        .lock()
                        .map_err(|_| anyhow!("PTY stdin mutex poisoned"))?;
                    stdin.write_all(script.as_bytes())?;
                    stdin.flush()?;
                }

                let mut stdout = session
                    .stdout
                    .lock()
                    .map_err(|_| anyhow!("PTY stdout mutex poisoned"))?;

                let mut buf = [0u8; 2048];
                let mut pending = String::new();
                let mut output = String::new();
                let mut exit_code: Option<i32> = None;

                loop {
                    let read = stdout.read(&mut buf)?;
                    if read == 0 {
                        return Err(anyhow!(
                            "Shell session ended before emitting completion marker."
                        ));
                    }

                    let chunk = String::from_utf8_lossy(&buf[..read]).to_string();
                    if let Some(cb) = observer_worker.as_ref() {
                        let seq_value = seq_worker.fetch_add(1, Ordering::Relaxed);
                        (cb)(ProcessStreamChunk {
                            channel: ProcessStreamChannel::Stdout,
                            chunk: chunk.clone(),
                            seq: seq_value,
                            is_final: false,
                            exit_code: None,
                        });
                    }

                    pending.push_str(&chunk);

                    // Process complete lines only. This avoids prematurely matching markers inside
                    // echoed input lines like: `echo "__IOI_DONE:...__"`.
                    while let Some(idx) = {
                        let nl = pending.find('\n');
                        let cr = pending.find('\r');
                        match (nl, cr) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        }
                    } {
                        let line = pending[..idx].to_string();
                        pending.drain(..=idx);

                        let trimmed = line.trim_end_matches('\r');
                        if trimmed.trim().is_empty() {
                            continue;
                        }

                        // PTY sessions may have input echo enabled; filter out echoed script lines.
                        if sent_lines.contains(trimmed) {
                            continue;
                        }

                        if trimmed == done_marker {
                            let code =
                                exit_code.ok_or_else(|| anyhow!("Missing exit code marker."))?;
                            return Ok((output, code));
                        }

                        if let Some(rest) = trimmed.strip_prefix(&rc_prefix) {
                            exit_code = rest.trim().parse::<i32>().ok();
                            continue;
                        }

                        output.push_str(trimmed);
                        output.push('\n');
                    }
                }
            });

            let (output, exit_code) = match time::timeout(options.timeout, run).await {
                Ok(joined) => joined.map_err(|e| anyhow!("PTY exec join failed: {}", e))??,
                Err(_) => {
                    timed_out = true;
                    // Kill the session; it's unsafe to keep using a potentially wedged shell.
                    drop(_guard);
                    self.terminate().await?;
                    (String::new(), -1)
                }
            };

            emit_final_status(&observer, &seq, timed_out, exit_code);

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

        #[cfg(windows)]
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
            let end_label = format!("__ioi_end_{}__", marker_id);

            let cmd_line = build_cmd_command_line(trimmed, args);

            let mut stdin_temp_path = None;
            if let Some(bytes) = options.stdin_data.as_deref() {
                let path = std::env::temp_dir().join(format!(
                    "ioi_stdin_{}_{}.tmp",
                    std::process::id(),
                    marker_id
                ));
                // Best-effort: if we fail to stage stdin, fall back to no-stdin execution.
                if tokio::fs::write(&path, bytes).await.is_ok() {
                    stdin_temp_path = Some(path);
                }
            }

            let script = build_session_script_windows(
                cwd,
                &cmd_line,
                stdin_temp_path.as_deref(),
                &rc_prefix,
                &done_marker,
                &end_label,
            );

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

            if let Some(path) = stdin_temp_path.as_ref() {
                let _ = tokio::fs::remove_file(path).await;
            }

            emit_final_status(&observer, &seq, timed_out, exit_code);

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

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (command, args, cwd, options);
            Err(anyhow!(
                "Persistent shell sessions are not supported on this platform."
            ))
        }
    }
}

fn emit_final_status(
    observer: &Option<ProcessStreamObserver>,
    seq: &Arc<AtomicU64>,
    timed_out: bool,
    exit_code: i32,
) {
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
}
