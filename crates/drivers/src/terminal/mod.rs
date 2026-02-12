// Path: crates/drivers/src/terminal/mod.rs

use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use wait_timeout::ChildExt;

pub struct TerminalDriver;

impl TerminalDriver {
    pub fn new() -> Self {
        Self
    }

    /// Executes a command.
    /// If `detach` is true, it spawns the process and returns immediately (for GUI apps).
    /// If `detach` is false, it waits up to 5 seconds for the command to finish.
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
        let mut cmd = Command::new(command);
        cmd.args(args);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }

        // Security: In a real production build, this is where you would sandbox the process.
        // For local mode, we run it directly but enforce a timeout or detach policy.

        if detach {
            // Detached mode: Spawn and forget (letting it run in background)
            // Redirect stdout/stderr to null to avoid holding pipe handles which might hang the parent
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
            cmd.stdin(std::process::Stdio::null());

            // [FIX] On Unix, create a new session to prevent the child from receiving
            // SIGINT when the parent (ioi-local) is Ctrl+C'd.
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                unsafe {
                    cmd.pre_exec(|| {
                        // setsid() creates a new session. The process becomes the session leader
                        // of a new process group and has no controlling terminal.
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
            let pid = child.id();
            return Ok(format!(
                "Launched background process '{}' (PID: {})",
                command, pid
            ));
        }

        // Standard blocking mode (with timeout)
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn command '{}': {}", command, e))?;

        let timeout = Duration::from_secs(5);

        match child.wait_timeout(timeout)? {
            Some(status) => {
                let output = child.wait_with_output()?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if status.success() {
                    Ok(stdout.to_string())
                } else {
                    Ok(format!("Command failed: {}\nStderr: {}", status, stderr))
                }
            }
            None => {
                child.kill()?;
                child.wait()?;
                Err(anyhow!(
                    "Command timed out after 5 seconds. Use 'detach: true' for long-running apps."
                ))
            }
        }
    }
}
