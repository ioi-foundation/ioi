// crates/drivers/src/terminal/mod.rs

use anyhow::{anyhow, Result};
use std::process::Command;
use std::time::Duration;
use wait_timeout::ChildExt; // You may need to add 'wait-timeout' to drivers/Cargo.toml

pub struct TerminalDriver;

impl TerminalDriver {
    pub fn new() -> Self {
        Self
    }

    /// Executes a command and returns stdout/stderr.
    /// Includes a timeout to prevent the agent from hanging the Kernel.
    pub async fn execute(&self, command: &str, args: &[String]) -> Result<String> {
        // Security: In a real production build, this is where you would sandbox the process.
        // For local mode, we run it directly but enforce a timeout.
        
        let mut child = Command::new(command)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
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
                Err(anyhow!("Command timed out after 5 seconds"))
            }
        }
    }
}