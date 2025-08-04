// Path: crates/forge/tests/container_e2e.rs

use anyhow::Result;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

struct DockerCompose {
    file_path: String,
}

impl DockerCompose {
    fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }
    fn up(&self) -> Result<()> {
        let status = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.file_path)
            .arg("up")
            .arg("--build")
            .arg("-d")
            .status()?;
        if !status.success() {
            anyhow::bail!("docker-compose up failed");
        }
        std::thread::sleep(Duration::from_secs(10));
        Ok(())
    }
    fn down(&self) -> Result<()> {
        Command::new("docker-compose")
            .arg("-f")
            .arg(&self.file_path)
            .arg("down")
            .output()?;
        Ok(())
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        if let Err(e) = self.down() {
            eprintln!("Failed to run docker-compose down: {}", e);
        }
    }
}

async fn tail_logs_for_pattern(
    container_name: &str,
    pattern: &str,
    timeout_duration: Duration,
) -> Result<()> {
    let mut child = TokioCommand::new("docker")
        .args(["logs", "-f", container_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // FIX: Read from stderr instead of stdout
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr).lines();

    timeout(timeout_duration, async {
        while let Ok(Some(line)) = reader.next_line().await {
            println!("[{}] {}", container_name, line);
            if line.contains(pattern) {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("Log stream ended before pattern found"))
    })
    .await??;
    child.kill().await?;
    Ok(())
}

#[tokio::test]
async fn test_container_attestation_and_communication() -> Result<()> {
    // 1. LAUNCH the three-container validator
    let compose = DockerCompose::new("../../docker/standard_validator/docker-compose.yml");
    compose.up()?;

    // 2. ASSERT startup and attestation server
    tail_logs_for_pattern(
        "guardian",
        "mTLS attestation server listening on 0.0.0.0:8443",
        Duration::from_secs(20),
    )
    .await?;

    // 3. ASSERT that both containers connect and attest
    tail_logs_for_pattern(
        "orchestration",
        "Successfully attested to Guardian",
        Duration::from_secs(20),
    )
    .await?;
    tail_logs_for_pattern(
        "workload",
        "Successfully attested to Guardian",
        Duration::from_secs(20),
    )
    .await?;

    // 4. ASSERT that the Guardian received the connections
    // We expect two successful handshakes.
    tail_logs_for_pattern(
        "guardian",
        "Received successful attestation handshake",
        Duration::from_secs(20),
    )
    .await?;
    tail_logs_for_pattern(
        "guardian",
        "Received successful attestation handshake",
        Duration::from_secs(20),
    )
    .await?;

    Ok(())
}
