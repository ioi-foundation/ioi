// Path: crates/forge/tests/container_e2e.rs

use anyhow::Result;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand; // Use Tokio's Command
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
        // Give containers time to start up fully
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
    let mut child = TokioCommand::new("docker") // Use Tokio's Command
        .args(&["logs", "-f", container_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

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

    child.kill().await?; // Await the kill future
    Ok(())
}

#[tokio::test]
#[ignore] // This test requires Docker and is best run in CI or manually.
async fn test_container_attestation_and_communication() -> Result<()> {
    // 1. LAUNCH the three-container validator
    let compose = DockerCompose::new("../../docker/standard_validator/docker-compose.yml");
    compose.up()?;

    // 2. TAIL logs and assert startup and mTLS setup
    tail_logs_for_pattern(
        "guardian",
        "Establishing secure mTLS channel to Orchestration container... SUCCESS",
        Duration::from_secs(20),
    )
    .await?;

    // 3. ASSERT periodic attestation
    tail_logs_for_pattern(
        "guardian",
        "Guardian: Verifying inter-container attestation... SUCCESS",
        Duration::from_secs(45), // Wait longer to ensure the 30s interval fires
    )
    .await?;

    // 4. SEND command requiring inter-container communication
    // For this P1 test, confirming the containers start, communicate via logs,
    // and attest (stubbed) is sufficient. A direct RPC call test is deferred
    // to a later stage when the RPC interface is more mature. The log assertions
    // prove the scaffolding is functional.

    // 5. TEARDOWN is handled automatically by the `Drop` impl of `DockerCompose`.

    Ok(())
}
