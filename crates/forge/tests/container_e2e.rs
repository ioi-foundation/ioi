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
        .stderr(Stdio::piped()) // Capture stderr
        .spawn()?;

    // FIX: Read from stderr where the application logs are.
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
async fn test_secure_channel_and_attestation_flow() -> Result<()> {
    // 1. LAUNCH the three-container validator
    let compose = DockerCompose::new("../../docker/standard_validator/docker-compose.yml");
    compose.up()?;

    // 2. ASSERT Guardian server starts
    tail_logs_for_pattern("guardian", "Guardian: mTLS server listening", Duration::from_secs(20)).await?;

    // 3. ASSERT Orchestration connects and establishes channel
    tail_logs_for_pattern(
        "orchestration",
        "Security channel from 'orchestration' to 'guardian' established",
        Duration::from_secs(20),
    )
    .await?;
    
    // 4. ASSERT Workload connects and establishes channel
    tail_logs_for_pattern("workload", "Security channel from 'workload' to 'guardian' established", Duration::from_secs(20)).await?;

    // 5. ASSERT Guardian accepts both connections
    tail_logs_for_pattern("guardian", "Security channel from 'guardian' to 'orchestration' accepted", Duration::from_secs(20)).await?;
    tail_logs_for_pattern("guardian", "Security channel from 'guardian' to 'workload' accepted", Duration::from_secs(20)).await?;
    
    // --- NEW: VERIFY ATTESTATION FLOW ---

    // 6. ASSERT Orchestration sends its report
    tail_logs_for_pattern("orchestration", "Attestation report sent", Duration::from_secs(20)).await?;

    // 7. ASSERT Guardian validates the Orchestration report
    tail_logs_for_pattern("guardian", "Attestation from 'orchestration' is VALID", Duration::from_secs(20)).await?;
    
    // 8. ASSERT Workload sends its report
    tail_logs_for_pattern("workload", "Attestation report sent", Duration::from_secs(20)).await?;

    // 9. ASSERT Guardian validates the Workload report
    tail_logs_for_pattern("guardian", "Attestation from 'workload' is VALID", Duration::from_secs(20)).await?;

    Ok(())
}