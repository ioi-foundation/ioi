// Path: crates/forge/tests/security_e2e.rs
#![cfg(all(feature = "validator-bins"))]

use anyhow::Result;
// FIX: Import Sha256 directly from dcrypt, as ioi_crypto does not re-export it
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_forge::testing::build_test_artifacts;
use ioi_validator::common::GuardianContainer;
use ioi_validator::config::GuardianConfig;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use tempfile::tempdir;

/// Helper to get path to a built binary in target/release
fn get_binary_path(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let path = root.join("target/release").join(name);
    if !path.exists() {
        panic!(
            "Binary {} not found at {:?}. Run 'cargo build --release' first.",
            name, path
        );
    }
    path
}

#[tokio::test]
async fn test_guardian_binary_integrity_enforcement() -> Result<()> {
    // 0. Rebuild Validator Binaries to ensure they have the latest code changes
    // This is crucial because we modified the Guardian source code to support test overrides,
    // and the test runs the binary from target/release which might be stale.
    println!("--- Rebuilding Guardian Binary ---");
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "ioi-node",
            "--bin",
            "guardian",
            "--features",
            "validator-bins",
        ])
        .status()
        .expect("Failed to execute cargo build for guardian");
    assert!(status.success(), "Failed to rebuild guardian binary");

    // 1. Setup artifacts
    build_test_artifacts(); // Ensures binaries exist
    let temp_dir = tempdir()?;
    let bin_dir = temp_dir.path().to_path_buf();

    // 2. Copy binaries to temp dir to simulate a deployment
    let orch_src = get_binary_path("orchestration");
    let work_src = get_binary_path("workload");

    let orch_dst = bin_dir.join("orchestration");
    let work_dst = bin_dir.join("workload");

    std::fs::copy(&orch_src, &orch_dst)?;
    std::fs::copy(&work_src, &work_dst)?;

    // 3. Compute Hashes
    let orch_bytes = std::fs::read(&orch_dst)?;
    let work_bytes = std::fs::read(&work_dst)?;
    let orch_hash = hex::encode(Sha256::digest(&orch_bytes)?);
    let work_hash = hex::encode(Sha256::digest(&work_bytes)?);

    // 4. Test Case: Valid Configuration
    // We fake "current_exe" logic by manually pointing to the temp dir in the check if possible,
    // BUT Guardian::verify_binaries uses std::env::current_exe().
    // To test this unit-style without spawning a process, we can instantiate GuardianContainer
    // and call a modified check function, OR we can use the public API if we trick it.
    // Since we can't easily mock current_exe safely in parallel tests, we will mock the logic
    // by creating a mock structure or checking the logic directly if we exposed `check_file`.
    //
    // Better approach: Spawn `guardian` process with a config file in the temp dir.
    // However, `guardian` binary expects to be in the same folder as `orchestration`.
    // So we copy `guardian` there too.

    let guard_src = get_binary_path("guardian");
    let guard_dst = bin_dir.join("guardian");
    std::fs::copy(&guard_src, &guard_dst)?;

    // Create valid config
    let valid_config_path = bin_dir.join("guardian.toml");
    // [FIX] Use binary_dir_override to point the guardian to the temp dir, ensuring it checks the copied binaries.
    let valid_config = format!(
        r#"
        signature_policy = "Fixed"
        enforce_binary_integrity = true
        approved_orchestrator_hash = "{}"
        approved_workload_hash = "{}"
        binary_dir_override = "{}"
        "#,
        orch_hash,
        work_hash,
        bin_dir.to_string_lossy()
    );
    std::fs::write(&valid_config_path, valid_config)?;

    // Spawn Guardian and expect it to start (or at least pass init)
    // It will fail binding ports eventually or connecting to things, but if it passes binary check
    // it proceeds. If it fails check, it panics immediately.
    let mut valid_proc = std::process::Command::new(&guard_dst)
        .arg("--config-dir")
        .arg(&bin_dir)
        .arg("--agentic-model-path")
        .arg("dummy_model.bin") // Dummy path
        .env("CERTS_DIR", bin_dir.to_string_lossy().as_ref())
        .env("TELEMETRY_ADDR", "127.0.0.1:0") // Random port
        .env("GUARDIAN_LISTEN_ADDR", "127.0.0.1:0")
        .spawn()?;

    // Give it a moment. If it crashes immediately, it failed.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    if let Ok(Some(status)) = valid_proc.try_wait() {
        panic!("Valid guardian process exited unexpectedly with {}", status);
    }
    valid_proc.kill()?;
    let _ = valid_proc.wait(); // Ensure resources are released

    // 5. Test Case: Tampered Binary
    // Append a byte to orchestration
    let mut f = std::fs::OpenOptions::new().append(true).open(&orch_dst)?;
    f.write_all(b"\0")?;
    f.sync_all()?; // Force write to disk
    drop(f);

    // Debug: Verify the hash actually changed
    let tampered_bytes = std::fs::read(&orch_dst)?;
    let tampered_hash = hex::encode(Sha256::digest(&tampered_bytes)?);
    assert_ne!(
        orch_hash, tampered_hash,
        "Test setup error: Orchestration binary modification failed to change hash!"
    );

    // Spawn again
    // We use spawn + polling instead of output() to avoid hanging if the security check fails (false negative)
    let mut tampered_proc = std::process::Command::new(&guard_dst)
        .arg("--config-dir")
        .arg(&bin_dir)
        .arg("--agentic-model-path")
        .arg("dummy_model.bin")
        .env("CERTS_DIR", bin_dir.to_string_lossy().as_ref())
        .env("TELEMETRY_ADDR", "127.0.0.1:0")
        .env("GUARDIAN_LISTEN_ADDR", "127.0.0.1:0")
        .env("RUST_LOG", "info") // Make sure we get info logs
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(status)) = tampered_proc.try_wait() {
            // Process exited, check the output
            let output = tampered_proc.wait_with_output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                !status.success(),
                "Tampered guardian should exit with error code"
            );
            assert!(
                stderr.contains("SECURITY VIOLATION") || stderr.contains("hash mismatch"),
                "Guardian did not detect tampered binary. Stderr: {}",
                stderr
            );
            break;
        }

        if start.elapsed() > std::time::Duration::from_secs(5) {
            let _ = tampered_proc.kill();

            // Attempt to read what it said
            let mut stderr_out = String::new();
            if let Some(mut stderr) = tampered_proc.stderr.take() {
                let _ = stderr.read_to_string(&mut stderr_out);
            }

            panic!(
                "Guardian failed to detect binary tampering (process continued running instead of exiting).\nGuardian Logs:\n{}",
                stderr_out
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}
