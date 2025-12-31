// Path: crates/cli/src/testing/signing_oracle.rs
use anyhow::{anyhow, Result};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::key_store::encrypt_key; // NEW
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use std::io::Write; // NEW
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

/// Manages the lifecycle of a local `ioi-signer` process (the A-DMFT Signing Oracle) for testing.
pub struct SigningOracleGuard {
    process: std::process::Child,
    pub url: String,
    pub key_path: PathBuf,
    _temp_dir: TempDir, // Keeps state file alive
}

impl SigningOracleGuard {
    pub fn spawn(key_seed: Option<&[u8]>) -> Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let state_path = temp_dir.path().join("signer_state.bin");
        let key_path = temp_dir.path().join("signer_key.seed");

        // Default test password
        let password = "test-password";

        let seed_bytes = if let Some(seed) = key_seed {
            seed.to_vec()
        } else {
            let kp = Ed25519KeyPair::generate()?;
            kp.private_key().as_bytes().to_vec()
        };

        // [FIX] Encrypt the key before writing to disk
        let encrypted_key = encrypt_key(&seed_bytes, password)?;
        std::fs::write(&key_path, encrypted_key)?;

        // Pick a random port
        let port = portpicker::pick_unused_port().ok_or(anyhow!("No free ports"))?;
        let addr = format!("127.0.0.1:{}", port);

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // We are in crates/cli. Workspace root is ../../
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        // Check release first, then debug
        let binary_path_release = workspace_root.join("target/release/ioi-signer");
        let binary_path_debug = workspace_root.join("target/debug/ioi-signer");

        let binary_path = if binary_path_release.exists() {
            binary_path_release
        } else if binary_path_debug.exists() {
            binary_path_debug
        } else {
            return Err(anyhow!("ioi-signer binary not found. Run `cargo build -p ioi-node --bin ioi-signer --features validator-bins` first."));
        };

        let mut process = Command::new(binary_path)
            .arg("--state-file")
            .arg(&state_path)
            .arg("--key-file")
            .arg(&key_path)
            .arg("--listen-addr")
            .arg(&addr)
            .env("RUST_LOG", "error")
            .stdin(Stdio::piped()) // [FIX] Pipe stdin for password
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        // [FIX] Write password to stdin immediately
        if let Some(mut stdin) = process.stdin.take() {
            stdin.write_all(password.as_bytes())?;
            // Close stdin to signal EOF (some readers might wait for newline or EOF)
        }

        // Wait for the port to be open
        let start = std::time::Instant::now();
        let mut connected = false;
        while start.elapsed() < Duration::from_secs(5) {
            if std::net::TcpStream::connect(&addr).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if !connected {
            // If failed, try to read stderr to see why
            let _ = process.kill();
            let output = process.wait_with_output()?;
            return Err(anyhow!(
                "Timed out waiting for ioi-signer. Stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            process,
            url: format!("http://{}", addr),
            key_path,
            _temp_dir: temp_dir,
        })
    }

    pub fn get_keypair(&self) -> Result<libp2p::identity::Keypair> {
        // To return the keypair to the test, we must decrypt what we wrote.
        // In a real test scenario, we know the password ("test-password").
        let encrypted = std::fs::read(&self.key_path)?;
        let decrypted = ioi_crypto::key_store::decrypt_key(&encrypted, "test-password")?;

        let oracle_sk = Ed25519PrivateKey::from_bytes(&decrypted.0)?;
        let oracle_kp = Ed25519KeyPair::from_private_key(&oracle_sk)?;

        let oracle_pk_bytes = oracle_kp.public_key().to_bytes();

        let mut libp2p_bytes = [0u8; 64];
        libp2p_bytes[..32].copy_from_slice(&decrypted.0);
        libp2p_bytes[32..].copy_from_slice(&oracle_pk_bytes);
        Ok(libp2p::identity::Keypair::from(
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut libp2p_bytes)?,
        ))
    }
}

impl Drop for SigningOracleGuard {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
