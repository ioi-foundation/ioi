// Path: crates/forge/src/testing/signing_oracle.rs
use anyhow::{anyhow, Result};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
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

        if let Some(seed) = key_seed {
            std::fs::write(&key_path, seed)?;
        } else {
            let kp = Ed25519KeyPair::generate()?;
            std::fs::write(&key_path, kp.private_key().as_bytes())?;
        }

        // Pick a random port
        let port = portpicker::pick_unused_port().ok_or(anyhow!("No free ports"))?;
        let addr = format!("127.0.0.1:{}", port);

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // We are in crates/forge. Workspace root is ../../
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

        let process = Command::new(binary_path)
            .arg("--state-file")
            .arg(&state_path)
            .arg("--key-file")
            .arg(&key_path)
            .arg("--listen-addr")
            .arg(&addr)
            // Suppress logs unless test fails/captures them, or set to info/debug for verbose
            .env("RUST_LOG", "error")
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

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
            return Err(anyhow!("Timed out waiting for ioi-signer to bind to {}", addr));
        }

        Ok(Self {
            process,
            url: format!("http://{}", addr),
            key_path,
            _temp_dir: temp_dir,
        })
    }

    pub fn get_keypair(&self) -> Result<libp2p::identity::Keypair> {
        let seed = std::fs::read(&self.key_path)?;
        let oracle_sk = Ed25519PrivateKey::from_bytes(&seed)?;
        let oracle_kp = Ed25519KeyPair::from_private_key(&oracle_sk)?;

        let oracle_pk_bytes = oracle_kp.public_key().to_bytes();

        let mut libp2p_bytes = [0u8; 64];
        libp2p_bytes[..32].copy_from_slice(&seed);
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