// Path: crates/validator/src/common/guardian.rs

//! Implements the Guardian container, the root of trust for the validator,
//! and the GuardianSigner abstraction for Oracle-anchored signing.

use crate::config::GuardianConfig;
use crate::standard::workload::ipc::create_ipc_server_config;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
// FIX: Import Sha256 and HashFunction directly from dcrypt
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::validator::Container;
use ioi_client::security::SecurityChannel;
use ioi_crypto::key_store::{decrypt_key, encrypt_key};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_ipc::IpcClientType;
use ioi_types::app::SignatureBundle;
use ioi_types::error::ValidatorError;
use rcgen::{Certificate, CertificateParams, KeyUsagePurpose, SanType};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::AsyncReadExt;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor, TlsStream};

// --- Signing Abstraction for Oracle-Anchored Consensus ---

/// Abstract interface for a signing authority.
/// This allows the Orchestrator to use either a local key (for development)
/// or a remote, cryptographically isolated Oracle (for production non-equivocation enforcement).
#[async_trait]
pub trait GuardianSigner: Send + Sync {
    /// Signs a consensus payload (usually a block header hash).
    /// Returns the signature along with the Oracle's counter and trace.
    async fn sign_consensus_payload(&self, payload_hash: [u8; 32]) -> Result<SignatureBundle>;

    /// Returns the public key bytes of the signer.
    fn public_key(&self) -> Vec<u8>;
}

/// Local implementation for development/testing.
/// Mimics the Oracle's interface but uses an in-memory keypair and zeroed metadata.
pub struct LocalSigner {
    keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair,
}

impl LocalSigner {
    /// Creates a new `LocalSigner` with the given keypair.
    pub fn new(keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair) -> Self {
        Self { keypair }
    }
}

#[async_trait]
impl GuardianSigner for LocalSigner {
    async fn sign_consensus_payload(&self, payload_hash: [u8; 32]) -> Result<SignatureBundle> {
        // To support Oracle-anchored logic even in dev mode, we must construct the same payload structure:
        // Payload_Hash || Counter (0) || Trace (0)
        // This ensures verification logic in the consensus engine remains consistent.
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&payload_hash);
        sig_input.extend_from_slice(&0u64.to_be_bytes());
        sig_input.extend_from_slice(&[0u8; 32]);

        let signature = self.keypair.private_key().sign(&sig_input)?.to_bytes();

        Ok(SignatureBundle {
            signature,
            counter: 0,
            trace_hash: [0u8; 32],
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().to_bytes()
    }
}

/// Remote implementation connecting to the `ioi-signer` Oracle.
pub struct RemoteSigner {
    url: String,
    client: reqwest::Client,
    // Cache public key on startup to avoid async overhead in tight loops
    public_key: Vec<u8>,
}

impl RemoteSigner {
    /// Creates a new `RemoteSigner` that connects to the specified Oracle URL
    /// and uses the provided public key for validation.
    pub fn new(url: String, public_key: Vec<u8>) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
            public_key,
        }
    }
}

#[async_trait]
impl GuardianSigner for RemoteSigner {
    async fn sign_consensus_payload(&self, payload_hash: [u8; 32]) -> Result<SignatureBundle> {
        // The Oracle expects the hash as a hex string.
        let resp = self
            .client
            .post(format!("{}/sign", self.url))
            .json(&serde_json::json!({
                "payload_hash": hex::encode(payload_hash)
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Parse response: { signature: "hex", counter: 123, trace_hash: "hex" }
        let sig_hex = resp["signature"]
            .as_str()
            .ok_or(anyhow!("Missing signature in Oracle response"))?;
        let counter = resp["counter"]
            .as_u64()
            .ok_or(anyhow!("Missing counter in Oracle response"))?;
        let trace_hex = resp["trace_hash"]
            .as_str()
            .ok_or(anyhow!("Missing trace_hash in Oracle response"))?;

        let signature = hex::decode(sig_hex)?;
        let trace_hash_vec = hex::decode(trace_hex)?;
        let trace_hash: [u8; 32] = trace_hash_vec
            .try_into()
            .map_err(|_| anyhow!("Invalid trace hash length"))?;

        Ok(SignatureBundle {
            signature,
            counter,
            trace_hash,
        })
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

// --- Guardian Container ---

/// Holds open file handles to the binaries to prevent modification while running.
/// On Linux, writing to an executing file returns ETXTBSY.
pub struct BinaryGuard {
    _handles: Vec<File>,
}

/// The GuardianContainer is the root of trust.
#[derive(Debug, Clone)]
pub struct GuardianContainer {
    /// The secure channel to the Orchestrator container.
    pub orchestration_channel: SecurityChannel,
    /// The secure channel to the Workload container.
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
}

/// Generates a self-signed CA and server/client certificates for mTLS.
pub fn generate_certificates_if_needed(certs_dir: &Path) -> Result<()> {
    if certs_dir.join("ca.pem").exists() {
        return Ok(());
    }
    log::info!(
        "Generating mTLS CA and certificates in {}",
        certs_dir.display()
    );
    std::fs::create_dir_all(certs_dir)?;

    let mut ca_params = CertificateParams::new(vec!["IOI SDK Local CA".to_string()]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = Certificate::from_params(ca_params)?;
    std::fs::write(certs_dir.join("ca.pem"), ca_cert.serialize_pem()?)?;
    std::fs::write(
        certs_dir.join("ca.key"),
        ca_cert.serialize_private_key_pem(),
    )?;

    let signers = [
        ("guardian-server", vec!["guardian", "localhost"]),
        ("workload-server", vec!["workload", "localhost"]),
        ("orchestration", vec![]),
        ("workload", vec![]),
    ];
    for (name, domains) in &signers {
        let mut params = CertificateParams::new(vec![name.to_string()]);
        params.subject_alt_names = domains
            .iter()
            .map(|d| SanType::DnsName(d.to_string()))
            .chain(vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())])
            .collect();
        let cert = Certificate::from_params(params)?;
        std::fs::write(
            certs_dir.join(format!("{}.pem", name)),
            cert.serialize_pem_with_signer(&ca_cert)?,
        )?;
        std::fs::write(
            certs_dir.join(format!("{}.key", name)),
            cert.serialize_private_key_pem(),
        )?;
    }
    Ok(())
}

impl GuardianContainer {
    /// Creates a new Guardian container instance.
    pub fn new(_config: GuardianConfig) -> Result<Self> {
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Attests to the integrity of an agentic model file by computing its hash.
    pub async fn attest_weights(&self, model_path: &str) -> Result<Vec<u8>, String> {
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| format!("Failed to read agentic model file: {}", e))?;
        // FIX: Remove explicit type annotation to allow compiler inference
        let local_hash_array = Sha256::digest(&model_bytes).map_err(|e| e.to_string())?;
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash_array)
        );
        Ok(local_hash_array.to_vec())
    }

    /// Locates, hashes, and locks sibling binaries relative to the current executable.
    pub fn verify_binaries(&self, config: &GuardianConfig) -> Result<Option<BinaryGuard>> {
        // If explicit opt-out, warn loudly.
        if !config.enforce_binary_integrity {
            tracing::warn!(
                "SECURITY WARNING: Binary integrity enforcement is DISABLED. \
                This node is vulnerable to runtime binary swapping attacks."
            );
            return Ok(None);
        }

        // Use override if present, otherwise resolve relative to current executable.
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            let my_path = std::env::current_exe()?;
            my_path
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let orch_path = bin_dir.join("orchestration");
        let work_path = bin_dir.join("workload");

        // If enabled (default), hashes MUST be present.
        let orch_hash = config.approved_orchestrator_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_orchestrator_hash` is missing in guardian.toml")
        })?;

        let work_hash = config.approved_workload_hash.as_deref().ok_or_else(|| {
            anyhow!("Guardian failed to start: `enforce_binary_integrity` is true, but `approved_workload_hash` is missing in guardian.toml")
        })?;

        let orch_handle = self.check_binary(&orch_path, Some(orch_hash), "Orchestrator")?;
        let work_handle = self.check_binary(&work_path, Some(work_hash), "Workload")?;

        log::info!("[Guardian] Binary integrity verified. Executables locked.");

        Ok(Some(BinaryGuard {
            _handles: vec![orch_handle, work_handle],
        }))
    }

    fn check_binary(&self, path: &Path, expected_hash: Option<&str>, label: &str) -> Result<File> {
        let expected = expected_hash.ok_or_else(|| {
            anyhow!(
                "Integrity enforcement enabled but no hash provided for {}",
                label
            )
        })?;

        log::info!("[Guardian] Verifying {} at {:?}", label, path);

        // Open file for reading (this handle ensures the file exists and locks it if OS supports)
        let mut file =
            File::open(path).map_err(|e| anyhow!("Failed to open {} binary: {}", label, e))?;

        // Read entire binary into memory for hashing
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Compute SHA-256 using dcrypt
        let digest = Sha256::digest(&buffer).map_err(|e| anyhow!("Hashing failed: {}", e))?;
        let hex_digest = hex::encode(digest);

        if hex_digest != expected {
            return Err(anyhow!(
                "SECURITY VIOLATION: {} binary hash mismatch!\nExpected: {}\nComputed: {}",
                label,
                expected,
                hex_digest
            ));
        }

        // Return the open file handle to keep a lock reference (OS dependent)
        Ok(file)
    }

    /// Resolves the secure passphrase from environment or interactive prompt.
    fn resolve_passphrase(confirm: bool) -> Result<String> {
        if let Ok(p) = std::env::var("IOI_GUARDIAN_KEY_PASS") {
            return Ok(p);
        }

        if atty::is(atty::Stream::Stdin) {
            eprint!("Enter Guardian Key Passphrase: ");
            std::io::stderr().flush()?;
            let pass = rpassword::read_password()?;

            if confirm {
                eprint!("Confirm Passphrase: ");
                std::io::stderr().flush()?;
                let conf = rpassword::read_password()?;
                if pass != conf {
                    return Err(anyhow!("Passphrases do not match"));
                }
            }

            if pass.is_empty() {
                return Err(anyhow!("Empty passphrase not allowed"));
            }
            Ok(pass)
        } else {
            Err(anyhow!(
                "No TTY and IOI_GUARDIAN_KEY_PASS not set. Cannot decrypt key."
            ))
        }
    }

    /// Loads an encrypted key file from disk, decrypts it, and returns the raw bytes.
    /// Rejects raw 32-byte keys (legacy seeds) to enforce encryption-at-rest.
    pub fn load_encrypted_file(path: &Path) -> Result<Vec<u8>> {
        let content = std::fs::read(path)?;

        // Check for Magic Header defined in ioi_crypto::key_store
        if content.starts_with(b"IOI_ENC_V1") {
            let pass = Self::resolve_passphrase(false)?;
            let secret = decrypt_key(&content, &pass)?;
            // secret is SensitiveBytes(Vec<u8>), needs explicit clone to move out
            Ok(secret.0.clone())
        } else {
            // Safety check for legacy/raw keys.
            if content.len() == 32 {
                return Err(anyhow!(
                    "SECURITY ERROR: Found unsafe raw key at {:?}. \
                    The IOI SDK requires all validator keys to be encrypted. \
                    Please delete this file to generate a new secure key, or migrate it manually.",
                    path
                ));
            }
            Err(anyhow!(
                "Unknown key file format or unencrypted file. Encryption is mandatory."
            ))
        }
    }

    /// Encrypts the provided data with a passphrase and saves it to disk.
    pub fn save_encrypted_file(path: &Path, data: &[u8]) -> Result<()> {
        println!("--- Encrypting New Secure Key ---");
        let pass = Self::resolve_passphrase(true)?;
        let encrypted = encrypt_key(data, &pass)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&encrypted)?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, &encrypted)?;

        Ok(())
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self, listen_addr: &str) -> Result<(), ValidatorError> {
        self.is_running.store(true, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;

        let certs_dir = std::env::var("CERTS_DIR").map_err(|_| {
            ValidatorError::Config("CERTS_DIR environment variable must be set".to_string())
        })?;
        let server_config: Arc<ServerConfig> = create_ipc_server_config(
            &format!("{}/ca.pem", certs_dir),
            &format!("{}/guardian-server.pem", certs_dir),
            &format!("{}/guardian-server.key", certs_dir),
        )
        .map_err(|e| ValidatorError::Config(e.to_string()))?;
        let acceptor = TlsAcceptor::from(server_config);

        let orch_channel = self.orchestration_channel.clone();
        let work_channel = self.workload_channel.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let orch_c = orch_channel.clone();
                let work_c = work_channel.clone();
                tokio::spawn(async move {
                    let server_conn = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => return log::error!("[Guardian] TLS accept error: {}", e),
                    };
                    let mut tls_stream = TlsStream::Server(server_conn);

                    let mut kem_ss = match server_post_handshake(
                        &mut tls_stream,
                        ioi_crypto::security::SecurityLevel::Level3,
                    )
                    .await
                    {
                        Ok(ss) => ss,
                        Err(e) => {
                            return log::error!(
                                "[Guardian] Post-quantum key exchange FAILED: {}",
                                e
                            );
                        }
                    };

                    let app_key = match derive_application_key(&tls_stream, &mut kem_ss) {
                        Ok(k) => k,
                        Err(e) => {
                            return log::error!("[Guardian] App key derivation FAILED: {}", e)
                        }
                    };
                    let mut aead_stream = AeadWrappedStream::new(tls_stream, app_key);

                    let mut id_buf = [0u8; 1];
                    match aead_stream.read(&mut id_buf).await {
                        Ok(1) => {
                            let client_id_byte = id_buf[0];
                            log::info!(
                                "[Guardian] Post-quantum channel established for client {}",
                                client_id_byte
                            );
                            match IpcClientType::try_from(client_id_byte) {
                                Ok(IpcClientType::Orchestrator) => {
                                    orch_c.accept_server_connection(aead_stream).await
                                }
                                Ok(IpcClientType::Workload) => {
                                    work_c.accept_server_connection(aead_stream).await
                                }
                                Err(_) => log::warn!(
                                    "[Guardian] Unknown client ID byte: {}",
                                    client_id_byte
                                ),
                            }
                        }
                        Ok(n) => log::warn!(
                            "[Guardian] Expected 1-byte client ID frame, but received {} bytes.",
                            n
                        ),
                        Err(e) => log::error!("[Guardian] Failed to read client ID frame: {}", e),
                    }
                });
            }
        });

        log::info!("Guardian container started and listening.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        self.is_running.store(false, Ordering::SeqCst);
        log::info!("Guardian container stopped.");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "guardian"
    }
}
