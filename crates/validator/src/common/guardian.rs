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
use ioi_crypto::key_store::{decrypt_key, encrypt_key, load_api_key};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_ipc::IpcClientType;
use ioi_types::app::{
    account_id_from_key_material, AccountId, BinaryMeasurement, BootAttestation, SignatureBundle,
    SignatureSuite,
};
use ioi_types::error::ValidatorError;
// [FIX] Added Ia5String and KeyPair for rcgen 0.13 compatibility
use rcgen::{CertificateParams, Ia5String, KeyPair, KeyUsagePurpose, SanType};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
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

/// A signed attestation for a specific AI model snapshot.
/// Used to authorize the loading of large weights into the Workload container.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModelAttestation {
    /// The canonical account ID of the validator issuing this attestation.
    pub validator_id: AccountId,
    /// The SHA-256 hash of the model weights file.
    pub model_hash: [u8; 32],
    /// The UNIX timestamp when the attestation was generated.
    pub timestamp: u64,
    /// The cryptographic signature over the attestation data.
    pub signature: Vec<u8>,
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
    /// The path to the directory containing configuration and keys.
    config_dir: PathBuf,
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

    // [FIX] rcgen 0.13 changes: CertificateParams::new returns Result
    let mut ca_params = CertificateParams::new(vec!["IOI Kernel Local CA".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // [FIX] Generate keypair explicitly
    let ca_keypair = KeyPair::generate()?;
    // [FIX] Use self_signed
    let ca_cert = ca_params.self_signed(&ca_keypair)?;

    // [FIX] Use pem() instead of serialize_pem()
    std::fs::write(certs_dir.join("ca.pem"), ca_cert.pem())?;
    std::fs::write(certs_dir.join("ca.key"), ca_keypair.serialize_pem())?;

    let signers = [
        ("guardian-server", vec!["guardian", "localhost"]),
        ("workload-server", vec!["workload", "localhost"]),
        ("orchestration", vec![]),
        ("workload", vec![]),
    ];
    for (name, domains) in &signers {
        // [FIX] CertificateParams::new returns Result
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        params.subject_alt_names = domains
            .iter()
            .map(|d| {
                // [FIX] Use Ia5String for DnsName
                SanType::DnsName(Ia5String::try_from(d.to_string()).expect("valid dns name"))
            })
            .chain(vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())])
            .collect();

        let keypair = KeyPair::generate()?;
        // [FIX] Use signed_by
        let cert = params.signed_by(&keypair, &ca_cert, &ca_keypair)?;

        std::fs::write(certs_dir.join(format!("{}.pem", name)), cert.pem())?;
        std::fs::write(
            certs_dir.join(format!("{}.key", name)),
            keypair.serialize_pem(),
        )?;
    }
    Ok(())
}

impl GuardianContainer {
    /// Creates a new Guardian container instance.
    pub fn new(config_dir: PathBuf, _config: GuardianConfig) -> Result<Self> {
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
            config_dir,
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

    /// Measures a model file and issues an attestation.
    /// This is called before the Workload is allowed to load the model into VRAM.
    pub async fn attest_model_snapshot(
        &self,
        keypair: &libp2p::identity::Keypair,
        model_path: &Path,
    ) -> Result<ModelAttestation> {
        log::info!("[Guardian] Attesting model snapshot at {:?}", model_path);

        if !model_path.exists() {
            return Err(anyhow!("Model file not found: {:?}", model_path));
        }

        // Compute SHA-256 of the model file
        // For large models (GBs), we stream read.
        let mut file = File::open(model_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher
                .update(&buffer[..count])
                .map_err(|e| anyhow!(e.to_string()))?;
        }

        let hash_digest = hasher.finalize().map_err(|e| anyhow!(e.to_string()))?;
        let mut model_hash = [0u8; 32];
        // [FIX] Unwrap the result of finalize() before using as_ref() and handle error with ?
        model_hash.copy_from_slice(hash_digest.as_ref());

        // Construct attestation
        let pk_bytes = keypair.public().encode_protobuf();
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = ModelAttestation {
            validator_id: AccountId(account_hash),
            model_hash,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: Vec::new(),
        };

        // Sign the deterministic tuple (validator_id, model_hash, timestamp)
        // Note: Real impl would use a dedicated serialization for signing
        let sign_payload = bincode::serialize(&(
            &attestation.validator_id,
            &attestation.model_hash,
            &attestation.timestamp,
        ))?;
        attestation.signature = keypair.sign(&sign_payload)?;

        log::info!(
            "[Guardian] Generated attestation for model hash: {}",
            hex::encode(model_hash)
        );
        Ok(attestation)
    }

    /// Generates a signed `BootAttestation` by hashing the local binaries.
    ///
    /// # Arguments
    /// * `keypair`: The identity keypair used to sign the attestation.
    /// * `config`: The Guardian configuration (used to resolve binary paths).
    pub fn generate_boot_attestation(
        &self,
        keypair: &libp2p::identity::Keypair,
        config: &GuardianConfig,
    ) -> Result<BootAttestation> {
        // Resolve binary directory
        let bin_dir = if let Some(dir) = &config.binary_dir_override {
            Path::new(dir).to_path_buf()
        } else {
            std::env::current_exe()?
                .parent()
                .ok_or(anyhow!("Cannot determine binary directory"))?
                .to_path_buf()
        };

        let measure = |name: &str| -> Result<BinaryMeasurement> {
            let path = bin_dir.join(name);
            if !path.exists() {
                return Err(anyhow!("Binary not found: {:?}", path));
            }
            let bytes = std::fs::read(&path)?;
            let hash = Sha256::digest(&bytes).map_err(|e| anyhow!(e))?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&hash);

            Ok(BinaryMeasurement {
                name: name.to_string(),
                sha256,
                size: bytes.len() as u64,
            })
        };

        let guardian_meas = measure("guardian")?;
        let orch_meas = measure("orchestration")?;
        let workload_meas = measure("workload")?;

        let pk_bytes = keypair.public().encode_protobuf();
        // Assuming Ed25519 for the identity key
        // [FIX] Use SignatureSuite::ED25519
        let account_hash = account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
            .map_err(|e| anyhow!(e))?;

        let mut attestation = BootAttestation {
            validator_account_id: AccountId(account_hash),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            guardian: guardian_meas,
            orchestration: orch_meas,
            workload: workload_meas,
            build_metadata: env!("CARGO_PKG_VERSION").to_string(), // Or inject git hash via env
            signature: Vec::new(),
        };

        // Sign it
        let sign_bytes = attestation.to_sign_bytes()?;
        let signature = keypair.sign(&sign_bytes)?;
        attestation.signature = signature;

        log::info!(
            "[Guardian] Generated BootAttestation for validator {}. Guardian Hash: {}",
            hex::encode(account_hash),
            hex::encode(attestation.guardian.sha256)
        );

        Ok(attestation)
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
        if content.starts_with(b"IOI-GKEY") {
            let pass = Self::resolve_passphrase(false)?;
            let secret = decrypt_key(&content, &pass)?;
            // secret is SensitiveBytes(Vec<u8>), needs explicit clone to move out
            Ok(secret.0.clone())
        } else {
            // Safety check for legacy/raw keys.
            if content.len() == 32 {
                return Err(anyhow!(
                    "SECURITY ERROR: Found unsafe raw key at {:?}. \
                    The IOI Kernel requires all validator keys to be encrypted. \
                    Please delete this file to generate a new secure key, or migrate it manually.",
                    path
                ));
            }
            // Support previous magic if transitioning
            if content.starts_with(b"IOI_ENC_V1") {
                let _pass = Self::resolve_passphrase(false)?;
                // Using the updated decrypt_key might fail if logic changed strictly.
                // We assume complete migration or compatible logic.
                // But updated decrypt_key checks for IOI-GKEY.
                return Err(anyhow!(
                    "Legacy encrypted key found. Please migrate to V1 format."
                ));
            }

            Err(anyhow!(
                "Unknown key file format or unencrypted file. Encryption is mandatory."
            ))
        }
    }

    /// Encrypts the provided data with a passphrase and saves it to disk using Atomic Write.
    /// 1. Writes to temp file.
    /// 2. Fsyncs.
    /// 3. Renames to final path.
    pub fn save_encrypted_file(path: &Path, data: &[u8]) -> Result<()> {
        println!("--- Encrypting New Secure Key ---");
        let pass = Self::resolve_passphrase(true)?;
        let encrypted = encrypt_key(data, &pass)?;

        // Atomic write pattern: Write to .tmp, sync, rename
        let mut temp_path = path.to_path_buf();
        if let Some(ext) = path.extension() {
            let mut ext_str = ext.to_os_string();
            ext_str.push(".tmp");
            temp_path.set_extension(ext_str);
        } else {
            temp_path.set_extension("tmp");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }

        std::fs::rename(temp_path, path)?;

        Ok(())
    }

    /// Executes a secure HTTP call on behalf of a workload.
    pub async fn secure_http_call(
        &self,
        target_domain: &str,
        path: &str,
        method: &str,
        body: Vec<u8>,
        secret_id: &str,
        signer: &libp2p::identity::Keypair,
    ) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
        // 1. Load the API Key (Decrypted only in memory scope)
        let key_path = self.config_dir.join(format!("{}.key", secret_id));
        let pass = Self::resolve_passphrase(false)?;
        let api_key = load_api_key(&key_path, &pass)?;

        // 2. Setup HTTP Client
        let client = Client::builder()
            .https_only(true)
            .build()?;

        // 3. Execute Request
        let url = format!("https://{}{}", target_domain, path);
        let resp = client
            .request(method.parse()?, url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        // 4. Capture TLS Info (Simplified)
        // In a production environment, this would extract the peer certificate digest.
        // For implementation, we compute a placeholder hash representing the TLS session.
        let cert_hash = [0xAA; 32]; 

        let response_bytes = resp.bytes().await?.to_vec();
        
        // 5. Sign the Attestation
        // Sign(target_domain || cert_hash || hash(response_body))
        let signature = self.sign_egress_attestation(signer, target_domain, &cert_hash, &response_bytes)?;
        
        Ok((response_bytes, cert_hash, signature))
    }
    
    fn sign_egress_attestation(&self, signer: &libp2p::identity::Keypair, domain: &str, cert: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        payload.extend_from_slice(domain.as_bytes());
        payload.extend_from_slice(cert);
        let body_hash = Sha256::digest(body).map_err(|e| anyhow!(e))?;
        payload.extend_from_slice(&body_hash);

        let signature = signer.sign(&payload)?;
        Ok(signature)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_no_plaintext_at_rest() {
        let seed = [0xAAu8; 32]; // Distinct pattern to search for
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guardian.key");

        // Mock the environment variable for passphrase
        unsafe { std::env::set_var("IOI_GUARDIAN_KEY_PASS", "test_pass") };

        // Write key using the new atomic save_encrypted_file
        GuardianContainer::save_encrypted_file(&path, &seed).expect("Save failed");

        // Verify file exists
        assert!(path.exists());

        // Read raw file content
        let content = std::fs::read(&path).expect("Read failed");

        // 1. Verify Magic Header
        assert_eq!(&content[0..8], b"IOI-GKEY", "Header mismatch");

        // 2. Scan entire file to ensure the raw seed pattern does not appear
        assert!(
            content.windows(32).all(|window| window != seed),
            "Plaintext seed found on disk! Encryption failed."
        );

        // 3. Verify we can decrypt it back
        let loaded = GuardianContainer::load_encrypted_file(&path).expect("Load failed");
        assert_eq!(loaded, seed.to_vec(), "Roundtrip mismatch");
    }
}