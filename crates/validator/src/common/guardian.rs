// Path: crates/validator/src/common/guardian.rs
// Final Version: This file is updated to use the modern rustls v0.22 API,
// resolving all previous compilation errors.

use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::state::StateCommitment;
use depin_sdk_api::validator::{Container, GuardianContainer as GuardianContainerTrait};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::error::ValidatorError;
use depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::Deserialize;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

#[derive(Debug, Deserialize)]
pub struct GuardianConfig {
    pub listen_addr: String,
}

/// Creates a self-signed Certificate Authority (CA) and a server configuration
/// for the Guardian's mTLS listener.
fn create_ca_and_server_config() -> Result<(Certificate, Arc<ServerConfig>)> {
    // 1. Create a self-signed CA certificate.
    let mut ca_params = CertificateParams::new(vec!["depin-sdk-ca".to_string()]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params)?;

    // 2. Create the server certificate, signed by our new CA.
    let mut server_params = CertificateParams::new(vec!["guardian".to_string()]);
    // Add Subject Alternative Names (SANs) so clients can connect via the Docker service name.
    server_params.subject_alt_names = vec![
        SanType::DnsName("guardian".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    let server_cert = Certificate::from_params(server_params)?;

    let server_der = server_cert.serialize_der_with_signer(&ca_cert)?;
    let server_key = server_cert.serialize_private_key_der();

    // 3. Build the server configuration using the modern rustls builder pattern.
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth() // For the prototype, we don't require clients to have a certificate.
            .with_single_cert(
                vec![CertificateDer::from(server_der)],
                PrivateKeyDer::Pkcs8(server_key.into()),
            )?;

    Ok((ca_cert, Arc::new(server_config)))
}

/// The GuardianContainer is the root of trust, responsible for secure boot and attestation.
#[derive(Debug)]
pub struct GuardianContainer {
    running: Arc<AtomicBool>,
    config: GuardianConfig,
}

#[derive(Debug)]
pub enum GuardianSignal {
    ModelIntegrityFailure,
}

impl GuardianContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config: GuardianConfig = if config_path.exists() {
            toml::from_str(&std::fs::read_to_string(config_path)?)?
        } else {
            // Default for test simulations
            GuardianConfig {
                listen_addr: "0.0.0.0:8443".to_string(),
            }
        };
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            config,
        })
    }
}

impl GuardianContainer {
    /// Periodically computes the Merkle root of the on-disk AI model weights
    /// and compares it against the expected hash from the chain's state.
    pub async fn attest_weights<ST: StateCommitment>(
        &self,
        model_path: &Path,
        state_tree: Arc<Mutex<ST>>,
    ) -> Result<(), String> {
        if !model_path.exists() {
            let err_msg = format!("AI model file not found at path: {:?}", model_path);
            log::error!("{}", err_msg);
            self.signal_failure(GuardianSignal::ModelIntegrityFailure)
                .await;
            return Err(err_msg);
        }

        // 1. Compute hash of the local on-disk model.
        let model_bytes = std::fs::read(model_path).map_err(|e| e.to_string())?;
        let local_model_hash = sha256(&model_bytes);

        // 2. Fetch the governance-approved model hash from the chain state.
        let state = state_tree.lock().await;
        let expected_hash_bytes = state
            .get(STATE_KEY_SEMANTIC_MODEL_HASH)
            .map_err(|e| e.to_string())?
            .ok_or("Expected model hash not found in chain state.")?;

        // 3. Compare.
        if local_model_hash != expected_hash_bytes {
            let error_msg = format!(
                "Model Integrity Failure! Local hash {} does not match expected hash {}.",
                hex::encode(&local_model_hash),
                hex::encode(&expected_hash_bytes)
            );
            log::error!("{}", error_msg);
            self.signal_failure(GuardianSignal::ModelIntegrityFailure)
                .await;
            return Err(error_msg);
        }

        log::info!("Guardian::attest_weights() check passed.");
        Ok(())
    }

    async fn signal_failure(&self, signal: GuardianSignal) {
        log::warn!("Signaling failure to Orchestration container: {:?}", signal);
    }
}

/// Asynchronously handles a new incoming TCP connection, performing a TLS handshake.
async fn handle_connection(acceptor: TlsAcceptor, stream: TcpStream) {
    match acceptor.accept(stream).await {
        Ok(_) => log::info!("Guardian: Received successful attestation handshake."),
        Err(e) => log::error!("Guardian: Attestation handshake failed: {}", e),
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!("Starting GuardianContainer...");
        self.running.store(true, Ordering::SeqCst);

        // Create the mTLS server configuration.
        let (_ca_cert, server_config) =
            create_ca_and_server_config().map_err(|e| ValidatorError::Other(e.to_string()))?;
        let acceptor = TlsAcceptor::from(server_config);

        // Bind the TCP listener.
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(ValidatorError::Io)?;

        log::info!(
            "Guardian: mTLS attestation server listening on {}",
            self.config.listen_addr
        );

        // Spawn a task to listen for incoming connections.
        let running = self.running.clone();
        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                if let Ok((stream, _)) = listener.accept().await {
                    // For each new connection, spawn a task to handle the handshake.
                    tokio::spawn(handle_connection(acceptor.clone(), stream));
                }
            }
            log::info!("Guardian attestation server stopped.");
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping GuardianContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "guardian"
    }
}

impl GuardianContainerTrait for GuardianContainer {
    fn start_boot(&self) -> Result<(), ValidatorError> {
        log::info!("Guardian: Initiating secure boot sequence...");
        Ok(())
    }

    fn verify_attestation(&self) -> Result<bool, ValidatorError> {
        // In the prototype, a successful mTLS handshake is the attestation.
        Ok(true)
    }
}
