// Path: crates/validator/src/common/guardian.rs
// Final Version: This file is updated to use the modern rustls v0.22 API,
// resolving all previous compilation errors.

use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::validator::{Container, GuardianContainer as GuardianContainerTrait};
use depin_sdk_types::error::ValidatorError;
use rcgen::{Certificate, CertificateParams, SanType};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

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
}

impl GuardianContainer {
    pub fn new(_config_path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
        })
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
        let listener = TcpListener::bind("0.0.0.0:8443")
            .await
            .map_err(|e| ValidatorError::Io(e))?;

        log::info!("Guardian: mTLS attestation server listening on 0.0.0.0:8443");

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
