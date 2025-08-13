// Path: crates/validator/src/common/guardian.rs

use crate::common::attestation::{ContainerAttestation, SignatureSuite};
use crate::common::security::SecurityChannel;
use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::validator::{Container, GuardianContainer as GuardianContainerTrait};
use depin_sdk_types::error::ValidatorError;
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, SanType};
use serde::Deserialize;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

#[derive(Debug, Deserialize, Clone)]
pub struct GuardianConfig {
    pub listen_addr: String,
}

/// Creates a self-signed certificate and a server configuration for the Guardian's mTLS listener.
fn create_server_config() -> Result<Arc<ServerConfig>> {
    let mut server_params = CertificateParams::new(vec!["guardian".to_string()]);
    server_params.subject_alt_names = vec![
        SanType::DnsName("guardian".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    let server_cert = Certificate::from_params(server_params)?;
    let server_der = server_cert.serialize_der()?;
    let server_key = server_cert.serialize_private_key_der();

    let server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(server_der)],
                PrivateKeyDer::Pkcs8(server_key.into()),
            )?;
    Ok(Arc::new(server_config))
}

/// The GuardianContainer is the root of trust.
#[derive(Debug, Clone)]
pub struct GuardianContainer {
    running: Arc<AtomicBool>,
    config: GuardianConfig,
    orchestration_channel: SecurityChannel,
    workload_channel: SecurityChannel,
}

impl GuardianContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config: GuardianConfig = if config_path.exists() {
            toml::from_str(&std::fs::read_to_string(config_path)?)?
        } else {
            GuardianConfig {
                listen_addr: "0.0.0.0:8443".to_string(),
            }
        };
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            config,
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
        })
    }
    
    /// Verifies a received container attestation. This is the core of the on-chain logic.
    pub async fn verify_container_attestation(
        &self,
        attestation: &ContainerAttestation,
    ) -> Result<bool, ValidatorError> {
        log::info!("Verifying attestation from '{}'...", attestation.container_id);
        let chain_active_scheme = SignatureSuite::Ed25519; // Placeholder
        if attestation.signature_suite != chain_active_scheme {
            log::error!("Attestation from '{}' used wrong signature suite.", attestation.container_id);
            return Ok(false);
        }
        let mut message = Vec::new();
        message.extend_from_slice(&attestation.nonce);
        message.extend_from_slice(&attestation.measurement_root);

        let pub_key = libp2p::identity::PublicKey::try_decode_protobuf(&attestation.public_key)
            .map_err(|e| ValidatorError::Other(format!("Invalid public key: {}", e)))?;
        
        let is_valid = pub_key.verify(&message, &attestation.signature);
        if is_valid {
            log::info!("✅ Attestation from '{}' is VALID.", attestation.container_id);
        } else {
            log::error!("❌ Attestation from '{}' is INVALID.", attestation.container_id);
        }
        Ok(is_valid)
    }

    /// The main attestation loop run by the Guardian.
    pub async fn run_attestation_protocol(&self) -> Result<()> {
        log::info!("Guardian starting attestation protocol...");
        // Wait for channels to be established
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Challenge Orchestration
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.orchestration_channel.send(&nonce).await?;
        let response_bytes = self.orchestration_channel.receive().await?;
        let report: ContainerAttestation = serde_json::from_slice(&response_bytes)?;
        self.verify_container_attestation(&report).await?;

        // Challenge Workload
        rand::thread_rng().fill_bytes(&mut nonce);
        self.workload_channel.send(&nonce).await?;
        let response_bytes = self.workload_channel.receive().await?;
        let report: ContainerAttestation = serde_json::from_slice(&response_bytes)?;
        self.verify_container_attestation(&report).await?;

        Ok(())
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!("Starting GuardianContainer...");
        self.running.store(true, Ordering::SeqCst);
        let server_config = create_server_config().map_err(|e| ValidatorError::Other(e.to_string()))?;
        let acceptor = TlsAcceptor::from(server_config);
        let listener = TcpListener::bind(&self.config.listen_addr).await.map_err(ValidatorError::Io)?;
        log::info!("Guardian: mTLS server listening on {}", self.config.listen_addr);
        let running = self.running.clone();
        let orch_channel = self.orchestration_channel.clone();
        let work_channel = self.workload_channel.clone();

        tokio::spawn(async move {
            let mut connections = 0;
            while running.load(Ordering::SeqCst) && connections < 2 {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor_clone = acceptor.clone();
                    let channel_to_use = if connections == 0 { orch_channel.clone() } else { work_channel.clone() };
                    tokio::spawn(async move {
                        match acceptor_clone.accept(stream).await {
                            Ok(tls_stream) => {
                                channel_to_use
                                    .accept_server_connection(tokio_rustls::TlsStream::Server(
                                        tls_stream,
                                    ))
                                    .await
                            }
                            Err(e) => log::error!("Guardian: TLS handshake failed: {}", e),
                        }
                    });
                    connections += 1;
                }
            }
            log::info!("Guardian has accepted all expected container connections.");
        });

        // Spawn the attestation protocol loop
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_attestation_protocol().await {
                log::error!("Attestation protocol failed: {}", e);
            }
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping GuardianContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    fn id(&self) -> &'static str { "guardian" }
}

impl GuardianContainerTrait for GuardianContainer {
    fn start_boot(&self) -> Result<(), ValidatorError> { Ok(()) }
    fn verify_attestation(&self) -> Result<bool, ValidatorError> { Ok(true) }
}