// crates/validator/src/common/guardian.rs

//! Implements the Guardian container, the root of trust for the validator.
//!
//! The `GuardianContainer` is responsible for establishing secure mTLS channels
//! with other containers and performing attestations, such as verifying the
//! integrity of an agentic AI model's weights before the validator participates in consensus.
//! It also includes helper functions for generating the necessary mTLS certificates.

use crate::config::GuardianConfig;
use crate::standard::workload_ipc_server::create_ipc_server_config;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::validator::Container;
use ioi_client::security::SecurityChannel;
use ioi_crypto::{
    algorithms::hash::sha256,
    transport::hybrid_kem_tls::{derive_application_key, server_post_handshake, AeadWrappedStream},
};
use ioi_ipc::IpcClientType;
use ioi_types::error::ValidatorError;
use rcgen::{Certificate, CertificateParams, KeyUsagePurpose, SanType};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::AsyncReadExt;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor, TlsStream};

/// The GuardianContainer is the root of trust.
#[derive(Debug, Clone)]
pub struct GuardianContainer {
    /// A secure mTLS channel for communicating with the Orchestration container.
    pub orchestration_channel: SecurityChannel,
    /// A secure mTLS channel for communicating with the Workload container.
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
}

/// Generates a self-signed CA and server/client certificates for mTLS if they do not already exist.
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
    /// Creates a new, unstarted GuardianContainer.
    pub fn new(_config: GuardianConfig) -> Result<Self> {
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Computes the SHA-256 hash of the agentic model file.
    pub async fn attest_weights(&self, model_path: &str) -> Result<Vec<u8>, String> {
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| format!("Failed to read agentic model file: {}", e))?;
        let local_hash_array = sha256(&model_bytes).map_err(|e| e.to_string())?;
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash_array)
        );
        Ok(local_hash_array.to_vec())
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
                    // Wrap the concrete server stream into the generic TlsStream enum
                    let mut tls_stream = TlsStream::Server(server_conn);

                    // --- POST-HANDSHAKE HYBRID KEY EXCHANGE (before any app bytes) ---
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

                    // --- BIND & WRAP ---
                    let app_key = match derive_application_key(&tls_stream, &mut kem_ss) {
                        Ok(k) => k,
                        Err(e) => {
                            return log::error!("[Guardian] App key derivation FAILED: {}", e)
                        }
                    };
                    let mut aead_stream = AeadWrappedStream::new(tls_stream, app_key);

                    // Now, read the first application byte (the client ID) from the AEAD stream.
                    let mut id_buf = [0u8; 1];
                    match aead_stream.read(&mut id_buf).await {
                        Ok(1) => {
                            let client_id_byte = id_buf[0];
                            log::info!(
                                "[Guardian] Post-quantum channel established for client {}",
                                client_id_byte
                            );
                            // Use the shared enum instead of magic numbers
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