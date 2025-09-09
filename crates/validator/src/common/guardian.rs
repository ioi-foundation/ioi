// crates/validator/src/common/guardian.rs

use crate::config::GuardianConfig;
use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::validator::Container;
use depin_sdk_client::security::SecurityChannel;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::error::ValidatorError;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsAcceptor;

/// The GuardianContainer is the root of trust.
#[derive(Debug, Clone)]
pub struct GuardianContainer {
    pub orchestration_channel: SecurityChannel,
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
}

impl GuardianContainer {
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
        let local_hash = sha256(&model_bytes);
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash)
        );
        Ok(local_hash)
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self, listen_addr: &str) -> Result<(), ValidatorError> {
        self.is_running.store(true, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let server_config = crate::standard::workload_ipc_server::create_ipc_server_config()
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
                    if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                        // Read the first byte to identify the client (1=Orch, 2=Workload)
                        if let Ok(id_byte) = tls_stream.read_u8().await {
                            match id_byte {
                                1 => {
                                    orch_c
                                        .accept_server_connection(tokio_rustls::TlsStream::Server(
                                            tls_stream,
                                        ))
                                        .await
                                }
                                2 => {
                                    work_c
                                        .accept_server_connection(tokio_rustls::TlsStream::Server(
                                            tls_stream,
                                        ))
                                        .await
                                }
                                _ => log::warn!("[Guardian] Unknown client ID byte: {}", id_byte),
                            }
                        }
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
