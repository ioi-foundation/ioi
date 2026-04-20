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
#[path = "server/tests.rs"]
mod tests;
