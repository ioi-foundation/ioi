// Path: crates/node/src/bin/guardian.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

use anyhow::Result;
use clap::Parser;
use ioi_api::validator::Container;
use ioi_ipc::control::guardian_control_server::{GuardianControl, GuardianControlServer};
use ioi_ipc::control::{SecureEgressRequest, SecureEgressResponse};
use ioi_types::app::GuardianReport;
use ioi_validator::common::{generate_certificates_if_needed, GuardianContainer};
use ioi_validator::config::GuardianConfig;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Parser, Debug)]
struct GuardianOpts {
    #[clap(long)]
    config_dir: String,
    #[clap(long)]
    agentic_model_path: String,
    #[clap(
        long,
        env = "GUARDIAN_LISTEN_ADDR",
        help = "Overrides listen_addr in guardian.toml"
    )]
    listen_addr: Option<String>,
}

struct GuardianControlImpl {
    container: Arc<GuardianContainer>,
    keypair: libp2p::identity::Keypair,
}

#[tonic::async_trait]
impl GuardianControl for GuardianControlImpl {
    async fn secure_egress(
        &self,
        request: Request<SecureEgressRequest>,
    ) -> Result<Response<SecureEgressResponse>, Status> {
        let req = request.into_inner();

        // Handle optional json_patch_path (empty string in proto3 means missing/none)
        let json_patch = if req.json_patch_path.is_empty() {
            None
        } else {
            Some(req.json_patch_path.as_str())
        };

        let (body, cert_hash, signature) = self
            .container
            .secure_http_call(
                &req.domain,
                &req.path,
                &req.method,
                req.body,
                &req.secret_id,
                &self.keypair,
                json_patch, // [FIX] Pass the new argument
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SecureEgressResponse {
            body,
            cert_hash: cert_hash.to_vec(),
            guardian_signature: signature,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // [FIX] Install default crypto provider for rustls 0.23+
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Initialize tracing FIRST
    ioi_telemetry::init::init_tracing()?;

    // 2. Spawn the telemetry server
    let telemetry_addr_str =
        std::env::var("TELEMETRY_ADDR").unwrap_or_else(|_| "127.0.0.1:9617".to_string());
    let telemetry_addr = telemetry_addr_str.parse()?;
    tokio::spawn(ioi_telemetry::http::run_server(telemetry_addr));

    let opts = GuardianOpts::parse();
    tracing::info!(target: "guardian", event = "startup", config_dir = %opts.config_dir);

    let certs_dir = std::env::var("CERTS_DIR")
        .map_err(|_| anyhow::anyhow!("CERTS_DIR environment variable must be set"))?;
    generate_certificates_if_needed(Path::new(&certs_dir))?;

    let config_dir_path = Path::new(&opts.config_dir);
    let config: GuardianConfig = toml::from_str(&std::fs::read_to_string(
        config_dir_path.join("guardian.toml"),
    )?)?;

    let listen_addr = opts
        .listen_addr
        .unwrap_or_else(|| "127.0.0.1:8443".to_string());
    tracing::info!(target: "guardian", listen_addr = %listen_addr);

    let guardian = Arc::new(GuardianContainer::new(
        config_dir_path.to_path_buf(),
        config.clone(),
    )?);

    // --- PHASE 2 IMPLEMENTATION: Boot Measurement ---
    // Verify binaries immediately upon instantiation, before starting network services.
    // The guard prevents the underlying files from being modified while the Guardian is running.
    // If verification fails, this call returns an error and the process exits safely.
    let _binary_integrity_guard = guardian.verify_binaries(&config)?;

    guardian.start(&listen_addr).await?;

    // Print the readiness signal for the test harness after the listener is up.
    eprintln!("GUARDIAN_IPC_LISTENING_ON_{}", listen_addr);

    // Prepare key for boot attestation logic.
    // In production, the key is already loaded, but here we reload or access it.
    // This is safe because the file is encrypted-at-rest.
    let identity_key_path = Path::new(&certs_dir)
        .parent()
        .ok_or(anyhow::anyhow!("Invalid certs dir path"))?
        .join("identity.key");

    let keypair_bytes = GuardianContainer::load_encrypted_file(&identity_key_path)?;
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&keypair_bytes)?;

    // Spawn gRPC server for Control Plane (Secure Egress)
    // NOTE: This assumes the Guardian listens on a separate port/interface for gRPC commands
    // or multiplexes on the existing channel. For now, we assume a separate port defined in config or env.
    // In a real mTLS setup, this would be part of the `workload_channel` logic.
    // For simplicity in this scaffold, we launch a separate tonic server if GUARDIAN_GRPC_ADDR is set.
    if let Ok(grpc_addr_str) = std::env::var("GUARDIAN_GRPC_ADDR") {
        let grpc_addr = grpc_addr_str.parse()?;
        let control_service = GuardianControlImpl {
            container: guardian.clone(),
            keypair: keypair.clone(),
        };

        tokio::spawn(async move {
            tracing::info!("Guardian Control gRPC listening on {}", grpc_addr);
            Server::builder()
                .add_service(GuardianControlServer::new(control_service))
                .serve(grpc_addr)
                .await
                .expect("Guardian gRPC server failed");
        });
    }

    let guardian_clone = guardian.clone();
    tokio::spawn(async move {
        // Wait for the orchestration channel to be established before sending the report.
        // This resolves the race condition that caused the test timeout.
        while !guardian_clone.orchestration_channel.is_established().await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 1. Agentic Model Hash
        let local_hash_result = guardian_clone
            .attest_weights(&opts.agentic_model_path)
            .await;

        // FIX: Propagate errors or log them, don't just return Ok(()) silently on error cases
        // inside the Result-returning async block.
        let agentic_hash = match local_hash_result {
            Ok(hash) => hash,
            Err(e) => {
                tracing::error!(target: "guardian", event = "agentic_attest_fail", error = %e);
                return Ok::<(), anyhow::Error>(());
            }
        };

        // 2. Binary Boot Attestation
        let boot_attestation = match guardian_clone.generate_boot_attestation(&keypair, &config) {
            Ok(att) => att,
            Err(e) => {
                tracing::error!(target: "guardian", event = "boot_attest_fail", error = %e);
                return Ok::<(), anyhow::Error>(());
            }
        };

        // 3. Construct Combined Report
        let report = GuardianReport {
            agentic_hash,
            binary_attestation: boot_attestation,
        };

        // Serialize
        let report_bytes = match serde_json::to_vec(&report) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(target: "guardian", event = "report_serialize_fail", error = %e, "Failed to serialize attestation report");
                return Ok::<(), anyhow::Error>(());
            }
        };

        if let Some(mut stream) = guardian_clone.orchestration_channel.take_stream().await {
            // FIX: Send length prefix to prevent OOM on the receiver side (Orchestrator).
            // We chain the write operations to handle errors in one place.
            let write_result = async {
                let len = report_bytes.len() as u32;
                stream.write_u32(len).await?;
                stream.write_all(&report_bytes).await?;
                Ok::<(), std::io::Error>(())
            }
            .await;

            if let Err(e) = write_result {
                tracing::error!(
                    target: "guardian",
                    event = "attestation_send_fail",
                    error = %e,
                    "Failed to send agentic attestation report to Orchestrator"
                );
            } else {
                tracing::info!(
                    target: "guardian",
                    event = "attestation_sent",
                    "Sent comprehensive attestation report to Orchestrator."
                );
                // Gracefully shut down the write side of the stream to signal EOF to the reader.
                if let Err(e) = stream.shutdown().await {
                    tracing::error!(
                        target: "guardian",
                        event = "attestation_shutdown_fail",
                        error = %e,
                        "Failed to shutdown stream after sending attestation"
                    );
                }
            }
        } else {
            tracing::error!(
                target: "guardian",
                event = "attestation_send_fail",
                error = "Orchestration channel not established or already taken",
                "Failed to send agentic attestation report to Orchestrator"
            );
        }
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!(target: "guardian", event = "shutdown", reason = "ctrl-c");
        }
    }

    guardian.stop().await?;
    tracing::info!(target: "guardian", event = "shutdown", reason = "complete");

    Ok(())
}
