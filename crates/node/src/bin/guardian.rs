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
use ioi_validator::common::{generate_certificates_if_needed, GuardianContainer};
use ioi_validator::config::GuardianConfig;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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

#[tokio::main]
async fn main() -> Result<()> {
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

    let config: GuardianConfig = toml::from_str(&std::fs::read_to_string(
        Path::new(&opts.config_dir).join("guardian.toml"),
    )?)?;

    let listen_addr = opts
        .listen_addr
        .unwrap_or_else(|| "127.0.0.1:8443".to_string());
    tracing::info!(target: "guardian", listen_addr = %listen_addr);

    let guardian = Arc::new(GuardianContainer::new(config)?);
    guardian.start(&listen_addr).await?;

    // Print the readiness signal for the test harness after the listener is up.
    eprintln!("GUARDIAN_IPC_LISTENING_ON_{}", listen_addr);

    let guardian_clone = guardian.clone();
    tokio::spawn(async move {
        // Wait for the orchestration channel to be established before sending the report.
        // This resolves the race condition that caused the test timeout.
        while !guardian_clone.orchestration_channel.is_established().await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let local_hash_result = guardian_clone
            .attest_weights(&opts.agentic_model_path)
            .await;
        let report_bytes = serde_json::to_vec(&local_hash_result)?;

        if let Some(mut stream) = guardian_clone.orchestration_channel.take_stream().await {
            if let Err(e) = stream.write_all(&report_bytes).await {
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
                    "Sent agentic attestation report to Orchestrator."
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
