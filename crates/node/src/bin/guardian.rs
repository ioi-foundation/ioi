// Path: crates/node/src/bin/guardian.rs
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use depin_sdk_api::validator::Container;
use depin_sdk_validator::common::{generate_certificates_if_needed, GuardianContainer};
use depin_sdk_validator::config::GuardianConfig;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
    depin_sdk_telemetry::init::init_tracing();

    // 2. Spawn the telemetry server
    let telemetry_addr_str =
        std::env::var("TELEMETRY_ADDR").unwrap_or_else(|_| "127.0.0.1:9617".to_string());
    let telemetry_addr = telemetry_addr_str.parse()?;
    tokio::spawn(depin_sdk_telemetry::http::run_server(telemetry_addr));

    let opts = GuardianOpts::parse();
    tracing::info!(target: "guardian", event = "startup", config_dir = %opts.config_dir);

    let certs_dir = std::env::var("CERTS_DIR").expect("CERTS_DIR environment variable must be set");
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
        let report_bytes = serde_json::to_vec(&local_hash_result).unwrap();
        if let Err(e) = guardian_clone
            .orchestration_channel
            .send(&report_bytes)
            .await
        {
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
        }
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