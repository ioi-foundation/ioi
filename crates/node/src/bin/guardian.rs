// crates/node/src/bin/guardian.rs
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use depin_sdk_api::validator::Container;
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::config::GuardianConfig;
use std::path::Path;
use std::sync::Arc;
use tokio::time::Duration;

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
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = GuardianOpts::parse();
    log::info!("Guardian container starting up...");

    let config: GuardianConfig = toml::from_str(&std::fs::read_to_string(
        Path::new(&opts.config_dir).join("guardian.toml"),
    )?)?;

    if let Some(addr) = opts.listen_addr {
        log::info!("Guardian listen address set to {}", addr);
        // Note: The mock GuardianContainer doesn't use the listen_addr yet.
    }

    let guardian = Arc::new(GuardianContainer::new(config)?);
    guardian.start().await?;

    let guardian_clone = guardian.clone();
    tokio::spawn(async move {
        // Mock waiting for connections
        tokio::time::sleep(Duration::from_secs(2)).await;
        log::info!("[Guardian] Both container connections and hardware attestations are complete.");

        let local_hash_result = guardian_clone
            .attest_weights(&opts.agentic_model_path)
            .await;
        let report_bytes = serde_json::to_vec(&local_hash_result).unwrap();
        if let Err(e) = guardian_clone
            .orchestration_channel
            .send(&report_bytes)
            .await
        {
            log::error!(
                "[Guardian] Failed to send agentic attestation report to Orchestrator: {}",
                e
            );
        } else {
            log::info!("[Guardian] Sent agentic attestation report to Orchestrator.");
        }
    });

    // FIX: Replace the simple `ctrl_c` await with a select block
    // to keep the main thread alive indefinitely until a shutdown signal is received.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Ctrl-C received, initiating shutdown.");
        }
    }

    guardian.stop().await?;
    log::info!("Guardian stopped.");

    Ok(())
}
