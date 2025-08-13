// Path: crates/node/src/main.rs
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use depin_sdk_validator::common::attestation::{ContainerAttestation, SignatureSuite};
use depin_sdk_validator::common::security::SecurityChannel;
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(name = "depin-sdk-node", about = "A sovereign chain node.")]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Runs only the Orchestration container logic.
    Orchestration(ContainerOpts),
    /// Runs only the Workload container logic.
    Workload(ContainerOpts),
}

#[derive(Parser, Debug)]
struct ContainerOpts {}

// --- Helper Function for Attestation ---
async fn run_attestation_client(container_id: &str, channel: &SecurityChannel, keypair: &libp2p::identity::Keypair) -> anyhow::Result<()> {
    log::info!("[{}] Attestation client starting...", container_id);
    let nonce = channel.receive().await?;
    log::info!("[{}] Received nonce of length {}", container_id, nonce.len());
    
    let measurement_root = depin_sdk_crypto::algorithms::hash::sha256(container_id.as_bytes());
    
    let mut message_to_sign = Vec::new();
    message_to_sign.extend_from_slice(&nonce);
    message_to_sign.extend_from_slice(&measurement_root);
    let signature = keypair.sign(&message_to_sign)?;

    let report = ContainerAttestation {
        container_id: container_id.to_string(),
        measurement_root,
        nonce,
        public_key: keypair.public().encode_protobuf(),
        signature,
        signature_suite: SignatureSuite::Ed25519,
    };
    let report_bytes = serde_json::to_vec(&report)?;
    channel.send(&report_bytes).await?;
    log::info!("[{}] Attestation report sent.", container_id);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Orchestration(_) => {
            log::info!("Orchestration container starting up...");
            tokio::time::sleep(Duration::from_secs(5)).await;
            let guardian_addr = std::env::var("GUARDIAN_ADDR")?;
            let channel = SecurityChannel::new("orchestration", "guardian");
            channel.establish_client(&guardian_addr, "guardian").await?;
            
            let keypair = libp2p::identity::Keypair::generate_ed25519(); // Use a real, persisted key in production
            run_attestation_client("orchestration", &channel, &keypair).await?;

            log::info!("Orchestration container running. Attestation complete.");
            tokio::signal::ctrl_c().await?;
        }
        Command::Workload(_) => {
            log::info!("Workload container starting up...");
            tokio::time::sleep(Duration::from_secs(5)).await;
            let guardian_addr = std::env::var("GUARDIAN_ADDR")?;
            let channel = SecurityChannel::new("workload", "guardian");
            channel.establish_client(&guardian_addr, "guardian").await?;
            
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            run_attestation_client("workload", &channel, &keypair).await?;
            
            log::info!("Workload container running. Attestation complete.");
            tokio::signal::ctrl_c().await?;
        }
    }
    Ok(())
}