// crates/node/src/bin/orchestration.rs

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::validator::container::Container;
use depin_sdk_chain::Chain;
use depin_sdk_client::security::SecurityChannel;
use depin_sdk_client::WorkloadClient;
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
use depin_sdk_commitment::tree::file::FileStateTree;
use depin_sdk_consensus::util::engine_from_config;
use depin_sdk_network::libp2p::Libp2pSync;
use depin_sdk_types::config::OrchestrationConfig;
use depin_sdk_validator::{rpc::run_rpc_server, standard::OrchestrationContainer};
use libp2p::{identity, Multiaddr};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Mutex;
use tokio::time::Duration;

#[derive(Parser, Debug)]
struct OrchestrationOpts {
    #[clap(long, help = "Path to the orchestration.toml configuration file.")]
    config: PathBuf,
    #[clap(long, help = "Path to the identity keypair file.")]
    identity_key_file: PathBuf,
    #[clap(long, env = "LISTEN_ADDRESS")]
    listen_address: Multiaddr,
    #[clap(long, env = "BOOTNODE")]
    bootnode: Option<Multiaddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = OrchestrationOpts::parse();
    log::info!(
        "Orchestration container starting up with config: {:?}",
        opts.config
    );

    let config_path = opts.config.clone();
    let config_str = fs::read_to_string(&config_path).map_err(|e| {
        anyhow!(
            "Failed to read orchestration config file at {:?}: {}",
            config_path,
            e
        )
    })?;
    let config: OrchestrationConfig = toml::from_str(&config_str)
        .map_err(|e| anyhow!("Failed to parse orchestration.toml: {}", e))?;

    let local_key = {
        let key_path = &opts.identity_key_file;
        if key_path.exists() {
            let mut bytes = Vec::new();
            fs::File::open(key_path)?.read_to_end(&mut bytes)?;
            identity::Keypair::from_protobuf_encoding(&bytes)?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
            keypair
        }
    };

    let (syncer, swarm_commander, network_event_receiver) =
        Libp2pSync::new(local_key.clone(), opts.listen_address, opts.bootnode)?;

    let consensus_engine = engine_from_config(&config)?;

    let is_quarantined = Arc::new(AtomicBool::new(false));

    let orchestration = Arc::new(OrchestrationContainer::<
        HashCommitmentScheme,
        FileStateTree<HashCommitmentScheme>,
        _,
    >::new(
        &config_path,
        syncer,
        network_event_receiver,
        swarm_commander.clone(),
        consensus_engine,
        local_key,
        is_quarantined.clone(),
    )?);

    let workload_client = {
        let workload_ipc_addr =
            std::env::var("WORKLOAD_IPC_ADDR").unwrap_or_else(|_| "127.0.0.1:8555".to_string());
        Arc::new(WorkloadClient::new(&workload_ipc_addr).await?)
    };

    let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
    if !guardian_addr.is_empty() {
        let is_quarantined_clone = is_quarantined.clone();
        let workload_client_clone = workload_client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let guardian_channel = SecurityChannel::new("orchestration", "guardian");
            if let Err(e) = guardian_channel
                .establish_client(&guardian_addr, "guardian")
                .await
            {
                log::error!(
                    "[Orchestration] Failed to connect to Guardian: {}. Quarantining.",
                    e
                );
                is_quarantined_clone.store(true, Ordering::SeqCst);
                return;
            }
            log::info!("[Orchestration] Attestation channel to Guardian established.");

            log::info!("[Orchestrator] Waiting for agentic attestation report from Guardian...");
            match guardian_channel.receive().await {
                Ok(report_bytes) => {
                    let report: Result<Vec<u8>, String> =
                        serde_json::from_slice(&report_bytes).unwrap();
                    match report {
                        Ok(local_hash) => {
                            log::info!(
                                "[Orchestrator] Received local model hash from Guardian: {}",
                                hex::encode(&local_hash)
                            );
                            match workload_client_clone.get_expected_model_hash().await {
                                Ok(expected_hash) => {
                                    if local_hash == expected_hash {
                                        log::info!("[Orchestrator] agentic model hash matches on-chain state. Node is healthy.");
                                    } else {
                                        log::error!("[Orchestrator] Model Integrity Failure! Local hash {} != on-chain hash {}. Quarantining node.", hex::encode(local_hash), hex::encode(expected_hash));
                                        is_quarantined_clone.store(true, Ordering::SeqCst);
                                    }
                                }
                                Err(e) => {
                                    log::error!("[Orchestrator] Failed to get expected model hash from Workload: {}. Quarantining node.", e);
                                    is_quarantined_clone.store(true, Ordering::SeqCst);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("[Orchestrator] Guardian reported an error during local hashing: {}. Quarantining node.", e);
                            is_quarantined_clone.store(true, Ordering::SeqCst);
                        }
                    }
                }
                Err(e) => {
                    log::error!("[Orchestrator] Failed to receive agentic report from Guardian: {}. Quarantining node.", e);
                    is_quarantined_clone.store(true, Ordering::SeqCst);
                }
            }
        });
    } else {
        log::warn!("GUARDIAN_ADDR not set, skipping Guardian attestation.");
    }

    let chain_ref = Arc::new(Mutex::new(
        Chain::<HashCommitmentScheme>::new_for_orchestrator(),
    ));
    orchestration.set_chain_and_workload_client(chain_ref, workload_client.clone());

    let rpc_handle = run_rpc_server(
        &config.rpc_listen_address,
        orchestration.tx_pool.clone(),
        workload_client,
        swarm_commander,
        config.clone(),
    )
    .await?;

    orchestration.start().await?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Ctrl-C received, initiating shutdown.");
        }
    }

    log::info!("Shutdown signal received.");
    orchestration.stop().await?;
    rpc_handle.abort();
    log::info!("Orchestration container stopped gracefully.");

    Ok(())
}
