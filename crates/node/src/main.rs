// Path: crates/node/src/main.rs

#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_chain::Chain;
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
use depin_sdk_commitment::tree::file::FileStateTree;
use depin_sdk_consensus::{
    round_robin::RoundRobinBftEngine, Consensus, ConsensusDecision, ConsensusEngine,
};
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{Block, BlockHeader, ChainTransaction};
use depin_sdk_types::config::WorkloadConfig;
use depin_sdk_types::error::CoreError;
use depin_sdk_validator::common::attestation::{ContainerAttestation, SignatureSuite};
use depin_sdk_validator::common::ipc::{WorkloadRequest, WorkloadResponse};
use depin_sdk_validator::common::security::SecurityChannel;
use depin_sdk_validator::standard::workload_client::WorkloadClient;
use depin_sdk_vm_wasm::WasmVm;
use libp2p::identity;
use rcgen::{Certificate, CertificateParams, SanType};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{watch, Mutex};
use tokio::time::{self, Duration};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

#[derive(Parser, Debug)]
#[clap(name = "depin-sdk-node", about = "A sovereign chain node.")]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Orchestration(ContainerOpts),
    Workload(ContainerOpts),
}

#[derive(Parser, Debug)]
struct ContainerOpts {}

fn create_ipc_server_config() -> Result<Arc<ServerConfig>> {
    let mut server_params = CertificateParams::new(vec!["workload".to_string()]);
    server_params.subject_alt_names = vec![
        SanType::DnsName("workload".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    let server_cert = Certificate::from_params(server_params)?;
    let server_der = server_cert.serialize_der()?;
    let server_key = server_cert.serialize_private_key_der();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_der)],
            PrivateKeyDer::Pkcs8(server_key.into()),
        )?;
    Ok(Arc::new(server_config))
}

async fn run_attestation_client(
    container_id: &str,
    channel: &SecurityChannel,
    keypair: &libp2p::identity::Keypair,
) -> Result<()> {
    log::info!("[{}] Attestation client starting...", container_id);
    let nonce = channel.receive().await?;
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
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Orchestration(_) => {
            log::info!("Orchestration container starting up...");

            // --- Phase 1: Connect to Guardian and Attest ---
            let guardian_addr = std::env::var("GUARDIAN_ADDR")?;
            let guardian_channel = SecurityChannel::new("orchestration", "guardian");
            guardian_channel
                .establish_client(&guardian_addr, "guardian")
                .await?;
            let keypair_for_attestation = libp2p::identity::Keypair::generate_ed25519();
            run_attestation_client("orchestration", &guardian_channel, &keypair_for_attestation)
                .await?;
            log::info!("Orchestration: Attestation with Guardian complete.");

            // --- Phase 2: Instantiate All Core SDK Components ---
            let state_file = "orchestration_state.json";
            let local_key = {
                let key_path = Path::new(state_file).with_extension("json.identity.key");
                if key_path.exists() {
                    let mut bytes = Vec::new();
                    fs::File::open(&key_path)?.read_to_end(&mut bytes)?;
                    identity::Keypair::from_protobuf_encoding(&bytes)?
                } else {
                    let keypair = identity::Keypair::generate_ed25519();
                    fs::File::create(&key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
                    keypair
                }
            };

            let listen_addr = "/ip4/0.0.0.0/tcp/0".parse()?;
            let (syncer, swarm_commander, mut network_event_receiver) =
                Libp2pSync::new(local_key.clone(), listen_addr, None)?;

            let mut consensus_engine: Consensus<ChainTransaction> =
                Consensus::RoundRobin(Box::new(RoundRobinBftEngine::new()));

            let workload_ipc_addr =
                std::env::var("WORKLOAD_IPC_ADDR").unwrap_or_else(|_| "127.0.0.1:8555".to_string());
            let _workload_client = WorkloadClient::new(&workload_ipc_addr)?;
            log::info!(
                "Orchestration: WorkloadClient ready to connect to {}",
                workload_ipc_addr
            );

            let mut chain = Chain::new(
                HashCommitmentScheme::new(),
                UnifiedTransactionModel::new(HashCommitmentScheme::new()),
                "depin-chain-1",
                vec![],
                Box::new(|_| Err(CoreError::Custom("Not implemented".to_string()))),
            );

            let tx_pool = Arc::new(Mutex::new(VecDeque::<ChainTransaction>::new()));
            let (_shutdown_sender, mut shutdown_receiver) = watch::channel(false);

            // --- Phase 3: Run the Main Event Loop ---
            log::info!("Orchestration container entering main event loop.");
            let mut block_production_interval = time::interval(Duration::from_secs(10));
            block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            // FIX: Bind the Arc to a variable to extend its lifetime.
            let node_state_arc = syncer.get_node_state();
            let mut node_state = node_state_arc.lock().await;
            *node_state = NodeState::Syncing;
            drop(node_state);

            loop {
                tokio::select! {
                    Some(event) = network_event_receiver.recv() => {
                        if let NetworkEvent::GossipBlock(block) = event {
                             log::info!("[Orchestrator] Received gossiped block #{}. Processing...", block.header.height);
                            chain.state.recent_blocks.push(block);
                            chain.state.status.height += 1;
                        }
                    },
                    _ = block_production_interval.tick() => {
                        // FIX: Bind the Arc to a variable to extend its lifetime.
                        let node_state_arc = syncer.get_node_state();
                        let mut node_state = node_state_arc.lock().await;
                        if *node_state != NodeState::Synced {
                             *node_state = NodeState::Synced;
                             log::info!("[Orchestrator] No peers found. Assuming genesis node. State -> Synced.");
                        }
                        drop(node_state);

                        // FIX: Bind the Arc to a variable to extend its lifetime.
                        let known_peers_arc = syncer.get_known_peers();
                        let known_peers_guard = known_peers_arc.lock().await;
                        let decision = consensus_engine.decide(
                            &syncer.get_local_peer_id(),
                            chain.state.status.height + 1,
                            0,
                            &[],
                            &known_peers_guard,
                        ).await;
                        drop(known_peers_guard);

                        if let ConsensusDecision::ProduceBlock(_) = decision {
                            log::info!("Consensus decision: Produce block for height {}.", chain.state.status.height + 1);

                            let mut txs = tx_pool.lock().await.drain(..).collect::<Vec<_>>();
                            let coinbase = chain.state.transaction_model.create_coinbase_transaction(
                                chain.state.status.height + 1,
                                &syncer.get_local_peer_id().to_bytes()
                            ).unwrap();
                            txs.insert(0, coinbase);

                            let prev_hash = chain.state.recent_blocks.last().map_or(vec![0;32], |b| b.header.state_root.clone());
                            let mut header = BlockHeader {
                                height: chain.state.status.height + 1,
                                prev_hash,
                                state_root: vec![1; 32],
                                transactions_root: vec![2; 32],
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                validator_set: vec![],
                                producer: local_key.public().encode_protobuf(),
                                signature: vec![],
                            };
                            let header_hash = header.hash_for_signing();
                            header.signature = local_key.sign(&header_hash).unwrap();
                            let new_block = Block { header, transactions: txs };

                            chain.state.status.height += 1;
                            chain.state.recent_blocks.push(new_block.clone());
                            log::info!("Produced and processed new block #{}", new_block.header.height);

                            let data = serde_json::to_vec(&new_block).unwrap();
                            swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
                        }
                    },
                    _ = shutdown_receiver.changed() => {
                        if *shutdown_receiver.borrow() {
                            log::info!("Orchestration main loop received shutdown signal.");
                            break;
                        }
                    }
                }
            }
            log::info!("Orchestration main loop finished.");
            syncer.stop().await?;
        }
        Command::Workload(_) => {
            log::info!("Workload container starting up...");
            // --- Phase 1: Connect to Guardian and Attest ---
            let guardian_addr = std::env::var("GUARDIAN_ADDR")?;
            let guardian_channel = SecurityChannel::new("workload", "guardian");
            guardian_channel
                .establish_client(&guardian_addr, "guardian")
                .await?;

            let keypair = libp2p::identity::Keypair::generate_ed25519();
            run_attestation_client("workload", &guardian_channel, &keypair).await?;
            log::info!("Workload: Attestation with Guardian complete.");

            // --- Phase 2: Instantiate the real WorkloadContainer logic ---
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = FileStateTree::new("workload_state.json", commitment_scheme);
            let workload_config = WorkloadConfig {
                enabled_vms: vec!["WASM".to_string()],
            };
            let wasm_vm = Box::new(WasmVm::new());
            let workload_container = Arc::new(depin_sdk_api::validator::WorkloadContainer::new(
                workload_config,
                state_tree,
                wasm_vm,
            ));
            log::info!("Workload: State and VM initialized.");

            // --- Phase 3: Set up IPC server and enter main processing loop ---
            let ipc_server_addr =
                std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());
            let ipc_channel = SecurityChannel::new("workload", "orchestration");
            let listener = tokio::net::TcpListener::bind(&ipc_server_addr).await?;
            log::info!("Workload: IPC server listening on {}", ipc_server_addr);

            let server_config = create_ipc_server_config()?;
            let acceptor = TlsAcceptor::from(server_config);
            let (stream, _) = listener.accept().await?;
            let tls_stream = acceptor.accept(stream).await?;
            ipc_channel
                .accept_server_connection(tokio_rustls::TlsStream::Server(tls_stream))
                .await;
            log::info!("Workload: IPC connection established with Orchestration.");

            loop {
                let request_bytes = match ipc_channel.receive().await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log::error!("Workload: IPC receive error: {}. Closing.", e);
                        break;
                    }
                };
                let request: WorkloadRequest = serde_json::from_slice(&request_bytes)?;
                log::info!("Workload: Received request: {:?}", request);

                let response = match request {
                    WorkloadRequest::CallContract {
                        address,
                        input_data,
                        context,
                    } => {
                        let res = workload_container
                            .call_contract(address, input_data, context)
                            .await;
                        WorkloadResponse::CallContract(res.map_err(|e| e.to_string()))
                    }
                    _ => WorkloadResponse::ExecuteTransaction(Err(
                        "Request type not implemented".to_string()
                    )),
                };
                let response_bytes = serde_json::to_vec(&response)?;
                ipc_channel.send(&response_bytes).await?;
            }
        }
    }
    Ok(())
}
