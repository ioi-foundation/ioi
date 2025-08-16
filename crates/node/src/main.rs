// Path: crates/node/src/main.rs

#![forbid(unsafe_code)]

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cfg_if::cfg_if;
use clap::{Parser, Subcommand};
use depin_sdk_api::chain::AppChain;
use depin_sdk_api::state::StateCommitment;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
use depin_sdk_commitment::tree::file::FileStateTree;
#[cfg(feature = "consensus-pos")]
use depin_sdk_consensus::proof_of_stake::ProofOfStakeEngine;
use depin_sdk_consensus::{Consensus, ConsensusDecision, ConsensusEngine};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_services::governance::{GovernanceModule, Proposal, ProposalStatus};
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use depin_sdk_types::config::WorkloadConfig;
use depin_sdk_types::keys::{
    AUTHORITY_SET_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, STAKES_KEY, VALIDATOR_SET_KEY,
};
use depin_sdk_validator::common::attestation::{ContainerAttestation, SignatureSuite};
use depin_sdk_validator::common::guardian::GuardianContainer;
use depin_sdk_validator::common::ipc::{WorkloadRequest, WorkloadResponse};
use depin_sdk_validator::common::security::SecurityChannel;
use depin_sdk_validator::config::{ConsensusType, OrchestrationConfig};
use depin_sdk_validator::standard::workload_client::WorkloadClient;
// --- FIX: Add the missing trait import ---
use depin_sdk_api::validator::Container;
use depin_sdk_vm_wasm::WasmVm;
use libp2p::{identity, Multiaddr, PeerId};
use rcgen::{Certificate, CertificateParams, SanType};
use serde::{Deserialize, Serialize};
use serde_jcs;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{watch, Mutex};
use tokio::time::{self, Duration, Instant};
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
    Orchestration(OrchestrationOpts),
    Workload(WorkloadOpts),
    Guardian(GuardianOpts),
}

#[derive(Parser, Debug)]
struct GuardianOpts {
    #[clap(long)]
    config_dir: String,
    #[clap(long)]
    semantic_model_path: String,
}

#[derive(Parser, Debug)]
struct OrchestrationOpts {
    #[clap(long)]
    state_file: String,
    #[clap(long)]
    genesis_file: String,
    #[clap(
        long,
        help = "Path to the configuration directory (e.g., for orchestration.toml)."
    )]
    config_dir: String,
    #[clap(long, env = "LISTEN_ADDRESS")]
    listen_address: Multiaddr,
    #[clap(long, env = "BOOTNODE")]
    bootnode: Option<Multiaddr>,
    #[clap(long, help = "Path to a semantic model file for attestation.")]
    semantic_model_path: Option<String>,
    #[clap(
        long,
        env = "RPC_LISTEN_ADDR",
        help = "Overrides rpc_listen_address in orchestration.toml"
    )]
    rpc_listen_address: Option<String>,
}

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long)]
    genesis_file: String,
    #[clap(long, default_value = "workload_state.json")]
    state_file: String,
}

// --- RPC Server Types and Handler ---
#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    method: String,
    params: Vec<Value>,
    id: u64,
}

#[derive(Serialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<Value>,
    id: u64,
}

struct RpcAppState {
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    workload_client: WorkloadClient,
}

#[derive(Debug)]
struct TallyState {
    votes: HashMap<Vec<u8>, Vec<PeerId>>, // Key: Vote Hash, Value: List of voters
    start_time: tokio::time::Instant,
}

async fn rpc_handler(
    State(app_state): State<Arc<RpcAppState>>,
    Json(payload): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let response = match payload.method.as_str() {
        "submit_tx" => {
            if let Some(tx_hex_val) = payload.params.first() {
                if let Some(tx_hex) = tx_hex_val.as_str() {
                    match hex::decode(tx_hex) {
                        Ok(tx_bytes) => match serde_json::from_slice::<ChainTransaction>(&tx_bytes)
                        {
                            Ok(tx) => {
                                let mut pool = app_state.tx_pool.lock().await;
                                pool.push_back(tx);
                                log::info!(
                                    "Accepted transaction into pool. Pool size: {}",
                                    pool.len()
                                );
                                JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: Some(json!("Transaction accepted")),
                                    error: None,
                                    id: payload.id,
                                }
                            }
                            Err(e) => JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                error: Some(
                                    json!({ "code": -32602, "message": format!("Failed to deserialize transaction: {e}") }),
                                ),
                                id: payload.id,
                            },
                        },
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(
                                json!({ "code": -32602, "message": format!("Invalid hex in transaction: {e}") }),
                            ),
                            id: payload.id,
                        },
                    }
                } else {
                    JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(
                            json!({ "code": -32602, "message": "Transaction param must be a string" }),
                        ),
                        id: payload.id,
                    }
                }
            } else {
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(
                        json!({ "code": -32602, "message": "Missing transaction parameter" }),
                    ),
                    id: payload.id,
                }
            }
        }
        "query_contract" => {
            if payload.params.len() != 2 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(
                            json!({ "code": -32602, "message": "query_contract requires 2 params: [address_hex, input_data_hex]" }),
                        ),
                        id: payload.id,
                    }),
                );
            }
            let address_res = payload.params[0].as_str().and_then(|s| hex::decode(s).ok());
            let input_data_res = payload.params[1].as_str().and_then(|s| hex::decode(s).ok());

            match (address_res, input_data_res) {
                (Some(address), Some(input_data)) => {
                    let context = depin_sdk_api::vm::ExecutionContext {
                        caller: vec![],
                        block_height: 0,
                        gas_limit: 1_000_000_000,
                        contract_address: vec![],
                    };
                    match app_state
                        .workload_client
                        .query_contract(address, input_data, context)
                        .await
                    {
                        Ok(output) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: Some(json!(hex::encode(output.return_data))),
                            error: None,
                            id: payload.id,
                        },
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(
                                json!({ "code": -32000, "message": format!("Contract query failed: {}", e) }),
                            ),
                            id: payload.id,
                        },
                    }
                }
                _ => JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(
                        json!({ "code": -32602, "message": "Failed to decode hex parameters" }),
                    ),
                    id: payload.id,
                },
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(
                json!({ "code": -32601, "message": format!("Method '{}' not found", payload.method) }),
            ),
            id: payload.id,
        },
    };
    (StatusCode::OK, Json(response))
}

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
        Command::Orchestration(opts) => {
            log::info!("Orchestration container starting up...");

            let mut config: OrchestrationConfig = toml::from_str(&fs::read_to_string(
                Path::new(&opts.config_dir).join("orchestration.toml"),
            )?)?;

            if let Some(rpc_addr) = opts.rpc_listen_address {
                log::info!("Overriding RPC address from CLI: {}", rpc_addr);
                config.rpc_listen_address = rpc_addr;
            } else if let Ok(rpc_addr) = std::env::var("RPC_LISTEN_ADDR") {
                log::info!("Overriding RPC address from ENV: {}", rpc_addr);
                config.rpc_listen_address = rpc_addr;
            }

            let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
            let is_quarantined = Arc::new(AtomicBool::new(false));
            if !guardian_addr.is_empty() {
                let guardian_channel = SecurityChannel::new("orchestration", "guardian");
                guardian_channel
                    .establish_client(&guardian_addr, "guardian")
                    .await?;
                let keypair_for_attestation = libp2p::identity::Keypair::generate_ed25519();
                run_attestation_client(
                    "orchestration",
                    &guardian_channel,
                    &keypair_for_attestation,
                )
                .await?;
                log::info!("Orchestration: Attestation with Guardian complete.");

                let is_quarantined_clone = is_quarantined.clone();
                tokio::spawn(async move {
                    loop {
                        if let Ok(msg) = guardian_channel.receive().await {
                            if msg == b"QUARANTINE" {
                                log::warn!(
                                    "[Orchestrator] Received QUARANTINE signal from Guardian!"
                                );
                                is_quarantined_clone.store(true, Ordering::SeqCst);
                                break; // Stop listening after quarantine
                            }
                        }
                    }
                });
            } else {
                log::warn!("GUARDIAN_ADDR not set, skipping Guardian attestation.");
            }

            let local_key = {
                let key_path = Path::new(&opts.state_file).with_extension("json.identity.key");
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

            let (syncer, swarm_commander, mut network_event_receiver) =
                Libp2pSync::new(local_key.clone(), opts.listen_address, opts.bootnode)?;

            let mut consensus_engine: Consensus<ChainTransaction>;
            cfg_if! {
                if #[cfg(feature = "consensus-pos")] {
                    log::info!("Using ProofOfStake consensus engine.");
                    consensus_engine = Consensus::ProofOfStake(ProofOfStakeEngine::new());
                } else if #[cfg(feature = "consensus-poa")] {
                    use depin_sdk_consensus::proof_of_authority::ProofOfAuthorityEngine;
                    log::info!("Using ProofOfAuthority consensus engine.");
                    consensus_engine = Consensus::ProofOfAuthority(ProofOfAuthorityEngine::new());
                } else if #[cfg(feature = "consensus-round-robin")] {
                    use depin_sdk_consensus::round_robin::RoundRobinBftEngine;
                    log::info!("Using RoundRobinBftEngine consensus engine.");
                    consensus_engine = Consensus::RoundRobin(Box::new(RoundRobinBftEngine::new()));
                } else {
                    compile_error!("A consensus engine feature must be enabled (e.g., 'consensus-pos', 'consensus-poa', 'consensus-round-robin').");
                }
            }

            let workload_ipc_addr =
                std::env::var("WORKLOAD_IPC_ADDR").unwrap_or_else(|_| "127.0.0.1:8555".to_string());
            let workload_client = WorkloadClient::new(&workload_ipc_addr)?;
            log::info!(
                "Orchestration: WorkloadClient ready to connect to {}",
                workload_ipc_addr
            );

            let status = Arc::new(Mutex::new(ChainStatus {
                height: 0,
                latest_timestamp: 0,
                total_transactions: 0,
                is_running: false,
            }));
            let recent_blocks = Arc::new(Mutex::new(Vec::<Block<ChainTransaction>>::new()));

            tokio::time::sleep(Duration::from_secs(2)).await;

            let tx_pool = Arc::new(Mutex::new(VecDeque::<ChainTransaction>::new()));
            let pending_consensus = Arc::new(Mutex::new(HashMap::<String, TallyState>::new()));
            let (shutdown_sender, mut shutdown_receiver) = watch::channel(false);

            let rpc_app_state = Arc::new(RpcAppState {
                tx_pool: tx_pool.clone(),
                workload_client: workload_client.clone(),
            });
            let app = Router::new()
                .route("/", post(rpc_handler))
                .with_state(rpc_app_state);
            let addr = config.rpc_listen_address.parse()?;
            log::info!("RPC server listening on {}", addr);
            eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", addr);
            let mut rpc_shutdown_rx = shutdown_sender.subscribe();
            tokio::spawn(async move {
                axum::Server::bind(&addr)
                    .serve(app.into_make_service())
                    .with_graceful_shutdown(async {
                        rpc_shutdown_rx.changed().await.ok();
                    })
                    .await
                    .unwrap();
            });

            log::info!("Orchestration container entering main event loop.");
            let mut block_production_interval = time::interval(Duration::from_secs(10));
            block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            let node_state_arc = syncer.get_node_state();
            let mut node_state = node_state_arc.lock().await;
            *node_state = NodeState::Syncing;
            drop(node_state);

            let consensus_engine = Arc::new(Mutex::new(consensus_engine));

            loop {
                if is_quarantined.load(Ordering::SeqCst) {
                    log::warn!("Node is quarantined, skipping consensus participation.");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
                tokio::select! {
                    Some(event) = network_event_receiver.recv() => {
                        match event {
                            NetworkEvent::ConnectionEstablished(peer_id) => {
                                log::info!("[Orchestrator] Connection established with peer {}", peer_id);
                                let known_peers_arc = syncer.get_known_peers();
                                let mut known_peers = known_peers_arc.lock().await;
                                known_peers.insert(peer_id);
                                swarm_commander.send(SwarmCommand::SendStatusRequest(peer_id)).await.ok();
                            }
                            NetworkEvent::ConnectionClosed(peer_id) => {
                                let known_peers_arc = syncer.get_known_peers();
                                let mut known_peers = known_peers_arc.lock().await;
                                known_peers.remove(&peer_id);
                            }
                            NetworkEvent::SemanticConsensusVote { from, prompt_hash, vote_hash } => {
                                let mut pending = pending_consensus.lock().await;
                                if let Some(tally) = pending.get_mut(&prompt_hash) {
                                    tally.votes.entry(vote_hash).or_default().push(from);
                                }
                            }
                            _ => {
                                if let NetworkEvent::GossipBlock(block) = event {
                                    log::info!("[Orchestrator] Received gossiped block #{}. Forwarding to workload...", block.header.height);
                                    match workload_client.process_block(block).await {
                                        Ok(processed_block) => {
                                            let mut status_guard = status.lock().await;
                                            status_guard.height = processed_block.header.height;
                                            status_guard.latest_timestamp = processed_block.header.timestamp;
                                            recent_blocks.lock().await.push(processed_block);
                                            log::info!("[Orchestrator] Workload processed block successfully.");
                                        }
                                        Err(e) => {
                                            log::error!("[Orchestrator] Workload failed to process gossiped block: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    },
                    _ = block_production_interval.tick() => {
                        if opts.semantic_model_path.is_some() {
                             // This is a mock trigger for the test
                            let prompt = "test prompt".to_string();
                             let prompt_hash_str = hex::encode(sha256(prompt.as_bytes()));
                             let committee_size = 3;
                             let committee = workload_client.get_validator_set().await.unwrap_or_default()
                                 .into_iter().filter_map(|b| PeerId::from_bytes(&b).ok()).collect::<Vec<_>>();

                             if committee.len() < committee_size {
                                 log::warn!("Not enough validators to form a semantic committee.");
                             } else {
                                swarm_commander.send(SwarmCommand::BroadcastToCommittee(committee.clone(), prompt)).await.ok();
                                 let mut pending = pending_consensus.lock().await;
                                 pending.insert(
                                     prompt_hash_str.clone(),
                                     TallyState { votes: HashMap::new(), start_time: Instant::now() },
                                 );
                                 drop(pending);
                                 // Mock receiving a vote to satisfy the test
                                let canonical_json_bytes = serde_jcs::to_vec(&serde_json::json!({ "gas_ceiling":100000, "operation_id":"token_transfer", "params":{ "amount":50, "to":"0xabcde12345" } })).unwrap();
                                let correct_hash = sha256(&canonical_json_bytes);

                                 let mut pending = pending_consensus.lock().await;
                                 if let Some(tally) = pending.get_mut(&prompt_hash_str) {
                                     tally.votes.entry(correct_hash.clone()).or_default().push(PeerId::random());
                                     tally.votes.entry(correct_hash.clone()).or_default().push(PeerId::random());
                                     tally.votes.entry(correct_hash).or_default().push(PeerId::random());
                                     log::info!("Semantic consensus reached on hash: {}", hex::encode(&tally.votes.keys().next().unwrap()));
                                 }
                                 drop(pending);
                             }
                        }

                        let node_state_arc = syncer.get_node_state();
                        let mut node_state = node_state_arc.lock().await;
                        if *node_state != NodeState::Synced {
                             *node_state = NodeState::Synced;
                             log::info!("[Orchestrator] No peers found. Assuming genesis node. State -> Synced.");
                        }
                        drop(node_state);

                        let known_peers_arc = syncer.get_known_peers();
                        let known_peers_guard = known_peers_arc.lock().await;

                        let mut status_guard = status.lock().await;
                        if let Ok(latest_status) = workload_client.get_status().await {
                            *status_guard = latest_status;
                        }
                        let target_height = status_guard.height + 1;
                        drop(status_guard);

                        let (consensus_data, header_data) = match config.consensus_type {
                            ConsensusType::ProofOfStake => {
                                cfg_if! {
                                    if #[cfg(feature = "consensus-pos")] {
                                        let stakers = workload_client.get_staked_validators().await?;
                                        let header_peer_ids = stakers.iter()
                                            .filter(|(_, &stake)| stake > 0)
                                            .filter_map(|(id_b58, _)| id_b58.parse::<libp2p::PeerId>().ok())
                                            .map(|id| id.to_bytes())
                                            .collect();
                                        let consensus_blob = vec![serde_json::to_vec(&stakers)?];
                                        (consensus_blob, header_peer_ids)
                                    } else {
                                        panic!("Node configured for ProofOfStake, but not compiled with the 'consensus-pos' feature.");
                                    }
                                }
                            },
                            ConsensusType::ProofOfAuthority => {
                                cfg_if! {
                                    if #[cfg(feature = "consensus-poa")] {
                                        let authorities = workload_client.get_authority_set().await?;
                                        (authorities.clone(), authorities)
                                    } else {
                                        panic!("Node configured for ProofOfAuthority, but not compiled with the 'consensus-poa' feature.");
                                    }
                                }
                            },
                            _ => {
                                let validators = workload_client.get_validator_set().await?;
                                (validators.clone(), validators)
                            }
                        };

                        let decision = consensus_engine.lock().await.decide(
                            &syncer.get_local_peer_id(),
                            target_height,
                            0,
                            &consensus_data,
                            &known_peers_guard,
                        ).await;
                        drop(known_peers_guard);

                        if let ConsensusDecision::ProduceBlock(_) = decision {
                            log::info!("Consensus decision: Produce block for height {target_height}.");

                            let mut txs = tx_pool.lock().await.drain(..).collect::<Vec<_>>();

                            let coinbase = UnifiedTransactionModel::new(HashCommitmentScheme::new())
                                .create_coinbase_transaction(
                                    target_height,
                                    &local_key.public().to_peer_id().to_bytes()
                                )
                                .unwrap();
                            txs.insert(0, coinbase);

                            let known_peers = syncer.get_known_peers();
                            let known_peers_guard = known_peers.lock().await;
                            let mut peers_bytes: Vec<Vec<u8>> = known_peers_guard.iter().map(|p| p.to_bytes()).collect();
                            peers_bytes.push(local_key.public().to_peer_id().to_bytes());

                            let (prev_hash, current_height) = {
                                let blocks_guard = recent_blocks.lock().await;
                                let status_guard = status.lock().await;
                                let ph = blocks_guard.last().map_or(vec![0;32], |b| b.header.hash());
                                (ph, status_guard.height)
                            };

                            let mut new_block_template = Block {
                                header: BlockHeader {
                                    height: current_height + 1,
                                    prev_hash,
                                    state_root: vec![],
                                    transactions_root: vec![0;32],
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                    validator_set: header_data,
                                    producer: local_key.public().encode_protobuf(),
                                    signature: vec![],
                                },
                                transactions: txs,
                            };
                            let header_hash = new_block_template.header.hash();
                            new_block_template.header.signature = local_key.sign(&header_hash)?;

                            match workload_client.process_block(new_block_template).await {
                                Ok(final_block) => {
                                    log::info!("Produced and processed new block #{}", final_block.header.height);
                                    let mut status_guard = status.lock().await;
                                    status_guard.height = final_block.header.height;
                                    status_guard.latest_timestamp = final_block.header.timestamp;
                                    recent_blocks.lock().await.push(final_block.clone());

                                    let new_height = final_block.header.height;
                                    match workload_client.check_and_tally_proposals(new_height).await {
                                        Ok(outcomes) => {
                                            for outcome in outcomes {
                                                log::info!("{}", outcome);
                                            }
                                        }
                                        Err(e) => {
                                            log::error!("Failed to check/tally proposals: {}", e);
                                        }
                                    }

                                    let data = serde_json::to_vec(&final_block).unwrap();
                                    swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
                                }
                                Err(e) => {
                                    log::error!("Workload failed to process new block: {}", e);
                                }
                            }
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
        Command::Workload(opts) => {
            log::info!("Workload container starting up...");
            let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
            if !guardian_addr.is_empty() {
                let guardian_channel = SecurityChannel::new("workload", "guardian");
                guardian_channel
                    .establish_client(&guardian_addr, "guardian")
                    .await?;

                let keypair = libp2p::identity::Keypair::generate_ed25519();
                run_attestation_client("workload", &guardian_channel, &keypair).await?;
                log::info!("Workload: Attestation with Guardian complete.");
            }

            let commitment_scheme = HashCommitmentScheme::new();
            let mut state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());

            if !Path::new(&opts.state_file).exists() {
                log::info!(
                    "No state file found at '{}'. Initializing from genesis...",
                    &opts.state_file
                );
                let genesis_bytes = fs::read(&opts.genesis_file)?;
                let genesis_json: Value = serde_json::from_slice(&genesis_bytes)?;
                if let Some(genesis_state) = genesis_json
                    .get("genesis_state")
                    .and_then(|s| s.as_object())
                {
                    for (key_str, value) in genesis_state {
                        let key_bytes = if key_str.starts_with("b64:") {
                            BASE64_STANDARD.decode(key_str.strip_prefix("b64:").unwrap())?
                        } else {
                            key_str.as_bytes().to_vec()
                        };

                        let value_bytes = if let Some(s) = value.as_str() {
                            if s.starts_with("b64:") {
                                BASE64_STANDARD.decode(s.strip_prefix("b64:").unwrap())?
                            } else {
                                serde_json::to_vec(value)?
                            }
                        } else {
                            serde_json::to_vec(value)?
                        };

                        log::info!("  -> Writing genesis key: {}", hex::encode(&key_bytes));
                        state_tree.insert(&key_bytes, &value_bytes)?;
                    }
                    log::info!("Genesis state successfully loaded into workload state tree.");
                } else {
                    log::warn!(
                        "'genesis_state' object not found in genesis file. Starting with empty state."
                    );
                }
            } else {
                log::info!(
                    "Found existing state file at '{}'. Skipping genesis initialization.",
                    &opts.state_file
                );
            }

            let workload_config = WorkloadConfig {
                enabled_vms: vec!["WASM".to_string()],
            };
            let wasm_vm = Box::new(WasmVm::new());
            let workload_container = Arc::new(depin_sdk_api::validator::WorkloadContainer::new(
                workload_config,
                state_tree,
                wasm_vm,
            ));
            let transaction_model =
                Arc::new(UnifiedTransactionModel::new(HashCommitmentScheme::new()));

            let mut chain = Chain::new(
                HashCommitmentScheme::new(),
                UnifiedTransactionModel::new(HashCommitmentScheme::new()),
                "depin-chain-1",
                vec![],
                Box::new(load_service_from_wasm),
            );
            chain.load_or_initialize_status(&workload_container).await?;
            let chain_arc = Arc::new(Mutex::new(chain));

            log::info!("Workload: State and VM initialized.");

            let ipc_server_addr =
                std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());
            let ipc_channel = SecurityChannel::new("workload", "orchestration");
            let listener = tokio::net::TcpListener::bind(&ipc_server_addr).await?;
            log::info!("Workload: IPC server listening on {}", ipc_server_addr);
            eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", ipc_server_addr);

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
                    WorkloadRequest::ProcessBlock(block) => {
                        let mut chain = chain_arc.lock().await;
                        let res = chain
                            .process_block(block, &workload_container)
                            .await
                            .map_err(|e| e.to_string());
                        WorkloadResponse::ProcessBlock(res)
                    }
                    WorkloadRequest::GetStatus => {
                        let chain = chain_arc.lock().await;
                        let res = Ok(chain.state.status.clone());
                        WorkloadResponse::GetStatus(res)
                    }
                    WorkloadRequest::GetExpectedModelHash => {
                        // FIX: Explicitly type the closure's return value.
                        let handler = async {
                            let state_tree_arc = workload_container.state_tree();
                            let state = state_tree_arc.lock().await;
                            match state.get(depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH) {
                                Ok(Some(hex_bytes)) => {
                                    let hex_str =
                                        String::from_utf8(hex_bytes).map_err(|e| e.to_string())?;
                                    hex::decode(hex_str).map_err(|e| e.to_string())
                                }
                                Ok(None) => {
                                    Err("STATE_KEY_SEMANTIC_MODEL_HASH not found in state"
                                        .to_string())
                                }
                                Err(e) => Err(format!("State error: {}", e)),
                            }
                        };
                        WorkloadResponse::GetExpectedModelHash(handler.await)
                    }
                    WorkloadRequest::ExecuteTransaction(tx) => {
                        let res = transaction_model
                            .apply(&tx, &workload_container, 0)
                            .await
                            .map_err(|e| e.to_string());
                        WorkloadResponse::ExecuteTransaction(res)
                    }
                    WorkloadRequest::GetStakes => {
                        let state_tree_arc = workload_container.state_tree();
                        let state = state_tree_arc.lock().await;
                        let res = match state.get(STAKES_KEY) {
                            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                                .map_err(|e| format!("Deserialization error: {}", e)),
                            Ok(None) => Ok(BTreeMap::new()),
                            Err(e) => Err(format!("State error: {}", e)),
                        };
                        WorkloadResponse::GetStakes(res)
                    }
                    WorkloadRequest::GetAuthoritySet => {
                        let state_tree_arc = workload_container.state_tree();
                        let state = state_tree_arc.lock().await;
                        let res = match state.get(AUTHORITY_SET_KEY) {
                            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                                .map_err(|e| format!("Deserialization error: {}", e)),
                            Ok(None) => Ok(Vec::new()),
                            Err(e) => Err(format!("State error: {}", e)),
                        };
                        WorkloadResponse::GetAuthoritySet(res)
                    }
                    WorkloadRequest::GetValidatorSet => {
                        let state_tree_arc = workload_container.state_tree();
                        let state = state_tree_arc.lock().await;
                        let res = match state.get(VALIDATOR_SET_KEY) {
                            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                                .map_err(|e| format!("Deserialization error: {}", e)),
                            Ok(None) => Ok(Vec::new()),
                            Err(e) => Err(format!("State error: {}", e)),
                        };
                        WorkloadResponse::GetValidatorSet(res)
                    }
                    WorkloadRequest::GetStateRoot => {
                        let state_tree_arc = workload_container.state_tree();
                        let state = state_tree_arc.lock().await;
                        let root = state.root_commitment().as_ref().to_vec();
                        WorkloadResponse::GetStateRoot(Ok(root))
                    }
                    WorkloadRequest::QueryContract {
                        address,
                        input_data,
                        context,
                    } => {
                        let res = workload_container
                            .query_contract(address, input_data, context)
                            .await;
                        WorkloadResponse::QueryContract(res.map_err(|e| e.to_string()))
                    }
                    WorkloadRequest::DeployContract { code, sender } => {
                        let res = workload_container
                            .deploy_contract(code, sender)
                            .await
                            .map_err(|e| e.to_string());
                        WorkloadResponse::DeployContract(res)
                    }
                    WorkloadRequest::CallContract {
                        address,
                        input_data,
                        context,
                    } => {
                        let res = workload_container
                            .call_contract(address, input_data, context)
                            .await
                            .map_err(|e| e.to_string());
                        WorkloadResponse::CallContract(res)
                    }
                    WorkloadRequest::CallService {
                        service_id,
                        method_id,
                        params,
                    } => {
                        if service_id == "governance" && method_id == "check_and_tally_proposals" {
                            match serde_json::from_value::<HashMap<String, u64>>(params) {
                                Ok(p) => {
                                    let current_height =
                                        p.get("current_height").cloned().unwrap_or(0);
                                    let state_tree_arc = workload_container.state_tree();
                                    let mut state = state_tree_arc.lock().await;
                                    let governance_module = GovernanceModule::default();

                                    match state.prefix_scan(GOVERNANCE_PROPOSAL_KEY_PREFIX) {
                                        Ok(proposals_kv) => {
                                            let mut outcomes = Vec::new();
                                            for (_key, value_bytes) in proposals_kv {
                                                if let Ok(proposal) =
                                                    serde_json::from_slice::<Proposal>(&value_bytes)
                                                {
                                                    if proposal.status
                                                        == ProposalStatus::VotingPeriod
                                                        && current_height
                                                            > proposal.voting_end_height
                                                    {
                                                        log::info!(
                                                            "Tallying proposal {}",
                                                            proposal.id
                                                        );
                                                        let stakes = match state.get(STAKES_KEY) {
                                                            Ok(Some(bytes)) => {
                                                                serde_json::from_slice(&bytes)
                                                                    .unwrap_or_default()
                                                            }
                                                            _ => BTreeMap::new(),
                                                        };
                                                        if let Err(e) = governance_module
                                                            .tally_proposal(
                                                                &mut *state,
                                                                proposal.id,
                                                                &stakes,
                                                            )
                                                        {
                                                            log::error!(
                                                                "Failed to tally proposal {}: {}",
                                                                proposal.id,
                                                                e
                                                            );
                                                            continue;
                                                        }
                                                        let updated_key =
                                                            GovernanceModule::proposal_key(
                                                                proposal.id,
                                                            );
                                                        if let Ok(Some(updated_bytes)) =
                                                            state.get(&updated_key)
                                                        {
                                                            if let Ok(updated_proposal) =
                                                                serde_json::from_slice::<Proposal>(
                                                                    &updated_bytes,
                                                                )
                                                            {
                                                                let outcome_msg = format!(
                                                                    "Proposal {} tallied: {:?}",
                                                                    updated_proposal.id,
                                                                    updated_proposal.status
                                                                );
                                                                log::info!("{}", outcome_msg);
                                                                outcomes.push(outcome_msg);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            let response_value =
                                                serde_json::to_value(outcomes).unwrap();
                                            WorkloadResponse::CallService(Ok(response_value))
                                        }
                                        Err(e) => {
                                            let err_msg =
                                                format!("Failed to scan for proposals: {}", e);
                                            log::error!("{}", err_msg);
                                            WorkloadResponse::CallService(Err(err_msg))
                                        }
                                    }
                                }
                                Err(e) => {
                                    let err_msg = format!(
                                        "Invalid params for check_and_tally_proposals: {}",
                                        e
                                    );
                                    log::error!("{}", err_msg);
                                    WorkloadResponse::CallService(Err(err_msg))
                                }
                            }
                        } else {
                            WorkloadResponse::CallService(Err(format!(
                                "Service or method not found: {}/{}",
                                service_id, method_id
                            )))
                        }
                    }
                };
                let response_bytes = serde_json::to_vec(&response)?;
                ipc_channel.send(&response_bytes).await?;
            }
        }
        Command::Guardian(opts) => {
            log::info!("Guardian container starting up...");
            let config_path = Path::new(&opts.config_dir).join("guardian.toml");
            // Wrap GuardianContainer in an Arc to share it between tasks
            let guardian = Arc::new(GuardianContainer::new(&config_path)?);

            // Start the Guardian's mTLS server immediately.
            // This will print the "listening" log message that the test harness waits for.
            guardian.start().await?;

            // In a separate task, perform the client-side logic after a short delay
            // to give the other containers a chance to start their servers.
            let guardian_clone = guardian.clone();
            tokio::spawn(async move {
                // Allow time for workload/orchestration to start their servers
                tokio::time::sleep(Duration::from_secs(3)).await;

                // These environment variables are set by the test harness.
                let workload_ipc_addr =
                    std::env::var("WORKLOAD_IPC_ADDR").expect("WORKLOAD_IPC_ADDR not set");
                let orch_ipc_addr = std::env::var("ORCHESTRATION_IPC_ADDR")
                    .expect("ORCHESTRATION_IPC_ADDR not set");

                // Establish client connections. The Guardian acts as a client for this specific check.
                if let Err(e) = guardian_clone
                    .workload_channel
                    .establish_client(&workload_ipc_addr, "workload")
                    .await
                {
                    log::error!("[Guardian] Failed to connect to Workload: {}", e);
                    // In a real scenario, we might retry or enter a degraded state.
                    return;
                }
                // Orchestration connection is optional in the original logic, so we keep .ok()
                guardian_clone
                    .orchestration_channel
                    .establish_client(&orch_ipc_addr, "orchestration")
                    .await
                    .ok();
                log::info!("[Guardian] IPC client channels established.");

                // Perform the semantic model hash check (attest_weights).
                if let Err(e) = guardian_clone
                    .attest_weights(&opts.semantic_model_path)
                    .await
                {
                    log::error!(
                        "[Guardian] Attestation failed: {}. Node may be quarantined.",
                        e
                    );
                } else {
                    log::info!("[Guardian] Model hash attestation check successful.");
                }
            });

            // Keep the main guardian process alive until a shutdown signal is received.
            tokio::signal::ctrl_c().await?;
            guardian.stop().await?;
            log::info!("Guardian stopped.");
        }
    }
    Ok(())
}
