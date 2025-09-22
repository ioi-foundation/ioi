// Path: crates/node/src/bin/malicious-workload.rs
#![forbid(unsafe_code)]

//! A malicious workload container for testing proof verification.
//! This is a copy of the main workload binary with a modified IPC handler
//! that returns a tampered proof for a specific key.

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::{
    commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer,
};
use depin_sdk_chain::util::load_state_from_genesis_file;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_client::security::SecurityChannel;
use depin_sdk_commitment::primitives::hash::HashProof;
use depin_sdk_consensus::util::engine_from_config;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::Membership;
use depin_sdk_types::codec;
use depin_sdk_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use depin_sdk_types::keys::VALIDATOR_SET_KEY;
use depin_sdk_validator::standard::workload_ipc_server::{
    create_ipc_server_config,
    methods::{
        chain::{
            CheckTransactionsV1, GetAuthoritySetV1, GetLastBlockHashV1, GetNextValidatorSetV1,
            GetValidatorSetAtV1, GetValidatorSetForV1, ProcessBlockV1,
        },
        contract::{CallContractV1, DeployContractV1, QueryContractV1},
        staking::{GetNextStakesV1, GetStakesV1},
        state::{
            GetActiveKeyAtV1, GetRawStateV1, GetStateRootV1, PrefixScanV1, QueryStateAtResponse,
            QueryStateAtV1,
        },
        system::{
            CallServiceV1, CheckAndTallyProposalsV1, GetExpectedModelHashV1, GetGenesisStatusV1,
            GetStatusV1, GetWorkloadConfigV1,
        },
        RpcContext,
    },
    router::{RequestContext, Router},
};
use depin_sdk_vm_wasm::WasmVm;
use ipc_protocol::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
};
use tokio_rustls::TlsAcceptor;

// Imports for concrete types used in the factory
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "tree-iavl")]
use depin_sdk_commitment::tree::iavl::IAVLTree;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Generic function containing all logic after component instantiation.
#[allow(dead_code)]
async fn run_workload<CS, ST>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    CS::Proof: AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    CS::Commitment: std::fmt::Debug,
{
    if !Path::new(&config.state_file).exists() {
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        log::info!(
            "Found existing state file at '{}'. Skipping genesis initialization.",
            &config.state_file
        );
    }

    let wasm_vm = Box::new(WasmVm::new(config.fuel_costs.clone()));

    let mut initial_services = Vec::new();
    for service_config in &config.initial_services {
        match service_config {
            InitialServiceConfig::IdentityHub(migration_config) => {
                log::info!("[Workload] Instantiating initial service: IdentityHub");
                let hub = IdentityHub::new(migration_config.clone());
                initial_services
                    .push(Arc::new(hub) as Arc<dyn depin_sdk_api::services::UpgradableService>);
            }
            // --- FIX START ---
            InitialServiceConfig::Governance(_) => {
                // The malicious workload doesn't need to run governance, so we just ignore it.
            } // --- FIX END ---
        }
    }

    let services_for_dir: Vec<Arc<dyn Service>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn Service>)
        .collect();
    let service_directory = ServiceDirectory::new(services_for_dir);

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
    ));

    let temp_orch_config = OrchestrationConfig {
        chain_id: 1.into(),
        config_schema_version: 0,
        consensus_type: config.consensus_type,
        rpc_listen_address: String::new(),
        rpc_hardening: Default::default(), // FIX: Initialize the new field
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 0,
        round_robin_view_timeout_secs: 0,
        default_query_gas_limit: 0,
    };
    let consensus_engine = engine_from_config(&temp_orch_config)?;

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        Box::new(load_service_from_wasm),
        consensus_engine,
        workload_container.clone(),
    );
    chain.load_or_initialize_status(&workload_container).await?;
    let chain_arc = Arc::new(Mutex::new(chain));

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    // Use a modified IPC server for malicious behavior
    let ipc_server =
        MaliciousWorkloadIpcServer::new(ipc_server_addr, workload_container, chain_arc).await?;

    log::info!("MALICIOUS Workload: State, VM, and Chain initialized. Running IPC server.");
    ipc_server.run().await?;
    Ok(())
}

fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "tree-iavl") {
        enabled_features.push("tree-iavl");
    }
    if cfg!(feature = "tree-sparse-merkle") {
        enabled_features.push("tree-sparse-merkle");
    }
    if cfg!(feature = "tree-verkle") {
        enabled_features.push("tree-verkle");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the depin-sdk-node crate. Found: {:?}",
            enabled_features
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    check_features();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = WorkloadOpts::parse();
    log::info!(
        "MALICIOUS Workload container starting up with config: {:?}",
        opts.config
    );
    let config_str = fs::read_to_string(&opts.config)?;
    let config: WorkloadConfig = toml::from_str(&config_str)?;
    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "tree-iavl", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::IAVL,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            log::info!("Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = IAVLTree::new(commitment_scheme.clone());
            run_workload(state_tree, commitment_scheme, config).await
        }
        _ => {
            let err_msg = format!(
                "Unsupported or disabled state configuration for malicious workload. Please use IAVL/Hash."
            );
            log::error!("{}", err_msg);
            Err(anyhow!(err_msg))
        }
    }
}

// --- Malicious IPC Server Implementation ---

struct MaliciousWorkloadIpcServer<ST, CS>
where
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    address: String,
    workload_container: Arc<WorkloadContainer<ST>>,
    chain_arc: Arc<Mutex<Chain<CS, ST>>>,
    router: Arc<Router>,
    semaphore: Arc<Semaphore>,
}

impl<ST, CS> MaliciousWorkloadIpcServer<ST, CS>
where
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::fmt::Debug
        + Clone,
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    CS::Commitment: std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    pub async fn new(
        address: String,
        workload_container: Arc<WorkloadContainer<ST>>,
        chain_arc: Arc<Mutex<Chain<CS, ST>>>,
    ) -> Result<Self> {
        let mut router = Router::new();
        router.add_method(GetStatusV1::<CS, ST>::default());
        router.add_method(ProcessBlockV1::<CS, ST>::default());
        router.add_method(CheckTransactionsV1::<CS, ST>::default());
        router.add_method(GetLastBlockHashV1::<CS, ST>::default());
        router.add_method(GetExpectedModelHashV1::<CS, ST>::default());
        router.add_method(GetStakesV1::<CS, ST>::default());
        router.add_method(GetNextStakesV1::<CS, ST>::default());
        router.add_method(GetAuthoritySetV1::<CS, ST>::default());
        router.add_method(GetNextValidatorSetV1::<CS, ST>::default());
        router.add_method(GetValidatorSetForV1::<CS, ST>::default());
        router.add_method(GetStateRootV1::<CS, ST>::default());
        router.add_method(QueryContractV1::<CS, ST>::default());
        router.add_method(DeployContractV1::<CS, ST>::default());
        router.add_method(CallContractV1::<CS, ST>::default());
        router.add_method(CheckAndTallyProposalsV1::<CS, ST>::default());
        router.add_method(PrefixScanV1::<CS, ST>::default());
        router.add_method(GetRawStateV1::<CS, ST>::default());
        router.add_method(QueryStateAtV1::<CS, ST>::default());
        router.add_method(GetValidatorSetAtV1::<CS, ST>::default());
        router.add_method(GetActiveKeyAtV1::<CS, ST>::default());
        router.add_method(CallServiceV1::<CS, ST>::default());
        router.add_method(GetWorkloadConfigV1::<CS, ST>::default());
        router.add_method(GetGenesisStatusV1::<CS, ST>::default());

        Ok(Self {
            address,
            workload_container,
            chain_arc,
            router: Arc::new(router),
            semaphore: Arc::new(Semaphore::new(64)),
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.address).await?;
        log::info!(
            "MALICIOUS Workload: IPC server listening on {}",
            self.address
        );
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", self.address);

        let certs_dir =
            std::env::var("CERTS_DIR").expect("CERTS_DIR environment variable must be set");
        let server_config = create_ipc_server_config(
            &format!("{}/ca.pem", certs_dir),
            &format!("{}/workload-server.pem", certs_dir),
            &format!("{}/workload-server.key", certs_dir),
        )?;
        let acceptor = TlsAcceptor::from(server_config);

        let shared_ctx: Arc<RpcContext<CS, ST>> = Arc::new(RpcContext {
            chain: self.chain_arc.clone(),
            workload: self.workload_container.clone(),
        });

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            log::info!(
                "Workload: IPC server accepted new connection from {}",
                peer_addr
            );

            let acceptor_clone = acceptor.clone();
            let semaphore_clone = self.semaphore.clone();
            let router_clone = self.router.clone();
            let shared_ctx_clone = shared_ctx.clone();

            tokio::spawn(async move {
                let mut tls_stream = match acceptor_clone.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("TLS accept error from {}: {}", peer_addr, e);
                        return;
                    }
                };

                let client_id_byte = match tls_stream.read_u8().await {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("Failed to read client ID byte from {}: {}", peer_addr, e);
                        return;
                    }
                };
                log::info!(
                    "Workload: Client ID {} connected from {}",
                    client_id_byte,
                    peer_addr
                );

                let ipc_channel = SecurityChannel::new("workload", "orchestration");
                ipc_channel
                    .accept_server_connection(tokio_rustls::TlsStream::Server(tls_stream))
                    .await;

                loop {
                    let permit = match semaphore_clone.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            log::info!(
                                "IPC handler for {} shutting down (semaphore closed).",
                                peer_addr
                            );
                            return;
                        }
                    };

                    let request_bytes = match ipc_channel.receive().await {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            log::info!(
                                "IPC receive error from {}: {}. Closing connection.",
                                peer_addr,
                                e
                            );
                            return;
                        }
                    };

                    let response = match serde_json::from_slice::<JsonRpcRequest>(&request_bytes) {
                        Ok(req) => {
                            handle_request(req, shared_ctx_clone.clone(), router_clone.clone())
                                .await
                        }
                        Err(e) => Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("Parse error: {}", e),
                                data: None,
                            }),
                            id: JsonRpcId::Null,
                        }),
                    };

                    if let Some(res) = response {
                        let response_bytes = serde_json::to_vec(&res).unwrap();
                        if let Err(e) = ipc_channel.send(&response_bytes).await {
                            log::error!("Failed to send IPC response: {}", e);
                        }
                    }
                    drop(permit);
                }
            });
        }
    }
}

async fn handle_request<CS, ST>(
    req: JsonRpcRequest,
    shared_ctx: Arc<RpcContext<CS, ST>>,
    router: Arc<Router>,
) -> Option<JsonRpcResponse<serde_json::Value>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    if req.method == "state.queryStateAt.v1" {
        if let Ok(params) = serde_json::from_value::<
            depin_sdk_validator::standard::workload_ipc_server::methods::state::QueryStateAtParams,
        >(req.params.clone())
        {
            if params.key == VALIDATOR_SET_KEY {
                log::warn!("[MaliciousWorkload] Received request for VALIDATOR_SET_KEY. Returning tampered proof.");
                let fake_membership = Membership::Present(b"this_is_a_lie".to_vec());
                let tampered_inner_proof = b"this is not a valid serialized iavl proof".to_vec();
                let fake_proof = HashProof {
                    value: tampered_inner_proof,
                    selector: depin_sdk_api::commitment::Selector::Key(params.key),
                    additional_data: vec![],
                };
                let proof_bytes = codec::to_bytes_canonical(&fake_proof);
                let response_data = QueryStateAtResponse {
                    msg_version: 1,
                    scheme_id: 1,
                    scheme_version: 1,
                    membership: fake_membership,
                    proof_bytes,
                };
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: Some(serde_json::to_value(response_data).unwrap()),
                    error: None,
                    id: req.id.unwrap_or(JsonRpcId::Null),
                });
            }
        }
    }

    // For all other requests, behave normally
    let trace_id = uuid::Uuid::new_v4().to_string();
    let router_ctx = RequestContext {
        peer_id: "orchestration".into(),
        trace_id: trace_id.clone(),
    };
    let res = router
        .dispatch(shared_ctx, router_ctx, &req.method, req.params)
        .await;

    if req.id.is_some() {
        Some(match res {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(result),
                error: None,
                id: req.id.unwrap(),
            },
            Err(error) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: error.code,
                    message: error.message,
                    data: error
                        .data
                        .or_else(|| Some(serde_json::json!({ "trace_id": trace_id }))),
                }),
                id: req.id.unwrap(),
            },
        })
    } else {
        None
    }
}
