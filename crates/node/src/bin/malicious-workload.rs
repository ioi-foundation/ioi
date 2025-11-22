// Path: crates/node/src/bin/malicious-workload.rs
#![forbid(unsafe_code)]

//! A malicious workload container for testing proof verification.
//! This is a copy of the main workload binary with a modified IPC handler
//! that returns a tampered proof for a specific key.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::services::{access::ServiceDirectory, BlockchainService};
use ioi_api::{
    commitment::CommitmentScheme,
    state::StateManager,
    storage::NodeStore, // <-- FIX: Add the missing import for the NodeStore trait
    validator::WorkloadContainer,
};
use ioi_consensus::util::engine_from_config;
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_execution::util::load_state_from_genesis_file;
use ioi_execution::ExecutionMachine;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use ioi_services::identity::IdentityHub;
use ioi_state::primitives::hash::{HashCommitmentScheme, HashProof};
use ioi_state::tree::iavl::IAVLTree;
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{to_root_hash, Membership};
use ioi_types::codec;
use ioi_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use ioi_types::keys::{STATUS_KEY, VALIDATOR_SET_KEY};
use ioi_validator::standard::workload_ipc_server::{
    create_ipc_server_config,
    methods::{
        chain::{
            CheckTransactionsV1, GetAuthoritySetV1, GetBlockByHeightV1, GetBlocksRangeV1,
            GetLastBlockHashV1, GetNextValidatorSetV1, GetValidatorSetAtV1, GetValidatorSetForV1,
            ProcessBlockV1,
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
use ioi_vm_wasm::WasmRuntime;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsStream;

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
    CS::Proof: AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de> + std::fmt::Debug,
    CS::Commitment: std::fmt::Debug + From<Vec<u8>>,
{
    let db_path = Path::new(&config.state_file).with_extension("db");
    let db_preexisted = db_path.exists();

    let store = Arc::new(RedbEpochStore::open(&db_path, config.epoch_size)?);
    state_tree.attach_store(store.clone());

    if !db_preexisted {
        tracing::info!(
            target: "workload",
            event = "state_init",
            path = %db_path.display(),
            "No existing state DB found. Initializing from genesis {}.",
            config.genesis_file
        );
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        tracing::info!(
            target: "workload",
            event = "state_init",
            path = %db_path.display(),
            "Existing state DB found. Attempting recovery from stored state.",
        );
        // RECOVERY LOGIC: Re-hydrate live state from the last committed version in the store.
        if let Ok((head_height, _)) = store.head() {
            if head_height > 0 {
                if let Ok(Some(head_block)) = store.get_block_by_height(head_height) {
                    let recovered_root = &head_block.header.state_root.0;
                    state_tree.adopt_known_root(recovered_root, head_height)?;
                    tracing::warn!(target: "workload", event = "state_recovered", height = head_height, "Recovered and adopted durable head into state backend.");

                    let anchor = to_root_hash(recovered_root)?;

                    // Re-hydrate critical keys into the live state to make it usable.
                    if let Ok((Membership::Present(status_bytes), _)) =
                        state_tree.get_with_proof_at_anchor(&anchor, STATUS_KEY)
                    {
                        state_tree.insert(STATUS_KEY, &status_bytes)?;
                        tracing::info!(target: "workload", "Re-hydrated STATUS_KEY into current state.");
                    }
                    if let Ok((Membership::Present(vs_bytes), _)) =
                        state_tree.get_with_proof_at_anchor(&anchor, VALIDATOR_SET_KEY)
                    {
                        state_tree.insert(VALIDATOR_SET_KEY, &vs_bytes)?;
                        tracing::info!(target: "workload", "Re-hydrated VALIDATOR_SET_KEY into current state.");
                    }
                }
            }
        }
    }

    let wasm_vm = Box::new(WasmRuntime::new(config.fuel_costs.clone())?);

    let mut initial_services = Vec::new();
    for service_config in &config.initial_services {
        match service_config {
            InitialServiceConfig::IdentityHub(migration_config) => {
                log::info!("[Workload] Instantiating initial service: IdentityHub");
                let hub = IdentityHub::new(migration_config.clone());
                initial_services
                    .push(Arc::new(hub) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            InitialServiceConfig::Governance(_) => {}
            InitialServiceConfig::Oracle(_) => {}
            InitialServiceConfig::Ibc(_) => {}
        }
    }

    let services_for_dir: Vec<Arc<dyn BlockchainService>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn BlockchainService>)
        .collect();
    let service_directory = ServiceDirectory::new(services_for_dir);

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
        store,
    )?);

    let temp_orch_config = OrchestrationConfig {
        chain_id: 1.into(),
        config_schema_version: 0,
        consensus_type: config.consensus_type,
        rpc_listen_address: String::new(),
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 0,
        round_robin_view_timeout_secs: 0,
        default_query_gas_limit: 0,
        ibc_gateway_listen_address: None,
    };
    let consensus_engine = engine_from_config(&temp_orch_config)?;

    let mut machine = ExecutionMachine::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        consensus_engine,
        workload_container.clone(),
        config.service_policies.clone(), // [NEW] Pass policies
    );
    machine
        .load_or_initialize_status(&workload_container)
        .await?;
    let machine_arc = Arc::new(Mutex::new(machine));

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    // Use a modified IPC server for malicious behavior
    let ipc_server =
        MaliciousWorkloadIpcServer::new(ipc_server_addr, workload_container, machine_arc).await?;

    log::info!(
        "MALICIOUS Workload: State, VM, and ExecutionMachine initialized. Running IPC server."
    );
    ipc_server.run().await?;
    Ok(())
}

fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "state-iavl") {
        enabled_features.push("state-iavl");
    }
    if cfg!(feature = "state-sparse-merkle") {
        enabled_features.push("state-sparse-merkle");
    }
    if cfg!(feature = "state-verkle") {
        enabled_features.push("state-verkle");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the ioi-node crate. Found: {:?}",
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
        #[cfg(all(feature = "state-iavl", feature = "commitment-hash"))]
        (ioi_types::config::StateTreeType::IAVL, ioi_types::config::CommitmentSchemeType::Hash) => {
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
{
    address: String,
    workload_container: Arc<WorkloadContainer<ST>>,
    machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
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
    CS::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    pub async fn new(
        address: String,
        workload_container: Arc<WorkloadContainer<ST>>,
        machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
    ) -> Result<Self>
    where
        <CS as CommitmentScheme>::Proof: std::fmt::Debug,
    {
        let mut router = Router::new();
        // Register all methods
        router.add_method(GetStatusV1::<CS, ST>::default());
        router.add_method(ProcessBlockV1::<CS, ST>::default());
        router.add_method(CheckTransactionsV1::<CS, ST>::default());
        router.add_method(GetLastBlockHashV1::<CS, ST>::default());
        router.add_method(GetBlocksRangeV1::<CS, ST>::default());
        router.add_method(GetExpectedModelHashV1::<CS, ST>::default());
        router.add_method(GetStakesV1::<CS, ST>::default());
        router.add_method(GetBlockByHeightV1::<CS, ST>::default());
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
            machine_arc,
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

        let shared_ctx = Arc::new(RpcContext {
            machine: self.machine_arc.clone(),
            workload: self.workload_container.clone(),
        });

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            log::info!(
                "Workload: IPC server accepted new connection from {}",
                peer_addr
            );

            let acceptor_clone = acceptor.clone();
            let router_clone = self.router.clone();
            let shared_ctx_clone = shared_ctx.clone();
            let semaphore_clone = self.semaphore.clone();

            tokio::spawn(async move {
                let mut tls_stream = match acceptor_clone.accept(stream).await {
                    Ok(s) => TlsStream::Server(s),
                    Err(e) => {
                        log::error!("[WorkloadIPC] TLS accept error: {}", e);
                        return;
                    }
                };

                let mut kem_ss = match server_post_handshake(
                    &mut tls_stream,
                    ioi_crypto::security::SecurityLevel::Level3,
                )
                .await
                {
                    Ok(ss) => ss,
                    Err(e) => return log::error!("[WorkloadIPC] PQC key exchange FAILED: {}", e),
                };

                let app_key = match derive_application_key(&tls_stream, &mut kem_ss) {
                    Ok(k) => k,
                    Err(e) => return log::error!("[WorkloadIPC] App key derivation FAILED: {}", e),
                };
                let mut stream = AeadWrappedStream::new(tls_stream, app_key);

                let client_id_byte = match stream.read_u8().await {
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

                let (mut read_half, mut write_half) = tokio::io::split(stream);

                loop {
                    let _permit = match semaphore_clone.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let len = match read_half.read_u32().await {
                        Ok(len) => len as usize,
                        Err(_) => return,
                    };

                    const MAX_IPC_MESSAGE_SIZE: usize = 1_048_576; // 1 MiB
                    if len == 0 || len > MAX_IPC_MESSAGE_SIZE {
                        return;
                    }

                    let mut request_buf = vec![0; len];
                    if read_half.read_exact(&mut request_buf).await.is_err() {
                        return;
                    }

                    let response = handle_request(
                        &request_buf,
                        shared_ctx_clone.clone(),
                        router_clone.clone(),
                    )
                    .await;

                    if let Some(res) = response {
                        let response_bytes = serde_json::to_vec(&res).unwrap_or_default();

                        if write_half
                            .write_u32(response_bytes.len() as u32)
                            .await
                            .is_err()
                        {
                            continue;
                        }

                        if write_half.write_all(&response_bytes).await.is_err() {
                            continue;
                        }
                    }
                    drop(_permit);
                }
            });
        }
    }
}
async fn handle_request<CS, ST>(
    request_bytes: &[u8],
    shared_ctx: Arc<RpcContext<CS, ST>>,
    router: Arc<Router>,
) -> Option<JsonRpcResponse<serde_json::Value>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    let req: JsonRpcRequest = match serde_json::from_slice(request_bytes) {
        Ok(req) => req,
        Err(e) => {
            if serde_json::from_slice::<Vec<serde_json::Value>>(request_bytes).is_ok() {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: "Batch requests are not supported".into(),
                        data: None,
                    }),
                    id: JsonRpcId::Null,
                });
            }
            return Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: format!("Parse error: {}", e),
                    data: None,
                }),
                id: JsonRpcId::Null,
            });
        }
    };

    let Some(id) = req.id.clone() else {
        return None;
    };

    if req.method == "state.queryStateAt.v1" {
        if let Ok(params) = serde_json::from_value::<
            ioi_validator::standard::workload_ipc_server::methods::state::QueryStateAtParams,
        >(req.params.clone())
        {
            if params.key == VALIDATOR_SET_KEY {
                log::warn!("[MaliciousWorkload] Received request for VALIDATOR_SET_KEY. Returning tampered proof.");
                let fake_membership = Membership::Present(b"this_is_a_lie".to_vec());
                let tampered_inner_proof = b"this is not a valid serialized iavl proof".to_vec();
                let fake_proof = HashProof {
                    value: tampered_inner_proof,
                    selector: ioi_api::commitment::Selector::Key(params.key),
                    additional_data: vec![],
                };
                let proof_bytes = codec::to_bytes_canonical(&fake_proof).unwrap();
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
                    id,
                });
            }
        }
    }

    let trace_id = uuid::Uuid::new_v4().to_string();
    let router_ctx = RequestContext {
        peer_id: "orchestration".into(),
        trace_id: trace_id.clone(),
    };
    let res = router
        .dispatch(shared_ctx, router_ctx, &req.method, req.params)
        .await;

    Some(match res {
        Ok(result) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
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
            id,
        },
    })
}
