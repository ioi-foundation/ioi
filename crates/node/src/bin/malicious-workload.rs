// Path: crates/node/src/bin/malicious-workload.rs
#![forbid(unsafe_code)]

//! A malicious workload container for testing proof verification.
//! This binary uses the shared initialization logic but substitutes the IPC server
//! with one that returns tampered proofs for specific keys.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::{
    commitment::CommitmentScheme,
    state::{ProofProvider, StateManager},
    validator::WorkloadContainer,
};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_execution::ExecutionMachine;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use ioi_state::primitives::hash::{HashCommitmentScheme, HashProof};
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::Membership;
use ioi_types::codec;
use ioi_types::config::WorkloadConfig;
use ioi_types::keys::VALIDATOR_SET_KEY;
// Import shared setup and standard IPC methods from the library
use ioi_validator::standard::workload::{
    ipc::{
        create_ipc_server_config,
        methods::{
            chain::{
                CheckTransactionsV1, GetAuthoritySetV1, GetBlockByHeightV1, GetBlocksRangeV1,
                GetLastBlockHashV1, GetNextValidatorSetV1, GetValidatorSetAtV1,
                GetValidatorSetForV1, ProcessBlockV1,
            },
            contract::{CallContractV1, DeployContractV1, QueryContractV1},
            staking::{GetNextStakesV1, GetStakesV1},
            state::{
                GetActiveKeyAtV1, GetRawStateV1, GetStateRootV1, PrefixScanV1,
                QueryStateAtResponse, QueryStateAtV1,
            },
            system::{
                CallServiceV1, CheckAndTallyProposalsV1, DebugPinHeightV1, DebugTriggerGcV1,
                DebugUnpinHeightV1, GetExpectedModelHashV1, GetGenesisStatusV1, GetStatusV1,
                GetWorkloadConfigV1,
            },
            RpcContext,
        },
        router::{RequestContext, Router},
    },
    setup::setup_workload,
};
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
};
use tokio_rustls::{TlsAcceptor, TlsStream};

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Wrapper to run the shared setup and then the malicious server.
async fn run_malicious_workload<CS, ST>(
    state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + Debug,
    CS::Proof: serde::Serialize + for<'de> serde::Deserialize<'de> + AsRef<[u8]> + Debug + Clone,
    CS::Commitment: Debug + From<Vec<u8>>,
{
    // 1. Shared Setup
    let (workload_container, machine_arc) =
        setup_workload(state_tree, commitment_scheme, config).await?;

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    // 2. Malicious Server
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
    // Malicious workload specifically targets IAVL/Hash for the proof tamper test.
    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature. Found: {:?}",
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
            run_malicious_workload(state_tree, commitment_scheme, config).await
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

// --- Malicious IPC Server Implementation (Local Definition) ---

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
        // Register standard methods
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
        // Note: QueryStateAtV1 is registered but effectively overridden by the interception logic below
        router.add_method(QueryStateAtV1::<CS, ST>::default());
        router.add_method(GetValidatorSetAtV1::<CS, ST>::default());
        router.add_method(GetActiveKeyAtV1::<CS, ST>::default());
        router.add_method(CallServiceV1::<CS, ST>::default());
        router.add_method(GetWorkloadConfigV1::<CS, ST>::default());
        router.add_method(GetGenesisStatusV1::<CS, ST>::default());
        router.add_method(DebugPinHeightV1::<CS, ST>::default());
        router.add_method(DebugUnpinHeightV1::<CS, ST>::default());
        router.add_method(DebugTriggerGcV1::<CS, ST>::default());

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
                let server_conn = match acceptor_clone.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("[WorkloadIPC] TLS accept error: {}", e);
                        return;
                    }
                };
                // FIX: Remove double wrapping. `server_conn` is already a tokio_rustls::server::TlsStream.
                let mut tls_stream = TlsStream::Server(server_conn);

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

                let _client_id_byte = stream.read_u8().await.ok(); // Consume ID byte

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

                    if len == 0 || len > 10 * 1024 * 1024 {
                        return;
                    }

                    let mut request_buf = vec![0; len];
                    if read_half.read_exact(&mut request_buf).await.is_err() {
                        return;
                    }

                    // CALL THE LOCAL INTERCEPTING HANDLER
                    let response = handle_request(
                        &request_buf,
                        shared_ctx_clone.clone(),
                        router_clone.clone(),
                    )
                    .await;

                    if let Some(res) = response {
                        let response_bytes = serde_json::to_vec(&res).unwrap_or_default();
                        let frame_len_bytes = (response_bytes.len() as u32).to_be_bytes();
                        let mut frame_to_write = Vec::with_capacity(4 + response_bytes.len());
                        frame_to_write.extend_from_slice(&frame_len_bytes);
                        frame_to_write.extend_from_slice(&response_bytes);
                        let _ = write_half.write_all(&frame_to_write).await;
                    }
                    drop(_permit);
                }
            });
        }
    }
}

/// The intercepting request handler that injects malicious behavior.
async fn handle_request<CS, ST>(
    request_bytes: &[u8],
    shared_ctx: Arc<RpcContext<CS, ST>>,
    router: Arc<Router>,
) -> Option<JsonRpcResponse<serde_json::Value>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    let req: JsonRpcRequest = serde_json::from_slice(request_bytes).ok()?;
    let Some(id) = req.id.clone() else {
        return None;
    };

    // --- INTERCEPTION START ---
    if req.method == "state.queryStateAt.v1" {
        // FIX: Updated path to point to the correct module location
        if let Ok(params) = serde_json::from_value::<
            ioi_validator::standard::workload::ipc::methods::state::QueryStateAtParams,
        >(req.params.clone())
        {
            // Target the specific key we want to tamper with
            if params.key == VALIDATOR_SET_KEY {
                log::warn!("[MaliciousWorkload] Intercepting VALIDATOR_SET_KEY request. Returning tampered proof.");
                let fake_membership = Membership::Present(b"this_is_a_lie".to_vec());

                // Construct a syntactically valid but cryptographically invalid proof.
                // The Orchestrator should detect this via `verify_proof`.
                let tampered_inner_proof = b"invalid proof data".to_vec();
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
    // --- INTERCEPTION END ---

    // Fallback to standard dispatch for all other requests
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
                data: None,
            }),
            id,
        },
    })
}
