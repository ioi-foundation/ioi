// Path: crates/validator/src/standard/workload_ipc_server/mod.rs

//! Defines the individual RPC method handlers for the Workload IPC server.
pub mod methods;
/// Implements the RPC router for dispatching requests to the correct method handlers.
pub mod router;

use anyhow::{anyhow, Result};
use ioi_api::chain::ChainStateMachine;
use ioi_api::{
    commitment::CommitmentScheme,
    state::{PrunePlan, StateManager},
    validator::WorkloadContainer,
};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_execution::Chain;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use methods::{
    chain::{
        CheckTransactionsV1, GetAuthoritySetV1, GetBlockByHeightV1, GetBlocksRangeV1,
        GetLastBlockHashV1, GetNextValidatorSetV1, GetValidatorSetAtV1, GetValidatorSetForV1,
        ProcessBlockV1,
    },
    contract::{CallContractV1, DeployContractV1, QueryContractV1},
    staking::{GetNextStakesV1, GetStakesV1},
    state::{GetActiveKeyAtV1, GetRawStateV1, GetStateRootV1, PrefixScanV1, QueryStateAtV1},
    system::{
        CallServiceV1, CheckAndTallyProposalsV1, GetExpectedModelHashV1, GetGenesisStatusV1,
        GetStatusV1, GetWorkloadConfigV1,
    },
    RpcContext,
};
use rand::{thread_rng, Rng};
use router::{RequestContext, Router};
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
};
use tokio_rustls::{
    rustls::{RootCertStore, ServerConfig},
    TlsAcceptor, TlsStream,
};

/// Creates the mTLS server configuration for the IPC server.
/// It configures the server to require client certificates signed by the provided CA.
pub fn create_ipc_server_config(
    ca_cert_path: &str,
    server_cert_path: &str,
    server_key_path: &str,
) -> Result<Arc<ServerConfig>> {
    // Load CA cert
    let ca_cert_file = File::open(ca_cert_path)?;
    let mut reader = BufReader::new(ca_cert_file);
    let ca_certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(ca_certs);

    // Load server cert and key
    let server_cert_file = File::open(server_cert_path)?;
    let mut reader = BufReader::new(server_cert_file);
    let server_certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    let server_key_file = File::open(server_key_path)?;
    let mut reader = BufReader::new(server_key_file);
    let server_key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("No private key found in {}", server_key_path))?;

    // Create a client verifier that trusts our CA. This is the modern, correct way.
    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;
    Ok(Arc::new(server_config))
}

/// The IPC server for the Workload container.
/// It listens for secure mTLS connections from the Orchestration container
/// and handles JSON-RPC requests for block processing and state queries.
pub struct WorkloadIpcServer<ST, CS>
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

impl<ST, CS> WorkloadIpcServer<ST, CS>
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
    /// Creates a new `WorkloadIpcServer`.
    pub async fn new(
        address: String,
        workload_container: Arc<WorkloadContainer<ST>>,
        chain_arc: Arc<Mutex<Chain<CS, ST>>>,
    ) -> Result<Self> {
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
            chain_arc,
            router: Arc::new(router),
            semaphore: Arc::new(Semaphore::new(64)),
        })
    }

    /// Starts the IPC server and listens for incoming connections.
    /// This function runs indefinitely until the process is terminated.
    pub async fn run(self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.address).await?;
        log::info!("Workload: IPC server listening on {}", self.address);
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", self.address);

        let certs_dir = std::env::var("CERTS_DIR")
            .map_err(|_| anyhow!("CERTS_DIR environment variable must be set"))?;
        let server_config = create_ipc_server_config(
            &format!("{}/ca.pem", certs_dir),
            &format!("{}/workload-server.pem", certs_dir),
            &format!("{}/workload-server.key", certs_dir),
        )?;
        let acceptor = TlsAcceptor::from(server_config);

        // --- PHASE 3: INCREMENTAL GC TASK ---
        let state_tree_for_gc = self.workload_container.state_tree();
        let chain_for_gc = self.chain_arc.clone();
        let gc_config = self.workload_container.config().clone();
        let pins_for_gc = self.workload_container.pins.clone();
        let store_for_gc = self.workload_container.store.clone();
        tokio::spawn(async move {
            const GC_INTERVAL_SECS: u64 = 3600; // Prune every hour
            const BATCH_LIMIT: usize = 1_000;
            const MAX_BATCHES_PER_TICK: usize = 10;

            let mut interval = interval(Duration::from_secs(GC_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // Add +/- 10% jitter to the interval to desynchronize nodes
                let jitter_factor = thread_rng().gen_range(-0.10..=0.10);
                let jitter_millis =
                    ((GC_INTERVAL_SECS as f64 * jitter_factor).abs() * 1000.0) as u64;
                if jitter_millis > 0 {
                    tokio::time::sleep(Duration::from_millis(jitter_millis)).await;
                }

                // --- PHASE 1: Build PrunePlan (async, no locks on state tree) ---
                let plan = {
                    let current_height =
                        ChainStateMachine::status(&*chain_for_gc.lock().await).height;
                    let finalized_height = current_height; // Placeholder for real finality

                    let horizon_cutoff =
                        current_height.saturating_sub(gc_config.keep_recent_heights);
                    let finality_cutoff =
                        finalized_height.saturating_sub(gc_config.min_finality_depth);
                    let cutoff_height = horizon_cutoff.min(finality_cutoff);

                    // Defensive clamp: ensure we never try to prune the current height.
                    let cutoff_height = cutoff_height.min(current_height);

                    let excluded_heights = pins_for_gc.snapshot();

                    PrunePlan {
                        cutoff_height,
                        excluded_heights,
                    }
                };

                if let Ok(mut state_tree) = state_tree_for_gc.try_write() {
                    if let Err(e) =
                        state_tree.prune_batch(&plan, BATCH_LIMIT * MAX_BATCHES_PER_TICK)
                    {
                        log::error!("[GC] Failed to prune in-memory state versions: {}", e);
                    }
                } else {
                    log::warn!(
                        "[GC] Could not acquire lock for in-memory prune, skipping this cycle."
                    );
                }

                let cutoff_epoch = store_for_gc.epoch_of(plan.cutoff_height);
                let pinned_epochs: std::collections::BTreeSet<u64> = plan
                    .excluded_heights
                    .iter()
                    .map(|h| store_for_gc.epoch_of(*h))
                    .collect();

                for epoch_id in 0..cutoff_epoch {
                    if pinned_epochs.contains(&epoch_id) {
                        continue;
                    }
                    if store_for_gc.is_sealed(epoch_id).unwrap_or(false) {
                        if let Err(err) = store_for_gc.drop_sealed_epoch(epoch_id) {
                            log::error!("[GC] Failed to drop sealed epoch {}: {}", epoch_id, err);
                        } else {
                            log::info!("[GC] Dropped sealed epoch {}", epoch_id);
                        }
                    }
                }

                let mut total_pruned = 0;
                for _ in 0..MAX_BATCHES_PER_TICK {
                    let excluded_vec: Vec<u64> = plan.excluded_heights.iter().cloned().collect();
                    match store_for_gc.prune_batch(plan.cutoff_height, &excluded_vec, BATCH_LIMIT) {
                        Ok(stats) => {
                            total_pruned += stats.heights_pruned;
                            if stats.heights_pruned < BATCH_LIMIT {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("[GC] Store prune_batch failed: {}", e);
                            break;
                        }
                    }
                    tokio::task::yield_now().await;
                }
                if total_pruned > 0 {
                    log::debug!(
                        "[GC] Pruned {} heights (cutoff {}, excluded {})",
                        total_pruned,
                        plan.cutoff_height,
                        plan.excluded_heights.len()
                    );
                }
            }
        });

        let shared_ctx = Arc::new(RpcContext {
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
            let router_clone = self.router.clone();
            let shared_ctx_clone = shared_ctx.clone();
            let semaphore_clone = self.semaphore.clone();

            tokio::spawn(async move {
                let server_conn = match acceptor_clone.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => return log::error!("[WorkloadIPC] TLS accept error: {}", e),
                };
                let mut tls_stream = TlsStream::Server(server_conn);

                // --- POST-HANDSHAKE HYBRID KEY EXCHANGE (before any app bytes) ---
                let mut kem_ss = match server_post_handshake(
                    &mut tls_stream,
                    ioi_crypto::security::SecurityLevel::Level3,
                )
                .await
                {
                    Ok(ss) => ss,
                    Err(e) => {
                        return log::error!("[WorkloadIPC] PQC key exchange FAILED: {}", e);
                    }
                };

                // --- BIND & WRAP ---
                let app_key = match derive_application_key(&tls_stream, &mut kem_ss) {
                    Ok(k) => k,
                    Err(e) => return log::error!("[WorkloadIPC] App key derivation FAILED: {}", e),
                };
                let mut stream = AeadWrappedStream::new(tls_stream, app_key);

                let client_id_byte = match async {
                    let mut id_buf = [0u8; 1];
                    match stream.read(&mut id_buf).await {
                        Ok(1) => Ok(id_buf[0]),
                        Ok(0) => Err(anyhow!(
                            "Connection closed by {} before client ID was sent",
                            peer_addr
                        )),
                        Ok(n) => Err(anyhow!("Expected 1-byte client ID frame, got {} bytes", n)),
                        Err(e) => Err(anyhow!("Failed to read client ID frame: {}", e)),
                    }
                }
                .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        log::error!("{}", e);
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
                        Err(_) => {
                            log::info!(
                                "IPC handler for {} shutting down (semaphore closed).",
                                peer_addr
                            );
                            return;
                        }
                    };

                    let len = match read_half.read_u32().await {
                        Ok(len) => len as usize,
                        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            log::info!("IPC connection closed by {}", peer_addr);
                            return; // Clean EOF
                        }
                        Err(e) => {
                            log::info!(
                                "IPC receive error from {}: {}. Closing connection.",
                                peer_addr,
                                e
                            );
                            return;
                        }
                    };

                    const MAX_IPC_MESSAGE_SIZE: usize = 1_048_576; // 1 MiB
                    if len == 0 || len > MAX_IPC_MESSAGE_SIZE {
                        log::error!("[WorkloadIPCServer] Received invalid message length: {}. Closing connection.", len);
                        return;
                    }

                    let mut request_buf = vec![0; len];
                    if let Err(e) = read_half.read_exact(&mut request_buf).await {
                        log::error!("[WorkloadIPCServer] Failed to read full request payload (len={}): {}. Closing connection.", len, e);
                        return;
                    }

                    let response = handle_request(
                        &request_buf,
                        shared_ctx_clone.clone(),
                        router_clone.clone(),
                    )
                    .await;

                    if let Some(res) = response {
                        let response_bytes = match serde_json::to_vec(&res) {
                            Ok(b) => b,
                            Err(e) => {
                                log::error!("Failed to serialize IPC response: {}", e);
                                let err_res: JsonRpcResponse<serde_json::Value> = JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: None,
                                    error: Some(JsonRpcError {
                                        code: -32603,
                                        message:
                                            "Internal Server Error: Failed to serialize response"
                                                .to_string(),
                                        data: None,
                                    }),
                                    id: res.id,
                                };
                                serde_json::to_vec(&err_res).unwrap_or_default()
                            }
                        };

                        // --- FIX START: Combine length prefix and payload into a single write ---
                        let frame_len_bytes = (response_bytes.len() as u32).to_be_bytes();
                        let mut frame_to_write = Vec::with_capacity(4 + response_bytes.len());
                        frame_to_write.extend_from_slice(&frame_len_bytes);
                        frame_to_write.extend_from_slice(&response_bytes);

                        if let Err(e) = write_half.write_all(&frame_to_write).await {
                            log::error!(
                                "Failed to send IPC response frame to {}: {}",
                                peer_addr,
                                e
                            );
                        }
                        // --- FIX END ---
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

    let Some(id) = req.id else {
        // It's a notification, do nothing.
        return None;
    };

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
