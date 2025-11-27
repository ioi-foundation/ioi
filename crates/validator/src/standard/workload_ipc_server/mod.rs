// Path: crates/validator/src/standard/workload_ipc_server/mod.rs

//! Defines the individual RPC method handlers for the Workload IPC server.
pub mod methods;
/// Implements the RPC router for dispatching requests to the correct method handlers.
pub mod router;

use anyhow::{anyhow, Result};
// Removed unused ChainStateMachine
use ioi_api::{
    commitment::CommitmentScheme,
    state::StateManager, // Removed unused PrunePlan
    validator::WorkloadContainer,
};
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_execution::ExecutionMachine;
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
        CallServiceV1,
        CheckAndTallyProposalsV1,
        // [NEW] Debug methods
        DebugPinHeightV1,
        DebugTriggerGcV1,
        DebugUnpinHeightV1,
        GetExpectedModelHashV1,
        GetGenesisStatusV1,
        GetStatusV1,
        GetWorkloadConfigV1,
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
    machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
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
        machine_arc: Arc<Mutex<ExecutionMachine<CS, ST>>>,
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

        // [NEW] Register Debug Methods
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

        // --- PHASE 3: INCREMENTAL GC TASK (Refactored) ---
        // This task is now much simpler as it delegates logic to `WorkloadContainer`.
        let workload_for_gc = self.workload_container.clone();
        let machine_for_gc = self.machine_arc.clone();

        tokio::spawn(async move {
            // Use configured interval (default 3600s)
            let gc_interval_secs = workload_for_gc.config().gc_interval_secs.max(1);
            let mut ticker = interval(Duration::from_secs(gc_interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                // Add jitter only if interval is large enough to matter (avoid jitter on 1s test intervals)
                if gc_interval_secs > 10 {
                    let jitter_factor = thread_rng().gen_range(-0.10..=0.10);
                    let jitter_millis =
                        ((gc_interval_secs as f64 * jitter_factor).abs() * 1000.0) as u64;
                    if jitter_millis > 0 {
                        tokio::time::sleep(Duration::from_millis(jitter_millis)).await;
                    }
                }

                // Get current height from the machine
                let current_height = {
                    let guard = machine_for_gc.lock().await;
                    // The ChainStateMachine trait must be in scope to call .status()
                    // This is provided by the import `use ioi_api::chain::ChainStateMachine;`
                    // which we removed earlier because it was unused.
                    // But now we need it here to call .status().
                    // Re-adding it locally or ensuring trait is visible.
                    use ioi_api::chain::ChainStateMachine;
                    guard.status().height
                };

                // Delegate logic to the container
                if let Err(e) = workload_for_gc.run_gc_pass(current_height).await {
                    log::error!("[GC] Background pass failed: {}", e);
                }
            }
        });

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
