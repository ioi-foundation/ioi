// Path: crates/validator/src/standard/workload_ipc_server/mod.rs

pub mod methods;
pub mod router;

use anyhow::{anyhow, Result};
use depin_sdk_api::chain::AppChain;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    state::{PrunePlan, StateManager},
    validator::WorkloadContainer,
};
use depin_sdk_chain::Chain;
use depin_sdk_client::security::SecurityChannel;
use ipc_protocol::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use methods::{
    chain::{
        CheckTransactionsV1, GetAuthoritySetV1, GetLastBlockHashV1, GetNextValidatorSetV1,
        GetValidatorSetAtV1, GetValidatorSetForV1, ProcessBlockV1,
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
use router::{RequestContext, Router};
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
};
use tokio_rustls::{
    rustls::{pki_types::PrivateKeyDer, RootCertStore, ServerConfig},
    TlsAcceptor,
};

pub fn create_ipc_server_config(
    ca_cert_path: &str,
    server_cert_path: &str,
    server_key_path: &str,
) -> Result<Arc<ServerConfig>> {
    // Load CA cert
    let ca_cert_file = File::open(ca_cert_path)?;
    let mut reader = BufReader::new(ca_cert_file);
    let ca_certs = rustls_pemfile::certs(&mut reader)
        .map(|r| r.unwrap())
        .collect::<Vec<_>>();
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(ca_certs);

    // Load server cert and key
    let server_cert_file = File::open(server_cert_path)?;
    let mut reader = BufReader::new(server_cert_file);
    let server_certs = rustls_pemfile::certs(&mut reader)
        .map(|r| r.unwrap())
        .collect::<Vec<_>>();

    let server_key_file = File::open(server_key_path)?;
    let mut reader = BufReader::new(server_key_file);
    let server_key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("No private key found in {}", server_key_path))?;
    let server_key_der = PrivateKeyDer::from(server_key);

    // Create a client verifier that trusts our CA. This is the modern, correct way.
    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key_der)?;
    Ok(Arc::new(server_config))
}

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
    CS::Commitment: std::fmt::Debug + Send + Sync,
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
        // Register all methods
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
        log::info!("Workload: IPC server listening on {}", self.address);
        eprintln!("WORKLOAD_IPC_LISTENING_ON_{}", self.address);

        let certs_dir =
            std::env::var("CERTS_DIR").expect("CERTS_DIR environment variable must be set");
        let server_config = create_ipc_server_config(
            &format!("{}/ca.pem", certs_dir),
            &format!("{}/workload-server.pem", certs_dir),
            &format!("{}/workload-server.key", certs_dir),
        )?;
        let acceptor = TlsAcceptor::from(server_config);

        let state_tree_for_gc = self.workload_container.state_tree();
        let chain_for_gc = self.chain_arc.clone();
        let gc_config = self.workload_container.config().clone();
        let pins_for_gc = self.workload_container.pins.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Prune every hour
            let min_finality_depth = gc_config.min_finality_depth;
            let keep_recent_heights = gc_config.keep_recent_heights;

            loop {
                interval.tick().await;
                // --- PHASE 2: PrunePlan Generation ---
                let plan = {
                    let current_height = AppChain::status(&*chain_for_gc.lock().await).height;

                    // A real implementation would get finalized_height from the consensus engine state.
                    // For now, we use current_height as a safe proxy.
                    let finalized_height = current_height;

                    // Calculate the two potential cutoff points
                    let horizon_cutoff = current_height.saturating_sub(keep_recent_heights);
                    let finality_cutoff = finalized_height.saturating_sub(min_finality_depth);

                    // The actual cutoff is the minimum of the two, ensuring we satisfy both constraints.
                    let cutoff_height = horizon_cutoff.min(finality_cutoff);

                    // Get a snapshot of all actively pinned versions.
                    let excluded_heights = pins_for_gc.snapshot().await;

                    PrunePlan {
                        cutoff_height,
                        excluded_heights,
                    }
                };

                if plan.cutoff_height > 0 {
                    log::debug!(
                        "[GC] Pruning state versions older than height {}, excluding {} pinned versions.",
                        plan.cutoff_height, plan.excluded_heights.len()
                    );
                    let mut state = state_tree_for_gc.write().await;
                    if let Err(e) = state.prune(&plan) {
                        log::error!("[GC] State pruning failed: {}", e);
                    }
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

                    let response = match serde_json::from_slice::<serde_json::Value>(&request_bytes)
                    {
                        Ok(serde_json::Value::Array(_)) => Some(JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32600,
                                message: "Batch requests are not supported".into(),
                                data: None,
                            }),
                            id: JsonRpcId::Null,
                        }),
                        Ok(value) => match serde_json::from_value::<JsonRpcRequest>(value) {
                            Ok(req) => {
                                if req.jsonrpc != "2.0" {
                                    Some(JsonRpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        result: None,
                                        error: Some(JsonRpcError {
                                            code: -32600,
                                            message: "Invalid jsonrpc version".into(),
                                            data: None,
                                        }),
                                        id: req.id.unwrap_or(JsonRpcId::Null),
                                    })
                                } else {
                                    let trace_id = uuid::Uuid::new_v4().to_string();
                                    let router_ctx = RequestContext {
                                        peer_id: "orchestration".into(),
                                        trace_id: trace_id.clone(),
                                    };
                                    let res = router_clone
                                        .dispatch(
                                            shared_ctx_clone.clone(),
                                            router_ctx,
                                            &req.method,
                                            req.params,
                                        )
                                        .await;
                                    if let Some(id) = req.id {
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
                                                    data: error.data.or_else(|| {
                                                        Some(serde_json::json!({ "trace_id": trace_id }))
                                                    }),
                                                }),
                                                id,
                                            },
                                        })
                                    } else {
                                        None
                                    }
                                }
                            }
                            Err(e) => Some(JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32600,
                                    message: format!("Invalid Request: {}", e),
                                    data: None,
                                }),
                                id: JsonRpcId::Null,
                            }),
                        },
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
                            log::error!("Failed to send IPC response to {}: {}", peer_addr, e);
                        }
                    }
                    drop(permit);
                }
            });
        }
    }
}
