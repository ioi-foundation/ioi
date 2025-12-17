// Path: crates/validator/src/standard/orchestration/grpc_public.rs
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use ioi_api::chain::{StateRef, WorkloadClientApi};
use ioi_api::{commitment::CommitmentScheme, state::StateManager, transaction::TransactionModel};
use ioi_client::WorkloadClient;
use ioi_ipc::blockchain::{
    GetStatusRequest, GetStatusResponse, QueryRawStateRequest, QueryRawStateResponse,
    QueryStateAtRequest, QueryStateAtResponse,
};
use ioi_ipc::public::public_api_server::PublicApi;
use ioi_ipc::public::{
    GetBlockByHeightRequest, GetBlockByHeightResponse, SubmitTransactionRequest,
    SubmitTransactionResponse,
};
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    compute_next_timestamp, BlockTimingParams, BlockTimingRuntime, ChainTransaction, TxHash,
};
use ioi_types::codec;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;

pub struct PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::clone::Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    pub context_wrapper: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    pub workload_client: Arc<WorkloadClient>,
    pub tx_pool: Arc<Mutex<Mempool>>,
    pub swarm_sender: mpsc::Sender<SwarmCommand>,
    pub consensus_kick_tx: mpsc::UnboundedSender<()>,
    pub tx_model: Arc<UnifiedTransactionModel<CS>>,
}

impl<CS, ST, CE, V> PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    async fn get_context(&self) -> Result<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>, Status> {
        let guard = self.context_wrapper.lock().await;
        if let Some(ctx) = guard.as_ref() {
            Ok(ctx.clone())
        } else {
            Err(Status::unavailable("Node is initializing"))
        }
    }
}

#[tonic::async_trait]
impl<CS, ST, CE, V> PublicApi for PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    async fn submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let model = self.tx_model.clone();
        let tx_bytes = req.transaction_bytes.clone();

        let (tx, tx_hash) = tokio::task::spawn_blocking(move || {
            let t = model.deserialize_transaction(&tx_bytes).map_err(|e| {
                Status::invalid_argument(format!("Invalid transaction bytes: {}", e))
            })?;
            let h = t
                .hash()
                .map_err(|e| Status::internal(format!("Hashing failed: {}", e)))?;
            Ok::<(ChainTransaction, TxHash), Status>((t, h))
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))??;

        let tx_hash_hex = hex::encode(tx_hash);

        // --- ANTE CHECK VIA WORKLOAD ---
        {
            let ctx_guard = self.get_context().await?;
            let ctx = ctx_guard.lock().await;

            let (parent_height, parent_timestamp, parent_gas_used, parent_root_vec) =
                if let Some(last) = &ctx.last_committed_block {
                    (
                        last.header.height,
                        last.header.timestamp,
                        last.header.gas_used,
                        last.header.state_root.0.clone(),
                    )
                } else {
                    let root = ctx
                        .view_resolver
                        .genesis_root()
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?;
                    (0, 0, 0, root)
                };

            let parent_root = ioi_types::app::StateRoot(parent_root_vec.clone());
            let anchor = parent_root
                .to_anchor()
                .map_err(|e| Status::internal(e.to_string()))?;

            let parent_ref = StateRef {
                height: parent_height,
                state_root: parent_root_vec,
                block_hash: [0; 32],
            };

            // Access state via the resolver to get timing params
            let parent_view = ctx
                .view_resolver
                .resolve_anchored(&parent_ref)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            let timing_params: BlockTimingParams = parent_view
                .get(ioi_types::keys::BLOCK_TIMING_PARAMS_KEY)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .and_then(|b| codec::from_bytes_canonical(&b).ok())
                .unwrap_or_default();
            let timing_runtime: BlockTimingRuntime = parent_view
                .get(ioi_types::keys::BLOCK_TIMING_RUNTIME_KEY)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .and_then(|b| codec::from_bytes_canonical(&b).ok())
                .unwrap_or_default();

            let expected_ts = compute_next_timestamp(
                &timing_params,
                &timing_runtime,
                parent_height,
                parent_timestamp,
                parent_gas_used,
            )
            .unwrap_or(0);

            // Delegate full validation to the Workload container via IPC
            let results = self
                .workload_client
                .check_transactions_at(anchor, expected_ts, vec![tx.clone()])
                .await
                .map_err(|e| Status::internal(format!("Workload check failed: {}", e)))?;

            if let Some(Err(e)) = results.first() {
                return Err(Status::invalid_argument(format!(
                    "Transaction pre-check failed: {}",
                    e
                )));
            }
        }

        let tx_info = match &tx {
            ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
            ChainTransaction::Application(a) => match a {
                ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
                | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                    Some((header.account_id, header.nonce))
                }
                _ => None,
            },
            _ => None,
        };

        let needs_state_query = if let Some((acct, _)) = tx_info {
            self.tx_pool.lock().await.contains_account(&acct) == false
        } else {
            false
        };

        let committed_nonce = if needs_state_query {
            if let Some((acct, _)) = tx_info {
                let key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, acct.as_ref()].concat();
                match self.workload_client.query_raw_state(&key).await {
                    Ok(Some(b)) => ioi_types::codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
                    _ => 0,
                }
            } else {
                0
            }
        } else {
            0
        };

        {
            let pool = self.tx_pool.lock().await;
            let res = pool.add(tx, tx_hash, tx_info, committed_nonce);

            match res {
                AddResult::Ready => {
                    metrics().inc_mempool_transactions_added();
                    tracing::debug!(target: "rpc", event = "mempool_add", status="ready", tx_hash = tx_hash_hex);
                }
                AddResult::Future => {
                    metrics().inc_mempool_transactions_added();
                    tracing::debug!(target: "rpc", event = "mempool_add", status="future", tx_hash = tx_hash_hex);
                }
                AddResult::Rejected(reason) => {
                    if reason.contains("already in") {
                        return Ok(Response::new(SubmitTransactionResponse {
                            tx_hash: tx_hash_hex,
                        }));
                    }
                    return Err(Status::invalid_argument(format!(
                        "Mempool rejected: {}",
                        reason
                    )));
                }
            }
            metrics().set_mempool_size(pool.len() as f64);
        }

        let _ = self
            .swarm_sender
            .send(SwarmCommand::PublishTransaction(req.transaction_bytes))
            .await;
        let _ = self.consensus_kick_tx.send(());

        metrics().observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("submit_transaction", 0);

        Ok(Response::new(SubmitTransactionResponse {
            tx_hash: tx_hash_hex,
        }))
    }

    async fn query_state(
        &self,
        request: Request<QueryStateAtRequest>,
    ) -> Result<Response<QueryStateAtResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let context_arc = self.get_context().await?;
        let client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };
        let root = ioi_types::app::StateRoot(req.root);
        let response = client
            .query_state_at(root, &req.key)
            .await
            .map_err(|e: ioi_types::error::ChainError| Status::internal(e.to_string()))?;
        let response_bytes =
            codec::to_bytes_canonical(&response).map_err(|e| Status::internal(e))?;

        metrics().observe_request_duration("query_state", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("query_state", 0);

        Ok(Response::new(QueryStateAtResponse { response_bytes }))
    }

    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let client = self.workload_client.clone();
        let result = match client.query_raw_state(&req.key).await {
            Ok(Some(val)) => Ok(Response::new(QueryRawStateResponse {
                value: val,
                found: true,
            })),
            Ok(None) => Ok(Response::new(QueryRawStateResponse {
                value: vec![],
                found: false,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        };

        metrics().observe_request_duration("query_raw_state", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("query_raw_state", if result.is_ok() { 0 } else { 1 });

        result
    }

    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let start = Instant::now();
        let client = self.workload_client.clone();
        let status = client
            .get_status()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        metrics().observe_request_duration("get_status", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("get_status", 0);
        Ok(Response::new(GetStatusResponse {
            height: status.height,
            latest_timestamp: status.latest_timestamp,
            total_transactions: status.total_transactions,
            is_running: status.is_running,
        }))
    }

    async fn get_block_by_height(
        &self,
        request: Request<GetBlockByHeightRequest>,
    ) -> Result<Response<GetBlockByHeightResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let client = self.workload_client.clone();
        let blocks = client
            .get_blocks_range(req.height, 1, 10 * 1024 * 1024)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let block = blocks.into_iter().find(|b| b.header.height == req.height);
        let block_bytes = if let Some(b) = block {
            codec::to_bytes_canonical(&b).map_err(|e| Status::internal(e))?
        } else {
            vec![]
        };
        metrics().observe_request_duration("get_block_by_height", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("get_block_by_height", 0);
        Ok(Response::new(GetBlockByHeightResponse { block_bytes }))
    }
}
