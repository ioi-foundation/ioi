// Path: crates/validator/src/standard/orchestration/grpc_public.rs

use crate::standard::orchestration::context::{MainLoopContext, TxStatusEntry};
use crate::standard::orchestration::mempool::Mempool;
use ioi_api::chain::WorkloadClientApi;
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_client::WorkloadClient;
use ioi_ipc::blockchain::{
    GetStatusRequest, GetStatusResponse, QueryRawStateRequest, QueryRawStateResponse,
    QueryStateAtRequest, QueryStateAtResponse,
};
use ioi_ipc::public::public_api_server::PublicApi;
use ioi_ipc::public::{
    GetBlockByHeightRequest, GetBlockByHeightResponse, GetTransactionStatusRequest,
    GetTransactionStatusResponse, SubmitTransactionRequest, SubmitTransactionResponse, TxStatus,
};
use ioi_types::app::{ChainTransaction, StateRoot, TxHash};
use ioi_types::codec;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;

/// Implementation of the Public gRPC API.
///
/// This implementation is optimized for high-concurrency by offloading transaction
/// validation to a dedicated background ingestion worker.
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
    /// Handle to the main loop context for status cache access.
    pub context_wrapper: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    /// Client for querying state from the Workload container.
    pub workload_client: Arc<WorkloadClient>,
    /// The sharded mempool.
    pub tx_pool: Arc<Mempool>,
    /// Channel to send raw transactions to the ingestion worker.
    pub tx_ingest_tx: mpsc::Sender<(TxHash, Vec<u8>)>,
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
    /// Safely retrieves the MainLoopContext.
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
    /// Accepts a raw transaction, hashes it, and returns a receipt immediately.
    async fn submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let tx_bytes = req.transaction_bytes;

        // 1. Generate Receipt Hash
        let tx_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tx_bytes)
            .map_err(|e| Status::invalid_argument(format!("Hashing failed: {}", e)))?;
        let tx_hash_hex = hex::encode(tx_hash_bytes);

        // 2. Mark as Pending in status cache
        {
            let ctx_arc = self.get_context().await?;
            let ctx = ctx_arc.lock().await;
            let mut cache = ctx.tx_status_cache.lock().await;
            cache.put(
                tx_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Pending,
                    error: None,
                    block_height: None,
                },
            );
        }

        // 3. Offload to ingestion worker
        match self.tx_ingest_tx.try_send((tx_hash_bytes, tx_bytes)) {
            Ok(_) => {
                metrics().inc_requests_total("submit_transaction", 200);
                metrics()
                    .observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());

                Ok(Response::new(SubmitTransactionResponse {
                    tx_hash: tx_hash_hex,
                }))
            }
            Err(_) => {
                metrics().inc_requests_total("submit_transaction", 503);

                // Update cache to REJECTED if queue is full
                let ctx_arc = self.get_context().await?;
                let ctx = ctx_arc.lock().await;
                let mut cache = ctx.tx_status_cache.lock().await;
                cache.put(
                    tx_hash_hex,
                    TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some("Ingestion queue full".into()),
                        block_height: None,
                    },
                );

                Err(Status::resource_exhausted("Ingestion queue full"))
            }
        }
    }

    /// Queries the lifecycle status of a submitted transaction.
    async fn get_transaction_status(
        &self,
        request: Request<GetTransactionStatusRequest>,
    ) -> Result<Response<GetTransactionStatusResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;
        let ctx = ctx_arc.lock().await;

        let mut cache = ctx.tx_status_cache.lock().await;
        if let Some(entry) = cache.get(&req.tx_hash) {
            Ok(Response::new(GetTransactionStatusResponse {
                status: entry.status as i32,
                error_message: entry.error.clone().unwrap_or_default(),
                block_height: entry.block_height.unwrap_or(0),
            }))
        } else {
            Ok(Response::new(GetTransactionStatusResponse {
                status: TxStatus::Unknown as i32,
                error_message: "Transaction not found".into(),
                block_height: 0,
            }))
        }
    }

    /// Queries state at a specific root.
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

        let root = StateRoot(req.root);
        let response = client
            .query_state_at(root, &req.key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response_bytes =
            codec::to_bytes_canonical(&response).map_err(|e| Status::internal(e))?;

        metrics().observe_request_duration("query_state", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("query_state", 200);

        Ok(Response::new(QueryStateAtResponse { response_bytes }))
    }

    /// Queries raw state value.
    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let result = match self.workload_client.query_raw_state(&req.key).await {
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
        metrics().inc_requests_total("query_raw_state", if result.is_ok() { 200 } else { 500 });

        result
    }

    /// Gets the chain status.
    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let start = Instant::now();
        let status = self
            .workload_client
            .get_status()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics().observe_request_duration("get_status", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("get_status", 200);

        Ok(Response::new(GetStatusResponse {
            height: status.height,
            latest_timestamp: status.latest_timestamp,
            total_transactions: status.total_transactions,
            is_running: status.is_running,
        }))
    }

    /// Fetches a block by height.
    async fn get_block_by_height(
        &self,
        request: Request<GetBlockByHeightRequest>,
    ) -> Result<Response<GetBlockByHeightResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let blocks = self
            .workload_client
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
        metrics().inc_requests_total("get_block_by_height", 200);

        Ok(Response::new(GetBlockByHeightResponse { block_bytes }))
    }
}
