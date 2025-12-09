// Path: crates/validator/src/standard/orchestration/grpc_public.rs
use crate::standard::orchestration::context::MainLoopContext;
// [FIX] Removed unused anyhow import
use ioi_api::{commitment::CommitmentScheme, state::StateManager, transaction::TransactionModel};
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
use ioi_types::app::ChainTransaction;
use ioi_types::codec;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;
use std::time::Instant;

pub struct PublicApiImpl<CS, ST, CE, V>
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
    // [FIX] Hold the outer Arc which might be None initially
    pub context_wrapper: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
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

        let dummy_model =
            UnifiedTransactionModel::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
        let tx = dummy_model
            .deserialize_transaction(&req.transaction_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid transaction bytes: {}", e)))?;

        let context_arc = self.get_context().await?;
        let (workload_client, _, tx_pool, swarm_sender, kick_tx) = {
            let ctx = context_arc.lock().await;
            (
                ctx.view_resolver.workload_client().clone(),
                ctx.chain_id,
                ctx.tx_pool_ref.clone(),
                ctx.swarm_commander.clone(),
                ctx.consensus_kick_tx.clone(),
            )
        };

        // [FIX] Explicitly type the closure argument for map_err
        let root =
            workload_client
                .get_state_root()
                .await
                .map_err(|e: ioi_types::error::ChainError| {
                    Status::internal(format!("Failed to get state root: {}", e))
                })?;
        let anchor = root
            .to_anchor()
            .map_err(|e| Status::internal(format!("Failed to anchor root: {}", e)))?;

        let expected_timestamp = 0;

        let check_results = workload_client
            .check_transactions_at(anchor, expected_timestamp, vec![tx.clone()])
            .await
            .map_err(|e: ioi_types::error::ChainError| {
                Status::internal(format!("Pre-flight check IPC error: {}", e))
            })?;

        if let Some(Err(e)) = check_results.first() {
            return Err(Status::invalid_argument(format!(
                "Transaction rejected: {}",
                e
            )));
        }

        let tx_hash = tx
            .hash()
            .map_err(|e| Status::internal(format!("Hashing failed: {}", e)))?;
        let tx_hash_hex = hex::encode(tx_hash);

        {
            let mut pool = tx_pool.lock().await;
            if pool.iter().any(|(_, h)| *h == tx_hash) {
                return Ok(Response::new(SubmitTransactionResponse {
                    tx_hash: tx_hash_hex,
                }));
            }
            pool.push_back((tx, tx_hash));
            metrics().inc_mempool_transactions_added();
            metrics().set_mempool_size(pool.len() as f64);
            tracing::info!(target: "rpc", event = "mempool_add", new_size = pool.len());
        }

        let _ = swarm_sender
            .send(SwarmCommand::PublishTransaction(req.transaction_bytes))
            .await;
        let _ = kick_tx.send(());

        metrics().observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("submit_transaction", 0); // 0 = OK

        Ok(Response::new(SubmitTransactionResponse {
            tx_hash: tx_hash_hex,
        }))
    }

    async fn query_state(
        &self,
        request: Request<QueryStateAtRequest>,
    ) -> Result<Response<QueryStateAtResponse>, Status> {
        let req = request.into_inner();
        let context_arc = self.get_context().await?;
        let client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };

        let root = ioi_types::app::StateRoot(req.root);
        // [FIX] Explicitly type map_err
        let response = client
            .query_state_at(root, &req.key)
            .await
            .map_err(|e: ioi_types::error::ChainError| Status::internal(e.to_string()))?;

        let response_bytes = codec::to_bytes_canonical(&response)
            .map_err(|e| Status::internal(format!("Serialization error: {}", e)))?;

        Ok(Response::new(QueryStateAtResponse { response_bytes }))
    }

    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        let req = request.into_inner();
        let context_arc = self.get_context().await?;
        let client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };

        match client.query_raw_state(&req.key).await {
            Ok(Some(val)) => Ok(Response::new(QueryRawStateResponse {
                value: val,
                found: true,
            })),
            Ok(None) => Ok(Response::new(QueryRawStateResponse {
                value: vec![],
                found: false,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let start = Instant::now();
        let context_arc = self.get_context().await?;
        let client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };

        // [FIX] Explicitly type map_err
        let status = client
            .get_status()
            .await
            .map_err(|e: ioi_types::error::ChainError| Status::internal(e.to_string()))?;

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
        let context_arc = self.get_context().await?;
        let client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };

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
