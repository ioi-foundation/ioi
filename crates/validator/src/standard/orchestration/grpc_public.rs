// Path: crates/validator/src/standard/orchestration/grpc_public.rs

use crate::standard::orchestration::context::{MainLoopContext, TxStatusEntry};
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_client::WorkloadClient;
use ioi_ipc::blockchain::{
    GetStatusRequest, GetStatusResponse, QueryRawStateRequest, QueryRawStateResponse,
    QueryStateAtRequest, QueryStateAtResponse,
};
use ioi_ipc::public::public_api_server::PublicApi;
use ioi_ipc::public::{
    ChainEvent, DraftTransactionRequest, DraftTransactionResponse, GetBlockByHeightRequest,
    GetBlockByHeightResponse, GetContextBlobRequest, GetContextBlobResponse,
    GetSessionHistoryRequest, GetSessionHistoryResponse, GetTransactionStatusRequest,
    GetTransactionStatusResponse, SetRuntimeSecretRequest, SetRuntimeSecretResponse,
    SubmitTransactionRequest, SubmitTransactionResponse, SubscribeEventsRequest,
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;
use ioi_api::chain::WorkloadClientApi;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_scs::FrameType;
use ioi_services::agentic::desktop::runtime_secret;
use ioi_services::agentic::intent::IntentResolver;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainTransaction, SignatureProof, SignatureSuite,
    StateRoot, TxHash,
};
use ioi_types::codec;
use ioi_types::error::VmError;

mod events_handlers;
mod helpers;
mod inference;
mod session_handlers;
mod state_handlers;
mod tx_handlers;

use helpers::{map_routing_receipt, parse_session_id_hex};

#[cfg(test)]
mod tests;

/// Implementation of the Public gRPC API.
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    pub context_wrapper: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    pub workload_client: Arc<WorkloadClient>,
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    async fn submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        self.handle_submit_transaction(request).await
    }

    async fn get_transaction_status(
        &self,
        request: Request<GetTransactionStatusRequest>,
    ) -> Result<Response<GetTransactionStatusResponse>, Status> {
        self.handle_get_transaction_status(request).await
    }

    async fn query_state(
        &self,
        request: Request<QueryStateAtRequest>,
    ) -> Result<Response<QueryStateAtResponse>, Status> {
        self.handle_query_state(request).await
    }

    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        self.handle_query_raw_state(request).await
    }

    async fn get_status(
        &self,
        request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        self.handle_get_status(request).await
    }

    async fn get_block_by_height(
        &self,
        request: Request<GetBlockByHeightRequest>,
    ) -> Result<Response<GetBlockByHeightResponse>, Status> {
        self.handle_get_block_by_height(request).await
    }

    type SubscribeEventsStream = ReceiverStream<Result<ChainEvent, Status>>;

    async fn subscribe_events(
        &self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        self.handle_subscribe_events(request).await
    }

    async fn draft_transaction(
        &self,
        request: Request<DraftTransactionRequest>,
    ) -> Result<Response<DraftTransactionResponse>, Status> {
        self.handle_draft_transaction(request).await
    }

    async fn get_session_history(
        &self,
        request: Request<GetSessionHistoryRequest>,
    ) -> Result<Response<GetSessionHistoryResponse>, Status> {
        self.handle_get_session_history(request).await
    }

    async fn set_runtime_secret(
        &self,
        request: Request<SetRuntimeSecretRequest>,
    ) -> Result<Response<SetRuntimeSecretResponse>, Status> {
        self.handle_set_runtime_secret(request).await
    }

    async fn get_context_blob(
        &self,
        request: Request<GetContextBlobRequest>,
    ) -> Result<Response<GetContextBlobResponse>, Status> {
        self.handle_get_context_blob(request).await
    }
}
