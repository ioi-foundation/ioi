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
    ChainEvent, DraftTransactionRequest, DraftTransactionResponse, ExecuteAftQuvEffectRequest,
    ExecuteAftQuvEffectResponse, GetBlockByHeightRequest, GetBlockByHeightResponse,
    GetContextBlobRequest, GetContextBlobResponse, GetSessionHistoryRequest,
    GetSessionHistoryResponse, GetTransactionStatusRequest, GetTransactionStatusResponse,
    SetRuntimeSecretRequest, SetRuntimeSecretResponse, SubmitTransactionRequest,
    SubmitTransactionResponse, SubscribeEventsRequest,
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
use ioi_services::agentic::intent::IntentResolver;
use ioi_services::agentic::runtime::runtime_secret;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainTransaction, SignatureProof, SignatureSuite,
    StateRoot, TxHash,
};
use ioi_types::codec;

mod events_handlers;
mod helpers;
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

    async fn handle_execute_aft_quv_effect(
        &self,
        request: Request<ExecuteAftQuvEffectRequest>,
    ) -> Result<Response<ExecuteAftQuvEffectResponse>, Status> {
        use agentgres::consequence::{
            AcceptedEffectAuthorizationV1, ConsequenceStore, DurablePqAtomicRegisterV1,
            ExternalResourceV1,
        };
        use ioi_types::app::{QuvCandidateV0, QuvPushQueryV0};
        use rand::{rngs::OsRng, RngCore};

        let request = request.into_inner();
        if request.effect_id.trim().is_empty() {
            return Err(Status::invalid_argument("effect_id is empty"));
        }
        let candidate: QuvCandidateV0 = codec::from_bytes_canonical(&request.candidate_bytes)
            .map_err(|error| Status::invalid_argument(format!("invalid QUV candidate: {error}")))?;
        let context = self.get_context().await?;
        let (runtime_finality, endpoint) = {
            let guard = context.lock().await;
            (
                guard.runtime_finality.clone(),
                guard
                    .pqc_signer
                    .clone()
                    .ok_or_else(|| Status::failed_precondition("PQ executor key is absent"))?,
            )
        };
        let (admission, current_height, runtime_root) = {
            let finality = runtime_finality.lock().await;
            let admission = finality
                .committed_consequence_manifest(&request.effect_id)
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            let current_height = finality
                .last_admitted_block()
                .map_err(|error| Status::internal(error.to_string()))?
                .map(|block| block.header.height)
                .unwrap_or(admission.admitted_height);
            let runtime_root = finality.consequence_runtime_root();
            (admission, current_height, runtime_root)
        };
        let mut resource =
            DurablePqAtomicRegisterV1::open(runtime_root.join("quv-external-resource"), endpoint)
                .map_err(|error| Status::internal(error.to_string()))?;
        if resource.profile() != &admission.manifest.resource_profile {
            return Err(Status::failed_precondition(
                "executor PQ resource differs from the Agentgres-admitted manifest",
            ));
        }
        let mut consequence_store = ConsequenceStore::open(runtime_root.join("consequence"))
            .map_err(|error| Status::unavailable(error.to_string()))?;
        if !consequence_store.contains(&request.effect_id) {
            let (authorization, achieved) =
                AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
                    &admission.committed,
                    &admission.manifest,
                )
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            consequence_store
                .authorize(
                    admission.manifest,
                    &achieved,
                    &authorization,
                    current_height,
                )
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
        }
        let requirement = consequence_store
            .online_authorization_requirement(&request.effect_id)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        if candidate.payload_hash != requirement.payload_hash
            || candidate.slot.configuration_root != requirement.configuration_root
            || candidate.slot.policy_root != requirement.policy_root
            || candidate.slot.domain_id != requirement.conflict_domain_hash
            || candidate.slot.slot != requirement.conflict_slot
        {
            return Err(Status::invalid_argument(
                "QUV candidate does not match the durable effect manifest",
            ));
        }
        let mut verifier_nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut verifier_nonce);
        let receiver = super::quv::begin_online_authorization(
            &context,
            QuvPushQueryV0 {
                verifier_nonce,
                candidate,
            },
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let authorization = receiver
            .await
            .map_err(|_| Status::unavailable("QUV operation ended without a decision"))?
            .map_err(Status::failed_precondition)?;
        let receipt = consequence_store
            .execute_with_online_authorization(&request.effect_id, &mut resource, authorization)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let consequence_receipt_jcs =
            serde_jcs::to_vec(&receipt).map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(ExecuteAftQuvEffectResponse {
            consequence_receipt_jcs,
            portable_final_receipt: false,
        }))
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

    async fn execute_aft_quv_effect(
        &self,
        request: Request<ExecuteAftQuvEffectRequest>,
    ) -> Result<Response<ExecuteAftQuvEffectResponse>, Status> {
        self.handle_execute_aft_quv_effect(request).await
    }
}
