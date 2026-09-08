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

// A conflict diagnosis is attached only to the verifier's typed refusal.
// This metadata is not an authorization or transferable conflict proof.
fn quv_operation_failure_status(error: anyhow::Error) -> Status {
    use ioi_consensus::aft::query_unanimity::QuvError;
    if matches!(
        error.downcast_ref::<QuvError>(),
        Some(QuvError::ConflictDisclosed)
    ) {
        let mut status = Status::aborted(error.to_string());
        status.metadata_mut().insert(
            "ioi-quv-refusal",
            tonic::metadata::MetadataValue::from_static("conflict-disclosed-v0"),
        );
        status
    } else {
        Status::failed_precondition(error.to_string())
    }
}

// Durable preflight is complete before network/readiness waiting. Reopen the
// store afterward: another request may have changed its durable state meanwhile.
async fn after_releasing_consequence_store<T>(
    store: agentgres::consequence::ConsequenceStore,
    wait: impl std::future::Future<Output = T>,
) -> T {
    let result = wait.await;
    drop(store);
    result
}

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
        let (authorization, achieved) =
            AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
                &admission.committed,
                &admission.manifest,
            )
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        consequence_store
            .prepare_online_effect(
                admission.manifest,
                &achieved,
                &authorization,
                current_height,
            )
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let requirement = consequence_store
            .online_effect_binding(&request.effect_id)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        if candidate.payload_hash != requirement.payload_hash
            || candidate.slot.configuration_root != requirement.configuration_root
            || candidate.slot.policy_root != requirement.policy_root
            || candidate.slot.domain_id != requirement.conflict_domain_hash
            || candidate.slot.slot != requirement.conflict_slot
            || candidate.slot.predecessor != requirement.predecessor
            || candidate.slot.authority_mode != requirement.authority_mode
        {
            return Err(Status::invalid_argument(
                "QUV candidate does not match the durable effect manifest",
            ));
        }
        if let Some(receipt) = consequence_store
            .online_retry_result(&request.effect_id, &mut resource)
            .map_err(|error| Status::failed_precondition(error.to_string()))?
        {
            let consequence_receipt_jcs =
                serde_jcs::to_vec(&receipt).map_err(|error| Status::internal(error.to_string()))?;
            let mut response = Response::new(ExecuteAftQuvEffectResponse {
                consequence_receipt_jcs,
                portable_final_receipt: false,
            });
            // Diagnostic height of committed readmission, never authority.
            response.metadata_mut().insert(
                "ioi-quv-result-height",
                current_height
                    .to_string()
                    .parse()
                    .map_err(|_| Status::internal("cannot encode result height"))?,
            );
            return Ok(response);
        }
        let mut verifier_nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut verifier_nonce);
        let authorization = after_releasing_consequence_store(consequence_store, async {
            let receiver = super::quv::begin_online_authorization(
                &context,
                QuvPushQueryV0 {
                    verifier_nonce,
                    candidate,
                },
            )
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
            receiver
                .await
                .map_err(|_| Status::unavailable("QUV operation ended without a decision"))?
                .map_err(quv_operation_failure_status)
        })
        .await?;
        let mut consequence_store = ConsequenceStore::open(runtime_root.join("consequence"))
            .map_err(|error| Status::unavailable(error.to_string()))?;
        // Keep committed admission and height stable through the synchronous
        // claim/call boundary. The online wait may have outlived the admission
        // snapshot used to start the operation.
        let finality = runtime_finality.lock().await;
        let admission = finality
            .committed_consequence_manifest(&request.effect_id)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let current_height = finality
            .last_admitted_block()
            .map_err(|error| Status::internal(error.to_string()))?
            .map(|block| block.header.height)
            .unwrap_or(0);
        let (admitted_authorization, achieved) =
            AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
                &admission.committed,
                &admission.manifest,
            )
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        consequence_store
            .prepare_online_effect(
                admission.manifest,
                &achieved,
                &admitted_authorization,
                current_height,
            )
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        // Reopen may observe completion by another relying request. A current
        // committed readmission permits lookup-only result retrieval; it does
        // not spend this grant or authorize a second external mutation.
        let receipt = match consequence_store
            .online_retry_result(&request.effect_id, &mut resource)
            .map_err(|error| Status::failed_precondition(error.to_string()))?
        {
            Some(receipt) => receipt,
            None => consequence_store
                .execute_with_online_authorization(
                    &request.effect_id,
                    &mut resource,
                    authorization,
                    current_height,
                )
                .map_err(|error| Status::failed_precondition(error.to_string()))?,
        };
        drop(finality);
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

#[cfg(test)]
mod quv_refusal_status_tests {
    use super::{after_releasing_consequence_store, quv_operation_failure_status};
    use ioi_consensus::aft::query_unanimity::QuvError;

    #[tokio::test]
    async fn quv_wait_releases_consequence_lock_and_reopen_restores_exclusion() {
        use agentgres::consequence::ConsequenceStore;
        let temp = tempfile::tempdir().unwrap();
        let store = ConsequenceStore::open(temp.path()).unwrap();
        assert!(ConsequenceStore::open(temp.path()).is_err());
        after_releasing_consequence_store(store, async {
            let other = ConsequenceStore::open(temp.path())
                .expect("online wait must not monopolize consequence storage");
            assert!(ConsequenceStore::open(temp.path()).is_err());
            drop(other);
        })
        .await;
        let reopened = ConsequenceStore::open(temp.path()).unwrap();
        assert!(ConsequenceStore::open(temp.path()).is_err());
        drop(reopened);
    }

    #[test]
    fn conflict_status_preserves_type_and_never_classifies_message_text() {
        let typed =
            anyhow::Error::new(QuvError::ConflictDisclosed).context("online verifier finished");
        let status = quv_operation_failure_status(typed);
        assert_eq!(status.code(), tonic::Code::Aborted);
        assert_eq!(
            status.metadata().get("ioi-quv-refusal").unwrap(),
            "conflict-disclosed-v0"
        );
        for error in [
            anyhow::anyhow!("a valid conflict was disclosed"),
            anyhow::Error::new(QuvError::NoValidReplies),
            anyhow::Error::new(QuvError::Io("a valid conflict was disclosed".into())),
        ] {
            let status = quv_operation_failure_status(error);
            assert_eq!(status.code(), tonic::Code::FailedPrecondition);
            assert!(status.metadata().get("ioi-quv-refusal").is_none());
        }
    }
}
