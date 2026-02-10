// Path: crates/validator/src/standard/orchestration/grpc_public.rs

use crate::standard::orchestration::context::{MainLoopContext, TxStatusEntry};
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_client::WorkloadClient;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::{
    GetStatusRequest, GetStatusResponse, QueryRawStateRequest, QueryRawStateResponse,
    QueryStateAtRequest, QueryStateAtResponse,
};
use ioi_ipc::public::public_api_server::PublicApi;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, BlockCommitted, ChainEvent, DraftTransactionRequest,
    DraftTransactionResponse, GetBlockByHeightRequest, GetBlockByHeightResponse,
    GetContextBlobRequest, GetContextBlobResponse, GetTransactionStatusRequest,
    GetTransactionStatusResponse, SubmissionStatus, SubmitTransactionRequest,
    SubmitTransactionResponse, SubscribeEventsRequest, TxStatus,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainTransaction, RoutingReceiptEvent, SignatureProof,
    SignatureSuite, StateRoot, TxHash,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_services::agentic::intent::IntentResolver;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;

use ioi_api::chain::WorkloadClientApi;

fn routing_policy_binding_hash(intent_hash: &str, policy_decision: &str) -> String {
    let payload = format!(
        "ioi::routing-policy-binding::v1::{}::{}",
        intent_hash, policy_decision
    );
    sha256(payload.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

fn map_routing_receipt(
    receipt: RoutingReceiptEvent,
    signer: Option<(&libp2p::identity::Keypair, &str)>,
) -> ioi_ipc::public::RoutingReceipt {
    let (failure_class, has_failure_class) = if let Some(class) = receipt.failure_class {
        let code = match class {
            ioi_types::app::RoutingFailureClass::FocusMismatch => 1,
            ioi_types::app::RoutingFailureClass::TargetNotFound => 2,
            ioi_types::app::RoutingFailureClass::PermissionOrApprovalRequired => 3,
            ioi_types::app::RoutingFailureClass::ToolUnavailable => 4,
            ioi_types::app::RoutingFailureClass::NonDeterministicUI => 5,
            ioi_types::app::RoutingFailureClass::UnexpectedState => 6,
            ioi_types::app::RoutingFailureClass::TimeoutOrHang => 7,
            ioi_types::app::RoutingFailureClass::UserInterventionNeeded => 8,
            ioi_types::app::RoutingFailureClass::VisionTargetNotFound => 9,
            ioi_types::app::RoutingFailureClass::NoEffectAfterAction => 10,
            ioi_types::app::RoutingFailureClass::TierViolation => 11,
            ioi_types::app::RoutingFailureClass::MissingDependency => 12,
            ioi_types::app::RoutingFailureClass::ContextDrift => 13,
        };
        (code, true)
    } else {
        (0, false)
    };

    let policy_binding_hash = if receipt.policy_binding_hash.is_empty() {
        routing_policy_binding_hash(&receipt.intent_hash, &receipt.policy_decision)
    } else {
        receipt.policy_binding_hash.clone()
    };

    let (policy_binding_sig, policy_binding_signer) = if let Some((keypair, signer_pk_hex)) = signer
    {
        match keypair.sign(policy_binding_hash.as_bytes()) {
            Ok(sig) => (hex::encode(sig), signer_pk_hex.to_string()),
            Err(_) => (
                receipt.policy_binding_sig.clone().unwrap_or_default(),
                receipt.policy_binding_signer.clone().unwrap_or_default(),
            ),
        }
    } else {
        (
            receipt.policy_binding_sig.clone().unwrap_or_default(),
            receipt.policy_binding_signer.clone().unwrap_or_default(),
        )
    };

    ioi_ipc::public::RoutingReceipt {
        session_id: hex::encode(receipt.session_id),
        step_index: receipt.step_index,
        intent_hash: receipt.intent_hash,
        policy_decision: receipt.policy_decision,
        tool_name: receipt.tool_name,
        tool_version: receipt.tool_version,
        pre_state: Some(ioi_ipc::public::RoutingStateSummary {
            agent_status: receipt.pre_state.agent_status,
            tier: receipt.pre_state.tier,
            step_index: receipt.pre_state.step_index,
            consecutive_failures: receipt.pre_state.consecutive_failures as u32,
            target_hint: receipt.pre_state.target_hint.unwrap_or_default(),
        }),
        action_json: receipt.action_json,
        post_state: Some(ioi_ipc::public::RoutingPostStateSummary {
            agent_status: receipt.post_state.agent_status,
            tier: receipt.post_state.tier,
            step_index: receipt.post_state.step_index,
            consecutive_failures: receipt.post_state.consecutive_failures as u32,
            success: receipt.post_state.success,
            verification_checks: receipt.post_state.verification_checks,
        }),
        artifacts: receipt.artifacts,
        failure_class,
        has_failure_class,
        stop_condition_hit: receipt.stop_condition_hit,
        escalation_path: receipt.escalation_path.unwrap_or_default(),
        scs_lineage_ptr: receipt.scs_lineage_ptr.unwrap_or_default(),
        mutation_receipt_ptr: receipt.mutation_receipt_ptr.unwrap_or_default(),
        policy_binding_hash,
        policy_binding_sig,
        policy_binding_signer,
    }
}

#[allow(dead_code)] // [FIX] Suppress unused warning for struct
struct SafetyModelAsInference {
    model: Arc<dyn LocalSafetyModel>,
}

#[async_trait::async_trait]
impl InferenceRuntime for SafetyModelAsInference {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let input_str = String::from_utf8_lossy(input_context);

        let mock_json = format!(
            r#"{{
            "operation_id": "start_agent",
            "params": {{ 
                "goal": "{}" 
            }},
            "gas_ceiling": 5000000
        }}"#,
            input_str.trim().escape_debug()
        );

        Ok(mock_json.into_bytes())
    }

    async fn load_model(&self, _hash: [u8; 32], _path: &std::path::Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

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
        let start = Instant::now();
        let req = request.into_inner();
        let tx_bytes = req.transaction_bytes;

        let tx_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tx_bytes)
            .map_err(|e| Status::invalid_argument(format!("Hashing failed: {}", e)))?;
        let tx_hash_hex = hex::encode(tx_hash_bytes);

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

        match self.tx_ingest_tx.try_send((tx_hash_bytes, tx_bytes)) {
            Ok(_) => {
                metrics().inc_requests_total("submit_transaction", 200);
                metrics()
                    .observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());

                tracing::info!(
                    target: "rpc",
                    "Received transaction via gRPC. Hash: {}",
                    tx_hash_hex
                );

                Ok(Response::new(SubmitTransactionResponse {
                    tx_hash: tx_hash_hex,
                    status: SubmissionStatus::Accepted as i32,
                    approval_reason: String::new(),
                }))
            }
            Err(_) => {
                metrics().inc_requests_total("submit_transaction", 503);
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

    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let client: &dyn WorkloadClientApi = &*self.workload_client;

        let result: Result<Response<QueryRawStateResponse>, Status> =
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
            };

        metrics().observe_request_duration("query_raw_state", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("query_raw_state", if result.is_ok() { 200 } else { 500 });

        result
    }

    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let start = Instant::now();
        let client: &dyn WorkloadClientApi = &*self.workload_client;
        let status = client
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

    async fn get_block_by_height(
        &self,
        request: Request<GetBlockByHeightRequest>,
    ) -> Result<Response<GetBlockByHeightResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let client: &dyn WorkloadClientApi = &*self.workload_client;
        let blocks = client
            .get_blocks_range(req.height, 1, 10 * 1024 * 1024)
            .await
            .map_err(|e: ioi_types::error::ChainError| Status::internal(e.to_string()))?;

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

    type SubscribeEventsStream = ReceiverStream<Result<ChainEvent, Status>>;

    async fn subscribe_events(
        &self,
        _request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        let ctx_arc = self.get_context().await?;
        let (tx, rx) = mpsc::channel(128);
        let ctx_clone = ctx_arc.clone();

        tokio::spawn(async move {
            let mut tip_rx = {
                let ctx = ctx_clone.lock().await;
                ctx.tip_sender.subscribe()
            };

            let mut event_rx = {
                let ctx = ctx_clone.lock().await;
                ctx.event_broadcaster.subscribe()
            };
            let (receipt_signing_keypair, receipt_signer_pubkey) = {
                let ctx = ctx_clone.lock().await;
                (
                    ctx.local_keypair.clone(),
                    hex::encode(ctx.local_keypair.public().encode_protobuf()),
                )
            };

            loop {
                tokio::select! {
                    Ok(_) = tip_rx.changed() => {
                        let tip = tip_rx.borrow().clone();
                        let event = ChainEvent {
                            event: Some(ChainEventEnum::Block(
                                BlockCommitted {
                                    height: tip.height,
                                    state_root: hex::encode(&tip.state_root),
                                    tx_count: 0,
                                }
                            )),
                        };
                        if tx.send(Ok(event)).await.is_err() { break; }
                    }

                    Ok(kernel_event) = event_rx.recv() => {
                         tracing::info!(target: "rpc", "PublicAPI processing KernelEvent: {:?}", kernel_event);

                         let mapped_event = match kernel_event {
                             ioi_types::app::KernelEvent::AgentThought { session_id, token } => {
                                 Some(ChainEventEnum::Thought(
                                     ioi_ipc::public::AgentThought {
                                         session_id: hex::encode(session_id),
                                         content: token,
                                         is_final: false,
                                         visual_hash: "".to_string(),
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::AgentStep(step) => {
                                 Some(ChainEventEnum::Thought(
                                     ioi_ipc::public::AgentThought {
                                         session_id: hex::encode(step.session_id),
                                         content: step.raw_output,
                                         is_final: true,
                                         visual_hash: hex::encode(step.visual_hash),
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::BlockCommitted { height, tx_count } => {
                                 Some(ChainEventEnum::Block(
                                     ioi_ipc::public::BlockCommitted {
                                         height,
                                         state_root: "".into(),
                                         tx_count: tx_count as u64,
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::GhostInput { device, description } => {
                                 Some(ChainEventEnum::Ghost(
                                     ioi_ipc::public::GhostInput {
                                         device,
                                         description,
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::FirewallInterception { verdict, target, request_hash, session_id } => {
                                 Some(ChainEventEnum::Action(
                                     ioi_ipc::public::ActionIntercepted {
                                         session_id: session_id.map(hex::encode).unwrap_or_default(),
                                         target,
                                         verdict,
                                         reason: hex::encode(request_hash),
                                     }
                                 ))
                             },
                            ioi_types::app::KernelEvent::AgentActionResult { session_id, step_index, tool_name, output, agent_status } => {
                                 Some(ChainEventEnum::ActionResult(
                                     ioi_ipc::public::AgentActionResult {
                                         session_id: hex::encode(session_id),
                                         step_index,
                                         tool_name,
                                         output,
                                         agent_status,
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::AgentSpawn { parent_session_id, new_session_id, name, role, budget, goal } => {
                                 Some(ChainEventEnum::Spawn(
                                     ioi_ipc::public::AgentSpawn {
                                         parent_session_id: hex::encode(parent_session_id),
                                         new_session_id: hex::encode(new_session_id),
                                         name,
                                         role,
                                         budget,
                                         goal,
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::RoutingReceipt(receipt) => {
                                 Some(ChainEventEnum::RoutingReceipt(
                                     map_routing_receipt(
                                         receipt,
                                         Some((
                                             &receipt_signing_keypair,
                                             receipt_signer_pubkey.as_str(),
                                         )),
                                     )
                                 ))
                             },
                             // [FIX] Handle SystemUpdate event
                             ioi_types::app::KernelEvent::SystemUpdate { component, status } => {
                                 Some(ChainEventEnum::System(
                                     ioi_ipc::public::SystemUpdate {
                                         component,
                                         status,
                                     }
                                 ))
                             },
                         };

                         if let Some(event_enum) = mapped_event {
                             let event = ChainEvent { event: Some(event_enum) };
                             if tx.send(Ok(event)).await.is_err() { break; }
                         }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn draft_transaction(
        &self,
        request: Request<DraftTransactionRequest>,
    ) -> Result<Response<DraftTransactionResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;

        let (
            chain_id,
            inference_runtime,
            keypair,
            nonce_manager,
            workload_client,
            account_id_bytes,
        ) = {
            let ctx = ctx_arc.lock().await;
            let account_id = account_id_from_key_material(
                SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default();

            (
                ctx.chain_id,
                ctx.inference_runtime.clone(),
                ctx.local_keypair.clone(),
                ctx.nonce_manager.clone(),
                ctx.view_resolver.workload_client().clone(),
                account_id,
            )
        };

        let account_id = AccountId(account_id_bytes);

        let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();

        let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(b)) => codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
            _ => 0,
        };

        let nonce = {
            let mut guard = nonce_manager.lock().await;
            let entry = guard.entry(account_id).or_insert(0);

            if *entry < state_nonce {
                *entry = state_nonce;
            }

            let use_nonce = *entry;
            *entry += 1;

            use_nonce
        };

        let resolver = IntentResolver::new(inference_runtime);
        let address_book = std::collections::HashMap::new();

        let tx_bytes = resolver
            .resolve_intent(&req.intent, chain_id, nonce, &address_book)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut tx: ChainTransaction = codec::from_bytes_canonical(&tx_bytes)
            .map_err(|e| Status::internal(format!("Failed to deserialize draft: {}", e)))?;

        let signer_pk_bytes = keypair.public().encode_protobuf();
        let signer_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &signer_pk_bytes)
                .map_err(|e| Status::internal(e.to_string()))?,
        );

        let signed_tx_bytes = match &mut tx {
            ChainTransaction::Settlement(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(|e| Status::internal(e))?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(|e| Status::internal(e))?
            }
            ChainTransaction::System(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(|e| Status::internal(e))?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(|e| Status::internal(e))?
            }
            _ => {
                return Err(Status::unimplemented(
                    "Auto-signing not supported for this transaction type",
                ))
            }
        };

        Ok(Response::new(DraftTransactionResponse {
            transaction_bytes: signed_tx_bytes,
            summary_markdown: format!(
                "**Action:** Execute `{}` (Auto-Signed, Nonce {})",
                req.intent, nonce
            ),
            required_capabilities: vec!["wallet::sign".into()],
        }))
    }

    async fn get_context_blob(
        &self,
        request: Request<GetContextBlobRequest>,
    ) -> Result<Response<GetContextBlobResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;

        let scs_arc = {
            let ctx = ctx_arc.lock().await;
            ctx.scs.clone()
        };

        let scs_arc =
            scs_arc.ok_or_else(|| Status::unimplemented("SCS not available on this node"))?;
        let scs = scs_arc
            .lock()
            .map_err(|_| Status::internal("SCS lock poisoned"))?;

        let hash_bytes = hex::decode(&req.blob_hash)
            .map_err(|_| Status::invalid_argument("Invalid hex hash"))?;

        let hash_arr: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid hash length"))?;

        let frame_id = scs
            .visual_index
            .get(&hash_arr)
            .copied()
            .ok_or_else(|| Status::not_found("Blob not found"))?;

        let payload = scs
            .read_frame_payload(frame_id)
            .map_err(|e| Status::internal(format!("Failed to read frame: {}", e)))?;

        Ok(Response::new(GetContextBlobResponse {
            data: payload.to_vec(),
            mime_type: "application/octet-stream".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_receipt_chain_event_payload_is_complete() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let signer_pk = hex::encode(keypair.public().encode_protobuf());

        let receipt = RoutingReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            intent_hash: "abcd1234".to_string(),
            policy_decision: "allowed".to_string(),
            tool_name: "sys__exec".to_string(),
            tool_version: "1.0.0".to_string(),
            pre_state: ioi_types::app::RoutingStateSummary {
                agent_status: "Running".to_string(),
                tier: "ToolFirst".to_string(),
                step_index: 42,
                consecutive_failures: 0,
                target_hint: Some("terminal".to_string()),
            },
            action_json: "{\"name\":\"sys__exec\"}".to_string(),
            post_state: ioi_types::app::RoutingPostStateSummary {
                agent_status: "Running".to_string(),
                tier: "ToolFirst".to_string(),
                step_index: 43,
                consecutive_failures: 0,
                success: true,
                verification_checks: vec!["policy_decision=allowed".to_string()],
            },
            artifacts: vec!["trace://agent_step/42".to_string()],
            failure_class: None,
            stop_condition_hit: false,
            escalation_path: None,
            scs_lineage_ptr: Some("scs://skill/abc".to_string()),
            mutation_receipt_ptr: Some("scs://mutation-receipt/def".to_string()),
            policy_binding_hash: String::new(),
            policy_binding_sig: None,
            policy_binding_signer: None,
        };

        let mapped = map_routing_receipt(receipt.clone(), Some((&keypair, signer_pk.as_str())));
        let event = ChainEvent {
            event: Some(ChainEventEnum::RoutingReceipt(mapped.clone())),
        };

        match event.event {
            Some(ChainEventEnum::RoutingReceipt(payload)) => {
                assert_eq!(payload.session_id, hex::encode(receipt.session_id));
                assert_eq!(payload.step_index, receipt.step_index);
                assert_eq!(payload.intent_hash, receipt.intent_hash);
                assert_eq!(payload.policy_decision, receipt.policy_decision);
                assert_eq!(payload.tool_name, receipt.tool_name);
                assert_eq!(payload.tool_version, receipt.tool_version);
                assert_eq!(payload.action_json, receipt.action_json);
                assert_eq!(payload.artifacts, receipt.artifacts);
                assert_eq!(
                    payload.pre_state.as_ref().map(|s| s.tier.as_str()),
                    Some("ToolFirst")
                );
                assert_eq!(
                    payload
                        .post_state
                        .as_ref()
                        .map(|s| s.verification_checks.len())
                        .unwrap_or_default(),
                    1
                );
                assert!(!payload.policy_binding_hash.is_empty());
                assert!(!payload.policy_binding_sig.is_empty());
                assert_eq!(payload.policy_binding_signer, signer_pk);

                let signer_bytes =
                    hex::decode(&payload.policy_binding_signer).expect("valid signer hex");
                let signature =
                    hex::decode(&payload.policy_binding_sig).expect("valid signature hex");
                let signer_key = libp2p::identity::PublicKey::try_decode_protobuf(&signer_bytes)
                    .expect("decode signer key");
                assert!(signer_key.verify(payload.policy_binding_hash.as_bytes(), &signature));
            }
            other => panic!("expected routing receipt chain event, got: {:?}", other),
        }
    }
}
