// Path: crates/validator/src/standard/orchestration/grpc_public.rs

use crate::standard::orchestration::context::{MainLoopContext, TxStatusEntry};
// [FIX] Removed unused WorkloadClientApi import
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_client::WorkloadClient;
use ioi_ipc::blockchain::{
    GetStatusRequest,
    GetStatusResponse,
    QueryRawStateRequest,
    QueryRawStateResponse,
    QueryStateAtRequest,
    QueryStateAtResponse,
};
use ioi_ipc::public::public_api_server::PublicApi;
use ioi_ipc::public::{
    BlockCommitted,
    ChainEvent,
    DraftTransactionRequest,
    DraftTransactionResponse,
    GetBlockByHeightRequest,
    GetBlockByHeightResponse,
    GetContextBlobRequest,
    GetContextBlobResponse,
    GetTransactionStatusRequest,
    GetTransactionStatusResponse,
    SubmissionStatus,
    SubmitTransactionRequest,
    SubmitTransactionResponse,
    SubscribeEventsRequest,
    TxStatus,
};
// [FIX] Removed unused SigningKeyPair import
use ioi_types::app::{ChainTransaction, StateRoot, TxHash, SignatureProof, SignatureSuite};
use ioi_types::codec;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::metrics::rpc_metrics as metrics;
use ioi_services::agentic::intent::IntentResolver;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;

// [FIX] Import WorkloadClientApi via trait object usage if needed, or remove if unused.
// It is used in get_status/query_raw_state, so we must import it.
use ioi_api::chain::WorkloadClientApi;

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
        let classification = self.model.classify_intent(&input_str).await
            .map_err(|e| VmError::HostError(e.to_string()))?;
            
        let mock_json = format!(r#"{{
            "operation_id": "transfer",
            "params": {{ "to": "0x0000000000000000000000000000000000000000000000000000000000000000", "amount": 100 }},
            "gas_ceiling": 10000,
            "note": "Generated via SafetyModel classification: {:?}"
        }}"#, classification);
        
        Ok(mock_json.into_bytes())
    }

    async fn load_model(&self, _hash: [u8; 32], _path: &std::path::Path) -> Result<(), VmError> { Ok(()) }
    async fn unload_model(&self, _hash: [u8; 32]) -> Result<(), VmError> { Ok(()) }
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
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
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
        
        let result: Result<Response<QueryRawStateResponse>, Status> = match client.query_raw_state(&req.key).await {
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

            loop {
                tokio::select! {
                    Ok(_) = tip_rx.changed() => {
                        let tip = tip_rx.borrow().clone();
                        let event = ChainEvent {
                            event: Some(ioi_ipc::public::chain_event::Event::Block(
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
                         let mapped_event = match kernel_event {
                             ioi_types::app::KernelEvent::AgentStep(step) => {
                                 Some(ioi_ipc::public::chain_event::Event::Thought(
                                     ioi_ipc::public::AgentThought {
                                         session_id: hex::encode(step.session_id),
                                         content: step.raw_output,
                                         is_final: step.success,
                                     }
                                 ))
                             },
                             ioi_types::app::KernelEvent::BlockCommitted { height, tx_count } => {
                                 Some(ioi_ipc::public::chain_event::Event::Block(
                                     ioi_ipc::public::BlockCommitted {
                                         height,
                                         state_root: "".into(),
                                         tx_count: tx_count as u64,
                                     }
                                 ))
                             },
                             _ => None
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

        // 1. Resolve Dependencies
        let (chain_id, nonce, safety_model, keypair) = {
            let ctx = ctx_arc.lock().await;
            let account_id = ioi_types::app::account_id_from_key_material(
                ioi_types::app::SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default();

            let nonce_manager = ctx.nonce_manager.lock().await;
            let nonce = nonce_manager
                .get(&ioi_types::app::AccountId(account_id))
                .copied()
                .unwrap_or(0);

            (ctx.chain_id, nonce, ctx.safety_model.clone(), ctx.local_keypair.clone())
        };

        let adapter = Arc::new(SafetyModelAsInference { model: safety_model });
        let resolver = IntentResolver::new(adapter);
        let address_book = std::collections::HashMap::new();

        // 2. Resolve Intent -> Unsigned Transaction Bytes
        let tx_bytes = resolver
            .resolve_intent(&req.intent, chain_id, nonce, &address_book)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // 3. [FIXED] Sign the Transaction for Mode 0 (User Node)
        // Deserialize the raw bytes back to ChainTransaction
        let mut tx: ChainTransaction = codec::from_bytes_canonical(&tx_bytes)
             .map_err(|e| Status::internal(format!("Failed to deserialize draft: {}", e)))?;

        // Extract mutable reference to fields we need to sign
        // We handle this directly in the match to avoid conflicting types
        let signed_tx_bytes = match &mut tx {
            ChainTransaction::Settlement(s) => {
                 let sign_bytes = s.to_sign_bytes().map_err(|e| Status::internal(e))?;
                 let sig = keypair.sign(&sign_bytes).map_err(|e| Status::internal(e.to_string()))?;
                 s.signature_proof = SignatureProof {
                     suite: SignatureSuite::ED25519,
                     public_key: keypair.public().encode_protobuf(),
                     signature: sig,
                 };
                 codec::to_bytes_canonical(&tx).map_err(|e| Status::internal(e))?
            },
            ChainTransaction::System(s) => {
                 let sign_bytes = s.to_sign_bytes().map_err(|e| Status::internal(e))?;
                 let sig = keypair.sign(&sign_bytes).map_err(|e| Status::internal(e.to_string()))?;
                 s.signature_proof = SignatureProof {
                     suite: SignatureSuite::ED25519,
                     public_key: keypair.public().encode_protobuf(),
                     signature: sig,
                 };
                 codec::to_bytes_canonical(&tx).map_err(|e| Status::internal(e))?
            },
            _ => return Err(Status::unimplemented("Auto-signing not supported for this transaction type"))
        };

        Ok(Response::new(DraftTransactionResponse {
            transaction_bytes: signed_tx_bytes,
            summary_markdown: format!("**Action:** Execute `{}` (Auto-Signed)", req.intent),
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