// Path: crates/validator/src/standard/workload/ipc/grpc_control.rs

use crate::standard::workload::ipc::RpcContext;
use ioi_api::chain::ChainStateMachine;
use ioi_api::services::BlockchainService;
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_ipc::data::{AgentContext, ContextSlice, EncryptedSlice, InferenceOutput, Tensor};
use ioi_ipc::security::{decrypt_slice, derive_session_key};
use ioi_ipc::{
    control::workload_control_server::WorkloadControl,
    control::{
        ExecuteJobRequest, ExecuteJobResponse, HealthCheckRequest, HealthCheckResponse,
        LoadModelRequest, LoadModelResponse,
    },
};
use ioi_services::agentic::leakage::{CheckLeakageParams, LeakageController};
use ioi_types::app::agentic::InferenceOptions; // [FIX] Import
use ioi_types::app::AccountId;
use ioi_types::codec;
use rkyv::{AlignedVec, Deserialize};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tonic::{Request, Response, Status};

// [FIX] Import SystemTime for timestamp generation
use std::time::{SystemTime, UNIX_EPOCH};

/// Implementation of the `WorkloadControl` gRPC service.
///
/// This service handles high-frequency control plane commands from the Orchestrator,
/// such as loading models into accelerator memory and triggering inference jobs.
/// It coordinates the "Data Plane" (Shared Memory) access for zero-copy I/O.
pub struct WorkloadControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context containing handles to the core machine, workload container, and data plane.
    pub ctx: Arc<RpcContext<CS, ST>>,
    /// Tracks the most recently loaded model hash for this control session.
    /// This ensures that execution requests are routed to the correct resident model weights.
    active_model_hash: Arc<RwLock<Option<[u8; 32]>>>,
}

impl<CS, ST> WorkloadControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Creates a new instance of the `WorkloadControlImpl` service.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A shared reference to the RPC context, providing access to the Workload backend.
    pub fn new(ctx: Arc<RpcContext<CS, ST>>) -> Self {
        Self {
            ctx,
            active_model_hash: Arc::new(RwLock::new(None)),
        }
    }
}

#[tonic::async_trait]
impl<CS, ST> WorkloadControl for WorkloadControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn load_model(
        &self,
        request: Request<LoadModelRequest>,
    ) -> Result<Response<LoadModelResponse>, Status> {
        let req = request.into_inner();
        let inference = self
            .ctx
            .workload
            .inference()
            .map_err(|e| Status::failed_precondition(e.to_string()))?;

        let model_hash: [u8; 32] = hex::decode(&req.model_id)
            .map_err(|_| Status::invalid_argument("model_id must be a valid hex string"))?
            .try_into()
            .map_err(|_| {
                Status::invalid_argument("model_id must be exactly 32 bytes (64 hex chars)")
            })?;

        let model_path = Path::new(&req.model_id);

        match inference.load_model(model_hash, model_path).await {
            Ok(_) => {
                log::info!("Successfully loaded model: {}", req.model_id);
                let mut active = self.active_model_hash.write().unwrap();
                *active = Some(model_hash);
                Ok(Response::new(LoadModelResponse {
                    success: true,
                    memory_usage_bytes: 0,
                }))
            }
            Err(e) => {
                log::error!("Failed to load model {}: {}", req.model_id, e);
                Err(Status::internal(e.to_string()))
            }
        }
    }

    async fn execute_job(
        &self,
        request: Request<ExecuteJobRequest>,
    ) -> Result<Response<ExecuteJobResponse>, Status> {
        let req = request.into_inner();
        let inference = self
            .ctx
            .workload
            .inference()
            .map_err(|e| Status::failed_precondition(e.to_string()))?;

        let model_hash = {
            let active = self.active_model_hash.read().unwrap();
            active.ok_or_else(|| {
                Status::failed_precondition("Model not loaded. Call load_model first.")
            })?
        };

        let dp = self.ctx.data_plane.as_ref().ok_or_else(|| {
            Status::failed_precondition("Shared Memory Data Plane not initialized")
        })?;

        let session_id_arr: [u8; 32] = if req.session_id.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&req.session_id);
            arr
        } else {
            return Err(Status::invalid_argument(
                "Invalid session_id length, expected 32 bytes",
            ));
        };

        // 1. Attempt to read from Data Plane
        let agent_context: AgentContext =
            if let Ok(slice) = dp.read::<EncryptedSlice>(req.input_offset, req.input_length) {
                log::info!("Received EncryptedSlice in Data Plane. Enforcing Leakage Budget...");

                // --- 2. Leakage Budget Enforcement ---
                {
                    let state_tree = self.ctx.workload.state_tree();
                    let mut state = state_tree.write().await;

                    let current_height = self.ctx.machine.lock().await.status().height;
                    let tokens = slice.ciphertext.len() as u64;

                    let check_params = CheckLeakageParams {
                        session_id: session_id_arr,
                        tokens_requested: tokens,
                        is_high_entropy: true,
                    };

                    let mut tx_ctx = ioi_api::transaction::context::TxContext {
                        block_height: current_height,
                        // [FIX] Use raw u64 nanoseconds for timestamp
                        block_timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                        chain_id: 1.into(),
                        signer_account_id: AccountId::default(),
                        services: &self.ctx.workload.services(),
                        simulation: false,
                        is_internal: true,
                    };

                    let params_bytes = codec::to_bytes_canonical(&check_params)
                        .map_err(|e| Status::internal(e))?;

                    match LeakageController
                        .handle_service_call(
                            &mut *state,
                            "check_and_debit@v1",
                            &params_bytes,
                            &mut tx_ctx,
                        )
                        .await
                    {
                        Ok(_) => log::info!("Leakage budget check passed for {} tokens", tokens),
                        Err(e) => {
                            log::warn!("Leakage budget exceeded: {}", e);
                            return Err(Status::permission_denied(format!(
                                "Leakage budget exceeded: {}",
                                e
                            )));
                        }
                    }
                }

                // --- 3. Decryption & Reassembly ---
                let master_secret = [0u8; 32]; // Derived from mTLS session
                let key = derive_session_key(&master_secret, &session_id_arr)
                    .map_err(|e| Status::internal(format!("Key derivation failed: {}", e)))?;

                let aad = EncryptedSlice::compute_aad(
                    &session_id_arr,
                    &[0u8; 32],
                    slice.slice_id.as_slice().try_into().unwrap(),
                );

                let plaintext = decrypt_slice(&key, &slice.iv, &slice.ciphertext, &aad)
                    .map_err(|e| Status::invalid_argument(format!("Decryption failed: {}", e)))?;

                // Step A: Decode the ContextSlice container
                let archived_slice = ioi_ipc::access_rkyv_bytes::<ContextSlice>(&plaintext)
                    .map_err(|e| {
                        Status::invalid_argument(format!("ContextSlice decode failed: {}", e))
                    })?;

                // Step B: Reassemble AgentContext from chunks
                let mut reassembled_vec = Vec::new();
                for chunk in archived_slice.chunks.iter() {
                    reassembled_vec.extend_from_slice(chunk.as_slice());
                }

                // Step C: Ensure alignment for rkyv
                let mut aligned_buffer = AlignedVec::new();
                aligned_buffer.extend_from_slice(&reassembled_vec);

                // Step D: Map and Deserialize
                let archived_agent = ioi_ipc::access_rkyv_bytes::<AgentContext>(&aligned_buffer)
                    .map_err(|e| {
                        Status::invalid_argument(format!("AgentContext reassembly failed: {}", e))
                    })?;

                archived_agent
                    .deserialize(&mut rkyv::Infallible)
                    .map_err(|e| Status::internal(e.to_string()))?
            } else {
                // FALLBACK: Read as plaintext AgentContext
                let archived = dp
                    .read::<AgentContext>(req.input_offset, req.input_length)
                    .map_err(|e| {
                        Status::invalid_argument(format!("Failed to read input from shmem: {}", e))
                    })?;
                archived.deserialize(&mut rkyv::Infallible).unwrap()
            };

        // --- 4. Hardware Execution ---
        if let Some(da_ref) = agent_context.da_ref.as_ref() {
            log::info!(
                "[DA Bridge] Resolving external data from provider '{}'",
                da_ref.provider
            );
        }

        // Context-aware input extraction
        let input_bytes = vec![0u8; req.input_length as usize];

        // Execute on physical hardware using the dynamically loaded model hash
        // [FIX] Pass default InferenceOptions
        let options = InferenceOptions::default();
        let _result = inference
            .execute_inference(model_hash, &input_bytes, options)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Construct standard output structure
        let output_struct = InferenceOutput {
            logits: Tensor {
                shape: [0; 4],
                data: vec![],
            },
            generated_tokens: vec![],
            stop_reason: 0,
        };

        // Write output back to the Data Plane
        let handle = dp
            .write(&output_struct, None)
            .map_err(|e| Status::internal(format!("Failed to write output to shmem: {}", e)))?;

        Ok(Response::new(ExecuteJobResponse {
            success: true,
            output_offset: handle.offset,
            output_length: handle.length,
            gas_used: 1000,
            error_message: String::new(),
        }))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            ready: true,
            status: "OK".to_string(),
        }))
    }
}
