// Path: crates/validator/src/standard/workload/ipc/grpc_control.rs

use crate::standard::workload::ipc::RpcContext;
use ioi_api::chain::ChainStateMachine; // [FIX] Required for .status()
use ioi_api::services::BlockchainService;
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_ipc::data::EncryptedSlice;
use ioi_ipc::security::{decrypt_slice, derive_session_key};
use ioi_ipc::{
    control::workload_control_server::WorkloadControl,
    control::{
        ExecuteJobRequest, ExecuteJobResponse, HealthCheckRequest, HealthCheckResponse,
        LoadModelRequest, LoadModelResponse,
    },
    data::AgentContext,
};
use ioi_services::agentic::leakage::{CheckLeakageParams, LeakageController};
use ioi_types::app::AccountId;
use ioi_types::codec;
use rkyv::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Implementation of the `WorkloadControl` gRPC service.
///
/// This service handles high-frequency commands from the Orchestrator.
/// It coordinates model loading, hardware acceleration, and data privacy (slicing).
pub struct WorkloadControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context containing handles to the machine, workload, and data plane.
    pub ctx: Arc<RpcContext<CS, ST>>,
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

        let model_path = Path::new(&req.model_id);

        let model_hash = if req.model_id.len() == 64 {
            hex::decode(&req.model_id)
                .unwrap_or(vec![0u8; 32])
                .try_into()
                .unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };

        match inference.load_model(model_hash, model_path).await {
            Ok(_) => {
                log::info!("Successfully loaded model: {}", req.model_id);
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

        let dp = self.ctx.data_plane.as_ref().ok_or_else(|| {
            Status::failed_precondition("Shared Memory Data Plane not initialized")
        })?;

        // Extract session_id from request
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
        // We first try to read as an EncryptedSlice (Privacy-enabled flow).
        // If that fails, we fall back to a plaintext AgentContext (Legacy/Direct mode).
        let agent_context: AgentContext =
            if let Ok(slice) = dp.read::<EncryptedSlice>(req.input_offset, req.input_length) {
                log::info!("Received EncryptedSlice in Data Plane. Enforcing Leakage Budget...");

                let mut slice_id_arr = [0u8; 32];
                slice_id_arr.copy_from_slice(slice.slice_id.as_slice());

                // --- 2. Leakage Budget Enforcement (Control Plane Proxy) ---
                {
                    // Access on-chain state to verify the session's budget
                    let state_tree = self.ctx.workload.state_tree();
                    let mut state = state_tree.write().await;

                    let controller = LeakageController;
                    let current_height = self.ctx.machine.lock().await.status().height;

                    // Token cost calculation (heuristic based on ciphertext size)
                    let tokens = slice.ciphertext.len() as u64;

                    let check_params = CheckLeakageParams {
                        session_id: session_id_arr, // Use session_id from request
                        tokens_requested: tokens,
                        is_high_entropy: true,
                    };

                    let mut tx_ctx = ioi_api::transaction::context::TxContext {
                        block_height: current_height,
                        block_timestamp: ibc_primitives::Timestamp::now(),
                        chain_id: 1.into(),
                        signer_account_id: AccountId::default(),
                        services: &self.ctx.workload.services(),
                        simulation: false,
                        is_internal: true,
                    };

                    let params_bytes = codec::to_bytes_canonical(&check_params)
                        .map_err(|e| Status::internal(e))?;

                    // Invoke the Leakage Controller service logic
                    match controller
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

                // --- 3. Decryption (Privacy Airlock) ---
                // Mock Session Key: Derived from the shared mTLS master secret.
                let master_secret = [0u8; 32];

                // FIX: Use session_id_arr for key derivation instead of slice_id_arr
                let key = derive_session_key(&master_secret, &session_id_arr)
                    .map_err(|e| Status::internal(format!("Key derivation failed: {}", e)))?;

                // Reconstruct AAD: SessionID || PolicyHash || SliceID
                // FIX: Use session_id_arr for AAD construction
                let aad = EncryptedSlice::compute_aad(&session_id_arr, &[0u8; 32], &slice_id_arr);

                let plaintext = decrypt_slice(&key, &slice.iv, &slice.ciphertext, &aad)
                    .map_err(|e| Status::invalid_argument(format!("Decryption failed: {}", e)))?;

                // Deserialize the decrypted plaintext into an AgentContext
                rkyv::from_bytes::<AgentContext>(&plaintext).map_err(|e| {
                    Status::invalid_argument(format!("Inner deserialization failed: {}", e))
                })?
            } else {
                // FALLBACK: Read as plaintext AgentContext
                let archived = dp
                    .read::<AgentContext>(req.input_offset, req.input_length)
                    .map_err(|e| {
                        Status::invalid_argument(format!("Failed to read input from shmem: {}", e))
                    })?;
                archived.deserialize(&mut rkyv::Infallible).unwrap()
            };

        // --- 4. Hardware Execution (Cognitive Plane) ---
        if let Some(da_ref) = agent_context.da_ref.as_ref() {
            log::info!(
                "[DA Bridge] Resolving external data from provider '{}', blob_id: {}",
                da_ref.provider,
                hex::encode(&da_ref.blob_id)
            );
        }

        let input_bytes = vec![0u8; req.input_length as usize];

        // The model hash identifying the cognitive task
        let model_hash = [0u8; 32];

        // Execute on physical hardware (GPU via Driver, or CPU Fallback)
        let _result = inference
            .execute_inference(model_hash, &input_bytes)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Construct standard output structure
        use ioi_ipc::data::{InferenceOutput, Tensor};
        let output_struct = InferenceOutput {
            logits: Tensor {
                shape: [0; 4],
                data: vec![],
            },
            generated_tokens: vec![],
            stop_reason: 0,
        };

        // Write output back to the Data Plane for Orchestrator to collect
        let handle = dp
            .write(&output_struct, None)
            .map_err(|e| Status::internal(format!("Failed to write output to shmem: {}", e)))?;

        Ok(Response::new(ExecuteJobResponse {
            success: true,
            output_offset: handle.offset,
            output_length: handle.length,
            gas_used: 1000, // Placeholder
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
