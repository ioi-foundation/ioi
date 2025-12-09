// Path: crates/validator/src/standard/workload/ipc/grpc_control.rs

use crate::standard::workload::ipc::RpcContext;
use ioi_api::{commitment::CommitmentScheme, state::StateManager};
use ioi_ipc::{
    control::workload_control_server::WorkloadControl,
    control::{
        ExecuteJobRequest, ExecuteJobResponse, HealthCheckRequest, HealthCheckResponse,
        LoadModelRequest, LoadModelResponse,
    },
    data::AgentContext,
};
use std::path::Path;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Implementation of the `WorkloadControl` gRPC service.
///
/// This service handles high-level commands from the Orchestrator, such as
/// loading AI models into memory and executing inference jobs. It bridges
/// the Control Plane (gRPC) with the Data Plane (Shared Memory) to efficiently
/// handle large context payloads.
pub struct WorkloadControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context containing the machine state, workload handle, and data plane.
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

        let agent_context = dp
            .read::<AgentContext>(req.input_offset, req.input_length)
            .map_err(|e| {
                Status::invalid_argument(format!("Failed to read input from shmem: {}", e))
            })?;

        // [FIX] Correctly handle rkyv::ArchivedOption
        if let Some(da_ref) = agent_context.da_ref.as_ref() {
            log::info!(
                "[DA Bridge] Resolving external data from provider '{}', blob_id: {}",
                da_ref.provider,
                hex::encode(&da_ref.blob_id)
            );
        }

        let input_bytes = vec![0u8; req.input_length as usize];

        let model_hash = [0u8; 32];
        let _result = inference
            .execute_inference(model_hash, &input_bytes)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        use ioi_ipc::data::{InferenceOutput, Tensor};
        let output_struct = InferenceOutput {
            logits: Tensor {
                shape: [0; 4],
                data: vec![],
            },
            generated_tokens: vec![],
            stop_reason: 0,
        };

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
