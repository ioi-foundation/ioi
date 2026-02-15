use super::*;
use std::time::Instant;

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
    pub(super) async fn handle_query_state(
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

        let response_bytes = codec::to_bytes_canonical(&response).map_err(Status::internal)?;

        metrics().observe_request_duration("query_state", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("query_state", 200);

        Ok(Response::new(QueryStateAtResponse { response_bytes }))
    }

    pub(super) async fn handle_query_raw_state(
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

    pub(super) async fn handle_get_status(
        &self,
        _request: Request<GetStatusRequest>,
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

    pub(super) async fn handle_get_block_by_height(
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
        let block_bytes = if let Some(block) = block {
            codec::to_bytes_canonical(&block).map_err(Status::internal)?
        } else {
            vec![]
        };

        metrics().observe_request_duration("get_block_by_height", start.elapsed().as_secs_f64());
        metrics().inc_requests_total("get_block_by_height", 200);

        Ok(Response::new(GetBlockByHeightResponse { block_bytes }))
    }

    pub(super) async fn handle_get_context_blob(
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
