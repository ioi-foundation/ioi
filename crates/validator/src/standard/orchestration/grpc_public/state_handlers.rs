use super::*;
use std::time::Instant;

fn push_candidate_once(candidates: &mut Vec<String>, candidate: String) {
    if !candidate.is_empty() && !candidates.iter().any(|existing| existing == &candidate) {
        candidates.push(candidate);
    }
}

fn context_blob_artifact_candidates(blob_ref: &str) -> Vec<String> {
    let trimmed = blob_ref.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    push_candidate_once(&mut candidates, trimmed.to_string());

    let lowered = trimmed.to_ascii_lowercase();
    if lowered != trimmed {
        push_candidate_once(&mut candidates, lowered.clone());
    }

    for prefix in ["ioi-memory://artifact/", "memory://artifact/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            push_candidate_once(&mut candidates, rest.to_string());
            let rest_lowered = rest.to_ascii_lowercase();
            if rest_lowered != rest {
                push_candidate_once(&mut candidates, rest_lowered);
            }
        }
    }

    let normalized_hash = trimmed
        .strip_prefix("sha256:")
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    let looks_like_hex_hash =
        normalized_hash.len() == 64 && normalized_hash.bytes().all(|byte| byte.is_ascii_hexdigit());

    if looks_like_hex_hash {
        push_candidate_once(
            &mut candidates,
            format!("desktop.visual_observation.{normalized_hash}"),
        );
        push_candidate_once(
            &mut candidates,
            format!("desktop.context_slice.{normalized_hash}"),
        );
    }

    candidates
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

        let block = self
            .workload_client
            .get_block_by_height(req.height)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
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

        let memory_runtime = {
            let ctx = ctx_arc.lock().await;
            ctx.memory_runtime.clone()
        };

        let memory_runtime = memory_runtime
            .ok_or_else(|| Status::unimplemented("memory runtime not available on this node"))?;

        for artifact_id in context_blob_artifact_candidates(&req.blob_hash) {
            let payload = memory_runtime
                .load_artifact_blob(&artifact_id)
                .map_err(|error| Status::internal(error.to_string()))?;
            if let Some(payload) = payload {
                return Ok(Response::new(GetContextBlobResponse {
                    data: payload,
                    mime_type: "application/octet-stream".to_string(),
                }));
            }
        }

        Err(Status::not_found("Blob not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::context_blob_artifact_candidates;

    #[test]
    fn context_blob_candidates_expand_visual_hashes_into_memory_artifacts() {
        let candidates = context_blob_artifact_candidates(
            "sha256:ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
        );
        assert!(candidates.contains(
            &"desktop.visual_observation.abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                .to_string()
        ));
    }
}
