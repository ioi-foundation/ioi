use super::*;
use ioi_ipc::public::SessionHistoryMessage;

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
    pub(super) async fn handle_get_session_history(
        &self,
        request: Request<GetSessionHistoryRequest>,
    ) -> Result<Response<GetSessionHistoryResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id_hex(&req.session_id_hex)?;
        let ctx_arc = self.get_context().await?;
        let scs_arc = {
            let ctx = ctx_arc.lock().await;
            ctx.scs.clone()
        };

        let Some(scs_arc) = scs_arc else {
            return Ok(Response::new(GetSessionHistoryResponse {
                messages: vec![],
            }));
        };

        let scs = scs_arc
            .lock()
            .map_err(|_| Status::internal("SCS lock poisoned"))?;

        let mut messages = Vec::<SessionHistoryMessage>::new();
        if let Some(frame_ids) = scs.session_index.get(&session_id) {
            for &frame_id in frame_ids {
                let Some(frame) = scs.toc.frames.get(frame_id as usize) else {
                    continue;
                };
                if frame.frame_type != FrameType::Thought {
                    continue;
                }
                let payload = match scs.read_frame_payload(frame_id) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                let decoded = match codec::from_bytes_canonical::<
                    ioi_types::app::agentic::ChatMessage,
                >(&payload)
                {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };
                messages.push(SessionHistoryMessage {
                    role: decoded.role,
                    content: decoded.content,
                    timestamp: decoded.timestamp,
                });
            }
        }

        messages.sort_by_key(|msg| msg.timestamp);
        if !req.ascending {
            messages.reverse();
        }
        if req.limit > 0 && messages.len() > req.limit as usize {
            messages.truncate(req.limit as usize);
        }

        Ok(Response::new(GetSessionHistoryResponse { messages }))
    }

    pub(super) async fn handle_set_runtime_secret(
        &self,
        request: Request<SetRuntimeSecretRequest>,
    ) -> Result<Response<SetRuntimeSecretResponse>, Status> {
        let req = request.into_inner();
        if !req.secret_kind.eq_ignore_ascii_case("sudo_password") {
            return Err(Status::invalid_argument("Unsupported secret_kind"));
        }
        if req.secret_value.is_empty() {
            return Err(Status::invalid_argument("secret_value must be non-empty"));
        }

        let session_id = parse_session_id_hex(&req.session_id_hex)?;
        let ttl_seconds = if req.ttl_seconds == 0 {
            120u64
        } else {
            req.ttl_seconds.min(900) as u64
        };

        runtime_secret::set_secret(
            &hex::encode(session_id),
            "sudo_password",
            req.secret_value,
            req.one_time,
            ttl_seconds,
        )
        .map_err(Status::invalid_argument)?;

        Ok(Response::new(SetRuntimeSecretResponse { accepted: true }))
    }
}
