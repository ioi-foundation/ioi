use super::*;
use ioi_ipc::public::SessionHistoryMessage;

fn transcript_surface_content(message: &ioi_memory::StoredTranscriptMessage) -> String {
    if !message.model_content.trim().is_empty() {
        message.model_content.clone()
    } else if !message.store_content.trim().is_empty() {
        message.store_content.clone()
    } else {
        message.raw_content.clone()
    }
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
    pub(super) async fn handle_get_session_history(
        &self,
        request: Request<GetSessionHistoryRequest>,
    ) -> Result<Response<GetSessionHistoryResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id_hex(&req.session_id_hex)?;
        let ctx_arc = self.get_context().await?;
        let memory_runtime = {
            let ctx = ctx_arc.lock().await;
            ctx.memory_runtime.clone()
        };

        let Some(memory_runtime) = memory_runtime else {
            return Ok(Response::new(GetSessionHistoryResponse {
                messages: vec![],
            }));
        };

        let mut messages = memory_runtime
            .load_transcript_messages(session_id)
            .map_err(|error| Status::internal(error.to_string()))?
            .into_iter()
            .map(|message| {
                let content = transcript_surface_content(&message);
                SessionHistoryMessage {
                    role: message.role,
                    content,
                    timestamp: message.timestamp_ms,
                }
            })
            .collect::<Vec<_>>();

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

#[cfg(test)]
mod tests {
    use super::transcript_surface_content;

    #[test]
    fn transcript_surface_prefers_model_content() {
        let message = ioi_memory::StoredTranscriptMessage {
            model_content: "model".to_string(),
            store_content: "store".to_string(),
            raw_content: "raw".to_string(),
            ..Default::default()
        };

        assert_eq!(transcript_surface_content(&message), "model");
    }
}
