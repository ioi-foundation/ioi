pub async fn append_chat_to_scs(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    msg: &ChatMessage,
    _block_height: u64,
) -> Result<[u8; 32], TransactionError> {
    let recorded_message = build_recorded_message(&service.scrubber, msg).await;
    let payload =
        codec::to_bytes_canonical(&recorded_message).map_err(TransactionError::Serialization)?;
    let payload_checksum =
        digest32(&payload).map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .ok_or(TransactionError::Invalid(
            "Internal: transcript memory runtime not available".into(),
        ))?;

    memory_runtime
        .append_transcript_message(
            session_id,
            &stored_transcript_message_from_recorded(&recorded_message),
        )
        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

    // 2. Semantic Indexing
    // Keep indexing best-effort and bounded so action completion never waits on
    // long-running inference calls.
    let semantic_index_started_at = Instant::now();
    let semantic_budget_remaining =
        || SEMANTIC_INDEXING_BUDGET.saturating_sub(semantic_index_started_at.elapsed());

    let should_archive_message = should_embed_for_semantic_indexing(
        &recorded_message.role,
        &recorded_message.scrubbed_for_scs,
    );
    let semantic_vector = {
        let remaining = semantic_budget_remaining();
        if should_archive_message && !remaining.is_zero() {
            match timeout(
                remaining,
                service
                    .reasoning_inference
                    .embed_text(&recorded_message.scrubbed_for_scs),
            )
            .await
            {
                Ok(Ok(vec)) => Some(vec),
                Ok(Err(e)) => {
                    log::warn!("Transcript semantic embedding failed: {}", e);
                    None
                }
                Err(_) => {
                    log::warn!(
                        "Transcript semantic embedding timed out for session {} after {:?}.",
                        hex::encode(&session_id[..4]),
                        SEMANTIC_INDEXING_BUDGET
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    if should_archive_message {
        let metadata_json = serde_json::to_string(&json!({
            "session_id": hex::encode(session_id),
            "role": recorded_message.role,
            "timestamp_ms": recorded_message.timestamp_ms,
            "trace_hash": recorded_message.trace_hash.map(hex::encode),
            "trust_level": "runtime_observed",
        }))
        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

        match memory_runtime.insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "chat_message".to_string(),
            content: recorded_message.scrubbed_for_scs.clone(),
            metadata_json,
        }) {
            Ok(Some(record_id)) => {
                if let Some(vector) = semantic_vector.as_ref() {
                    if let Err(error) = memory_runtime.upsert_archival_embedding(record_id, vector)
                    {
                        log::warn!(
                            "Memory runtime transcript embedding write failed for record {}: {}",
                            record_id,
                            error
                        );
                    }
                }
                if enqueue_transcript_enrichment_jobs(memory_runtime, session_id, record_id) {
                    spawn_memory_enrichment_tick(service, "transcript_append");
                }
            }
            Ok(None) => {}
            Err(error) => {
                log::warn!(
                    "Memory runtime transcript archival insert failed: {}",
                    error
                );
            }
        }
    }

    Ok(payload_checksum)
}

pub fn hydrate_session_history(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    hydrate_session_history_surface(service, session_id, false)
}

pub fn hydrate_session_history_raw(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    hydrate_session_history_surface(service, session_id, true)
}

fn hydrate_session_history_surface(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    raw: bool,
) -> Result<Vec<ChatMessage>, TransactionError> {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .ok_or(TransactionError::Invalid(
            "Internal: transcript memory runtime not available".into(),
        ))?;
    let messages = memory_runtime
        .load_transcript_messages(session_id)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let surface = if raw {
        TranscriptSurface::Raw
    } else {
        TranscriptSurface::Model
    };
    Ok(messages
        .iter()
        .map(|message| chat_message_from_transcript(message, surface))
        .collect())
}

#[cfg(test)]
fn decode_session_message(payload: &[u8], raw: bool) -> Option<ChatMessage> {
    if let Ok(message) = codec::from_bytes_canonical::<RecordedMessage>(&payload) {
        let content = if raw {
            if message.raw_content.is_empty() {
                message.scrubbed_for_model.clone()
            } else {
                message.raw_content
            }
        } else if message.scrubbed_for_model.is_empty() {
            message.scrubbed_for_scs
        } else {
            message.scrubbed_for_model
        };

        Some(ChatMessage {
            role: message.role,
            content,
            timestamp: message.timestamp_ms,
            trace_hash: message.trace_hash,
        })
    } else {
        None
    }
}

fn stored_transcript_message_from_recorded(message: &RecordedMessage) -> StoredTranscriptMessage {
    StoredTranscriptMessage {
        role: message.role.clone(),
        timestamp_ms: message.timestamp_ms,
        trace_hash: message.trace_hash,
        raw_content: message.raw_content.clone(),
        model_content: if message.scrubbed_for_model.is_empty() {
            message.scrubbed_for_scs.clone()
        } else {
            message.scrubbed_for_model.clone()
        },
        store_content: message.scrubbed_for_scs.clone(),
        raw_reference: message.raw_reference.clone(),
        privacy_metadata: TranscriptPrivacyMetadata {
            redaction_version: message.privacy_metadata.redaction_version.clone(),
            sensitive_fields_mask: message.privacy_metadata.sensitive_fields_mask.clone(),
            policy_id: message.privacy_metadata.policy_id.clone(),
            policy_version: message.privacy_metadata.policy_version.clone(),
            scrubbed_for_model_hash: message.privacy_metadata.scrubbed_for_model_hash.clone(),
        },
    }
}

fn chat_message_from_transcript(
    message: &StoredTranscriptMessage,
    surface: TranscriptSurface,
) -> ChatMessage {
    let content = match surface {
        TranscriptSurface::Model => {
            if message.model_content.is_empty() {
                message.store_content.clone()
            } else {
                message.model_content.clone()
            }
        }
        TranscriptSurface::Raw => {
            if message.raw_content.is_empty() {
                if message.model_content.is_empty() {
                    message.store_content.clone()
                } else {
                    message.model_content.clone()
                }
            } else {
                message.raw_content.clone()
            }
        }
        TranscriptSurface::Store => message.store_content.clone(),
    };

    ChatMessage {
        role: message.role.clone(),
        content,
        timestamp: message.timestamp_ms,
        trace_hash: message.trace_hash,
    }
}

fn digest32(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let digest = sha256(bytes)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn redact_fields_from_map(redaction_map: &RedactionMap) -> Vec<String> {
    let mut fields: Vec<String> = redaction_map
        .entries
        .iter()
        .map(|entry| match &entry.redaction_type {
            RedactionType::Pii => "pii".to_string(),
            RedactionType::Secret => "secret".to_string(),
            RedactionType::Custom(custom) => format!("custom:{custom}"),
        })
        .collect();

    let unique: HashSet<String> = fields.drain(..).collect();
    let mut normalized: Vec<String> = unique.into_iter().collect();
    normalized.sort_unstable();
    normalized
}

async fn scrub_message_text_for_ingest(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> (String, Vec<String>) {
    match scrubber.scrub(input).await {
        Ok((scrubbed, redaction_map)) => (scrubbed, redact_fields_from_map(&redaction_map)),
        Err(_) => (
            MESSAGE_SANITIZED_PLACEHOLDER.to_string(),
            vec!["scrubber_failure".to_string()],
        ),
    }
}

async fn build_recorded_message(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    msg: &ChatMessage,
) -> RecordedMessage {
    let (scrubbed_for_model, sensitive_fields_mask) =
        scrub_message_text_for_ingest(scrubber, &msg.content).await;
    let scrubbed_for_model_hash = sha256(scrubbed_for_model.as_bytes())
        .ok()
        .map(|digest| hex::encode(digest));
    RecordedMessage {
        role: msg.role.clone(),
        timestamp_ms: msg.timestamp,
        trace_hash: msg.trace_hash,
        raw_content: msg.content.clone(),
        scrubbed_for_model: scrubbed_for_model.clone(),
        scrubbed_for_scs: scrubbed_for_model,
        raw_reference: None,
        privacy_metadata: MessagePrivacyMetadata {
            redaction_version: DEFAULT_MESSAGE_REDACTION_VERSION.to_string(),
            sensitive_fields_mask,
            policy_id: DEFAULT_MESSAGE_PRIVACY_POLICY_ID.to_string(),
            policy_version: DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION.to_string(),
            scrubbed_for_model_hash,
        },
    }
}

#[cfg(test)]
#[path = "transcript/tests.rs"]
mod tests;
