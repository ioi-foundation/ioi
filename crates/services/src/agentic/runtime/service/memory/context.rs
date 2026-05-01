fn summarize_ui_snapshot_for_memory(
    active_window_title: &str,
    active_url: Option<&str>,
    snapshot_hash: &str,
    snapshot_xml: &str,
) -> String {
    let structural_lines = snapshot_xml
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && (line.contains("button")
                    || line.contains("textbox")
                    || line.contains("link")
                    || line.contains("dialog")
                    || line.contains("modal")
                    || line.contains("menu")
                    || line.contains("heading")
                    || line.contains("tab")
                    || line.contains("checkbox")
                    || line.contains("combobox")
                    || line.contains("role=")
                    || line.contains("tag_name="))
        })
        .take(24)
        .collect::<Vec<_>>();
    let mut summary = format!(
        "Window: {}\nURL: {}\nSnapshot Hash: {}\nObserved Structure:\n",
        active_window_title,
        active_url.unwrap_or("unavailable"),
        snapshot_hash
    );
    if structural_lines.is_empty() {
        summary.push_str(
            snapshot_xml
                .lines()
                .take(12)
                .collect::<Vec<_>>()
                .join("\n")
                .as_str(),
        );
    } else {
        summary.push_str(&structural_lines.join("\n"));
    }
    summary
}

fn assistant_message_is_structured_tool_call(text: &str) -> bool {
    fn is_tool_call_payload(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                matches!(map.get("name"), Some(Value::String(_)))
                    && matches!(map.get("arguments"), Some(Value::Object(_)))
                    && map
                        .keys()
                        .all(|key| matches!(key.as_str(), "name" | "arguments"))
            }
            _ => false,
        }
    }

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Array(items)) => !items.is_empty() && items.iter().all(is_tool_call_payload),
        Ok(value) => is_tool_call_payload(&value),
        Err(_) => false,
    }
}

fn should_embed_for_semantic_indexing(role: &str, scrubbed_text: &str) -> bool {
    if role.eq_ignore_ascii_case("user") {
        return true;
    }

    role.eq_ignore_ascii_case("assistant")
        && !assistant_message_is_structured_tool_call(scrubbed_text)
}

#[derive(Debug, Clone)]
pub struct HybridRetrievalResult {
    pub output: String,
    pub receipt: Option<WorkloadMemoryRetrieveReceipt>,
}

pub(crate) fn archival_memory_inspect_id(record_id: i64) -> Option<u64> {
    u64::try_from(record_id)
        .ok()
        .and_then(|id| MEMORY_RUNTIME_INSPECT_ID_OFFSET.checked_add(id))
}

pub(crate) fn archival_record_id_from_inspect_id(inspect_id: u64) -> Option<i64> {
    inspect_id
        .checked_sub(MEMORY_RUNTIME_INSPECT_ID_OFFSET)
        .and_then(|value| i64::try_from(value).ok())
}

/// Retrieve a work graph manifest from the legacy market registry state.
pub async fn fetch_work_graph_manifest(
    state: &dyn StateAccess,
    hash: [u8; 32],
) -> Option<WorkGraphManifest> {
    let key = [MARKET_ASSET_REGISTRY_PREFIX, &hash].concat();
    let bytes = state.get(&key).ok()??;
    match codec::from_bytes_canonical::<ioi_types::app::agentic::IntelligenceAsset>(&bytes).ok()? {
        ioi_types::app::agentic::IntelligenceAsset::Swarm(manifest) => Some(manifest),
        _ => None,
    }
}

fn enqueue_enrichment_job_best_effort(
    memory_runtime: &ioi_memory::MemoryRuntime,
    job: &NewEnrichmentJob,
) -> bool {
    match memory_runtime.enqueue_enrichment_job(job) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => {
            log::warn!("Failed to enqueue enrichment job {}: {}", job.kind, error);
            false
        }
    }
}

fn enqueue_transcript_enrichment_jobs(
    memory_runtime: &ioi_memory::MemoryRuntime,
    session_id: [u8; 32],
    source_record_id: i64,
) -> bool {
    let payload = serde_json::to_string(&TranscriptEnrichmentPayload {
        source_record_id,
        session_id_hex: Some(hex::encode(session_id)),
    })
    .unwrap_or_else(|_| "{}".to_string());
    let jobs = [
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.fact_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!("transcript.fact_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.entity_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!("transcript.entity_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.procedure_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!(
                "transcript.procedure_extraction:{source_record_id}"
            )),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "archival.embedding".to_string(),
            payload_json: serde_json::to_string(&ArchivalEmbeddingPayload { source_record_id })
                .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("archival.embedding:{source_record_id}")),
        },
    ];
    jobs.iter()
        .any(|job| enqueue_enrichment_job_best_effort(memory_runtime, job))
}

fn enqueue_ui_enrichment_jobs(
    memory_runtime: &ioi_memory::MemoryRuntime,
    session_id: [u8; 32],
    source_record_id: i64,
    artifact_id: &str,
) -> bool {
    let payload = serde_json::to_string(&UiObservationEnrichmentPayload {
        source_record_id,
        artifact_id: artifact_id.to_string(),
    })
    .unwrap_or_else(|_| "{}".to_string());
    let jobs = [
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "ui.observation.summary".to_string(),
            payload_json: payload,
            dedupe_key: Some(format!("ui.observation.summary:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "ui.relationship_extraction".to_string(),
            payload_json: serde_json::to_string(&UiObservationEnrichmentPayload {
                source_record_id,
                artifact_id: artifact_id.to_string(),
            })
            .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("ui.relationship_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "archival.embedding".to_string(),
            payload_json: serde_json::to_string(&ArchivalEmbeddingPayload { source_record_id })
                .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("archival.embedding:{source_record_id}")),
        },
    ];
    jobs.iter()
        .any(|job| enqueue_enrichment_job_best_effort(memory_runtime, job))
}

fn spawn_memory_enrichment_tick(service: &RuntimeAgentService, reason: &'static str) {
    let Some(memory_runtime) = service.memory_runtime.clone() else {
        return;
    };
    let inference = service.reasoning_inference.clone();
    tokio::spawn(async move {
        match process_pending_memory_enrichment_jobs_once(memory_runtime, inference, 6).await {
            Ok(report) => {
                if report.claimed > 0 {
                    log::info!(
                        "Memory enrichment tick ({}) claimed={} completed={} failed={} inserted={} rejected={}",
                        reason,
                        report.claimed,
                        report.completed,
                        report.failed,
                        report.inserted_records,
                        report.rejected_candidates,
                    );
                }
            }
            Err(error) => {
                log::warn!("Memory enrichment tick ({}) failed: {}", reason, error);
            }
        }
    });
}

pub fn kick_memory_enrichment(service: &RuntimeAgentService, reason: &'static str) {
    spawn_memory_enrichment_tick(service, reason);
}

async fn sync_system_core_memory(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
    perception: &PerceptionContext,
) -> Result<(), TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(());
    };

    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "goal.current",
        &agent_state.goal,
        "runtime_sync",
    )?;
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "environment.window.active",
        &perception.active_window_title,
        "runtime_sync",
    )?;

    let resolved_intent = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            format!(
                "{} (scope={:?}, band={:?}, score={:.3})",
                resolved.intent_id, resolved.scope, resolved.band, resolved.score
            )
        })
        .unwrap_or_default();
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "intent.resolved",
        &resolved_intent,
        "runtime_sync",
    )?;

    let failure_context = if perception.consecutive_failures > 0 {
        let reason = perception
            .last_failure_reason
            .clone()
            .unwrap_or_else(|| "UnknownFailure".to_string());
        format!(
            "consecutive_failures={} last_failure_reason={}",
            perception.consecutive_failures, reason
        )
    } else {
        String::new()
    };
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "execution.last_failure",
        &failure_context,
        "runtime_sync",
    )?;

    let active_url = service.browser.known_active_url().await.unwrap_or_default();
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "environment.browser.url",
        &active_url,
        "runtime_sync",
    )?;
    Ok(())
}

async fn persist_structured_ui_memory(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    active_window_title: &str,
    current_browser_snapshot: Option<&str>,
) -> Result<bool, TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(false);
    };
    let Some(snapshot_xml) = current_browser_snapshot
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };

    let snapshot_hash = digest_hex(snapshot_xml);
    let prior_checkpoint = memory_runtime
        .load_checkpoint_blob(session_id, MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .and_then(|blob| serde_json::from_slice::<UiSnapshotCheckpoint>(&blob).ok());
    if prior_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.snapshot_hash == snapshot_hash)
        .unwrap_or(false)
    {
        return Ok(false);
    }

    let active_url = service.browser.known_active_url().await;
    let artifact_id = format!(
        "desktop.ui.snapshot.{}.{}",
        hex::encode(&session_id[..4]),
        snapshot_hash.chars().take(16).collect::<String>()
    );
    let artifact_metadata = serde_json::to_string(&json!({
        "kind": "ui_snapshot_xml",
        "snapshot_hash": snapshot_hash,
        "active_window_title": active_window_title,
        "active_url": active_url,
        "trust_level": "runtime_observed",
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_artifact_json(session_id, &artifact_id, &artifact_metadata)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    memory_runtime
        .put_artifact_blob(session_id, &artifact_id, snapshot_xml.as_bytes())
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    let content = summarize_ui_snapshot_for_memory(
        active_window_title,
        active_url.as_deref(),
        &snapshot_hash,
        snapshot_xml,
    );
    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_observed",
        "snapshot_hash": snapshot_hash,
        "artifact_id": artifact_id,
        "active_window_title": active_window_title,
        "active_url": active_url,
        "source": "prompt_observation",
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "ui_observation".to_string(),
            content,
            metadata_json,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    let checkpoint = UiSnapshotCheckpoint {
        snapshot_hash,
        artifact_id: artifact_id.clone(),
        archival_record_id: record_id,
        active_url,
    };
    let payload = serde_json::to_vec(&checkpoint)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(
            session_id,
            MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT,
            &payload,
        )
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    if let Some(record_id) = record_id {
        let _ = enqueue_ui_enrichment_jobs(memory_runtime, session_id, record_id, &artifact_id);
        spawn_memory_enrichment_tick(service, "ui_memory");
    }

    Ok(true)
}

pub async fn prepare_prompt_memory_context(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
    perception: &PerceptionContext,
    current_browser_snapshot: Option<&str>,
) -> Result<String, TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(String::new());
    };
    sync_system_core_memory(service, session_id, agent_state, perception).await?;
    let _ = persist_structured_ui_memory(
        service,
        session_id,
        &perception.active_window_title,
        current_browser_snapshot,
    )
    .await?;
    format_prompt_eligible_core_memory(memory_runtime, session_id)
}
