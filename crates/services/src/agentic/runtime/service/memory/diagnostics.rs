pub fn persist_prompt_memory_diagnostics(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    diagnostics: &MemoryPromptDiagnostics,
) -> Result<(), TransactionError> {
    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_PROMPT_DIAGNOSTICS_CHECKPOINT,
        diagnostics,
    )
}

fn update_retrieval_diagnostics(
    memory_runtime: &ioi_memory::MemoryRuntime,
    query_hash: &str,
    candidate_count: usize,
    returned_count: usize,
    hits: &[MemoryRetrievalHitDiagnostic],
) -> Result<(), TransactionError> {
    let thread_id = diagnostics_thread_id(None);
    let mut diagnostics = load_checkpoint_json::<MemoryRetrievalDiagnostics>(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.search_count += 1;
    diagnostics.total_candidates_seen += candidate_count as u64;
    diagnostics.total_candidates_returned += returned_count as u64;
    if returned_count > 0 {
        diagnostics.successful_search_count += 1;
    } else {
        diagnostics.empty_search_count += 1;
    }
    diagnostics.usefulness_bps = if diagnostics.search_count == 0 {
        0
    } else {
        ((diagnostics.successful_search_count.saturating_mul(10_000)) / diagnostics.search_count)
            .min(10_000) as u32
    };
    diagnostics.last_query_hash = query_hash.to_string();
    diagnostics.last_candidate_count = candidate_count;
    diagnostics.last_returned_count = returned_count;
    diagnostics.last_hits = hits.to_vec();
    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn update_enrichment_diagnostics_success(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: Option<[u8; 32]>,
    job_kind: &str,
    outcome: &EnrichmentJobOutcome,
) -> Result<(), TransactionError> {
    let checkpoint_thread_id = diagnostics_thread_id(thread_id);
    let mut diagnostics = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.completed_jobs += 1;
    diagnostics.inserted_records += outcome.inserted_records as u64;
    diagnostics.rejected_candidates += outcome.rejected_candidates as u64;
    *diagnostics
        .completed_by_kind
        .entry(job_kind.to_string())
        .or_insert(0) += 1;
    for (scope, count) in &outcome.inserted_scopes {
        *diagnostics
            .inserted_by_scope
            .entry(scope.clone())
            .or_insert(0) += *count as u64;
    }
    for (reason, count) in &outcome.rejected_by_reason {
        *diagnostics
            .rejected_by_reason
            .entry(reason.clone())
            .or_insert(0) += *count as u64;
    }
    diagnostics.last_job_kind = Some(job_kind.to_string());
    diagnostics.last_error = None;
    persist_checkpoint_json(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn update_enrichment_diagnostics_failure(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: Option<[u8; 32]>,
    job_kind: &str,
    error: &str,
) -> Result<(), TransactionError> {
    let checkpoint_thread_id = diagnostics_thread_id(thread_id);
    let mut diagnostics = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.failed_jobs += 1;
    *diagnostics
        .failed_by_kind
        .entry(job_kind.to_string())
        .or_insert(0) += 1;
    diagnostics.last_job_kind = Some(job_kind.to_string());
    diagnostics.last_error = Some(error.to_string());
    persist_checkpoint_json(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn derived_memory_rejection_reason(scope: &str, kind: &str, content: &str) -> Option<&'static str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Some("empty_content");
    }
    if content_looks_secret_like(trimmed) {
        return Some("secret_like_content");
    }
    if trimmed.chars().count() < 12 {
        return Some("too_short");
    }
    if trimmed.chars().count() > 1_200 {
        return Some("too_long");
    }
    if kind == "entity"
        && trimmed.chars().count() > 16
        && trimmed
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit() || *ch == '-' || *ch == '_')
            .count()
            == trimmed.chars().count()
    {
        return Some("opaque_identifier");
    }
    if scope == MEMORY_RUNTIME_FACT_SCOPE && !trimmed.contains(' ') {
        return Some("low_information_fact");
    }
    None
}

fn load_core_memory_sections_status(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<Vec<MemoryCoreSectionStatus>, TransactionError> {
    let pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    let mut sections = Vec::new();
    for schema in CORE_MEMORY_SCHEMAS {
        let Some(section) = memory_runtime
            .load_core_memory_section(thread_id, schema.section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        else {
            continue;
        };
        if section.content.trim().is_empty() {
            continue;
        }
        sections.push(MemoryCoreSectionStatus {
            section: schema.section.to_string(),
            label: schema.label.to_string(),
            content: section.content,
            updated_at_ms: section.updated_at_ms,
            prompt_eligible: schema.prompt_eligible,
            tool_writable: schema.tool_writable,
            append_allowed: schema.append_allowed,
            pinned: effective_core_memory_pin(&pin_state, schema),
        });
    }
    Ok(sections)
}

fn load_core_memory_audits(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    limit: usize,
) -> Result<Vec<MemoryCoreAuditEntry>, TransactionError> {
    let records = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
            thread_id: Some(thread_id),
            text: String::new(),
            limit,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let mut audits = records
        .into_iter()
        .map(|record| {
            let metadata =
                serde_json::from_str::<Value>(&record.metadata_json).unwrap_or_else(|_| json!({}));
            MemoryCoreAuditEntry {
                archival_record_id: record.id,
                created_at_ms: record.created_at_ms,
                section: metadata
                    .get("section")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                action: metadata
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                source: metadata
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                accepted: metadata
                    .get("accepted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                rejection_reason: metadata
                    .get("rejection_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                previous_hash: metadata
                    .get("previous_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                new_hash: metadata
                    .get("new_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }
        })
        .collect::<Vec<_>>();
    audits.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    Ok(audits)
}

pub fn load_memory_session_status(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<MemorySessionStatus, TransactionError> {
    Ok(MemorySessionStatus {
        session_id_hex: hex::encode(thread_id),
        core_sections: load_core_memory_sections_status(memory_runtime, thread_id)?,
        core_audits: load_core_memory_audits(memory_runtime, thread_id, 24)?,
        prompt_diagnostics: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_PROMPT_DIAGNOSTICS_CHECKPOINT,
        )?,
        retrieval_diagnostics: load_checkpoint_json(
            memory_runtime,
            diagnostics_thread_id(None),
            MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
        )?,
        enrichment_diagnostics: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        )?,
        evaluation: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_EVALUATION_CHECKPOINT,
        )?,
    })
}

pub fn record_memory_session_evaluation(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    transcript_message_count: usize,
    compacted_message_count: usize,
    summary: &str,
) -> Result<MemorySessionEvaluation, TransactionError> {
    let core_sections = load_core_memory_sections_status(memory_runtime, thread_id)?;
    let enrichment = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    let ui_snapshots = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(thread_id),
            text: String::new(),
            limit: 256,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .into_iter()
        .filter(|record| record.kind == "ui_observation" || record.kind == "ui_summary")
        .count() as u64;

    let mut score_bps = 0u32;
    if !summary.trim().is_empty() {
        score_bps += 2_000;
    }
    if compacted_message_count >= 8 {
        score_bps += 1_500;
    }
    if !core_sections.is_empty() {
        score_bps += 2_000;
    }
    if ui_snapshots > 0 {
        score_bps += 1_500;
    }
    if enrichment.completed_jobs > 0 {
        score_bps += 2_000;
    }
    if enrichment.failed_jobs == 0 {
        score_bps += 1_000;
    }
    score_bps = score_bps.min(10_000);
    let assessment = if score_bps >= 8_500 {
        "strong".to_string()
    } else if score_bps >= 6_000 {
        "healthy".to_string()
    } else {
        "needs_attention".to_string()
    };

    let evaluation = MemorySessionEvaluation {
        updated_at_ms: unix_timestamp_ms_now(),
        session_id_hex: hex::encode(thread_id),
        transcript_message_count: transcript_message_count as u64,
        compacted_message_count: compacted_message_count as u64,
        summary_chars: summary.chars().count(),
        active_core_sections: core_sections.len(),
        ui_snapshot_count: ui_snapshots,
        enrichment_completed_jobs: enrichment.completed_jobs,
        enrichment_failed_jobs: enrichment.failed_jobs,
        score_bps,
        assessment: assessment.clone(),
    };

    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_EVALUATION_CHECKPOINT,
        &evaluation,
    )?;

    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_controlled",
        "session_id": hex::encode(thread_id),
        "score_bps": score_bps,
        "assessment": assessment,
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let content = format!(
        "session={} score_bps={} assessment={} transcript_messages={} compacted_messages={} core_sections={} ui_snapshots={} enrichment_completed={} enrichment_failed={}",
        hex::encode(thread_id),
        evaluation.score_bps,
        evaluation.assessment,
        evaluation.transcript_message_count,
        evaluation.compacted_message_count,
        evaluation.active_core_sections,
        evaluation.ui_snapshot_count,
        evaluation.enrichment_completed_jobs,
        evaluation.enrichment_failed_jobs
    );
    memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_EVALUATION_SCOPE.to_string(),
            thread_id: Some(thread_id),
            kind: "session_memory_health".to_string(),
            content,
            metadata_json,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    Ok(evaluation)
}

