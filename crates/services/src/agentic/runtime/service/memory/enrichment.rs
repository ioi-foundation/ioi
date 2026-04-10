fn extract_fact_candidates(text: &str) -> Vec<String> {
    let keywords = [
        " is ",
        " are ",
        " should ",
        " must ",
        " use ",
        " click ",
        " login ",
        " dashboard",
        " checkout",
        " url",
        " route",
        " modal",
        " page",
    ];
    let mut seen = HashSet::new();
    text.split(['\n', '.', '!', '?'])
        .map(str::trim)
        .filter(|candidate| candidate.chars().count() >= 24 && candidate.chars().count() <= 220)
        .filter(|candidate| {
            let lowered = candidate.to_ascii_lowercase();
            keywords.iter().any(|needle| lowered.contains(needle))
        })
        .filter(|candidate| seen.insert(candidate.to_string()))
        .take(4)
        .map(str::to_string)
        .collect()
}

fn extract_entity_candidates(text: &str) -> Vec<String> {
    let mut entities = Vec::new();
    let mut seen = HashSet::new();
    for token in text.split_whitespace() {
        let trimmed = token
            .trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '.' && ch != '/' && ch != '_');
        if trimmed.is_empty() {
            continue;
        }
        let looks_like_url = trimmed.starts_with("http://") || trimmed.starts_with("https://");
        let looks_like_named_entity = trimmed
            .chars()
            .next()
            .map(|ch| ch.is_ascii_uppercase())
            .unwrap_or(false)
            && trimmed.chars().count() > 2;
        if (looks_like_url || looks_like_named_entity) && seen.insert(trimmed.to_string()) {
            entities.push(trimmed.to_string());
        }
        if entities.len() >= 6 {
            break;
        }
    }
    entities
}

fn extract_procedure_candidate(text: &str) -> Option<String> {
    let compact = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let lowered = compact.to_ascii_lowercase();
    let has_procedure_shape = lowered.contains("step ")
        || lowered.contains("1.")
        || lowered.contains(" then ")
        || lowered.contains(" after ")
        || lowered.contains(" next ");
    if !has_procedure_shape {
        return None;
    }
    Some(normalize_core_memory_content(&compact, 480))
}

fn xml_attribute_value(line: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"{key}=""#);
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn xml_tag_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let tag = trimmed.strip_prefix('<')?;
    if tag.starts_with('/') {
        return None;
    }
    Some(
        tag.split(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
            .next()?
            .to_string(),
    )
}

fn extract_ui_relationship_candidates(
    source: &ioi_memory::ArchivalMemoryRecord,
    xml: &str,
) -> Vec<String> {
    let metadata =
        serde_json::from_str::<Value>(&source.metadata_json).unwrap_or_else(|_| json!({}));
    let active_window_title = metadata
        .get("active_window_title")
        .and_then(Value::as_str)
        .unwrap_or("Unknown Window");
    let active_url = metadata
        .get("active_url")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let snapshot_hash = metadata
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let contextual_tags = [
        "dialog",
        "modal",
        "heading",
        "tab",
        "tabpanel",
        "menu",
        "navigation",
    ];
    let control_tags = [
        "button", "link", "textbox", "combobox", "checkbox", "radio", "menuitem", "tab",
    ];
    let mut contexts: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    for raw_line in xml.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(tag) = xml_tag_name(line) else {
            continue;
        };
        let name = xml_attribute_value(line, "name")
            .or_else(|| xml_attribute_value(line, "id"))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        if contextual_tags.contains(&tag.as_str()) {
            if contexts.last().map(String::as_str) != Some(name.as_str()) {
                contexts.push(name.clone());
                if contexts.len() > 4 {
                    contexts.remove(0);
                }
            }
        }

        if !control_tags.contains(&tag.as_str()) {
            continue;
        }

        let context_path = if contexts.is_empty() {
            "direct viewport".to_string()
        } else {
            contexts.join(" > ")
        };
        let summary = normalize_core_memory_content(
            &format!(
                "Window {active_window_title} URL {active_url} control '{name}' role '{tag}' within {context_path}. Snapshot {snapshot_hash}."
            ),
            420,
        );
        if seen.insert(summary.clone()) {
            results.push(summary);
        }
        if results.len() >= 10 {
            break;
        }
    }

    results
}

async fn embed_archival_record_content(
    memory_runtime: &ioi_memory::MemoryRuntime,
    inference: &Arc<dyn InferenceRuntime>,
    record_id: i64,
) -> anyhow::Result<()> {
    let Some(record) = memory_runtime.load_archival_record(record_id)? else {
        return Ok(());
    };
    let embedding = inference.embed_text(&record.content).await?;
    memory_runtime.upsert_archival_embedding(record_id, &embedding)?;
    Ok(())
}

async fn insert_derived_archival_record(
    memory_runtime: &ioi_memory::MemoryRuntime,
    inference: &Arc<dyn InferenceRuntime>,
    scope: &str,
    thread_id: Option<[u8; 32]>,
    kind: &str,
    content: &str,
    source_record_id: i64,
) -> anyhow::Result<DerivedRecordInsertOutcome> {
    if let Some(reason) = derived_memory_rejection_reason(scope, kind, content) {
        return Ok(DerivedRecordInsertOutcome {
            inserted: None,
            rejection_reason: Some(reason.to_string()),
        });
    }

    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_derived",
        "source_record_id": source_record_id,
        "source": "enrichment_pipeline",
    }))?;
    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: scope.to_string(),
            thread_id,
            kind: kind.to_string(),
            content: content.to_string(),
            metadata_json,
        })?
        .ok_or_else(|| anyhow::anyhow!("archival store unavailable"))?;
    embed_archival_record_content(memory_runtime, inference, record_id).await?;
    Ok(DerivedRecordInsertOutcome {
        inserted: Some((record_id, scope.to_string())),
        rejection_reason: None,
    })
}

pub async fn process_pending_memory_enrichment_jobs_once(
    memory_runtime: Arc<ioi_memory::MemoryRuntime>,
    inference: Arc<dyn InferenceRuntime>,
    limit: usize,
) -> anyhow::Result<MemoryEnrichmentTickReport> {
    let jobs = memory_runtime.claim_enrichment_jobs(MEMORY_RUNTIME_ENRICHMENT_WORKER_ID, limit)?;
    let mut report = MemoryEnrichmentTickReport {
        claimed: jobs.len(),
        ..Default::default()
    };

    for job in jobs {
        let result: anyhow::Result<EnrichmentJobOutcome> = async {
            match job.kind.as_str() {
                "archival.embedding" => {
                    let payload =
                        serde_json::from_str::<ArchivalEmbeddingPayload>(&job.payload_json)?;
                    embed_archival_record_content(
                        &memory_runtime,
                        &inference,
                        payload.source_record_id,
                    )
                    .await?;
                    Ok(EnrichmentJobOutcome::default())
                }
                "transcript.fact_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let mut outcome = EnrichmentJobOutcome::default();
                    for fact in extract_fact_candidates(&source.content) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_FACT_SCOPE,
                            source.thread_id,
                            "fact",
                            &fact,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                "transcript.entity_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let mut outcome = EnrichmentJobOutcome::default();
                    for entity in extract_entity_candidates(&source.content) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_ENTITY_SCOPE,
                            source.thread_id,
                            "entity",
                            &entity,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                "transcript.procedure_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(procedure) = extract_procedure_candidate(&source.content) else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let insert = insert_derived_archival_record(
                        &memory_runtime,
                        &inference,
                        MEMORY_RUNTIME_PROCEDURE_SCOPE,
                        source.thread_id,
                        "procedure_candidate",
                        &procedure,
                        source.id,
                    )
                    .await?;
                    let mut outcome = EnrichmentJobOutcome::default();
                    if let Some((_, scope)) = insert.inserted {
                        outcome.inserted_records = 1;
                        outcome.inserted_scopes.insert(scope, 1);
                    } else if let Some(reason) = insert.rejection_reason {
                        outcome.rejected_candidates = 1;
                        outcome.rejected_by_reason.insert(reason, 1);
                    }
                    Ok(outcome)
                }
                "ui.observation.summary" => {
                    let payload =
                        serde_json::from_str::<UiObservationEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(blob) = memory_runtime.load_artifact_blob(&payload.artifact_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let xml = String::from_utf8_lossy(&blob);
                    let summary =
                        summarize_ui_snapshot_for_memory("Browser", None, &digest_hex(&xml), &xml);
                    let insert = insert_derived_archival_record(
                        &memory_runtime,
                        &inference,
                        MEMORY_RUNTIME_UI_SCOPE,
                        source.thread_id,
                        "ui_summary",
                        &summary,
                        source.id,
                    )
                    .await?;
                    let mut outcome = EnrichmentJobOutcome::default();
                    if let Some((_, scope)) = insert.inserted {
                        outcome.inserted_records = 1;
                        outcome.inserted_scopes.insert(scope, 1);
                    } else if let Some(reason) = insert.rejection_reason {
                        outcome.rejected_candidates = 1;
                        outcome.rejected_by_reason.insert(reason, 1);
                    }
                    Ok(outcome)
                }
                "ui.relationship_extraction" => {
                    let payload =
                        serde_json::from_str::<UiObservationEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(blob) = memory_runtime.load_artifact_blob(&payload.artifact_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let xml = String::from_utf8_lossy(&blob);
                    let mut outcome = EnrichmentJobOutcome::default();
                    for relationship in extract_ui_relationship_candidates(&source, &xml) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_UI_SCOPE,
                            source.thread_id,
                            "ui_control_relationship",
                            &relationship,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                other => Err(anyhow::anyhow!("unsupported enrichment job '{}'", other)),
            }
        }
        .await;

        match result {
            Ok(outcome) => {
                memory_runtime.complete_enrichment_job(job.id)?;
                update_enrichment_diagnostics_success(
                    &memory_runtime,
                    job.thread_id,
                    &job.kind,
                    &outcome,
                )?;
                report.completed += 1;
                report.inserted_records += outcome.inserted_records;
                report.rejected_candidates += outcome.rejected_candidates;
            }
            Err(error) => {
                memory_runtime.fail_enrichment_job(job.id, &error.to_string())?;
                update_enrichment_diagnostics_failure(
                    &memory_runtime,
                    job.thread_id,
                    &job.kind,
                    &error.to_string(),
                )?;
                report.failed += 1;
            }
        }
    }

    Ok(report)
}

