use super::*;

#[test]
fn sqlite_runtime_roundtrips_transcript_messages() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let thread_id = [0x11; 32];

    runtime
        .append_transcript_message(
            thread_id,
            &StoredTranscriptMessage {
                role: "user".to_string(),
                timestamp_ms: 123,
                trace_hash: None,
                raw_content: "raw secret".to_string(),
                model_content: "[REDACTED]".to_string(),
                store_content: "[REDACTED]".to_string(),
                raw_reference: None,
                privacy_metadata: TranscriptPrivacyMetadata {
                    redaction_version: "v1".to_string(),
                    sensitive_fields_mask: vec!["secret".to_string()],
                    policy_id: "policy".to_string(),
                    policy_version: "1".to_string(),
                    scrubbed_for_model_hash: None,
                },
            },
        )
        .expect("append");

    let messages = runtime
        .load_transcript_messages(thread_id)
        .expect("load transcript");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].raw_content, "raw secret");
    assert_eq!(messages[0].model_content, "[REDACTED]");
}

#[test]
fn sqlite_runtime_roundtrips_core_and_archival_memory() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let thread_id = [0x22; 32];

    runtime
        .replace_core_memory_section(thread_id, "current_goal", "checkout cart")
        .expect("replace core");
    let section = runtime
        .load_core_memory_section(thread_id, "current_goal")
        .expect("load core");
    assert!(section.is_some());
    assert_eq!(section.expect("section").content, "checkout cart");

    runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "user".to_string(),
            thread_id: Some(thread_id),
            kind: "fact".to_string(),
            content: "favorite color is blue".to_string(),
            metadata_json: "{}".to_string(),
        })
        .expect("insert archival");

    let results = runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: "user".to_string(),
            thread_id: Some(thread_id),
            text: "blue".to_string(),
            limit: 5,
        })
        .expect("search archival");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].content, "favorite color is blue");
}

#[test]
fn sqlite_runtime_roundtrips_semantic_archival_search() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let record_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "autopilot.retrieval".to_string(),
            thread_id: None,
            kind: "file_chunk".to_string(),
            content: "checkout flow instructions".to_string(),
            metadata_json: "{}".to_string(),
        })
        .expect("insert record")
        .expect("record id");
    runtime
        .upsert_archival_embedding(record_id, &[1.0, 0.0])
        .expect("store embedding");

    let other_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "autopilot.retrieval".to_string(),
            thread_id: None,
            kind: "file_chunk".to_string(),
            content: "calendar renewal notes".to_string(),
            metadata_json: "{}".to_string(),
        })
        .expect("insert record")
        .expect("record id");
    runtime
        .upsert_archival_embedding(other_id, &[0.0, 1.0])
        .expect("store embedding");

    let hits = runtime
        .semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
            scope: "autopilot.retrieval".to_string(),
            thread_id: None,
            text_filter: None,
            embedding: vec![1.0, 0.0],
            limit: 1,
        })
        .expect("semantic search");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.id, record_id);
    assert!(hits[0].score > 0.99);
}

#[test]
fn sqlite_runtime_roundtrips_execution_cache_entries() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let cache_key = [0x33; 32];

    runtime
        .upsert_execution_cache_json(cache_key, "{\"status\":\"success\"}")
        .expect("store cache entry");

    let cached = runtime
        .load_execution_cache_json(cache_key)
        .expect("load cache entry");
    assert_eq!(cached.as_deref(), Some("{\"status\":\"success\"}"));
}

#[test]
fn sqlite_runtime_roundtrips_artifact_records_and_blobs() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let thread_id = [0x44; 32];
    let artifact_id = "desktop.visual_observation.deadbeef";

    runtime
        .upsert_artifact_json(
            thread_id,
            artifact_id,
            r#"{"kind":"visual_observation","content_type":"image/png"}"#,
        )
        .expect("store artifact metadata");
    runtime
        .put_artifact_blob(thread_id, artifact_id, &[0x89, b'P', b'N', b'G'])
        .expect("store artifact blob");

    let artifacts = runtime
        .load_artifact_jsons(thread_id)
        .expect("load artifact metadata");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].artifact_id, artifact_id);

    let blob = runtime
        .load_artifact_blob(artifact_id)
        .expect("load artifact blob");
    assert_eq!(blob, Some(vec![0x89, b'P', b'N', b'G']));
}

#[test]
fn sqlite_runtime_hybrid_search_honors_scope_lexical_and_trust_filters() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let trusted_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "desktop.transcript".to_string(),
            thread_id: None,
            kind: "chat_message".to_string(),
            content: "checkout button appears inside the cart modal".to_string(),
            metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
        })
        .expect("insert trusted")
        .expect("record id");
    runtime
        .upsert_archival_embedding(trusted_id, &[1.0, 0.0])
        .expect("trusted embedding");

    let untrusted_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "desktop.ui.memory".to_string(),
            thread_id: None,
            kind: "ui_observation".to_string(),
            content: "checkout button might be somewhere else".to_string(),
            metadata_json: r#"{"trust_level":"model_asserted"}"#.to_string(),
        })
        .expect("insert untrusted")
        .expect("record id");
    runtime
        .upsert_archival_embedding(untrusted_id, &[0.9, 0.1])
        .expect("untrusted embedding");

    let hits = runtime
        .hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
            scopes: vec![
                "desktop.transcript".to_string(),
                "desktop.ui.memory".to_string(),
            ],
            thread_id: None,
            text: "checkout button".to_string(),
            embedding: Some(vec![1.0, 0.0]),
            limit: 5,
            candidate_limit: 8,
            allowed_trust_levels: vec!["runtime_observed".to_string()],
        })
        .expect("hybrid search");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.id, trusted_id);
    assert_eq!(hits[0].trust_level, "runtime_observed");
    assert!(hits[0].lexical_score > 0.0);
    assert!(hits[0].semantic_score.unwrap_or_default() > 0.9);
}

#[test]
fn sqlite_runtime_roundtrips_enrichment_queue_jobs() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let thread_id = [0x55; 32];

    let job_id = runtime
        .enqueue_enrichment_job(&NewEnrichmentJob {
            thread_id: Some(thread_id),
            kind: "fact_extraction".to_string(),
            payload_json: r#"{"record_id":1}"#.to_string(),
            dedupe_key: Some("fact:1".to_string()),
        })
        .expect("enqueue")
        .expect("job id");

    let deduped = runtime
        .enqueue_enrichment_job(&NewEnrichmentJob {
            thread_id: Some(thread_id),
            kind: "fact_extraction".to_string(),
            payload_json: r#"{"record_id":1}"#.to_string(),
            dedupe_key: Some("fact:1".to_string()),
        })
        .expect("dedupe enqueue")
        .expect("dedupe id");
    assert_eq!(deduped, job_id);

    let pending = runtime
        .load_enrichment_jobs(Some(EnrichmentJobStatus::Pending), 10)
        .expect("load pending");
    assert_eq!(pending.len(), 1);

    let claimed = runtime
        .claim_enrichment_jobs("worker-a", 5)
        .expect("claim jobs");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, job_id);
    assert_eq!(claimed[0].status, EnrichmentJobStatus::Claimed);
    assert_eq!(claimed[0].claimed_by.as_deref(), Some("worker-a"));
    assert_eq!(claimed[0].attempts, 1);

    runtime
        .fail_enrichment_job(job_id, "embedding provider unavailable")
        .expect("fail job");
    let failed = runtime
        .load_enrichment_jobs(Some(EnrichmentJobStatus::Failed), 10)
        .expect("load failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].last_error.as_deref(),
        Some("embedding provider unavailable")
    );

    let second_job_id = runtime
        .enqueue_enrichment_job(&NewEnrichmentJob {
            thread_id: Some(thread_id),
            kind: "summary".to_string(),
            payload_json: r#"{"thread_id":"abc"}"#.to_string(),
            dedupe_key: Some("summary:abc".to_string()),
        })
        .expect("enqueue second")
        .expect("second job id");
    let claimed_second = runtime
        .claim_enrichment_jobs("worker-b", 5)
        .expect("claim second");
    assert_eq!(claimed_second.len(), 1);
    assert_eq!(claimed_second[0].id, second_job_id);
    runtime
        .complete_enrichment_job(second_job_id)
        .expect("complete second");
    let completed = runtime
        .load_enrichment_jobs(Some(EnrichmentJobStatus::Completed), 10)
        .expect("load completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].id, second_job_id);
}
