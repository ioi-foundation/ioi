/// Hybrid retrieval of transcript memory via the runtime archival store.
pub async fn retrieve_context_hybrid(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> String {
    retrieve_context_hybrid_with_receipt(service, query, _visual_phash)
        .await
        .output
}

/// Hybrid Retrieval with a structured receipt payload suitable for workload events.
pub async fn retrieve_context_hybrid_with_receipt(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> HybridRetrievalResult {
    let default_policy = RetrievalSearchPolicy {
        k: 5,
        ef_search: 64,
        candidate_limit: 32,
        distance_metric: "cosine_distance".to_string(),
        embedding_normalized: true,
    };
    let query_hash = sha256(query.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default();

    let empty_failure_receipt =
        |backend: &str,
         distance_metric: &str,
         embedding_normalized: bool,
         certificate_mode: Option<&str>,
         error_class: Option<String>| WorkloadMemoryRetrieveReceipt {
            tool_name: "memory__search".to_string(),
            backend: backend.to_string(),
            query_hash: query_hash.clone(),
            index_root: String::new(),
            k: default_policy.k,
            ef_search: default_policy.ef_search,
            candidate_limit: default_policy.candidate_limit,
            candidate_count_total: 0,
            candidate_count_reranked: 0,
            candidate_truncated: false,
            distance_metric: distance_metric.to_string(),
            embedding_normalized,
            proof_ref: None,
            proof_hash: None,
            certificate_mode: certificate_mode.map(str::to_string),
            success: false,
            error_class,
        };

    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return HybridRetrievalResult {
            output: String::new(),
            receipt: Some(empty_failure_receipt(
                "ioi-memory:hybrid-archival",
                "hybrid_lexical_semantic",
                false,
                Some("none"),
                Some("UnexpectedState".to_string()),
            )),
        };
    };

    let embedding = match service.reasoning_inference.embed_text(query).await {
        Ok(vec) => vec,
        Err(e) => {
            log::warn!(
                "Failed to generate embedding for memory runtime retrieval: {}",
                e
            );
            return HybridRetrievalResult {
                output: String::new(),
                receipt: Some(empty_failure_receipt(
                    "ioi-memory:hybrid-archival",
                    "hybrid_lexical_semantic",
                    false,
                    Some("none"),
                    Some("UnexpectedState".to_string()),
                )),
            };
        }
    };

    let matches = match memory_runtime.hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
        scopes: vec![
            MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            MEMORY_RUNTIME_COMPACTION_SCOPE.to_string(),
            MEMORY_RUNTIME_FACT_SCOPE.to_string(),
            MEMORY_RUNTIME_ENTITY_SCOPE.to_string(),
            MEMORY_RUNTIME_PROCEDURE_SCOPE.to_string(),
            MEMORY_RUNTIME_UI_SCOPE.to_string(),
        ],
        thread_id: None,
        text: query.to_string(),
        embedding: Some(embedding),
        limit: default_policy.k as usize,
        candidate_limit: default_policy.candidate_limit as usize,
        allowed_trust_levels: vec![
            "runtime_observed".to_string(),
            "runtime_derived".to_string(),
            "runtime_controlled".to_string(),
            "standard".to_string(),
        ],
    }) {
        Ok(matches) => matches,
        Err(error) => {
            log::warn!("Memory runtime retrieval failed: {}", error);
            return HybridRetrievalResult {
                output: String::new(),
                receipt: Some(empty_failure_receipt(
                    "ioi-memory:hybrid-archival",
                    "hybrid_lexical_semantic",
                    false,
                    Some("none"),
                    Some("UnexpectedState".to_string()),
                )),
            };
        }
    };

    let mut output = String::new();
    let mut top_snippet_included = false;
    let mut included = 0usize;
    let mut diagnostic_hits = Vec::new();

    for (i, hit) in matches.iter().enumerate() {
        if hit.score < MEMORY_RUNTIME_RETRIEVAL_SCORE_THRESHOLD {
            continue;
        }

        let inspect_id = archival_memory_inspect_id(hit.record.id).unwrap_or_default();
        let metadata =
            serde_json::from_str::<Value>(&hit.record.metadata_json).unwrap_or_else(|_| json!({}));
        let kind = metadata
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or(hit.record.kind.as_str());
        let confidence = (hit.score.clamp(0.0, 1.0)) * 100.0;
        let scope = hit.record.scope.as_str();
        let trust_level = hit.trust_level.as_str();

        output.push_str(&format!(
            "- [ID:{}] Scope:{} Kind:{} Trust:{} Conf:{:.0}% | ",
            inspect_id, scope, kind, trust_level, confidence
        ));

        if i == 0 && !top_snippet_included {
            let snippet: String = hit
                .record
                .content
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            output.push_str(&format!("Snippet: \"{}...\"\n", snippet));
            top_snippet_included = true;
        } else {
            let mut summary: String = hit.record.content.chars().take(60).collect();
            if hit.record.content.chars().count() > 60 {
                summary.push_str("...");
            }
            output.push_str(&format!("Summary: \"{}\"\n", summary));
        }
        included += 1;
        if diagnostic_hits.len() < MEMORY_RUNTIME_DIAGNOSTIC_TOP_HITS {
            diagnostic_hits.push(MemoryRetrievalHitDiagnostic {
                inspect_id: Some(inspect_id),
                scope: scope.to_string(),
                kind: kind.to_string(),
                trust_level: trust_level.to_string(),
                score: hit.score,
            });
        }
    }

    if let Err(error) = update_retrieval_diagnostics(
        memory_runtime,
        &query_hash,
        matches.len(),
        included,
        &diagnostic_hits,
    ) {
        log::warn!("Failed to persist memory retrieval diagnostics: {}", error);
    }

    HybridRetrievalResult {
        output,
        receipt: Some(WorkloadMemoryRetrieveReceipt {
            tool_name: "memory__search".to_string(),
            backend: "ioi-memory:hybrid-archival".to_string(),
            query_hash,
            index_root: String::new(),
            k: default_policy.k,
            ef_search: default_policy.ef_search,
            candidate_limit: default_policy.candidate_limit,
            candidate_count_total: matches.len().min(u32::MAX as usize) as u32,
            candidate_count_reranked: matches.len().min(u32::MAX as usize) as u32,
            candidate_truncated: matches.len() > included.max(1),
            distance_metric: "hybrid_lexical_semantic".to_string(),
            embedding_normalized: false,
            proof_ref: None,
            proof_hash: None,
            certificate_mode: Some("none".to_string()),
            success: true,
            error_class: None,
        }),
    }
}

