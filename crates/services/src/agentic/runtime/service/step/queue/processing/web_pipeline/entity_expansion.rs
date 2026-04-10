#[derive(Debug, Clone, Serialize)]
struct GroundedEntityExpansionPayload {
    query_contract: String,
    locality_scope: String,
    required_entity_count: usize,
    source_url: String,
    source_title: Option<String>,
    source_text_excerpt: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GroundedEntityExpansionResponse {
    entities: Vec<String>,
}

fn normalize_grounding_text(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
}

fn normalized_contains_phrase(haystack: &str, needle: &str) -> bool {
    let compact_haystack = normalize_grounding_text(haystack)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let compact_needle = normalize_grounding_text(needle)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    !compact_needle.is_empty() && compact_haystack.contains(&compact_needle)
}

fn normalized_entity_name(name: &str) -> Option<String> {
    let compact = compact_whitespace(name);
    (!compact.trim().is_empty()).then_some(compact)
}

fn entity_expansion_target_marker(entity_name: &str) -> Option<String> {
    normalized_entity_name(entity_name)
        .map(|normalized| format!("{}{}", ENTITY_EXPANSION_TARGET_MARKER_PREFIX, normalized))
}

fn entity_expansion_query_marker(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    (!compact.trim().is_empty()).then_some(format!(
        "{}{}",
        ENTITY_EXPANSION_QUERY_MARKER_PREFIX, compact
    ))
}

fn entity_targets_from_attempted_urls(attempted_urls: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for attempted in attempted_urls {
        let Some(raw_target) = attempted
            .trim()
            .strip_prefix(ENTITY_EXPANSION_TARGET_MARKER_PREFIX)
        else {
            continue;
        };
        let Some(target) = normalized_entity_name(raw_target) else {
            continue;
        };
        let key = target.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        out.push(target);
    }
    out
}

fn entity_expansion_target_floor_met(
    existing_targets: &[String],
    new_targets: &[String],
    required_count: usize,
) -> bool {
    merged_entity_targets(existing_targets, new_targets).len() >= required_count.max(1)
}

fn source_matches_entity_name(source: &PendingSearchReadSummary, entity_name: &str) -> bool {
    let Some(entity) = normalized_entity_name(entity_name) else {
        return false;
    };
    let observed = format!(
        "{} {} {}",
        source.url,
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    );
    normalized_contains_phrase(&observed, &entity)
}

fn matched_entity_target_names(
    targets: &[String],
    sources: &[PendingSearchReadSummary],
) -> Vec<String> {
    let mut matched = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for target in targets {
        if !sources.iter().any(|source| source_matches_entity_name(source, target)) {
            continue;
        }
        let Some(normalized) = normalized_entity_name(target) else {
            continue;
        };
        let key = normalized.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        matched.push(normalized);
    }
    matched
}

fn selected_entity_target_sources(
    targets: &[String],
    sources: &[PendingSearchReadSummary],
    required_count: usize,
) -> Vec<PendingSearchReadSummary> {
    let mut selected = Vec::new();
    for target in targets {
        if selected.len() >= required_count.max(1) {
            break;
        }
        let Some(source) = sources
            .iter()
            .find(|source| source_matches_entity_name(source, target))
        else {
            continue;
        };
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if selected.iter().any(|existing: &PendingSearchReadSummary| {
            existing.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing.url.as_str(), trimmed)
        }) {
            continue;
        }
        selected.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title.clone(),
            excerpt: source.excerpt.trim().to_string(),
        });
    }
    selected
}

fn entity_detail_search_query(
    entity_name: &str,
    query_contract: &str,
    scope: Option<&str>,
) -> Option<String> {
    let entity_name = normalized_entity_name(entity_name)?;
    let mut parts = vec![format!("\"{}\"", entity_name)];
    let contract = compact_whitespace(query_contract);
    if !contract.trim().is_empty() {
        parts.push(contract);
    }
    if let Some(scope) = scope
        .map(compact_whitespace)
        .filter(|value| !value.trim().is_empty())
    {
        let has_scope = parts.iter().any(|part| normalized_contains_phrase(part, &scope));
        if !has_scope {
            parts.push(format!("\"{}\"", scope));
        }
    }
    Some(compact_whitespace(&parts.join(" ")))
}

fn lint_grounded_entity_targets(
    scope: &str,
    source_text: &str,
    entities: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entity in entities {
        let Some(candidate) = normalized_entity_name(entity) else {
            continue;
        };
        if !local_business_entity_name_allowed(&candidate, Some(scope)) {
            return Err(format!(
                "entity '{}' did not satisfy structural local-business validation",
                candidate
            ));
        }
        let key = candidate.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if !normalized_contains_phrase(source_text, &candidate) {
            return Err(format!(
                "entity '{}' was not explicitly grounded in the source text",
                candidate
            ));
        }
        normalized.push(candidate);
        if normalized.len() >= required_count {
            break;
        }
    }
    if normalized.is_empty() {
        return Err("no grounded entities were returned".to_string());
    }
    Ok(normalized)
}

async fn synthesize_grounded_entity_targets(
    service: &RuntimeAgentService,
    query_contract: &str,
    scope: &str,
    required_count: usize,
    source_url: &str,
    source_title: Option<&str>,
    source_text: &str,
) -> Result<Vec<String>, String> {
    let payload = GroundedEntityExpansionPayload {
        query_contract: query_contract.trim().to_string(),
        locality_scope: scope.trim().to_string(),
        required_entity_count: required_count,
        source_url: source_url.trim().to_string(),
        source_title: source_title.map(str::to_string),
        source_text_excerpt: source_text
            .chars()
            .take(WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_SOURCE_TEXT_CHARS)
            .collect(),
    };
    let payload_json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize grounded entity expansion payload: {}", err))?;
    let timeout = local_business_expansion_timeout();
    let mut feedback: Option<String> = None;
    let mut last_error = "grounded entity expansion failed".to_string();

    let structured = extract_structured_local_business_names(scope, source_text, required_count);
    if !structured.is_empty() {
        return lint_grounded_entity_targets(scope, source_text, &structured, required_count);
    }

    for attempt in 1..=WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
        let prompt = if let Some(previous_error) = feedback.as_deref() {
            format!(
                "Return JSON only with schema {{\"entities\":[string]}}.\n\
                 You are in CEC State 3 (Grounded Entity Expansion).\n\
                 Prior output failed lint: {}\n\
                 Re-extract only entities explicitly named in the source text that satisfy the query contract.\n\
                 Payload:\n{}",
                previous_error, payload_json
            )
        } else {
            format!(
                "Return JSON only with schema {{\"entities\":[string]}}.\n\
                 You are in CEC State 3 (Grounded Entity Expansion).\n\
                 Extract up to {} distinct entities explicitly named in the source text that satisfy the query contract.\n\
                 Requirements:\n\
                 - Use only entities explicitly named in the source text.\n\
                 - Respect the typed retrieval contract already encoded in the query contract.\n\
                 - Respect the locality scope already encoded in the query contract.\n\
                 - Return entity display names only, with no explanations.\n\
                 Payload:\n{}",
                required_count, payload_json
            )
        };
        let options = InferenceOptions {
            tools: vec![],
            temperature: 0.0,
            json_mode: true,
            max_tokens: WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_TOKENS,
            stop_sequences: Vec::new(),
            required_finality_tier: Default::default(),
            sealed_finality_proof: None,
            canonical_collapse_object: None,
        };
        let airlocked_prompt = match service
            .prepare_cloud_inference_input(
                None,
                "desktop_agent",
                "web_pipeline_grounded_entity_expansion",
                prompt.as_bytes(),
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                last_error = format!("grounded entity expansion airlock failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let raw = match tokio::time::timeout(
            timeout,
            service
                .reasoning_inference
                .execute_inference([0u8; 32], &airlocked_prompt, options),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                last_error = format!("grounded entity expansion inference failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            Err(_) => {
                last_error = format!(
                    "grounded entity expansion timed out after {}ms",
                    timeout.as_millis()
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let text = match String::from_utf8(raw) {
            Ok(text) => text,
            Err(err) => {
                last_error = format!("grounded entity expansion response was not UTF-8: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let json_text = extract_json_object(&text).unwrap_or(text.as_str());
        let parsed: GroundedEntityExpansionResponse = match serde_json::from_str(json_text) {
            Ok(parsed) => parsed,
            Err(err) => {
                last_error = format!(
                    "grounded entity expansion returned invalid JSON schema: {}",
                    err
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };

        match lint_grounded_entity_targets(scope, source_text, &parsed.entities, required_count) {
            Ok(validated) => return Ok(validated),
            Err(err) => {
                last_error = err;
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
            }
        }
    }

    Err(last_error)
}
