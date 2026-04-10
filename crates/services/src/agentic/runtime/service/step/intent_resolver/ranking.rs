use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IntentPrototypeCacheKey {
    matrix_version: String,
    matrix_source_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct IntentPrototype {
    intent_id: String,
    vector: Vec<f32>,
}

static INTENT_PROTOTYPE_CACHE: OnceLock<
    RwLock<BTreeMap<IntentPrototypeCacheKey, Vec<IntentPrototype>>>,
> = OnceLock::new();

fn intent_prototype_cache(
) -> &'static RwLock<BTreeMap<IntentPrototypeCacheKey, Vec<IntentPrototype>>> {
    INTENT_PROTOTYPE_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()))
}

pub(super) fn sort_scores_desc(scores: &mut [IntentCandidateScore]) {
    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.intent_id.cmp(&b.intent_id))
    });
}

pub(super) fn quantize_and_sort_scores(
    scores: &mut [IntentCandidateScore],
    policy: &IntentRoutingPolicy,
) {
    for score in scores.iter_mut() {
        score.score = quantize_score(score.score, policy);
    }
    sort_scores_desc(scores);
}

pub(super) fn select_deterministic_winner(
    ranked: &[IntentCandidateScore],
    matrix: &[IntentMatrixEntry],
    policy: &IntentRoutingPolicy,
) -> Option<IntentCandidateScore> {
    let top = ranked.first()?;
    let top_bps = score_to_bps(top.score);
    let tie_eps = tie_region_eps_bps(policy);
    let mut tie_candidates = ranked
        .iter()
        .filter(|candidate| top_bps.saturating_sub(score_to_bps(candidate.score)) <= tie_eps)
        .cloned()
        .collect::<Vec<_>>();
    tie_candidates.sort_by(|left, right| {
        let left_scope = scope_for_intent(matrix, &left.intent_id)
            .map(|scope| format!("{:?}", scope))
            .unwrap_or_else(|| "Unknown".to_string());
        let right_scope = scope_for_intent(matrix, &right.intent_id)
            .map(|scope| format!("{:?}", scope))
            .unwrap_or_else(|| "Unknown".to_string());
        left.intent_id
            .cmp(&right.intent_id)
            .then_with(|| left_scope.cmp(&right_scope))
    });
    tie_candidates.into_iter().next()
}

pub(super) fn should_abstain_for_ambiguity(
    ranked: &[IntentCandidateScore],
    winner: &IntentCandidateScore,
    policy: &IntentRoutingPolicy,
) -> bool {
    let Some(second) = ranked
        .iter()
        .find(|candidate| candidate.intent_id != winner.intent_id)
    else {
        return false;
    };
    let winner_bps = score_to_bps(winner.score);
    let second_bps = score_to_bps(second.score);
    let gap = winner_bps.saturating_sub(second_bps);
    gap < ambiguity_margin_bps(policy)
}

pub(super) fn all_candidate_scores_zero(scores: &[IntentCandidateScore]) -> bool {
    !scores.is_empty()
        && scores
            .iter()
            .all(|candidate| candidate.score <= f32::EPSILON)
}

pub(super) fn zero_ranked_candidates(matrix: &[IntentMatrixEntry]) -> Vec<IntentCandidateScore> {
    matrix
        .iter()
        .map(|entry| IntentCandidateScore {
            intent_id: entry.intent_id.clone(),
            score: 0.0,
        })
        .collect()
}

pub(super) fn canonical_descriptor_for_entry(entry: &IntentMatrixEntry) -> String {
    fn normalize_fragment(value: &str) -> Option<String> {
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
        (!normalized.is_empty()).then_some(normalized)
    }

    let mut fragments = Vec::new();
    if let Some(semantic_descriptor) = normalize_fragment(&entry.semantic_descriptor) {
        fragments.push(format!("semantic: {}", semantic_descriptor));
    }
    if !entry.aliases.is_empty() {
        let aliases = entry
            .aliases
            .iter()
            .filter_map(|alias| normalize_fragment(alias))
            .collect::<Vec<_>>();
        if !aliases.is_empty() {
            fragments.push(format!("aliases: {}", aliases.join(" | ")));
        }
    }
    if !entry.exemplars.is_empty() {
        let exemplars = entry
            .exemplars
            .iter()
            .filter_map(|exemplar| normalize_fragment(exemplar))
            .collect::<Vec<_>>();
        if !exemplars.is_empty() {
            fragments.push(format!("exemplars: {}", exemplars.join(" | ")));
        }
    }

    fragments.join(" || ")
}

async fn build_intent_prototypes(
    runtime: &Arc<dyn InferenceRuntime>,
    matrix: &[IntentMatrixEntry],
) -> Result<Vec<IntentPrototype>, TransactionError> {
    let mut prototypes = Vec::with_capacity(matrix.len());
    for entry in matrix {
        let descriptor = canonical_descriptor_for_entry(entry);
        match runtime.embed_text(&descriptor).await {
            Ok(vector) if !vector.is_empty() => {
                prototypes.push(IntentPrototype {
                    intent_id: entry.intent_id.clone(),
                    vector,
                });
            }
            Ok(_) => {}
            Err(e) => {
                log::warn!(
                    "IntentResolver prototype embedding failed intent={} descriptor={} error={}",
                    entry.intent_id,
                    descriptor,
                    e
                );
            }
        }
    }

    if prototypes.len() != matrix.len() {
        let mapped = prototypes
            .iter()
            .map(|prototype| prototype.intent_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let missing = matrix
            .iter()
            .filter_map(|entry| {
                (!mapped.contains(entry.intent_id.as_str())).then_some(entry.intent_id.clone())
            })
            .collect::<Vec<_>>();
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=ResolverContractViolation Intent prototype cache incomplete: missing [{}]",
            missing.join(", ")
        )));
    }

    Ok(prototypes)
}

#[async_trait]
pub trait IntentRankBackend: Send + Sync {
    async fn embed_or_rank(
        &self,
        query: &str,
        matrix_version: &str,
        matrix_source_hash: [u8; 32],
        matrix: &[IntentMatrixEntry],
        service: Option<&RuntimeAgentService>,
        session_id: Option<[u8; 32]>,
    ) -> Result<IntentRankResult, TransactionError>;
}

#[derive(Debug, Clone)]
pub(super) struct IntentRankResult {
    pub scores: Vec<IntentCandidateScore>,
    pub model_id: String,
    pub model_version: String,
    pub similarity_function_id: String,
}

pub(super) fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na <= f32::EPSILON || nb <= f32::EPSILON {
        return None;
    }
    Some((dot / (na.sqrt() * nb.sqrt())).clamp(-1.0, 1.0))
}

fn score_query_against_prototypes(
    query_embedding: &[f32],
    matrix: &[IntentMatrixEntry],
    prototypes: &[IntentPrototype],
) -> Vec<IntentCandidateScore> {
    let mut by_intent = BTreeMap::<&str, f32>::new();
    for prototype in prototypes {
        if let Some(cos) = cosine_similarity(query_embedding, &prototype.vector) {
            let normalized = ((cos + 1.0) * 0.5).clamp(0.0, 1.0);
            by_intent.insert(prototype.intent_id.as_str(), normalized);
        }
    }

    let mut scored = matrix
        .iter()
        .map(|entry| IntentCandidateScore {
            intent_id: entry.intent_id.clone(),
            score: *by_intent.get(entry.intent_id.as_str()).unwrap_or(&0.0),
        })
        .collect::<Vec<_>>();
    sort_scores_desc(&mut scored);
    scored
}

pub(super) fn vm_error_to_tx(err: VmError) -> TransactionError {
    TransactionError::Invalid(err.to_string())
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

fn parse_model_rank_scores(
    raw: &str,
    matrix: &[IntentMatrixEntry],
) -> Result<Vec<IntentCandidateScore>, TransactionError> {
    let parsed = serde_json::from_str::<serde_json::Value>(raw).or_else(|_| {
        let extracted = extract_first_json_object(raw).ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=ResolverContractViolation intent rank model output missing JSON"
                    .to_string(),
            )
        })?;
        serde_json::from_str::<serde_json::Value>(&extracted).map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation intent rank model output parse failed: {}",
                e
            ))
        })
    })?;

    let scores = parsed
        .get("scores")
        .and_then(|scores| scores.as_array())
        .ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=ResolverContractViolation intent rank model output missing scores[]"
                    .to_string(),
            )
        })?;

    let matrix_ids = matrix
        .iter()
        .map(|entry| entry.intent_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut score_map = BTreeMap::<String, f32>::new();
    for candidate in scores {
        let Some(intent_id) = candidate.get("intent_id").and_then(|value| value.as_str()) else {
            continue;
        };
        if !matrix_ids.contains(intent_id) {
            continue;
        }
        let score = candidate
            .get("score")
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0) as f32;
        score_map.insert(intent_id.to_string(), score);
    }

    let mut ranked = matrix
        .iter()
        .map(|entry| IntentCandidateScore {
            intent_id: entry.intent_id.clone(),
            score: *score_map.get(entry.intent_id.as_str()).unwrap_or(&0.0),
        })
        .collect::<Vec<_>>();
    sort_scores_desc(&mut ranked);
    Ok(ranked)
}

async fn rank_with_inference_model(
    runtime: &Arc<dyn InferenceRuntime>,
    query: &str,
    matrix: &[IntentMatrixEntry],
    service: Option<&RuntimeAgentService>,
    session_id: Option<[u8; 32]>,
) -> Result<Vec<IntentCandidateScore>, TransactionError> {
    if matrix.is_empty() {
        return Ok(vec![]);
    }

    let intent_rows = matrix
        .iter()
        .map(|entry| {
            json!({
                "intent_id": entry.intent_id,
                "semantic_descriptor": canonical_descriptor_for_entry(entry),
            })
        })
        .collect::<Vec<_>>();
    let payload = json!([
        {
            "role": "system",
            "content": "Rank user query semantic similarity to intent descriptors. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Query:\n{}\n\nIntents:\n{}\n\nReturn exactly one JSON object with this schema:\n{{\"scores\":[{{\"intent_id\":\"<intent_id>\",\"score\":<0_to_1_float>}}]}}\nRules:\n1) Include every listed intent_id exactly once.\n2) Scores must be in [0,1].\n3) Score only semantic fit to descriptor text.",
                query,
                serde_json::to_string_pretty(&intent_rows).unwrap_or_else(|_| "[]".to_string())
            )
        }
    ]);
    let input_bytes = serde_json::to_vec(&payload).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=ResolverContractViolation intent rank payload encode failed: {}",
            e
        ))
    })?;
    let inference_input = if let Some(desktop_service) = service {
        desktop_service
            .prepare_cloud_inference_input(
                session_id,
                "intent_resolver",
                INTENT_MODEL_RANK_MODEL_ID,
                &input_bytes,
            )
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=ResolverContractViolation intent rank airlock failed: {}",
                    e
                ))
            })?
    } else {
        input_bytes
    };
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &inference_input,
            ioi_types::app::agentic::InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 768,
                ..Default::default()
            },
        )
        .await
        .map_err(vm_error_to_tx)?;
    let raw = String::from_utf8(output).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=ResolverContractViolation intent rank model output utf8 failed: {}",
            e
        ))
    })?;
    parse_model_rank_scores(&raw, matrix)
}

#[async_trait]
impl IntentRankBackend for Arc<dyn InferenceRuntime> {
    async fn embed_or_rank(
        &self,
        query: &str,
        matrix_version: &str,
        matrix_source_hash: [u8; 32],
        matrix: &[IntentMatrixEntry],
        service: Option<&RuntimeAgentService>,
        session_id: Option<[u8; 32]>,
    ) -> Result<IntentRankResult, TransactionError> {
        if matrix.is_empty() {
            return Ok(IntentRankResult {
                scores: vec![],
                model_id: INTENT_EMBEDDING_MODEL_ID.to_string(),
                model_version: INTENT_EMBEDDING_MODEL_VERSION.to_string(),
                similarity_function_id: INTENT_SIMILARITY_FUNCTION_ID.to_string(),
            });
        }

        let key = IntentPrototypeCacheKey {
            matrix_version: matrix_version.to_string(),
            matrix_source_hash,
        };
        let cached = intent_prototype_cache()
            .read()
            .ok()
            .and_then(|cache| cache.get(&key).cloned());
        let prototypes = match cached {
            Some(existing) => Some(existing),
            None => match build_intent_prototypes(self, matrix).await {
                Ok(built) => {
                    if let Ok(mut cache) = intent_prototype_cache().write() {
                        cache.insert(key.clone(), built.clone());
                    }
                    Some(built)
                }
                Err(err) => {
                    log::warn!(
                        "IntentResolver embedding backend unavailable matrix_version={} matrix_source_hash={} error={}",
                        matrix_version,
                        hex::encode(matrix_source_hash),
                        err
                    );
                    None
                }
            },
        };
        if let Some(prototypes) = prototypes {
            match self.embed_text(query).await {
                Ok(query_embedding) => {
                    return Ok(IntentRankResult {
                        scores: score_query_against_prototypes(
                            &query_embedding,
                            matrix,
                            &prototypes,
                        ),
                        model_id: INTENT_EMBEDDING_MODEL_ID.to_string(),
                        model_version: INTENT_EMBEDDING_MODEL_VERSION.to_string(),
                        similarity_function_id: INTENT_SIMILARITY_FUNCTION_ID.to_string(),
                    });
                }
                Err(err) => {
                    log::warn!(
                        "IntentResolver query embedding failed matrix_version={} matrix_source_hash={} error={}",
                        matrix_version,
                        hex::encode(matrix_source_hash),
                        err
                    );
                }
            }
        }

        match rank_with_inference_model(self, query, matrix, service, session_id).await {
            Ok(ranked) => {
                log::info!(
                    "IntentResolver used model-ranking backend matrix_version={} matrix_source_hash={}",
                    matrix_version,
                    hex::encode(matrix_source_hash)
                );
                Ok(IntentRankResult {
                    scores: ranked,
                    model_id: INTENT_MODEL_RANK_MODEL_ID.to_string(),
                    model_version: INTENT_MODEL_RANK_MODEL_VERSION.to_string(),
                    similarity_function_id: INTENT_MODEL_RANK_SIMILARITY_FUNCTION_ID.to_string(),
                })
            }
            Err(err) => {
                log::warn!(
                    "IntentResolver model-ranking backend failed matrix_version={} matrix_source_hash={} error={}",
                    matrix_version,
                    hex::encode(matrix_source_hash),
                    err
                );
                Err(err)
            }
        }
    }
}

pub(super) fn scope_for_intent(
    matrix: &[IntentMatrixEntry],
    intent_id: &str,
) -> Option<IntentScopeProfile> {
    matrix
        .iter()
        .find(|entry| entry.intent_id == intent_id)
        .map(|entry| entry.scope)
}

pub(super) fn preferred_tier_for_intent(
    matrix: &[IntentMatrixEntry],
    intent_id: &str,
) -> Option<String> {
    matrix
        .iter()
        .find(|entry| entry.intent_id == intent_id)
        .map(|entry| entry.preferred_tier.clone())
}

pub fn should_pause_for_clarification(
    resolved: &ResolvedIntentState,
    policy: &IntentRoutingPolicy,
) -> bool {
    if resolved.intent_id == "conversation.reply" {
        return false;
    }

    if resolved.intent_id == "resolver.unclassified" {
        return matches!(
            policy.ambiguity.low_confidence_action,
            IntentAmbiguityAction::PauseForClarification
        );
    }

    match resolved.band {
        IntentConfidenceBand::Low => matches!(
            policy.ambiguity.low_confidence_action,
            IntentAmbiguityAction::PauseForClarification
        ),
        IntentConfidenceBand::Medium => matches!(
            policy.ambiguity.medium_confidence_action,
            IntentAmbiguityAction::PauseForClarification
        ),
        IntentConfidenceBand::High => false,
    }
}

pub fn preferred_tier(resolved: &ResolvedIntentState) -> ExecutionTier {
    preferred_tier_from_label(&resolved.preferred_tier, resolved.scope)
}
