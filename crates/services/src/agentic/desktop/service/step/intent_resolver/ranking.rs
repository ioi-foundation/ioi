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
    entry
        .semantic_descriptor
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

pub(super) async fn ensure_intent_prototypes(
    runtime: &Arc<dyn InferenceRuntime>,
    matrix_version: &str,
    matrix_source_hash: [u8; 32],
    matrix: &[IntentMatrixEntry],
) -> Result<(), TransactionError> {
    if matrix.is_empty() {
        return Ok(());
    }

    let key = IntentPrototypeCacheKey {
        matrix_version: matrix_version.to_string(),
        matrix_source_hash,
    };

    if let Ok(cache) = intent_prototype_cache().read() {
        if cache.contains_key(&key) {
            return Ok(());
        }
    }

    let prototypes = build_intent_prototypes(runtime, matrix).await?;
    let mut cache = intent_prototype_cache().write().map_err(|_| {
        TransactionError::Invalid(
            "ERROR_CLASS=ResolverContractViolation Intent prototype cache poisoned".to_string(),
        )
    })?;
    cache.insert(key, prototypes);
    Ok(())
}

#[async_trait]
pub trait IntentRankBackend: Send + Sync {
    async fn embed_or_rank(
        &self,
        query: &str,
        matrix_version: &str,
        matrix_source_hash: [u8; 32],
        matrix: &[IntentMatrixEntry],
    ) -> Result<Vec<IntentCandidateScore>, TransactionError>;
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

#[async_trait]
impl IntentRankBackend for Arc<dyn InferenceRuntime> {
    async fn embed_or_rank(
        &self,
        query: &str,
        matrix_version: &str,
        matrix_source_hash: [u8; 32],
        matrix: &[IntentMatrixEntry],
    ) -> Result<Vec<IntentCandidateScore>, TransactionError> {
        if matrix.is_empty() {
            return Ok(vec![]);
        }

        let key = IntentPrototypeCacheKey {
            matrix_version: matrix_version.to_string(),
            matrix_source_hash,
        };
        let prototypes = {
            let cache = intent_prototype_cache().read().map_err(|_| {
                TransactionError::Invalid(
                    "ERROR_CLASS=ResolverContractViolation Intent prototype cache poisoned"
                        .to_string(),
                )
            })?;
            cache.get(&key).cloned().ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=ResolverContractViolation Intent prototype cache miss matrix_version={} matrix_source_hash={}",
                    matrix_version,
                    hex::encode(matrix_source_hash)
                ))
            })?
        };

        let query_embedding = self.embed_text(query).await.map_err(vm_error_to_tx)?;
        Ok(score_query_against_prototypes(
            &query_embedding,
            matrix,
            &prototypes,
        ))
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
