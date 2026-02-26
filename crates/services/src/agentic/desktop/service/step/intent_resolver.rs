use crate::agentic::desktop::service::step::signals::{analyze_query_facets, QueryFacetProfile};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::rules::{ActionRules, Verdict};
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    CapabilityId, ExecutionApplicabilityClass, IntentAmbiguityAction, IntentCandidateScore,
    IntentConfidenceBand, IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile,
    ResolvedIntentState, ToolCapabilityBinding,
};
use ioi_types::app::{ActionTarget, IntentResolutionReceiptEvent, KernelEvent};
use ioi_types::error::{TransactionError, VmError};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::time::{timeout, Duration};

const INTENT_EMBED_RANK_TIMEOUT: Duration = Duration::from_secs(5);
const INTENT_PROTOTYPE_BUILD_TIMEOUT: Duration = Duration::from_secs(30);
const INTENT_QUERY_NORMALIZATION_VERSION: &str = "intent_query_norm_v1";
const INTENT_EMBEDDING_MODEL_ID: &str = "inference.embed_text";
const INTENT_EMBEDDING_MODEL_VERSION: &str = "v1";
const INTENT_SIMILARITY_FUNCTION_ID: &str = "cosine_similarity_v1";
const CIRC_CONTRACT_VERSION: &str = "circ.v0.5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentQueryBindingClass {
    None,
    HostLocal,
    RemotePublicFact,
    CommandDirected,
}

fn preferred_tier_from_label(label: &str, scope: IntentScopeProfile) -> ExecutionTier {
    match label {
        "visual_last" => ExecutionTier::VisualForeground,
        "ax_first" => ExecutionTier::VisualBackground,
        "tool_first" => ExecutionTier::DomHeadless,
        _ => match scope {
            IntentScopeProfile::UiInteraction => ExecutionTier::VisualForeground,
            _ => ExecutionTier::DomHeadless,
        },
    }
}

fn score_to_bps(score: f32) -> u16 {
    let clamped = score.clamp(0.0, 1.0);
    (clamped * 10_000.0).round() as u16
}

fn quantization_step_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.score_quantization_bps.clamp(1, 10_000)
}

fn tie_region_eps_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.tie_region_eps_bps.min(10_000)
}

fn ambiguity_margin_bps(policy: &IntentRoutingPolicy) -> u16 {
    policy.ambiguity_margin_bps.min(10_000)
}

fn is_ambiguity_abstain_exempt(policy: &IntentRoutingPolicy, intent_id: &str) -> bool {
    policy
        .ambiguity_abstain_exempt_intents
        .iter()
        .map(|id| id.trim())
        .any(|id| !id.is_empty() && id == intent_id)
}

fn quantize_score(score: f32, policy: &IntentRoutingPolicy) -> f32 {
    let step = quantization_step_bps(policy);
    let bps = score_to_bps(score);
    let remainder = bps % step;
    let rounded_bps = if remainder.saturating_mul(2) >= step {
        bps.saturating_add(step.saturating_sub(remainder))
    } else {
        bps.saturating_sub(remainder)
    }
    .min(10_000);
    (rounded_bps as f32 / 10_000.0).clamp(0.0, 1.0)
}

fn normalize_query_for_ranking(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn query_binding_for_intent(entry: &IntentMatrixEntry) -> IntentQueryBindingClass {
    match entry.intent_id.as_str() {
        "system.clock.read" => IntentQueryBindingClass::HostLocal,
        "web.research" => IntentQueryBindingClass::RemotePublicFact,
        "command.exec" => IntentQueryBindingClass::CommandDirected,
        _ => IntentQueryBindingClass::None,
    }
}

fn query_explicitly_targets_host_local_clock(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const HOST_LOCAL_CLOCK_MARKERS: [&str; 12] = [
        " this machine ",
        " this computer ",
        " this host ",
        " this system ",
        " local machine ",
        " local computer ",
        " local host ",
        " local system ",
        " on my machine ",
        " on my computer ",
        " on this machine ",
        " on this computer ",
    ];
    HOST_LOCAL_CLOCK_MARKERS
        .iter()
        .any(|marker| padded.contains(marker))
}

fn query_requires_remote_public_fact_grounding(facets: &QueryFacetProfile) -> bool {
    facets.grounded_external_required
        || facets.time_sensitive_public_fact
        || facets.goal.external_hits > 0
        || facets.goal.public_fact_hits > 0
        || facets.goal.explicit_url_hits > 0
}

fn intent_supports_remote_public_fact_grounding(entry: &IntentMatrixEntry) -> bool {
    let has_web_retrieve_capability = entry
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "web.retrieve");
    match entry.applicability_class {
        ExecutionApplicabilityClass::RemoteRetrieval => true,
        ExecutionApplicabilityClass::Mixed => has_web_retrieve_capability,
        _ => false,
    }
}

fn query_has_timer_scheduling_shape(query: &str) -> bool {
    let padded = format!(" {} ", query.to_ascii_lowercase());
    const TIMER_MARKERS: [&str; 6] = [
        " timer ",
        " countdown ",
        " alarm ",
        " remind me ",
        " reminder ",
        " notify me ",
    ];
    TIMER_MARKERS.iter().any(|marker| padded.contains(marker))
}

fn query_expresses_command_execution_intent(query: &str, query_facets: &QueryFacetProfile) -> bool {
    query_facets.goal.command_hits > 0
        || query_facets.goal.workspace_hits > 0
        || query_facets.goal.install_hits > 0
        || query_has_timer_scheduling_shape(query)
}

fn query_binding_satisfied(
    entry: &IntentMatrixEntry,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if query_requires_remote_public_fact_grounding(query_facets)
        && !intent_supports_remote_public_fact_grounding(entry)
    {
        return false;
    }
    match query_binding_for_intent(entry) {
        IntentQueryBindingClass::None => true,
        IntentQueryBindingClass::HostLocal => {
            query_explicitly_targets_host_local_clock(query)
                || !query_requires_remote_public_fact_grounding(query_facets)
        }
        IntentQueryBindingClass::RemotePublicFact => {
            query_requires_remote_public_fact_grounding(query_facets)
        }
        IntentQueryBindingClass::CommandDirected => {
            query_expresses_command_execution_intent(query, query_facets)
        }
    }
}

fn resolve_band(score: f32, policy: &IntentRoutingPolicy) -> IntentConfidenceBand {
    let high = policy
        .confidence
        .high_threshold_bps
        .max(policy.confidence.medium_threshold_bps)
        .min(10_000);
    let medium = policy.confidence.medium_threshold_bps.min(high);
    let score_bps = score_to_bps(score);
    if score_bps >= high {
        IntentConfidenceBand::High
    } else if score_bps >= medium {
        IntentConfidenceBand::Medium
    } else {
        IntentConfidenceBand::Low
    }
}

fn valid_preferred_tier_label(label: &str) -> bool {
    matches!(label, "tool_first" | "ax_first" | "visual_last")
}

fn effective_matrix(
    policy: &IntentRoutingPolicy,
) -> Result<Vec<IntentMatrixEntry>, TransactionError> {
    let mut merged = BTreeMap::<String, IntentMatrixEntry>::new();
    for entry in &policy.matrix {
        let intent_id = entry.intent_id.trim();
        if intent_id.is_empty() {
            return Err(TransactionError::Invalid(
                "ERROR_CLASS=OntologyViolation Intent matrix contains empty intent_id".to_string(),
            ));
        }
        let preferred_tier = entry.preferred_tier.trim();
        if !valid_preferred_tier_label(preferred_tier) {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has unsupported preferred_tier '{}'",
                intent_id, entry.preferred_tier
            )));
        }
        let semantic_descriptor = entry.semantic_descriptor.trim();
        if semantic_descriptor.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has empty semantic_descriptor",
                intent_id
            )));
        }
        let risk_class = entry.risk_class.trim();
        if risk_class.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has empty risk_class",
                intent_id
            )));
        }
        let mut normalized = entry.clone();
        normalized.intent_id = intent_id.to_string();
        normalized.semantic_descriptor = semantic_descriptor.to_string();
        normalized.risk_class = risk_class.to_string();
        normalized.preferred_tier = preferred_tier.to_string();
        normalized.required_capabilities = normalized
            .required_capabilities
            .iter()
            .filter_map(|capability| {
                let value = capability.0.trim();
                (!value.is_empty()).then_some(CapabilityId::from(value))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if merged
            .insert(normalized.intent_id.clone(), normalized)
            .is_some()
        {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent matrix contains duplicate intent_id '{}'",
                intent_id
            )));
        }
    }
    Ok(merged.into_values().collect())
}

fn matrix_source_hash(
    policy: &IntentRoutingPolicy,
    matrix: &[IntentMatrixEntry],
) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "matrix_version": policy.matrix_version,
        "matrix": matrix,
        "score_quantization_bps": quantization_step_bps(policy),
        "tie_region_eps_bps": tie_region_eps_bps(policy),
        "ambiguity_margin_bps": ambiguity_margin_bps(policy),
        "ambiguity_abstain_exempt_intents": policy.ambiguity_abstain_exempt_intents,
    });
    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn hash_payload(payload: &serde_json::Value) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn intent_set_hash(matrix: &[IntentMatrixEntry]) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "intents": matrix.iter().map(|entry| json!({
            "intent_id": entry.intent_id,
            "semantic_descriptor": entry.semantic_descriptor,
            "required_capabilities": entry.required_capabilities,
            "risk_class": entry.risk_class,
        })).collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

fn tool_registry_hash(bindings: &[ToolCapabilityBinding]) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "bindings": bindings.iter().map(|binding| json!({
            "tool_name": binding.tool_name,
            "action_target": binding.action_target.canonical_label(),
            "capabilities": binding.capabilities,
        })).collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

fn capability_ontology_hash(
    bindings: &[ToolCapabilityBinding],
) -> Result<[u8; 32], TransactionError> {
    let mut capability_ids = BTreeSet::<String>::new();
    for binding in bindings {
        for capability in &binding.capabilities {
            capability_ids.insert(capability.0.clone());
        }
    }
    let payload = json!({
        "capabilities": capability_ids.into_iter().collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

fn receipt_hash(
    query: &str,
    normalized_query: &str,
    resolved: &ResolvedIntentState,
    policy: &IntentRoutingPolicy,
    session_id: Option<[u8; 32]>,
    active_window_title: &str,
) -> Result<[u8; 32], TransactionError> {
    let query_hash =
        sha256(query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let normalized_query_hash = sha256(normalized_query.as_bytes())
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let payload = json!({
        "contract_version": CIRC_CONTRACT_VERSION,
        "query": query,
        "query_hash": hex::encode(query_hash.as_ref()),
        "normalized_query": normalized_query,
        "normalized_query_hash": hex::encode(normalized_query_hash.as_ref()),
        "query_normalization_version": resolved.query_normalization_version,
        "session_id": session_id.map(hex::encode),
        "active_window_title": active_window_title,
        "intent_id": resolved.intent_id,
        "scope": resolved.scope,
        "band": resolved.band,
        "score": resolved.score,
        "top_k": resolved.top_k,
        "required_capabilities": resolved.required_capabilities,
        "risk_class": resolved.risk_class,
        "preferred_tier": resolved.preferred_tier,
        "matrix_version": resolved.matrix_version,
        "embedding_model_id": resolved.embedding_model_id,
        "embedding_model_version": resolved.embedding_model_version,
        "similarity_function_id": resolved.similarity_function_id,
        "intent_set_hash": hex::encode(resolved.intent_set_hash),
        "tool_registry_hash": hex::encode(resolved.tool_registry_hash),
        "capability_ontology_hash": hex::encode(resolved.capability_ontology_hash),
        "matrix_source_hash": hex::encode(resolved.matrix_source_hash),
        "score_quantization_bps": quantization_step_bps(policy),
        "tie_region_eps_bps": tie_region_eps_bps(policy),
        "ambiguity_margin_bps": ambiguity_margin_bps(policy),
        "selected_intent_id": resolved.intent_id,
        "selected_score_quantized": resolved.score,
        "ambiguity_abstain_exempt_intents": policy.ambiguity_abstain_exempt_intents,
        "constrained": resolved.constrained,
    });
    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn emit_intent_resolution_receipt(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    resolved: &ResolvedIntentState,
    error_class: Option<String>,
) {
    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::IntentResolutionReceipt(
            IntentResolutionReceiptEvent {
                contract_version: CIRC_CONTRACT_VERSION.to_string(),
                session_id: Some(session_id),
                intent_id: resolved.intent_id.clone(),
                selected_intent_id: resolved.intent_id.clone(),
                scope: resolved.scope,
                band: resolved.band,
                score: resolved.score,
                selected_score_quantized: resolved.score,
                top_k: resolved.top_k.clone(),
                preferred_tier: resolved.preferred_tier.clone(),
                matrix_version: resolved.matrix_version.clone(),
                embedding_model_id: resolved.embedding_model_id.clone(),
                embedding_model_version: resolved.embedding_model_version.clone(),
                similarity_function_id: resolved.similarity_function_id.clone(),
                intent_set_hash: resolved.intent_set_hash,
                tool_registry_hash: resolved.tool_registry_hash,
                capability_ontology_hash: resolved.capability_ontology_hash,
                query_normalization_version: resolved.query_normalization_version.clone(),
                matrix_source_hash: resolved.matrix_source_hash,
                receipt_hash: resolved.receipt_hash,
                error_class,
                constrained: resolved.constrained,
            },
        ));
    }
}

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

fn sort_scores_desc(scores: &mut [IntentCandidateScore]) {
    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.intent_id.cmp(&b.intent_id))
    });
}

fn quantize_and_sort_scores(scores: &mut [IntentCandidateScore], policy: &IntentRoutingPolicy) {
    for score in scores.iter_mut() {
        score.score = quantize_score(score.score, policy);
    }
    sort_scores_desc(scores);
}

fn select_deterministic_winner(
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

fn should_abstain_for_ambiguity(
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

fn all_candidate_scores_zero(scores: &[IntentCandidateScore]) -> bool {
    !scores.is_empty()
        && scores
            .iter()
            .all(|candidate| candidate.score <= f32::EPSILON)
}

fn zero_ranked_candidates(matrix: &[IntentMatrixEntry]) -> Vec<IntentCandidateScore> {
    matrix
        .iter()
        .map(|entry| IntentCandidateScore {
            intent_id: entry.intent_id.clone(),
            score: 0.0,
        })
        .collect()
}

fn canonical_descriptor_for_entry(entry: &IntentMatrixEntry) -> String {
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

async fn ensure_intent_prototypes(
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

fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
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

fn vm_error_to_tx(err: VmError) -> TransactionError {
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

fn scope_for_intent(matrix: &[IntentMatrixEntry], intent_id: &str) -> Option<IntentScopeProfile> {
    matrix
        .iter()
        .find(|entry| entry.intent_id == intent_id)
        .map(|entry| entry.scope)
}

fn preferred_tier_for_intent(matrix: &[IntentMatrixEntry], intent_id: &str) -> Option<String> {
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

fn capability(id: &str) -> CapabilityId {
    CapabilityId::from(id)
}

fn tool_capability_bindings() -> Vec<ToolCapabilityBinding> {
    vec![
        ToolCapabilityBinding {
            tool_name: "agent__complete".to_string(),
            action_target: ActionTarget::Custom("agent__complete".to_string()),
            capabilities: vec![capability("agent.lifecycle")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__pause".to_string(),
            action_target: ActionTarget::Custom("agent__pause".to_string()),
            capabilities: vec![capability("agent.lifecycle")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__await_result".to_string(),
            action_target: ActionTarget::Custom("agent__await_result".to_string()),
            capabilities: vec![
                capability("agent.lifecycle"),
                capability("delegation.manage"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "chat__reply".to_string(),
            action_target: ActionTarget::Custom("chat__reply".to_string()),
            capabilities: vec![capability("conversation.reply")],
        },
        ToolCapabilityBinding {
            tool_name: "math__eval".to_string(),
            action_target: ActionTarget::Custom("math::eval".to_string()),
            capabilities: vec![capability("conversation.reply")],
        },
        ToolCapabilityBinding {
            tool_name: "system__fail".to_string(),
            action_target: ActionTarget::Custom("system__fail".to_string()),
            capabilities: vec![capability("system.failure")],
        },
        ToolCapabilityBinding {
            tool_name: "memory__search".to_string(),
            action_target: ActionTarget::Custom("memory::search".to_string()),
            capabilities: vec![capability("memory.access")],
        },
        ToolCapabilityBinding {
            tool_name: "memory__inspect".to_string(),
            action_target: ActionTarget::Custom("memory::inspect".to_string()),
            capabilities: vec![capability("memory.access")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__delegate".to_string(),
            action_target: ActionTarget::Custom("agent__delegate".to_string()),
            capabilities: vec![capability("delegation.manage")],
        },
        ToolCapabilityBinding {
            tool_name: "computer".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__click".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__type".to_string(),
            action_target: ActionTarget::GuiType,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__scroll".to_string(),
            action_target: ActionTarget::GuiScroll,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__snapshot".to_string(),
            action_target: ActionTarget::GuiInspect,
            capabilities: vec![capability("ui.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__click_element".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "ui__find".to_string(),
            action_target: ActionTarget::Custom("ui::find".to_string()),
            capabilities: vec![capability("ui.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "os__focus_window".to_string(),
            action_target: ActionTarget::WindowFocus,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "os__copy".to_string(),
            action_target: ActionTarget::ClipboardWrite,
            capabilities: vec![capability("clipboard.write")],
        },
        ToolCapabilityBinding {
            tool_name: "os__paste".to_string(),
            action_target: ActionTarget::ClipboardRead,
            capabilities: vec![capability("clipboard.read")],
        },
        ToolCapabilityBinding {
            tool_name: "os__launch_app".to_string(),
            action_target: ActionTarget::Custom("os::launch_app".to_string()),
            capabilities: vec![capability("app.launch")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__read_file".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__list_directory".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__search".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__write_file".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__patch".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__delete_path".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__create_directory".to_string(),
            action_target: ActionTarget::Custom("filesystem__create_directory".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__move_path".to_string(),
            action_target: ActionTarget::Custom("filesystem__move_path".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__copy_path".to_string(),
            action_target: ActionTarget::Custom("filesystem__copy_path".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec"), capability("command.probe")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec_session".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec"), capability("command.probe")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec_session_reset".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__change_directory".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__install_package".to_string(),
            action_target: ActionTarget::SysInstallPackage,
            capabilities: vec![capability("system.install_package")],
        },
        ToolCapabilityBinding {
            tool_name: "web__search".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "web__read".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "net__fetch".to_string(),
            action_target: ActionTarget::NetFetch,
            capabilities: vec![capability("net.fetch")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__navigate".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__snapshot".to_string(),
            action_target: ActionTarget::BrowserInspect,
            capabilities: vec![capability("browser.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__click".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__click_element".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__synthetic_click".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__scroll".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__type".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__key".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
    ]
}

fn is_mail_connector_tool(tool_name: &str) -> bool {
    tool_name.starts_with("wallet_network__mail_")
        || tool_name.starts_with("wallet_mail_")
        || tool_name.starts_with("mail__")
}

fn tool_capabilities(tool_name: &str) -> Vec<CapabilityId> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return vec![];
    }

    for binding in tool_capability_bindings() {
        if binding.tool_name == normalized {
            return binding.capabilities;
        }
    }

    if matches!(
        normalized.as_str(),
        "agent__complete" | "agent__pause" | "agent__await_result" | "agent__await"
    ) {
        return vec![capability("agent.lifecycle")];
    }
    if normalized == "chat__reply" {
        return vec![capability("conversation.reply")];
    }
    if normalized == "system__fail" {
        return vec![capability("system.failure")];
    }
    if normalized.starts_with("memory__") {
        return vec![capability("memory.access")];
    }
    if normalized.starts_with("agent__delegate") {
        return vec![capability("delegation.manage")];
    }
    if is_mail_connector_tool(&normalized) {
        return vec![capability("conversation.reply")];
    }
    vec![]
}

fn policy_explicitly_blocks_target(rules: &ActionRules, target: &ActionTarget) -> bool {
    let canonical = target.canonical_label();
    rules.rules.iter().any(|rule| {
        rule.action == Verdict::Block && (rule.target == "*" || rule.target == canonical)
    })
}

fn policy_blocks_tool(rules: &ActionRules, binding: &ToolCapabilityBinding) -> bool {
    policy_explicitly_blocks_target(rules, &binding.action_target)
}

fn capability_satisfiable(
    capability: &CapabilityId,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
) -> bool {
    bindings.iter().any(|binding| {
        !policy_blocks_tool(rules, binding) && binding.capabilities.iter().any(|c| c == capability)
    })
}

fn capability_known(capability: &CapabilityId, bindings: &[ToolCapabilityBinding]) -> bool {
    bindings
        .iter()
        .any(|binding| binding.capabilities.iter().any(|c| c == capability))
}

fn intent_feasible_without_policy(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if !query_binding_satisfied(entry, query, query_facets) {
        return false;
    }
    if entry.required_capabilities.is_empty() {
        return true;
    }
    entry
        .required_capabilities
        .iter()
        .all(|required| capability_known(required, bindings))
}

fn intent_feasible_for_execution(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if !query_binding_satisfied(entry, query, query_facets) {
        return false;
    }
    if entry.required_capabilities.is_empty() {
        return true;
    }
    entry
        .required_capabilities
        .iter()
        .all(|required| capability_satisfiable(required, bindings, rules))
}

fn infer_unclassified_error_class(
    ranked_candidates: &[IntentCandidateScore],
    matrix: &[IntentMatrixEntry],
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> String {
    if ranked_candidates.is_empty() || all_candidate_scores_zero(ranked_candidates) {
        return "IntentUnclassified".to_string();
    }

    let ranked_entries = ranked_candidates
        .iter()
        .filter_map(|candidate| {
            matrix
                .iter()
                .find(|entry| entry.intent_id == candidate.intent_id)
        })
        .collect::<Vec<_>>();

    if ranked_entries.is_empty() {
        return "ResolverContractViolation".to_string();
    }

    let has_policy_block = ranked_entries.iter().any(|entry| {
        intent_feasible_without_policy(entry, bindings, query, query_facets)
            && !intent_feasible_for_execution(entry, bindings, rules, query, query_facets)
    });
    if has_policy_block {
        return "PolicyBlocked".to_string();
    }

    "IntentInfeasible".to_string()
}

pub fn is_tool_allowed_for_resolution(
    resolved: Option<&ResolvedIntentState>,
    tool_name: &str,
) -> bool {
    let Some(resolved) = resolved else {
        return false;
    };
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized == "system__fail" {
        return true;
    }
    let tool_caps = tool_capabilities(tool_name);
    if tool_caps.is_empty() {
        return false;
    }
    if resolved.required_capabilities.is_empty() {
        return false;
    }
    tool_caps.iter().any(|tool_cap| {
        resolved
            .required_capabilities
            .iter()
            .any(|required| required == tool_cap)
    })
}

pub async fn resolve_step_intent(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    rules: &ActionRules,
    active_window_title: &str,
) -> Result<ResolvedIntentState, TransactionError> {
    let policy = &rules.ontology_policy.intent_routing;
    if !policy.enabled {
        return Ok(ResolvedIntentState {
            intent_id: "resolver.disabled".to_string(),
            scope: IntentScopeProfile::Unknown,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![IntentCandidateScore {
                intent_id: "resolver.disabled".to_string(),
                score: 1.0,
            }],
            required_capabilities: vec![],
            risk_class: "unknown".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: policy.matrix_version.clone(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: INTENT_QUERY_NORMALIZATION_VERSION.to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        });
    }

    let latest_user_message = service
        .hydrate_session_history(agent_state.session_id)
        .ok()
        .and_then(|history| {
            history
                .iter()
                .rfind(|m| m.role == "user")
                .map(|m| m.content.clone())
        })
        .unwrap_or_else(|| agent_state.goal.clone());

    let query = if latest_user_message.trim().is_empty() {
        agent_state.goal.clone()
    } else {
        latest_user_message
    };
    let normalized_query = normalize_query_for_ranking(&query);
    let ranking_query = if normalized_query.trim().is_empty() {
        query.clone()
    } else {
        normalized_query.clone()
    };
    let query_facets = analyze_query_facets(&query);
    let session_prefix = hex::encode(&agent_state.session_id[..4]);
    let query_hash = hex::encode(
        sha256(query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?,
    );
    let normalized_query_hash = hex::encode(
        sha256(ranking_query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?,
    );
    let raw_enabled = super::helpers::should_log_raw_prompt_content();
    if raw_enabled {
        let query_json = serde_json::to_string(&query)
            .unwrap_or_else(|_| "\"<query-serialization-error>\"".to_string());
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} normalized_query_hash={} normalization_version={} query_json={}",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash,
            normalized_query_hash,
            INTENT_QUERY_NORMALIZATION_VERSION,
            query_json
        );
    } else {
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} normalized_query_hash={} normalization_version={} query_json=<omitted:raw_prompt_disabled>",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash,
            normalized_query_hash,
            INTENT_QUERY_NORMALIZATION_VERSION
        );
    }
    let matrix = effective_matrix(policy)?;
    let matrix_hash = matrix_source_hash(policy, &matrix)?;
    let bindings = tool_capability_bindings();
    let intent_hash = intent_set_hash(&matrix)?;
    let registry_hash = tool_registry_hash(&bindings)?;
    let ontology_hash = capability_ontology_hash(&bindings)?;
    if matrix.is_empty() {
        log::warn!(
            "IntentResolver matrix is empty for version={}, abstaining.",
            policy.matrix_version
        );
    }

    let runtime = service.reasoning_inference.clone();
    let prototypes_ready = match timeout(
        INTENT_PROTOTYPE_BUILD_TIMEOUT,
        ensure_intent_prototypes(&runtime, &policy.matrix_version, matrix_hash, &matrix),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            log::warn!(
                "IntentResolver prototype build failed session={} error={}",
                session_prefix,
                e
            );
            false
        }
        Err(_) => {
            log::warn!(
                "IntentResolver prototype build timed out session={} timeout_ms={}",
                session_prefix,
                INTENT_PROTOTYPE_BUILD_TIMEOUT.as_millis()
            );
            false
        }
    };

    let mut ranked_candidates = if prototypes_ready {
        match timeout(
            INTENT_EMBED_RANK_TIMEOUT,
            runtime.embed_or_rank(&ranking_query, &policy.matrix_version, matrix_hash, &matrix),
        )
        .await
        {
            Ok(Ok(scores)) => scores,
            Ok(Err(e)) => {
                log::warn!(
                    "IntentResolver embedding rank failed session={} error={}",
                    session_prefix,
                    e
                );
                vec![]
            }
            Err(_) => {
                log::warn!(
                    "IntentResolver embedding rank timed out session={} timeout_ms={}",
                    session_prefix,
                    INTENT_EMBED_RANK_TIMEOUT.as_millis()
                );
                vec![]
            }
        }
    } else {
        vec![]
    };
    if ranked_candidates.is_empty() && !matrix.is_empty() {
        ranked_candidates = zero_ranked_candidates(&matrix);
    }
    quantize_and_sort_scores(&mut ranked_candidates, policy);
    let routed_top_k = ranked_candidates
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>();
    let selection_top_k = ranked_candidates
        .iter()
        .filter_map(|candidate| {
            let entry = matrix
                .iter()
                .find(|entry| entry.intent_id == candidate.intent_id)?;
            intent_feasible_for_execution(entry, &bindings, rules, &query, &query_facets)
                .then_some(candidate.clone())
        })
        .collect::<Vec<_>>();
    let mut resolver_error_class: Option<String> = None;
    if selection_top_k.is_empty() {
        log::warn!(
            "IntentResolverFeasibility no feasible candidates after capability/policy checks session={}",
            session_prefix
        );
        resolver_error_class = Some(infer_unclassified_error_class(
            &ranked_candidates,
            &matrix,
            &bindings,
            rules,
            &query,
            &query_facets,
        ));
    }
    let unclassified = selection_top_k.is_empty() || all_candidate_scores_zero(&selection_top_k);
    if unclassified && resolver_error_class.is_none() {
        resolver_error_class = Some("IntentUnclassified".to_string());
    }
    let mut winner = if unclassified {
        IntentCandidateScore {
            intent_id: "resolver.unclassified".to_string(),
            score: 0.0,
        }
    } else {
        select_deterministic_winner(&selection_top_k, &matrix, policy).unwrap_or(
            IntentCandidateScore {
                intent_id: "resolver.unclassified".to_string(),
                score: 0.0,
            },
        )
    };
    if winner.intent_id != "resolver.unclassified"
        && should_abstain_for_ambiguity(&selection_top_k, &winner, policy)
        && !is_ambiguity_abstain_exempt(policy, &winner.intent_id)
    {
        log::info!(
            "IntentResolverAmbiguityAbstain session={} winner={} score={:.3} ambiguity_margin_bps={}",
            session_prefix,
            winner.intent_id,
            winner.score,
            ambiguity_margin_bps(policy)
        );
        winner = IntentCandidateScore {
            intent_id: "resolver.unclassified".to_string(),
            score: 0.0,
        };
        resolver_error_class = Some("IntentUnclassified".to_string());
    }

    let (scope, preferred_tier, score, band, required_capabilities, risk_class) = if winner
        .intent_id
        == "resolver.unclassified"
    {
        (
            IntentScopeProfile::Unknown,
            "tool_first".to_string(),
            0.0,
            IntentConfidenceBand::Low,
            vec![],
            "unknown".to_string(),
        )
    } else {
        let entry = matrix
            .iter()
            .find(|entry| entry.intent_id == winner.intent_id)
            .ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=ResolverContractViolation Intent '{}' missing matrix binding",
                    winner.intent_id
                ))
            })?;
        let scope = scope_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation Intent '{}' missing matrix scope binding",
                winner.intent_id
            ))
        })?;
        let preferred_tier =
                preferred_tier_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=ResolverContractViolation Intent '{}' missing preferred tier binding",
                        winner.intent_id
                    ))
                })?;
        let score = winner.score.clamp(0.0, 1.0);
        (
            scope,
            preferred_tier,
            score,
            resolve_band(score, policy),
            entry.required_capabilities.clone(),
            entry.risk_class.clone(),
        )
    };
    let mut resolved = ResolvedIntentState {
        intent_id: winner.intent_id,
        scope,
        band,
        score,
        top_k: routed_top_k,
        required_capabilities,
        risk_class,
        preferred_tier,
        matrix_version: policy.matrix_version.clone(),
        embedding_model_id: INTENT_EMBEDDING_MODEL_ID.to_string(),
        embedding_model_version: INTENT_EMBEDDING_MODEL_VERSION.to_string(),
        similarity_function_id: INTENT_SIMILARITY_FUNCTION_ID.to_string(),
        intent_set_hash: intent_hash,
        tool_registry_hash: registry_hash,
        capability_ontology_hash: ontology_hash,
        query_normalization_version: INTENT_QUERY_NORMALIZATION_VERSION.to_string(),
        matrix_source_hash: matrix_hash,
        receipt_hash: [0u8; 32],
        // Constrained routing is deprecated (compat field only). We rely on policy gates + ontology.
        constrained: false,
    };
    resolved.receipt_hash = receipt_hash(
        &query,
        &ranking_query,
        &resolved,
        policy,
        Some(agent_state.session_id),
        active_window_title,
    )?;

    emit_intent_resolution_receipt(
        service,
        agent_state.session_id,
        &resolved,
        resolver_error_class,
    );

    Ok(resolved)
}

#[cfg(test)]
#[path = "intent_resolver/tests/mod.rs"]
mod tests;
