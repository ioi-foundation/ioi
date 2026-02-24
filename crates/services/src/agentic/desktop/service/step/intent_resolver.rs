use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::rules::{ActionRules, Verdict};
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    CapabilityId, IntentAmbiguityAction, IntentCandidateScore, IntentConfidenceBand,
    IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile, ResolvedIntentState,
    ToolCapabilityBinding,
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
                "Intent matrix contains empty intent_id".to_string(),
            ));
        }
        let preferred_tier = entry.preferred_tier.trim();
        if !valid_preferred_tier_label(preferred_tier) {
            return Err(TransactionError::Invalid(format!(
                "Intent '{}' has unsupported preferred_tier '{}'",
                intent_id, entry.preferred_tier
            )));
        }
        let semantic_descriptor = entry.semantic_descriptor.trim();
        if semantic_descriptor.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "Intent '{}' has empty semantic_descriptor",
                intent_id
            )));
        }
        let risk_class = entry.risk_class.trim();
        if risk_class.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "Intent '{}' has empty risk_class",
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
                "Intent matrix contains duplicate intent_id '{}'",
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
) {
    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::IntentResolutionReceipt(
            IntentResolutionReceiptEvent {
                session_id: Some(session_id),
                intent_id: resolved.intent_id.clone(),
                scope: resolved.scope,
                band: resolved.band,
                score: resolved.score,
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

fn scope_feasible_for_query(scope: IntentScopeProfile, locality_scope_required: bool) -> bool {
    if locality_scope_required {
        return matches!(scope, IntentScopeProfile::WebResearch);
    }
    true
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
            "Intent prototype cache incomplete: missing [{}]",
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
    let mut cache = intent_prototype_cache()
        .write()
        .map_err(|_| TransactionError::Invalid("Intent prototype cache poisoned".to_string()))?;
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
                TransactionError::Invalid("Intent prototype cache poisoned".to_string())
            })?;
            cache.get(&key).cloned().ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "Intent prototype cache miss matrix_version={} matrix_source_hash={}",
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
            action_target: ActionTarget::SysExec,
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
            capabilities: vec![capability("web.retrieve")],
        },
        ToolCapabilityBinding {
            tool_name: "web__read".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve")],
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

fn intent_feasible_for_execution(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    locality_scope_required: bool,
) -> bool {
    if !scope_feasible_for_query(entry.scope, locality_scope_required) {
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
    let locality_scope_required =
        super::queue::query_requires_runtime_locality_scope(&ranking_query);
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
            intent_feasible_for_execution(entry, &bindings, rules, locality_scope_required)
                .then_some(candidate.clone())
        })
        .collect::<Vec<_>>();
    if selection_top_k.is_empty() {
        log::warn!(
            "IntentResolverFeasibility no feasible candidates after capability/policy checks session={}",
            session_prefix
        );
    }
    let unclassified = selection_top_k.is_empty() || all_candidate_scores_zero(&selection_top_k);
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
    }

    let (scope, preferred_tier, score, band, required_capabilities, risk_class) =
        if winner.intent_id == "resolver.unclassified" {
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
                        "Intent '{}' missing matrix binding",
                        winner.intent_id
                    ))
                })?;
            let scope = scope_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "Intent '{}' missing matrix scope binding",
                    winner.intent_id
                ))
            })?;
            let preferred_tier =
                preferred_tier_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "Intent '{}' missing preferred tier binding",
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

    emit_intent_resolution_receipt(service, agent_state.session_id, &resolved);

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::{
        is_tool_allowed_for_resolution, resolve_band, resolve_step_intent,
        should_pause_for_clarification,
    };
    use crate::agentic::desktop::service::DesktopAgentService;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use crate::agentic::rules::ActionRules;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::agentic::{
        CapabilityId, InferenceOptions, IntentAmbiguityAction, IntentConfidenceBand,
        IntentConfidenceBandPolicy, IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile,
        ResolvedIntentState,
    };
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
    use std::path::Path;
    use std::sync::Arc;

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct ClockIntentRuntime;

    #[async_trait]
    impl InferenceRuntime for ClockIntentRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let text_lc = text.to_ascii_lowercase();
            if text_lc.contains("clock")
                || text_lc.contains("timestamp")
                || text_lc.contains("time is it")
            {
                return Ok(vec![1.0, 0.0, 0.0]);
            }
            if text_lc.contains("web")
                || text_lc.contains("research")
                || text_lc.contains("weather")
                || text_lc.contains("timer")
                || text_lc.contains("countdown")
            {
                return Ok(vec![0.0, 1.0, 0.0]);
            }
            if text_lc.contains("command")
                || text_lc.contains("terminal")
                || text_lc.contains("shell")
            {
                return Ok(vec![0.0, 0.0, 1.0]);
            }
            Ok(vec![0.0, 0.0, 1.0])
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct NoEmbeddingRuntime;

    #[async_trait]
    impl InferenceRuntime for NoEmbeddingRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Err(VmError::HostError("embeddings unavailable".to_string()))
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct WeatherVsClockRuntime;

    #[async_trait]
    impl InferenceRuntime for WeatherVsClockRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let text_lc = text.to_ascii_lowercase();
            let web_terms = [
                "web",
                "research",
                "online",
                "internet",
                "weather",
                "forecast",
                "temperature",
                "humidity",
                "wind",
                "status",
                "stock",
                "score",
            ];
            let clock_terms = ["time", "clock", "utc", "timestamp"];

            let mut web_score = 0.0f32;
            for term in web_terms {
                if text_lc.contains(term) {
                    web_score += 1.0;
                }
            }

            let mut clock_score = 0.0f32;
            for term in clock_terms {
                if text_lc.contains(term) {
                    clock_score += 1.0;
                }
            }

            if web_score == 0.0 && clock_score == 0.0 {
                return Ok(vec![0.1, 0.1, 1.0]);
            }

            Ok(vec![web_score, clock_score, 0.0])
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct TimerIntentRuntime;

    #[async_trait]
    impl InferenceRuntime for TimerIntentRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let text_lc = text.to_ascii_lowercase();
            if text_lc.contains("timer") || text_lc.contains("countdown") {
                return Ok(vec![1.0, 0.0, 0.0]);
            }
            if text_lc.contains("clock") || text_lc.contains("timestamp") {
                return Ok(vec![0.0, 1.0, 0.0]);
            }
            Ok(vec![0.0, 0.0, 1.0])
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct LocalitySkewedRuntime;

    #[async_trait]
    impl InferenceRuntime for LocalitySkewedRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let text_lc = text.to_ascii_lowercase();
            if text_lc.contains("system clock") || text_lc.contains("clock timestamp") {
                return Ok(vec![1.0, 0.0]);
            }
            if text_lc.contains("web") && text_lc.contains("research") {
                return Ok(vec![0.0, 1.0]);
            }
            if text_lc.contains("weather") {
                // Deliberately skew weather queries toward the clock vector so
                // we can assert no forced winner overrides are applied.
                return Ok(vec![0.95, 0.05]);
            }
            if text_lc.contains("time") || text_lc.contains("clock") {
                return Ok(vec![1.0, 0.0]);
            }
            Ok(vec![0.1, 0.1])
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct AmbiguousRuntime;

    #[async_trait]
    impl InferenceRuntime for AmbiguousRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(Vec::new())
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let text_lc = text.to_ascii_lowercase();
            if text_lc.contains("system clock") || text_lc.contains("clock timestamp") {
                return Ok(vec![1.0, 0.0]);
            }
            if text_lc.contains("shell or terminal")
                || (text_lc.contains("command") && text_lc.contains("execute"))
            {
                return Ok(vec![0.0, 1.0]);
            }
            if text_lc.contains("ambiguous clock command intent") {
                return Ok(vec![1.0, 1.0]);
            }
            Ok(vec![0.0, 0.0])
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "check and see if we have gimp installed".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            active_lens: None,
            command_history: Default::default(),
        }
    }

    #[test]
    fn conversation_scope_blocks_browser() {
        let state = ResolvedIntentState {
            intent_id: "conversation.reply".to_string(),
            scope: IntentScopeProfile::Conversation,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("conversation.reply")],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(!is_tool_allowed_for_resolution(
            Some(&state),
            "browser__navigate"
        ));
        assert!(!is_tool_allowed_for_resolution(Some(&state), "os__copy"));
        assert!(!is_tool_allowed_for_resolution(Some(&state), "os__paste"));
        assert!(is_tool_allowed_for_resolution(Some(&state), "chat__reply"));
        assert!(is_tool_allowed_for_resolution(
            Some(&state),
            "wallet_network__mail_reply"
        ));
        assert!(!is_tool_allowed_for_resolution(None, "browser__navigate"));
    }

    #[test]
    fn unregistered_prefixed_tools_do_not_gain_capabilities_by_name_shape() {
        let state = ResolvedIntentState {
            intent_id: "command.exec".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("command.exec")],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(!is_tool_allowed_for_resolution(
            Some(&state),
            "sys__nonexistent_custom_tool"
        ));
        assert!(!is_tool_allowed_for_resolution(
            Some(&state),
            "browser__unregistered_op"
        ));
    }

    #[test]
    fn ui_interaction_scope_allows_clipboard() {
        let state = ResolvedIntentState {
            intent_id: "ui.interact".to_string(),
            scope: IntentScopeProfile::UiInteraction,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("clipboard.read"),
                CapabilityId::from("clipboard.write"),
            ],
            risk_class: "low".to_string(),
            preferred_tier: "visual_last".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
    }

    #[test]
    fn command_execution_scope_allows_clipboard() {
        let state = ResolvedIntentState {
            intent_id: "command.exec".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("clipboard.read"),
                CapabilityId::from("clipboard.write"),
            ],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
    }

    #[test]
    fn workspace_ops_scope_allows_clipboard() {
        let state = ResolvedIntentState {
            intent_id: "workspace.ops".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("clipboard.read"),
                CapabilityId::from("clipboard.write"),
            ],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
        assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
    }

    #[test]
    fn confidence_thresholds_map_bands() {
        let mut policy = IntentRoutingPolicy::default();
        policy.confidence = IntentConfidenceBandPolicy {
            high_threshold_bps: 7_000,
            medium_threshold_bps: 4_500,
        };
        assert_eq!(resolve_band(0.91, &policy), IntentConfidenceBand::High);
        assert_eq!(resolve_band(0.52, &policy), IntentConfidenceBand::Medium);
        assert_eq!(resolve_band(0.2, &policy), IntentConfidenceBand::Low);
    }

    #[test]
    fn pause_policy_applies_to_medium_confidence_band() {
        let mut policy = IntentRoutingPolicy::default();
        policy.ambiguity.low_confidence_action = IntentAmbiguityAction::Proceed;
        policy.ambiguity.medium_confidence_action = IntentAmbiguityAction::PauseForClarification;

        let resolved = ResolvedIntentState {
            intent_id: "command.exec".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::Medium,
            score: 0.61,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("command.exec")],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        };

        assert!(should_pause_for_clarification(&resolved, &policy));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_never_emits_constrained_true() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let agent_state = test_agent_state();

        let mut rules = ActionRules::default();
        rules
            .ontology_policy
            .intent_routing
            .ambiguity
            .medium_confidence_action = IntentAmbiguityAction::ConstrainedProceed;
        rules
            .ontology_policy
            .intent_routing
            .ambiguity
            .low_confidence_action = IntentAmbiguityAction::ConstrainedProceed;

        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert!(!resolved.constrained);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_routes_clock_queries_to_system_clock_read() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(ClockIntentRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "What time is it right now on this machine?".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-clock-test".into();
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
        assert_eq!(resolved.intent_id, "system.clock.read");
        assert_eq!(
            resolved
                .top_k
                .first()
                .map(|candidate| candidate.intent_id.as_str()),
            Some("system.clock.read")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_routes_weather_queries_to_web_research_not_clock_read() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(WeatherVsClockRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "What's the weather like right now?".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version =
            "intent-matrix-v2-weather-test".into();
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();

        assert_eq!(resolved.intent_id, "web.research");
        assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_routes_timer_queries_to_command_exec() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(TimerIntentRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "Set a timer for 15 minutes".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v4-timer-test".into();
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();

        assert_eq!(resolved.intent_id, "command.exec");
        assert_ne!(resolved.intent_id, "system.clock.read");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_routing_is_not_driven_by_aliases_or_exemplars() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(ClockIntentRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "What time is it right now on this machine?".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version =
            "intent-matrix-v2-metadata-independence-test".into();
        rules.ontology_policy.intent_routing.matrix = vec![
            IntentMatrixEntry {
                intent_id: "web.research".to_string(),
                semantic_descriptor: "retrieve web research results".to_string(),
                required_capabilities: vec![],
                risk_class: "medium".to_string(),
                scope: IntentScopeProfile::WebResearch,
                preferred_tier: "tool_first".to_string(),
                aliases: vec!["clock".to_string(), "time".to_string()],
                exemplars: vec![
                    "what time is it on this machine".to_string(),
                    "read current utc clock timestamp".to_string(),
                ],
            },
            IntentMatrixEntry {
                intent_id: "system.clock.read".to_string(),
                semantic_descriptor: "read system clock timestamp".to_string(),
                required_capabilities: vec![],
                risk_class: "low".to_string(),
                scope: IntentScopeProfile::CommandExecution,
                preferred_tier: "tool_first".to_string(),
                aliases: vec!["weather".to_string()],
                exemplars: vec![
                    "what's the weather like right now".to_string(),
                    "current temperature humidity and wind".to_string(),
                ],
            },
        ];

        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert_eq!(resolved.intent_id, "system.clock.read");
        assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_routes_runtime_locality_queries_to_web_research_scope() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(LocalitySkewedRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "What's the weather like right now?".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version =
            "intent-matrix-v2-runtime-locality-no-forced-override-test".into();
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert_eq!(resolved.intent_id, "web.research");
        assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_abstains_when_embeddings_fail() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(NoEmbeddingRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "What time is it right now?".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version =
            "intent-matrix-v2-no-embed-test".into();
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert_eq!(resolved.intent_id, "resolver.unclassified");
        assert_eq!(resolved.scope, IntentScopeProfile::Unknown);
        assert_eq!(resolved.score, 0.0);
        assert_eq!(resolved.band, IntentConfidenceBand::Low);
        assert!(!resolved.top_k.is_empty());
        assert!(resolved
            .top_k
            .iter()
            .all(|candidate| candidate.score <= f32::EPSILON));
        assert!(should_pause_for_clarification(
            &resolved,
            &rules.ontology_policy.intent_routing
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_abstains_when_top_candidates_are_ambiguous() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(AmbiguousRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let mut agent_state = test_agent_state();
        agent_state.goal = "ambiguous clock command intent".to_string();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.matrix_version =
            "intent-matrix-v2-ambiguity-abstain-test".into();
        rules.ontology_policy.intent_routing.ambiguity_margin_bps = 200;
        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();

        assert_eq!(resolved.intent_id, "resolver.unclassified");
        assert_eq!(resolved.scope, IntentScopeProfile::Unknown);
        assert_eq!(resolved.band, IntentConfidenceBand::Low);
        assert!(resolved
            .top_k
            .iter()
            .any(|candidate| candidate.intent_id == "system.clock.read"));
        assert!(resolved
            .top_k
            .iter()
            .any(|candidate| candidate.intent_id == "command.exec"));
        assert!(should_pause_for_clarification(
            &resolved,
            &rules.ontology_policy.intent_routing
        ));
    }
}
