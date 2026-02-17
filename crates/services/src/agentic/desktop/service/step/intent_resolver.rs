use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::rules::ActionRules;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    InferenceOptions, IntentAmbiguityAction, IntentCandidateScore, IntentConfidenceBand,
    IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{IntentResolutionReceiptEvent, KernelEvent};
use ioi_types::error::{TransactionError, VmError};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

fn fallback_tier_for_scope(scope: IntentScopeProfile) -> &'static str {
    match scope {
        IntentScopeProfile::UiInteraction => "visual_last",
        _ => "tool_first",
    }
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

fn effective_matrix(policy: &IntentRoutingPolicy) -> Vec<IntentMatrixEntry> {
    let mut merged = BTreeMap::<String, IntentMatrixEntry>::new();
    for entry in IntentRoutingPolicy::default().matrix {
        merged.insert(entry.intent_id.clone(), entry);
    }
    for entry in &policy.matrix {
        merged.insert(entry.intent_id.clone(), entry.clone());
    }
    merged.into_values().collect()
}

fn matrix_source_hash(policy: &IntentRoutingPolicy, matrix: &[IntentMatrixEntry]) -> [u8; 32] {
    let payload = json!({
        "matrix_version": policy.matrix_version,
        "matrix": matrix,
    });
    let canonical = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();
    let mut out = [0u8; 32];
    if let Ok(digest) = sha256(&canonical) {
        out.copy_from_slice(digest.as_ref());
    }
    out
}

fn receipt_hash(
    query: &str,
    resolved: &ResolvedIntentState,
    session_id: Option<[u8; 32]>,
    active_window_title: &str,
) -> [u8; 32] {
    let payload = json!({
        "query": query,
        "session_id": session_id.map(hex::encode),
        "active_window_title": active_window_title,
        "intent_id": resolved.intent_id,
        "scope": resolved.scope,
        "band": resolved.band,
        "score": resolved.score,
        "top_k": resolved.top_k,
        "preferred_tier": resolved.preferred_tier,
        "matrix_version": resolved.matrix_version,
        "matrix_source_hash": hex::encode(resolved.matrix_source_hash),
        "constrained": resolved.constrained,
    });
    let canonical = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();
    let mut out = [0u8; 32];
    if let Ok(digest) = sha256(&canonical) {
        out.copy_from_slice(digest.as_ref());
    }
    out
}

#[async_trait]
pub trait IntentRankBackend: Send + Sync {
    async fn embed_or_rank(
        &self,
        query: &str,
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

fn matrix_prompt(query: &str, matrix: &[IntentMatrixEntry]) -> String {
    let candidates = matrix
        .iter()
        .map(|entry| {
            json!({
                "intent_id": entry.intent_id,
                "scope": entry.scope,
                "aliases": entry.aliases,
                "exemplars": entry.exemplars,
            })
        })
        .collect::<Vec<_>>();
    format!(
        "Classify user intent ontologically.\n\
         Input: {}\n\
         Return strict JSON: {{\"scores\":[{{\"intent_id\":\"...\",\"score\":0.0}}]}} where score is 0..1 and includes every candidate.\n\
         Candidates: {}",
        query,
        serde_json::to_string(&candidates).unwrap_or_else(|_| "[]".to_string())
    )
}

#[derive(Debug, Deserialize)]
struct RankedScoresResponse {
    scores: Vec<IntentCandidateScore>,
}

fn vm_error_to_tx(err: VmError) -> TransactionError {
    TransactionError::Invalid(err.to_string())
}

#[async_trait]
impl IntentRankBackend for Arc<dyn InferenceRuntime> {
    async fn embed_or_rank(
        &self,
        query: &str,
        matrix: &[IntentMatrixEntry],
    ) -> Result<Vec<IntentCandidateScore>, TransactionError> {
        if matrix.is_empty() {
            return Ok(vec![]);
        }

        let query_embedding = match self.embed_text(query).await {
            Ok(v) => v,
            // Callers can fall back to an airlocked inference-based ranker.
            Err(_) => return Ok(vec![]),
        };

        let mut scored = Vec::with_capacity(matrix.len());
        for entry in matrix {
            let mut best = -1.0f32;
            let mut exemplars = entry.exemplars.clone();
            exemplars.push(entry.intent_id.clone());
            exemplars.extend(entry.aliases.clone());
            for sample in exemplars {
                let emb = self
                    .embed_text(&sample)
                    .await
                    .map_err(vm_error_to_tx)
                    .unwrap_or_default();
                if let Some(cos) = cosine_similarity(&query_embedding, &emb) {
                    let normalized = ((cos + 1.0) * 0.5).clamp(0.0, 1.0);
                    if normalized > best {
                        best = normalized;
                    }
                }
            }
            scored.push(IntentCandidateScore {
                intent_id: entry.intent_id.clone(),
                score: best.max(0.0),
            });
        }
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(scored)
    }
}

async fn rank_with_airlocked_inference(
    service: &DesktopAgentService,
    session_id: Option<[u8; 32]>,
    runtime: &Arc<dyn InferenceRuntime>,
    query: &str,
    matrix: &[IntentMatrixEntry],
) -> Vec<IntentCandidateScore> {
    if matrix.is_empty() {
        return vec![];
    }

    let prompt = matrix_prompt(query, matrix);
    let options = InferenceOptions {
        temperature: 0.0,
        json_mode: true,
        ..Default::default()
    };
    let model_hash = [0u8; 32];

    let airlocked = match service
        .prepare_cloud_inference_input(
            session_id,
            "desktop_agent",
            &format!("model_hash:{}", hex::encode(model_hash)),
            prompt.as_bytes(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Intent rank fallback airlock rejected payload: {}", e);
            return vec![];
        }
    };

    let ranked = runtime
        .execute_inference(model_hash, &airlocked, options)
        .await
        .map_err(vm_error_to_tx)
        .and_then(|bytes| {
            let raw = String::from_utf8_lossy(&bytes).to_string();
            let parsed: RankedScoresResponse = serde_json::from_str(&raw).map_err(|e| {
                TransactionError::Invalid(format!(
                    "Intent rank fallback parse failed: {} | raw={}",
                    e, raw
                ))
            })?;
            Ok(parsed.scores)
        })
        .unwrap_or_default();

    if ranked.is_empty() {
        return vec![];
    }

    let mut by_id = BTreeMap::<String, f32>::new();
    for score in ranked {
        by_id.insert(score.intent_id, score.score.clamp(0.0, 1.0));
    }
    let mut out = matrix
        .iter()
        .map(|entry| IntentCandidateScore {
            intent_id: entry.intent_id.clone(),
            score: *by_id.get(&entry.intent_id).unwrap_or(&0.0),
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn scope_for_intent(matrix: &[IntentMatrixEntry], intent_id: &str) -> IntentScopeProfile {
    matrix
        .iter()
        .find(|entry| entry.intent_id == intent_id)
        .map(|entry| entry.scope)
        .unwrap_or(IntentScopeProfile::Unknown)
}

fn preferred_tier_for_intent(matrix: &[IntentMatrixEntry], intent_id: &str) -> String {
    matrix
        .iter()
        .find(|entry| entry.intent_id == intent_id)
        .map(|entry| entry.preferred_tier.clone())
        .unwrap_or_else(|| fallback_tier_for_scope(IntentScopeProfile::Unknown).to_string())
}

pub fn should_pause_for_clarification(
    resolved: &ResolvedIntentState,
    policy: &IntentRoutingPolicy,
) -> bool {
    matches!(resolved.band, IntentConfidenceBand::Low)
        && matches!(
            policy.ambiguity.low_confidence_action,
            IntentAmbiguityAction::PauseForClarification
        )
}

pub fn preferred_tier(resolved: &ResolvedIntentState) -> ExecutionTier {
    preferred_tier_from_label(&resolved.preferred_tier, resolved.scope)
}

fn tool_allowed_for_scope(scope: IntentScopeProfile, tool_name: &str) -> bool {
    if matches!(
        tool_name,
        "agent__complete" | "agent__pause" | "agent__await_result" | "agent__await"
    ) {
        return true;
    }
    let is_browser = tool_name.starts_with("browser__");
    let is_filesystem = tool_name.starts_with("filesystem__");
    let is_shell = tool_name == "sys__exec"
        || tool_name == "sys__install_package"
        || tool_name == "sys__change_directory";
    let is_ui = tool_name.starts_with("gui__")
        || tool_name == "computer"
        || tool_name == "ui__find"
        || tool_name == "os__focus_window";
    let is_launch = tool_name == "os__launch_app";
    let is_chat = tool_name == "chat__reply";
    let is_delegate = tool_name.starts_with("agent__delegate");
    let is_system = tool_name == "system__fail";

    match scope {
        IntentScopeProfile::Conversation => is_chat || is_system,
        IntentScopeProfile::WebResearch => is_browser || is_chat || is_system,
        IntentScopeProfile::WorkspaceOps => is_filesystem || is_chat || is_system,
        IntentScopeProfile::AppLaunch => is_launch || is_ui || is_chat || is_system,
        IntentScopeProfile::UiInteraction => {
            is_ui || is_browser || is_chat || is_system || is_launch
        }
        IntentScopeProfile::CommandExecution => is_shell || is_chat || is_system || is_filesystem,
        IntentScopeProfile::Delegation => is_delegate || is_chat || is_system,
        IntentScopeProfile::Unknown => is_chat || is_system,
    }
}

pub fn is_tool_allowed_for_resolution(
    resolved: Option<&ResolvedIntentState>,
    tool_name: &str,
) -> bool {
    let Some(resolved) = resolved else {
        return true;
    };
    tool_allowed_for_scope(resolved.scope, tool_name)
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
            preferred_tier: "tool_first".to_string(),
            matrix_version: policy.matrix_version.clone(),
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
    let session_prefix = hex::encode(&agent_state.session_id[..4]);
    let query_hash = sha256(query.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "sha256_error".to_string());
    let raw_enabled = super::helpers::should_log_raw_prompt_content();
    if raw_enabled {
        let query_json = serde_json::to_string(&query)
            .unwrap_or_else(|_| "\"<query-serialization-error>\"".to_string());
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} query_json={}",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash,
            query_json
        );
    } else {
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} query_json=<omitted:raw_prompt_disabled>",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash
        );
    }
    let matrix = effective_matrix(policy);
    let matrix_hash = matrix_source_hash(policy, &matrix);
    let runtime = service.reasoning_inference.clone();
    let mut top_k = runtime.embed_or_rank(&query, &matrix).await?;
    if top_k.is_empty() {
        // If embeddings are unavailable (or produced no signal), fall back to an
        // inference-based ranker, but run it through the Desktop Agent's cloud airlock.
        top_k = rank_with_airlocked_inference(
            service,
            Some(agent_state.session_id),
            &runtime,
            &query,
            &matrix,
        )
        .await;
    }
    if top_k.is_empty() {
        top_k.push(IntentCandidateScore {
            intent_id: "unknown".to_string(),
            score: 0.0,
        });
    }
    top_k.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let winner = top_k.first().cloned().unwrap_or(IntentCandidateScore {
        intent_id: "unknown".to_string(),
        score: 0.0,
    });
    let scope = scope_for_intent(&matrix, &winner.intent_id);
    let preferred_tier = preferred_tier_for_intent(&matrix, &winner.intent_id);
    let band = resolve_band(winner.score, policy);
    let mut resolved = ResolvedIntentState {
        intent_id: winner.intent_id,
        scope,
        band,
        score: winner.score.clamp(0.0, 1.0),
        top_k: top_k.into_iter().take(5).collect(),
        preferred_tier,
        matrix_version: policy.matrix_version.clone(),
        matrix_source_hash: matrix_hash,
        receipt_hash: [0u8; 32],
        // Constrained routing is deprecated (compat field only). We rely on policy gates + ontology.
        constrained: false,
    };
    resolved.receipt_hash = receipt_hash(
        &query,
        &resolved,
        Some(agent_state.session_id),
        active_window_title,
    );

    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::IntentResolutionReceipt(
            IntentResolutionReceiptEvent {
                session_id: Some(agent_state.session_id),
                intent_id: resolved.intent_id.clone(),
                scope: resolved.scope,
                band: resolved.band,
                score: resolved.score,
                top_k: resolved.top_k.clone(),
                preferred_tier: resolved.preferred_tier.clone(),
                matrix_version: resolved.matrix_version.clone(),
                matrix_source_hash: resolved.matrix_source_hash,
                receipt_hash: resolved.receipt_hash,
                constrained: resolved.constrained,
            },
        ));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::{is_tool_allowed_for_resolution, resolve_band, resolve_step_intent};
    use crate::agentic::desktop::service::DesktopAgentService;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use crate::agentic::rules::ActionRules;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::agentic::{
        IntentAmbiguityAction, IntentConfidenceBand, IntentConfidenceBandPolicy, IntentRoutingPolicy,
        IntentScopeProfile, ResolvedIntentState,
    };
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
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
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        };
        assert!(!is_tool_allowed_for_resolution(
            Some(&state),
            "browser__navigate"
        ));
        assert!(is_tool_allowed_for_resolution(Some(&state), "chat__reply"));
    }

    #[test]
    fn constrained_flag_no_longer_filters_tools() {
        // Simulate older persisted state where constrained=true.
        let state = ResolvedIntentState {
            intent_id: "command.exec".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::Medium,
            score: 0.6,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: true,
        };
        assert!(is_tool_allowed_for_resolution(Some(&state), "sys__exec"));
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

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_never_emits_constrained_true() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let service = DesktopAgentService::new(gui, terminal, browser, inference);

        let agent_state = test_agent_state();

        let mut rules = ActionRules::default();
        rules.ontology_policy.intent_routing.ambiguity.medium_confidence_action =
            IntentAmbiguityAction::ConstrainedProceed;
        rules.ontology_policy.intent_routing.ambiguity.low_confidence_action =
            IntentAmbiguityAction::ConstrainedProceed;

        let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
            .await
            .unwrap();
        assert!(!resolved.constrained);
    }
}
