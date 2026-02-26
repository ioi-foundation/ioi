use super::{
    is_ambiguity_abstain_exempt, is_tool_allowed_for_resolution, resolve_band, resolve_step_intent,
    should_abstain_for_ambiguity, should_pause_for_clarification, IntentCandidateScore,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use crate::agentic::rules::{ActionRules, Rule, RuleConditions, Verdict};
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::{
    CapabilityId, ExecutionApplicabilityClass, InferenceOptions, IntentAmbiguityAction,
    IntentConfidenceBand, IntentConfidenceBandPolicy, IntentMatrixEntry, IntentRoutingPolicy,
    IntentScopeProfile, ProviderSelectionMode, ResolvedIntentState, VerificationMode,
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
        if text_lc.contains("command") || text_lc.contains("terminal") || text_lc.contains("shell")
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
struct MathIntentRuntime;

#[async_trait]
impl InferenceRuntime for MathIntentRuntime {
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
        let has_digits = text_lc.chars().any(|ch| ch.is_ascii_digit());
        let has_math_symbol = text_lc
            .chars()
            .any(|ch| matches!(ch, '+' | '-' | '*' | '/' | '%' | '^' | '=' | 'x'));

        if text_lc.contains("arithmetic")
            || text_lc.contains("math")
            || text_lc.contains("calculate")
            || (has_digits && has_math_symbol)
        {
            return Ok(vec![1.0, 0.0, 0.0]);
        }

        if text_lc.contains("shell")
            || text_lc.contains("terminal")
            || text_lc.contains("command")
            || text_lc.contains("timer")
        {
            return Ok(vec![0.0, 1.0, 0.0]);
        }

        if text_lc.contains("respond conversationally")
            || text_lc.contains("draft a response")
            || text_lc.contains("reply")
        {
            return Ok(vec![0.0, 0.0, 1.0]);
        }

        Ok(vec![0.0, 0.0, 0.1])
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
            // query-binding feasibility must correct the winner.
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

#[derive(Debug, Default, Clone)]
struct HeadlinesDescriptorRuntime;

#[async_trait]
impl InferenceRuntime for HeadlinesDescriptorRuntime {
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
        if text_lc.contains("system clock") || text_lc.contains("host machine") {
            return Ok(vec![1.0, 0.0]);
        }
        if text_lc.contains("news") || text_lc.contains("headline") {
            return Ok(vec![0.0, 1.0]);
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

#[derive(Debug, Default, Clone)]
struct LaunchVsUiRuntime;

#[async_trait]
impl InferenceRuntime for LaunchVsUiRuntime {
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
        let tokens = text_lc
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|token| !token.trim().is_empty())
            .collect::<Vec<_>>();
        let has_token = |needle: &str| tokens.iter().any(|token| *token == needle);

        let launch_terms = [
            "launch",
            "start",
            "run",
            "named",
            "application",
            "app",
            "foreground",
            "calculator",
        ];
        let ui_terms = [
            "click", "type", "scroll", "press", "controls", "inside", "window", "already",
            "button", "field",
        ];

        let launch_score = launch_terms.iter().filter(|term| has_token(term)).count() as f32;
        let ui_score = ui_terms.iter().filter(|term| has_token(term)).count() as f32;

        Ok(vec![launch_score, ui_score])
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
fn math_intent_allows_math_eval_and_chat_reply_only() {
    let state = ResolvedIntentState {
        intent_id: "math.eval".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.97,
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
    assert!(is_tool_allowed_for_resolution(Some(&state), "math__eval"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "chat__reply"));
    assert!(!is_tool_allowed_for_resolution(Some(&state), "sys__exec"));
}

#[test]
fn math_eval_tool_stays_on_primitive_capability_surface() {
    let caps = super::tool_capabilities("math__eval");
    assert_eq!(caps, vec![CapabilityId::from("conversation.reply")]);
    assert!(!caps.iter().any(|cap| cap.as_str() == "math.eval"));
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

#[test]
fn ambiguity_abstain_exemption_is_policy_driven() {
    let mut policy = IntentRoutingPolicy::default();
    policy.ambiguity_abstain_exempt_intents = vec![
        "app.launch".to_string(),
        "command.exec".to_string(),
        "system.clock.read".to_string(),
    ];
    assert!(is_ambiguity_abstain_exempt(&policy, "app.launch"));
    assert!(is_ambiguity_abstain_exempt(&policy, "command.exec"));
    assert!(is_ambiguity_abstain_exempt(&policy, "system.clock.read"));
    assert!(!is_ambiguity_abstain_exempt(&policy, "ui.interaction"));
}

#[test]
fn default_policy_exempts_command_exec_from_ambiguity_abstain() {
    let policy = IntentRoutingPolicy::default();
    assert!(is_ambiguity_abstain_exempt(&policy, "command.exec"));
}

#[test]
fn policy_exemption_overrides_ambiguity_abstain_gate() {
    let mut policy = IntentRoutingPolicy::default();
    policy.ambiguity_margin_bps = 50;
    policy.ambiguity_abstain_exempt_intents = vec!["app.launch".to_string()];
    let ranked = vec![
        IntentCandidateScore {
            intent_id: "app.launch".to_string(),
            score: 0.646,
        },
        IntentCandidateScore {
            intent_id: "ui.interaction".to_string(),
            score: 0.642,
        },
    ];
    let winner = ranked[0].clone();
    assert!(should_abstain_for_ambiguity(&ranked, &winner, &policy));
    let abstain = should_abstain_for_ambiguity(&ranked, &winner, &policy)
        && !is_ambiguity_abstain_exempt(&policy, &winner.intent_id);
    assert!(!abstain);
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
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-weather-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_latest_headlines_queries_to_web_research_via_descriptor() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(HeadlinesDescriptorRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Give me the latest news headlines right now.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v11-headlines-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    assert_eq!(
        resolved
            .top_k
            .first()
            .map(|candidate| candidate.intent_id.as_str()),
        Some("web.research")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_calculator_to_app_launch_scope() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "open calculator".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-app-launch-disambiguation-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_click_queries_to_ui_interaction_scope() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "click the login button".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-ui-interaction-disambiguation-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "ui.interaction");
    assert_eq!(resolved.scope, IntentScopeProfile::UiInteraction);
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
async fn resolver_routes_calculator_queries_to_math_eval_not_command_exec() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What's 247 x 38?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v10-math-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "math.eval");
    assert_eq!(resolved.scope, IntentScopeProfile::Conversation);
    assert_ne!(resolved.intent_id, "command.exec");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_calculator_app_to_app_launch_not_math_eval() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open calculator app".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-open-calculator-app-launch-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_the_calculator_app_sentence_to_app_launch() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open the Calculator app.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-open-the-calculator-app-launch-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_keeps_app_launch_feasible_when_sys_exec_is_blocked() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open the Calculator app.".to_string();

    let mut rules = ActionRules::default();
    rules.rules.push(Rule {
        rule_id: Some("block-sys-exec".to_string()),
        target: "sys::exec".to_string(),
        conditions: RuleConditions::default(),
        action: Verdict::Block,
    });
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v11-open-calculator-with-sys-blocked".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
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
            applicability_class: ExecutionApplicabilityClass::RemoteRetrieval,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
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
            applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
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
async fn resolver_enforces_remote_public_fact_binding_when_embeddings_disagree() {
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
async fn resolver_keeps_host_local_clock_queries_on_system_clock_read() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LocalitySkewedRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What time is it right now on this machine?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-host-local-clock-binding-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "system.clock.read");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
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
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-no-embed-test".into();
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
    rules.ontology_policy.intent_routing.ambiguity_margin_bps = 10_000;
    rules
        .ontology_policy
        .intent_routing
        .ambiguity_abstain_exempt_intents = vec![];
    rules.ontology_policy.intent_routing.matrix = vec![
        IntentMatrixEntry {
            intent_id: "system.clock.read".to_string(),
            semantic_descriptor: "system clock timestamp".to_string(),
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec![],
            exemplars: vec![],
        },
        IntentMatrixEntry {
            intent_id: "command.exec".to_string(),
            semantic_descriptor: "shell or terminal command execute".to_string(),
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::TopologyDependent,
            requires_host_discovery: Some(true),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![
                "host_discovery".to_string(),
                "provider_selection".to_string(),
                "execution".to_string(),
                "verification".to_string(),
            ],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DynamicSynthesis),
            aliases: vec![],
            exemplars: vec![],
        },
    ];
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
