use super::{
    is_ambiguity_abstain_exempt, is_tool_allowed_for_resolution, resolve_band, resolve_step_intent,
    resolve_step_intent_with_state, should_abstain_for_ambiguity, should_pause_for_clarification,
    tool_capabilities, tool_capability_bindings, IntentCandidateScore,
};
use crate::agentic::rules::{ActionRules, Rule, RuleConditions, Verdict};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::{
    CapabilityId, ExecutionApplicabilityClass, InferenceOptions, IntentAmbiguityAction,
    IntentCatalogEntry, IntentConfidenceBand, IntentConfidenceBandPolicy, IntentQueryBindingClass,
    IntentRoutingPolicy, IntentScopeProfile, ProviderSelectionMode, ResolvedIntentState,
    VerificationMode,
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

fn query_from_prompt(prompt: &str) -> String {
    let marker = "query:\n";
    let Some(start) = prompt.find(marker).map(|idx| idx + marker.len()) else {
        return prompt.to_string();
    };
    let rest = &prompt[start..];
    let end = rest.find("\n\nreturn exactly one json object");
    match end {
        Some(idx) => rest[..idx].trim().to_string(),
        None => rest.trim().to_string(),
    }
}

fn query_from_input_context(input_context: &[u8]) -> String {
    let raw = String::from_utf8_lossy(input_context).to_string();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
        if let Some(messages) = value.as_array() {
            for message in messages {
                let role = message
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or_default();
                if role != "user" {
                    continue;
                }
                let content = message
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default();
                let extracted = query_from_prompt(&content.to_ascii_lowercase());
                if !extracted.is_empty() {
                    return extracted;
                }
            }
        }
    }
    query_from_prompt(&raw.to_ascii_lowercase())
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
        Err(VmError::HostError("inference unavailable".to_string()))
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
struct NoEmbeddingModelRankRuntime;

#[derive(Debug, Default, Clone)]
struct AutomationMonitorIntentRuntime;

#[derive(Debug, Default, Clone)]
struct AutomationMonitorVsWebResearchRuntime;

#[derive(Debug, Default, Clone)]
struct ModelRegistryIntentRuntime;

#[async_trait]
impl InferenceRuntime for NoEmbeddingModelRankRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("rename every file")
            && query.contains("downloads")
            && query.contains("lowercase")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if query.contains("rename every file")
            && query.contains("downloads")
            && query.contains("lowercase")
        {
            return Ok(serde_json::json!({
                "scores": [
                    {"intent_id": "command.exec", "score": 0.96},
                    {"intent_id": "workspace.ops", "score": 0.44},
                    {"intent_id": "app.launch", "score": 0.05}
                ]
            })
            .to_string()
            .into_bytes());
        }
        Ok(serde_json::json!({
            "scores": []
        })
        .to_string()
        .into_bytes())
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

#[async_trait]
impl InferenceRuntime for ModelRegistryIntentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        let query_padded = format!(" {} ", query);
        if prompt.contains("model_registry_control_requested") {
            let wants_unload = query_padded.contains(" unload ")
                || query_padded.contains(" evict ")
                || query_padded.contains(" deactivate ");
            let wants_load = !wants_unload
                && (query_padded.contains(" load ")
                    || query_padded.contains(" activate ")
                    || query_padded.contains(" warm "));
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "durable_automation_requested": false,
                "model_registry_control_requested": wants_load || wants_unload,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if query_padded.contains(" unload ")
            && query.contains("model")
            && (query.contains("whisper")
                || query.contains("free memory")
                || query.contains("vram"))
        {
            return Ok(serde_json::json!({
                "scores": [
                    {"intent_id": "model.registry.unload", "score": 0.98},
                    {"intent_id": "model.registry.load", "score": 0.31},
                    {"intent_id": "command.exec", "score": 0.21}
                ]
            })
            .to_string()
            .into_bytes());
        }
        if query_padded.contains(" load ")
            && query.contains("model")
            && (query.contains("codex") || query.contains("llama") || query.contains("runtime"))
        {
            return Ok(serde_json::json!({
                "scores": [
                    {"intent_id": "model.registry.load", "score": 0.98},
                    {"intent_id": "model.registry.unload", "score": 0.37},
                    {"intent_id": "command.exec", "score": 0.22}
                ]
            })
            .to_string()
            .into_bytes());
        }
        Ok(serde_json::json!({
            "scores": []
        })
        .to_string()
        .into_bytes())
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

#[async_trait]
impl InferenceRuntime for AutomationMonitorIntentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("durable_automation_requested")
            && query.contains("monitor hacker news")
            && query.contains("notify me whenever")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "durable_automation_requested": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if query.contains("monitor hacker news")
            && query.contains("notify me whenever")
            && query.contains("post-quantum cryptography")
        {
            return Ok(serde_json::json!({
                "scores": [
                    {"intent_id": "automation.monitor", "score": 0.98},
                    {"intent_id": "command.exec", "score": 0.61},
                    {"intent_id": "web.research", "score": 0.18}
                ]
            })
            .to_string()
            .into_bytes());
        }
        Ok(serde_json::json!({ "scores": [] }).to_string().into_bytes())
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

#[async_trait]
impl InferenceRuntime for AutomationMonitorVsWebResearchRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("durable_automation_requested")
            && query.contains("monitor hacker news")
            && query.contains("notify me whenever")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": true,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "durable_automation_requested": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if query.contains("monitor hacker news")
            && query.contains("notify me whenever")
            && query.contains("post-quantum cryptography")
        {
            return Ok(serde_json::json!({
                "scores": [
                    {"intent_id": "web.research", "score": 0.97},
                    {"intent_id": "automation.monitor", "score": 0.61},
                    {"intent_id": "command.exec", "score": 0.54}
                ]
            })
            .to_string()
            .into_bytes());
        }
        Ok(serde_json::json!({ "scores": [] }).to_string().into_bytes())
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
            "research live information",
            "latest news",
            "current events",
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
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required") && query.contains("weather") {
            return Ok(serde_json::json!({
                "remote_public_fact_required": true,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if prompt.contains("remote_public_fact_required")
            && query.contains("time")
            && (query.contains("this machine") || query.contains("this computer"))
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": true,
                "command_directed": false,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
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
        let terms = text_lc
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>();
        if terms
            .iter()
            .any(|term| matches!(*term, "time" | "clock" | "timestamp" | "utc"))
        {
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
struct MailReplyIntentRuntime;

#[async_trait]
impl InferenceRuntime for MailReplyIntentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("draft an email")
            && query.contains("send it")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        Ok(Vec::new())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();
        if text_lc.contains("compose draft and send an email")
            || text_lc.contains("outbound message")
        {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("read only this host machine local or utc clock timestamp") {
            return Ok(vec![-1.0, 0.0, 0.0]);
        }
        if text_lc.contains("execute local shell or terminal commands") {
            return Ok(vec![0.0, -1.0, 0.0]);
        }
        if text_lc.contains("draft an email to team@ioi.network saying tomorrow's standup is moved to 2 pm and send it")
        {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("respond conversationally without executing external side effects") {
            return Ok(vec![0.0, 0.0, 1.0]);
        }
        Ok(vec![0.0, 0.0, -1.0])
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct ClockSkewedCommandBindingRuntime;

#[async_trait]
impl InferenceRuntime for ClockSkewedCommandBindingRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("rename every file")
            && query.contains("downloads")
            && query.contains("lowercase")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        Ok(Vec::new())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();
        if text_lc.contains("read only this host machine local or utc clock timestamp") {
            return Ok(vec![1.0, 0.0]);
        }
        if text_lc.contains("execute local shell or terminal commands") {
            return Ok(vec![0.9, 0.1]);
        }
        if text_lc.contains("rename every file in my downloads folder to lowercase") {
            // Deliberately skew toward clock so query-binding feasibility must gate clock intents.
            return Ok(vec![1.0, 0.0]);
        }
        Ok(vec![0.0, 1.0])
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

#[derive(Debug, Default, Clone)]
struct LowConfidenceExemptRuntime;

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

#[async_trait]
impl InferenceRuntime for LowConfidenceExemptRuntime {
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
        if text_lc.contains("execute local shell or terminal commands") {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("inspect create and modify files in the local workspace") {
            return Ok(vec![0.0, 1.0, 0.0]);
        }
        if text_lc.contains("rename every file in my downloads folder to lowercase") {
            // Keep both candidates low-confidence but with a deterministic winner gap.
            return Ok(vec![0.10, 0.09, 1.0]);
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
struct LaunchVsUiRuntime;

#[async_trait]
impl InferenceRuntime for LaunchVsUiRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("open")
            && query.contains("calculator")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "app_launch_directed": true,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if prompt.contains("remote_public_fact_required")
            && query.contains("click")
            && query.contains("login")
            && query.contains("button")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "app_launch_directed": false,
                "direct_ui_input": true,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
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

#[derive(Debug, Default, Clone)]
struct DesktopFolderSkewedRuntime;

#[async_trait]
impl InferenceRuntime for DesktopFolderSkewedRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("create")
            && query.contains("folder")
            && query.contains("desktop")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        if prompt.contains("remote_public_fact_required")
            && query.contains("rename every file")
            && query.contains("downloads")
            && query.contains("lowercase")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        Ok(Vec::new())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();

        if text_lc.contains("open launch start or foreground") {
            return Ok(vec![10.0, 10.0]);
        }
        if text_lc.contains("execute local shell or terminal commands") {
            return Ok(vec![10.0, 8.0]);
        }
        if text_lc.contains("inspect and modify files in the local workspace") {
            return Ok(vec![2.0, 10.0]);
        }
        if text_lc.contains("create a new folder on my desktop called") {
            // Deliberately skew toward app.launch so query-binding constraints must
            // enforce feasibility and route to command.exec.
            return Ok(vec![10.0, 10.0]);
        }
        if text_lc.contains("rename every file in my downloads folder to lowercase") {
            // Filesystem-heavy local automation should stay command-exec directed.
            return Ok(vec![10.0, 8.0]);
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
struct InstallVsWebRuntime;

#[async_trait]
impl InferenceRuntime for InstallVsWebRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_ascii_lowercase();
        let query = query_from_input_context(input_context);
        if prompt.contains("remote_public_fact_required")
            && query.contains("download and install vlc media player")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": true,
                "app_launch_directed": false,
                "direct_ui_input": false,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        Ok(Vec::new())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();
        if text_lc.contains("download and install a named software package dependency")
            || text_lc.contains("host package manager")
        {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("research live information on the web") {
            return Ok(vec![0.0, 1.0, 0.0]);
        }
        if text_lc.contains("execute local shell or terminal commands") {
            return Ok(vec![0.0, 0.0, 1.0]);
        }
        if text_lc.contains("download and install vlc media player") {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        Ok(vec![0.0, 1.0, 1.0])
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
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
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

mod resolver_routing;
mod scope_policy;
