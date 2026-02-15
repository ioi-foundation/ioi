use crate::agentic::desktop::service::step::anti_loop::FailureClass;
use crate::agentic::desktop::service::step::ontology::{
    GateState, IncidentStage, IntentClass, ResolutionAction, StrategyName, StrategyNode,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const FORBIDDEN_LIFECYCLE_TOOLS: &[&str] = &[
    "agent__complete",
    "chat__reply",
    "system__fail",
    "agent__delegate",
];

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct PendingGate {
    pub request_hash: String,
    pub action_fingerprint: String,
    pub prompted_count: u32,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct IncidentState {
    pub active: bool,
    pub incident_id: String,
    pub root_retry_hash: String,
    pub root_tool_jcs: Vec<u8>,
    pub root_tool_name: String,
    pub intent_class: String,
    pub root_failure_class: String,
    pub root_error: Option<String>,
    pub stage: String,
    pub strategy_name: String,
    pub strategy_cursor: String,
    pub visited_node_fingerprints: Vec<String>,
    pub pending_gate: Option<PendingGate>,
    pub gate_state: String,
    pub resolution_action: String,
    pub transitions_used: u32,
    pub max_transitions: u32,
    pub started_step: u32,
    pub pending_remedy_fingerprint: Option<String>,
    pub pending_remedy_tool_jcs: Option<Vec<u8>>,
    pub retry_enqueued: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub(super) struct LegacyIncidentState {
    pub active: bool,
    pub incident_id: String,
    pub root_retry_hash: String,
    pub root_tool_jcs: Vec<u8>,
    pub root_tool_name: String,
    pub intent_class: String,
    pub root_failure_class: String,
    pub root_error: Option<String>,
    pub stage: String,
    pub strategy_name: String,
    pub strategy_cursor: String,
    pub visited_node_fingerprints: Vec<String>,
    pub pending_gate: Option<PendingGate>,
    pub gate_state: String,
    pub resolution_action: String,
    pub transitions_used: u32,
    pub max_transitions: u32,
    pub started_step: u32,
}

impl From<LegacyIncidentState> for IncidentState {
    fn from(value: LegacyIncidentState) -> Self {
        Self {
            active: value.active,
            incident_id: value.incident_id,
            root_retry_hash: value.root_retry_hash,
            root_tool_jcs: value.root_tool_jcs,
            root_tool_name: value.root_tool_name,
            intent_class: value.intent_class,
            root_failure_class: value.root_failure_class,
            root_error: value.root_error,
            stage: value.stage,
            strategy_name: value.strategy_name,
            strategy_cursor: value.strategy_cursor,
            visited_node_fingerprints: value.visited_node_fingerprints,
            pending_gate: value.pending_gate,
            gate_state: value.gate_state,
            resolution_action: value.resolution_action,
            transitions_used: value.transitions_used,
            max_transitions: value.max_transitions,
            started_step: value.started_step,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        }
    }
}

impl IncidentState {
    pub(super) fn new(
        root_retry_hash: &str,
        root_tool_jcs: &[u8],
        root_tool_name: &str,
        intent_class: IntentClass,
        root_failure_class: FailureClass,
        root_error: Option<&str>,
        strategy_name: StrategyName,
        strategy_node: StrategyNode,
        max_transitions: u32,
        started_step: u32,
    ) -> Self {
        let incident_id_seed = format!(
            "{}::{}::{}::{}",
            root_retry_hash,
            root_tool_name,
            started_step,
            now_millis()
        );
        let incident_id = sha256(incident_id_seed.as_bytes())
            .map(hex::encode)
            .unwrap_or_else(|_| hex::encode(root_retry_hash.as_bytes()));

        Self {
            active: true,
            incident_id,
            root_retry_hash: root_retry_hash.to_string(),
            root_tool_jcs: root_tool_jcs.to_vec(),
            root_tool_name: root_tool_name.to_string(),
            intent_class: intent_class.as_str().to_string(),
            root_failure_class: root_failure_class.as_str().to_string(),
            root_error: root_error.map(|v| v.to_string()),
            stage: IncidentStage::New.as_str().to_string(),
            strategy_name: strategy_name.as_str().to_string(),
            strategy_cursor: strategy_node.as_str().to_string(),
            visited_node_fingerprints: Vec::new(),
            pending_gate: None,
            gate_state: GateState::None.as_str().to_string(),
            resolution_action: ResolutionAction::None.as_str().to_string(),
            transitions_used: 0,
            max_transitions,
            started_step,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentDirective {
    Noop,
    AwaitApproval,
    QueueActions,
    PauseForUser,
    Escalate,
    MarkResolved,
    MarkExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDirective {
    PromptUser,
    SuppressDuplicatePrompt,
    PauseLoop,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentReceiptFields {
    pub intent_class: String,
    pub incident_id: String,
    pub incident_stage: String,
    pub strategy_name: String,
    pub strategy_node: String,
    pub gate_state: String,
    pub resolution_action: String,
}

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn canonical_tool_name(tool: &AgentTool) -> String {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{:?}", tool.target()))
}

pub(super) fn canonical_tool_args(tool: &AgentTool) -> serde_json::Value {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| value.get("arguments").cloned())
        .unwrap_or_else(|| json!({}))
}

pub(super) fn tool_fingerprint(tool: &AgentTool) -> String {
    let payload = json!({
        "name": canonical_tool_name(tool),
        "arguments": canonical_tool_args(tool),
    });
    let canonical = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();
    sha256(&canonical)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub fn action_fingerprint_from_tool_jcs(tool_jcs: &[u8]) -> String {
    sha256(tool_jcs)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}
