use super::deadline::ExecutionDeadline;
use ioi_types::app::{ActionTarget, RequiredReceiptManifest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationEnvelopeBase {
    pub session_id: [u8; 32],
    pub actor_id: String,
    pub request_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_hash: Option<[u8; 32]>,
    pub trace_context: TraceContext,
    pub target: ActionTarget,
    #[serde(default)]
    pub scope: Value,
    pub policy_decision_hash: [u8; 32],
    pub capability_lease_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_grant_hash: Option<[u8; 32]>,
    pub deadline: ExecutionDeadline,
    pub idempotency_key: String,
    pub required_receipt_manifest: RequiredReceiptManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub tool_name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub model_id: String,
    pub provider: String,
    pub capability: String,
    pub prompt_hash: [u8; 32],
    pub system_prompt_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_schema_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_schema_hash: Option<[u8; 32]>,
    pub token_budget: u64,
    pub fallback_policy: String,
    pub safety_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub artifact_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub workflow_id: String,
    pub step_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub graph_id: String,
    pub node_id: String,
    pub node_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub connector_id: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInvocationEnvelope {
    pub base: InvocationEnvelopeBase,
    pub plugin_id: String,
    pub operation: String,
}
