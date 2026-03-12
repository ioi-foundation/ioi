use crate::app::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Canonical adapter family for external execution wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    /// Model Context Protocol tool server.
    Mcp,
    /// Connected external provider or SaaS surface.
    Connector,
    /// On-chain or local runtime service method wrapper.
    Service,
    /// CLI wrapper.
    Cli,
    /// Local desktop app wrapper.
    LocalApp,
    /// Custom adapter family.
    Custom(String),
}

impl AdapterKind {
    /// Returns a deterministic label for receipts and projections.
    pub fn as_label(&self) -> &str {
        match self {
            Self::Mcp => "mcp",
            Self::Connector => "connector",
            Self::Service => "service",
            Self::Cli => "cli",
            Self::LocalApp => "local_app",
            Self::Custom(value) => value.as_str(),
        }
    }
}

/// Replay handling class bound to approvals and adapter side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum AdapterReplayClassification {
    /// Safe to replay without additional user intervention.
    ReplaySafe,
    /// Retry requires a fresh decision or invocation.
    RetryRequired,
}

impl AdapterReplayClassification {
    /// Returns a deterministic label for receipts and projections.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::ReplaySafe => "replay_safe",
            Self::RetryRequired => "retry_required",
        }
    }
}

/// Structured artifact pointer returned by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterArtifactPointer {
    /// Stable artifact URI or path reference.
    pub uri: String,
    /// Optional media type for the artifact payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Optional hash commitment for the artifact payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Optional human-readable artifact label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Summary of redaction applied to adapter request/response material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterRedactionSummary {
    /// Canonical list of redacted request/response field paths.
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    /// Total count of redactions applied across request + response material.
    pub redaction_count: u32,
    /// Version identifier for the redaction policy used.
    pub redaction_version: String,
}

/// Stable adapter failure structure used across wrapper families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterFailure {
    /// Machine-readable error class.
    pub error_class: String,
    /// Optional operator-facing failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Whether the failure is retryable.
    #[serde(default)]
    pub retryable: bool,
}

/// Discovery-time adapter definition projected into runtime tool metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterDefinition {
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Tool name projected into the planner/model.
    pub tool_name: String,
    /// Adapter family.
    pub kind: AdapterKind,
    /// Human-readable tool description.
    pub description: String,
    /// JSON schema for the request payload.
    pub request_schema: String,
    /// Optional JSON schema for the response payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
    /// Canonical action target exposed by this adapter.
    pub action_target: ActionTarget,
    /// Capability labels surfaced by this adapter tool.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Optional provider family used by provider selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
    /// Optional route label within the provider family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_label: Option<String>,
}

/// Typed adapter invocation request bound to a workload call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterCallRequest {
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Tool name being invoked.
    pub tool_name: String,
    /// Stable invocation identifier.
    pub invocation_id: String,
    /// Stable idempotency key for side-effectful calls.
    pub idempotency_key: String,
    /// Canonical action target label.
    pub action_target: String,
    /// Canonical JSON request payload bytes.
    pub request_payload: Vec<u8>,
}

/// Typed adapter invocation response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterCallResponse {
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Tool name that produced this response.
    pub tool_name: String,
    /// Adapter family.
    pub kind: AdapterKind,
    /// Canonical JSON response payload bytes.
    pub response_payload: Vec<u8>,
    /// Short operator-facing summary.
    pub summary: String,
    /// Optional history entry rendered back into the agent transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_entry: Option<String>,
    /// Artifact pointers returned by the adapter.
    #[serde(default)]
    pub artifact_pointers: Vec<AdapterArtifactPointer>,
    /// Optional redaction summary applied to request/response material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<AdapterRedactionSummary>,
    /// Optional failure payload when the adapter call did not succeed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<AdapterFailure>,
    /// Replay classification for this invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_classification: Option<AdapterReplayClassification>,
    /// Optional response schema used by this adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
}

/// Receipted adapter execution summary emitted on the workload event stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct AdapterReceipt {
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Tool name that produced this receipt.
    pub tool_name: String,
    /// Adapter family.
    pub kind: AdapterKind,
    /// Stable invocation identifier.
    pub invocation_id: String,
    /// Stable idempotency key.
    pub idempotency_key: String,
    /// Canonical action target label.
    pub action_target: String,
    /// Hash commitment to the request payload.
    pub request_hash: String,
    /// Optional hash commitment to the response payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    /// Whether execution succeeded.
    pub success: bool,
    /// Optional stable failure class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Artifact pointers returned by the adapter.
    #[serde(default)]
    pub artifact_pointers: Vec<AdapterArtifactPointer>,
    /// Optional redaction summary applied to receipt material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<AdapterRedactionSummary>,
    /// Replay classification for this invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_classification: Option<AdapterReplayClassification>,
}
