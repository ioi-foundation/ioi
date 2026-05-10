use super::*;

pub const DEFAULT_AGENT_HARNESS_WORKFLOW_ID: &str = "default-agent-harness";
pub const DEFAULT_AGENT_HARNESS_VERSION: &str = "2026.04.default-harness.v1";
pub const DEFAULT_AGENT_HARNESS_HASH: &str = "sha256:default-agent-harness-component-projection-v1";
pub const DEFAULT_AGENT_HARNESS_ACTIVATION_ID: &str =
    "activation:default-agent-harness:blessed-readonly";
pub const DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT: &str =
    "reviewed_import_activation_apply";
pub const DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS: u64 =
    5 * 60 * 1000;

pub const HARNESS_COMPONENT_VERSION_V1: &str = "1.0.0";
pub const HARNESS_INPUT_SCHEMA_ID: &str = "ioi.agent-harness.input.v1";
pub const HARNESS_OUTPUT_SCHEMA_ID: &str = "ioi.agent-harness.output.v1";
pub const HARNESS_ERROR_SCHEMA_ID: &str = "ioi.agent-harness.error.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExecutionMode {
    Projection,
    Shadow,
    Gated,
    Live,
}

impl HarnessExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Shadow => "shadow",
            Self::Gated => "gated",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessComponentReadiness {
    ProjectionOnly,
    Simulated,
    ShadowReady,
    LiveReady,
}

impl HarnessComponentReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectionOnly => "projection_only",
            Self::Simulated => "simulated",
            Self::ShadowReady => "shadow_ready",
            Self::LiveReady => "live_ready",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessReplayDeterminism {
    Deterministic,
    Nondeterministic,
    Redacted,
    Disabled,
}

impl HarnessReplayDeterminism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Nondeterministic => "nondeterministic",
            Self::Redacted => "redacted",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessReplayEnvelope {
    pub deterministic_envelope: bool,
    pub captures_input: bool,
    pub captures_output: bool,
    pub captures_policy_decision: bool,
    pub fixture_ref: Option<String>,
    pub determinism: HarnessReplayDeterminism,
    pub nondeterminism_reason: Option<String>,
    pub redaction_policy: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessNodeAttemptStatus {
    Projection,
    Shadow,
    Gated,
    Live,
    Succeeded,
    Failed,
    Blocked,
}

impl HarnessNodeAttemptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Shadow => "shadow",
            Self::Gated => "gated",
            Self::Live => "live",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessNodeAttemptRecord {
    pub attempt_id: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub workflow_node_id: String,
    pub component_id: String,
    pub component_kind: HarnessComponentKind,
    pub execution_mode: HarnessExecutionMode,
    pub readiness: HarnessComponentReadiness,
    pub attempt_index: u32,
    pub status: HarnessNodeAttemptStatus,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub error_class: Option<String>,
    pub policy_decision: Option<String>,
    pub started_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub receipt_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay: HarnessReplayEnvelope,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessDivergenceClass {
    None,
    HarmlessMetadata,
    MissingReceipt,
    PolicyDivergence,
    RoutingDivergence,
    OutputDivergence,
    BehavioralRegression,
    Unclassified,
}

impl HarnessDivergenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HarmlessMetadata => "harmless_metadata",
            Self::MissingReceipt => "missing_receipt",
            Self::PolicyDivergence => "policy_divergence",
            Self::RoutingDivergence => "routing_divergence",
            Self::OutputDivergence => "output_divergence",
            Self::BehavioralRegression => "behavioral_regression",
            Self::Unclassified => "unclassified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessShadowComparison {
    pub workflow_node_id: String,
    pub component_kind: HarnessComponentKind,
    pub live_attempt_id: String,
    pub shadow_attempt_id: String,
    pub divergence: HarnessDivergenceClass,
    pub blocking: bool,
    pub summary: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessShadowRun {
    pub schema_version: String,
    pub run_id: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub source_session_id: Option<String>,
    pub live_turn_id: Option<String>,
    pub execution_mode: HarnessExecutionMode,
    pub node_attempts: Vec<HarnessNodeAttemptRecord>,
    pub comparisons: Vec<HarnessShadowComparison>,
    pub blocking_divergence_count: u32,
    pub unclassified_divergence_count: u32,
    pub promotion_blocked: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessLiveShadowComparisonGate {
    pub schema_version: String,
    pub gate_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub target_execution_mode: HarnessExecutionMode,
    pub required_component_kinds: Vec<HarnessComponentKind>,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub comparison_count: u32,
    pub required_comparison_count: u32,
    pub all_required_components_present: bool,
    pub receipt_ready: bool,
    pub replay_ready: bool,
    pub divergence_ready: bool,
    pub blocking_divergence_count: u32,
    pub unclassified_divergence_count: u32,
    pub ready: bool,
    pub policy_decision: String,
    pub blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
}
