use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionClusterId {
    Cognition,
    RoutingModel,
    VerificationOutput,
    AuthorityTooling,
}

impl HarnessPromotionClusterId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cognition => "cognition",
            Self::RoutingModel => "routing_model",
            Self::VerificationOutput => "verification_output",
            Self::AuthorityTooling => "authority_tooling",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cognition => "Cognition",
            Self::RoutingModel => "Routing and model",
            Self::VerificationOutput => "Verification and output",
            Self::AuthorityTooling => "Authority and tooling",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessClusterPromotionStatus {
    ShadowReady,
    Gated,
    Blocked,
    Live,
}

impl HarnessClusterPromotionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShadowReady => "shadow_ready",
            Self::Gated => "gated",
            Self::Blocked => "blocked",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionCluster {
    pub cluster_id: HarnessPromotionClusterId,
    pub label: String,
    pub activation_order: u32,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub required_execution_mode: HarnessExecutionMode,
    pub minimum_readiness: HarnessComponentReadiness,
    pub promotion_rule: String,
    pub rollback_target: String,
    pub blocks_live_activation: bool,
    pub promotion_status: HarnessClusterPromotionStatus,
    pub replay_gate_proof: Option<HarnessPromotionClusterReplayGateProof>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionClusterReplayGateStatus {
    NotRun,
    Passed,
    Blocked,
    Failed,
}

impl HarnessPromotionClusterReplayGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Passed => "passed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessActivationGateImpact {
    Pending,
    Passed,
    Blocked,
}

impl HarnessActivationGateImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionClusterReplayGateProof {
    pub schema_version: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub gate_id: Option<String>,
    pub gate_status: HarnessPromotionClusterReplayGateStatus,
    pub activation_gate_impact: HarnessActivationGateImpact,
    pub total_fixtures: u32,
    pub passed_count: u32,
    pub blocked_count: u32,
    pub failed_count: u32,
    pub blocking_divergence_count: u32,
    pub replay_fixture_refs: Vec<String>,
    pub blocking_replay_fixture_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blockers: Vec<String>,
    pub verified_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessGatedClusterRun {
    pub schema_version: String,
    pub run_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub status: HarnessClusterPromotionStatus,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub shadow_run_id: String,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub activation_blockers: Vec<String>,
    pub gate_decision: String,
    pub rollback_target: String,
    pub canary_status: String,
    pub promotion_blocked: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionTransitionTarget {
    Gated,
    Live,
}

impl HarnessPromotionTransitionTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gated => "gated",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionTransitionEligibility {
    pub schema_version: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub target_execution_mode: HarnessPromotionTransitionTarget,
    pub current_status: HarnessClusterPromotionStatus,
    pub eligible: bool,
    pub readiness_ready: bool,
    pub receipt_ready: bool,
    pub replay_gate_ready: bool,
    pub canary_ready: bool,
    pub rollback_ready: bool,
    pub component_ids: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub canary_boundary_id: Option<String>,
    pub rollback_target: Option<String>,
    pub blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionTransitionAttempt {
    pub schema_version: String,
    pub transition_id: String,
    pub workflow_id: String,
    pub activation_id: Option<String>,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub target_execution_mode: HarnessPromotionTransitionTarget,
    pub previous_status: HarnessClusterPromotionStatus,
    pub next_status: HarnessClusterPromotionStatus,
    pub attempt_status: String,
    pub gate_decision: String,
    pub eligibility: HarnessPromotionTransitionEligibility,
    pub blockers: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessLivePromotionClusterReadiness {
    pub cluster_id: HarnessPromotionClusterId,
    pub label: String,
    pub current_status: HarnessClusterPromotionStatus,
    pub target_execution_mode: HarnessExecutionMode,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub readiness_ready: bool,
    pub receipt_ready: bool,
    pub replay_gate_ready: bool,
    pub canary_ready: bool,
    pub rollback_ready: bool,
    pub divergence_ready: bool,
    pub blocking_divergence_count: u32,
    pub unclassified_divergence_count: u32,
    pub attempt_ids: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub action_frame_ids: Vec<String>,
    pub divergence_classes: Vec<HarnessDivergenceClass>,
    pub rollback_target: String,
    pub blockers: Vec<String>,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessLivePromotionReadinessProof {
    pub schema_version: String,
    pub proof_id: String,
    pub dispatch_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub target_execution_mode: HarnessExecutionMode,
    pub required_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub cluster_readiness: Vec<HarnessLivePromotionClusterReadiness>,
    pub live_shadow_comparison_gate: HarnessLiveShadowComparisonGate,
    pub live_shadow_comparison_gate_ready: bool,
    pub all_clusters_ready: bool,
    pub promotion_eligible: bool,
    pub default_live_activation_ready: bool,
    pub invalid_fork_live_activation_blocked: bool,
    pub rollback_available: bool,
    pub rollback_target: String,
    pub activation_blockers: Vec<String>,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

