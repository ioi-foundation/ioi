use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerBinding {
    pub harness_workflow_id: String,
    pub harness_activation_id: Option<String>,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub source: String,
    pub selector_decision_id: Option<String>,
    pub default_dispatch_id: Option<String>,
    pub rollback_target: Option<String>,
    pub authority_binding_ready: bool,
    pub authority_binding_blockers: Vec<String>,
    pub live_promotion_readiness_proof_id: Option<String>,
    pub live_shadow_comparison_gate_id: Option<String>,
    pub live_shadow_comparison_gate_ready: bool,
    pub rollback_policy_decision: Option<String>,
    pub policy_decision: Option<String>,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkerBindingStatus {
    Projection,
    Blocked,
    Canary,
    Bound,
}

impl HarnessWorkerBindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Blocked => "blocked",
            Self::Canary => "canary",
            Self::Bound => "bound",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerBindingRegistryRecord {
    pub schema_version: String,
    pub registry_record_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub reviewed_package_snapshot_hash: String,
    pub reviewed_workflow_content_hash: String,
    pub reviewed_activation_id: String,
    pub reviewed_harness_workflow_id: String,
    pub reviewed_worker_binding_activation_id: String,
    pub reviewed_rollback_target: String,
    pub reviewed_replay_fixture_refs: Vec<String>,
    pub reviewed_worker_handoff_node_attempt_ids: Vec<String>,
    pub reviewed_worker_handoff_receipt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_id: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_status: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_diff_hash: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_receipt_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_replay_fixture_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_node_attempt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_rollback_target: String,
    pub reviewed_policy_posture: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub rollback_target: String,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub canary_result_id: String,
    pub policy_decision: String,
    pub binding_status: HarnessWorkerBindingStatus,
    pub blockers: Vec<String>,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub worker_binding: HarnessWorkerBinding,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkerAttachStatus {
    Unbound,
    Blocked,
    Canary,
    Bound,
    Resumed,
    RolledBack,
}

impl HarnessWorkerAttachStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Blocked => "blocked",
            Self::Canary => "canary",
            Self::Bound => "bound",
            Self::Resumed => "resumed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerAttachRequest {
    pub schema_version: String,
    pub request_id: String,
    pub worker_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub reviewed_package_snapshot_hash: String,
    pub reviewed_workflow_content_hash: String,
    pub reviewed_activation_id: String,
    pub reviewed_harness_workflow_id: String,
    pub reviewed_worker_binding_activation_id: String,
    pub reviewed_rollback_target: String,
    pub reviewed_replay_fixture_refs: Vec<String>,
    pub reviewed_worker_handoff_node_attempt_ids: Vec<String>,
    pub reviewed_worker_handoff_receipt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_id: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_status: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_diff_hash: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_receipt_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_replay_fixture_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_node_attempt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_rollback_target: String,
    pub reviewed_policy_posture: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub rollback_target: String,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub required_invariant_ids: Vec<String>,
    pub requested_status: HarnessWorkerAttachStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerAttachReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub worker_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub reviewed_package_snapshot_hash: String,
    pub reviewed_workflow_content_hash: String,
    pub reviewed_activation_id: String,
    pub reviewed_harness_workflow_id: String,
    pub reviewed_worker_binding_activation_id: String,
    pub reviewed_rollback_target: String,
    pub reviewed_replay_fixture_refs: Vec<String>,
    pub reviewed_worker_handoff_node_attempt_ids: Vec<String>,
    pub reviewed_worker_handoff_receipt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_id: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_status: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_diff_hash: String,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_receipt_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_replay_fixture_refs: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_node_attempt_ids: Vec<String>,
    #[serde(default)]
    pub reviewed_fork_mutation_canary_rollback_target: String,
    pub reviewed_policy_posture: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub registry_record_id: String,
    pub binding_status: HarnessWorkerBindingStatus,
    pub attach_status: HarnessWorkerAttachStatus,
    pub accepted: bool,
    pub blockers: Vec<String>,
    pub worker_binding: HarnessWorkerBinding,
    pub policy_decision: String,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkerAttachLifecyclePhase {
    Attach,
    Resume,
    Rollback,
}

impl HarnessWorkerAttachLifecyclePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Resume => "resume",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerAttachLifecycleEvent {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u32,
    pub phase: HarnessWorkerAttachLifecyclePhase,
    pub attempt_id: String,
    pub workflow_node_id: String,
    pub component_kind: HarnessComponentKind,
    pub attach_status: HarnessWorkerAttachStatus,
    pub receipt_id: String,
    pub receipt: HarnessWorkerAttachReceipt,
    pub registry_record_id: String,
    pub accepted: bool,
    pub rollback_available: bool,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub policy_decision: String,
    pub blockers: Vec<String>,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkerSessionStatus {
    Attached,
    Resumed,
    RollbackReady,
    RolledBack,
    Blocked,
}

impl HarnessWorkerSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Resumed => "resumed",
            Self::RollbackReady => "rollback_ready",
            Self::RolledBack => "rolled_back",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerSessionRecord {
    pub schema_version: String,
    pub session_record_id: String,
    pub session_id: String,
    pub worker_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub rollback_target: String,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub registry_record_id: String,
    pub current_status: HarnessWorkerSessionStatus,
    pub current_event_id: Option<String>,
    pub current_attempt_id: Option<String>,
    pub current_receipt_id: Option<String>,
    pub attach_event_id: Option<String>,
    pub resume_event_id: Option<String>,
    pub rollback_event_id: Option<String>,
    pub lifecycle_event_ids: Vec<String>,
    pub lifecycle_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub lifecycle_statuses: Vec<HarnessWorkerAttachStatus>,
    pub resumed: bool,
    pub rollback_available: bool,
    pub rollback_target_ready: bool,
    pub accepted: bool,
    pub blockers: Vec<String>,
    pub policy_decision: String,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub persistence_key: String,
    pub record_persistence_key: String,
    pub persisted_in_runtime_checkpoint: bool,
    pub restored_from_persisted_session: bool,
    pub runtime_checkpoint_source: String,
    pub persistence_blockers: Vec<String>,
    pub launch_authority_ready: bool,
    pub launch_authority_blockers: Vec<String>,
    pub launch_authority_invariant_ids: Vec<String>,
    pub launch_authority_invariant_blockers: Vec<String>,
    pub launch_authority_source: String,
    pub rollback_handoff_ready: bool,
    pub rollback_handoff_blockers: Vec<String>,
    pub rollback_handoff_target: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkerLaunchPhase {
    Launch,
    Resume,
    Rollback,
}

impl HarnessWorkerLaunchPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::Resume => "resume",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerLaunchEnvelope {
    pub schema_version: String,
    pub envelope_id: String,
    pub phase: HarnessWorkerLaunchPhase,
    pub workflow_node_id: String,
    pub component_kind: HarnessComponentKind,
    pub session_record_id: String,
    pub session_id: String,
    pub worker_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub registry_record_id: String,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub rollback_target: String,
    pub persistence_key: String,
    pub record_persistence_key: String,
    pub launch_authority_source: String,
    pub launch_authority_ready: bool,
    pub launch_authority_invariant_ids: Vec<String>,
    pub launch_authority_invariant_blockers: Vec<String>,
    pub rollback_handoff_ready: bool,
    pub accepted: bool,
    pub blockers: Vec<String>,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerHandoffReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub envelope_id: String,
    pub phase: HarnessWorkerLaunchPhase,
    pub workflow_node_id: String,
    pub component_kind: HarnessComponentKind,
    pub session_record_id: String,
    pub session_id: String,
    pub worker_id: String,
    pub workflow_id: String,
    pub activation_id: String,
    pub activation_hash: String,
    pub harness_hash: String,
    pub registry_record_id: String,
    pub readiness_proof_id: String,
    pub rollback_readiness_proof_id: String,
    pub rollback_live_shadow_comparison_gate_id: String,
    pub rollback_live_shadow_comparison_gate_ready: bool,
    pub rollback_activation_id: String,
    pub rollback_harness_hash: String,
    pub rollback_policy_decision: String,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub launch_authority_source: String,
    pub accepted: bool,
    pub handoff_status: String,
    pub blockers: Vec<String>,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub policy_decision: String,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn default_harness_worker_binding() -> HarnessWorkerBinding {
    HarnessWorkerBinding {
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Projection,
        source: "default".to_string(),
        selector_decision_id: None,
        default_dispatch_id: None,
        rollback_target: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        authority_binding_ready: false,
        authority_binding_blockers: vec!["worker_binding_authority_not_live".to_string()],
        live_promotion_readiness_proof_id: None,
        live_shadow_comparison_gate_id: None,
        live_shadow_comparison_gate_ready: false,
        rollback_policy_decision: Some(
            "block_default_harness_worker_rollback_from_live_shadow_gate".to_string(),
        ),
        policy_decision: None,
        required_invariant_ids: vec![
            DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string(),
        ],
        invariant_blockers: vec!["reviewed_import_activation_apply_not_live".to_string()],
    }
}

pub fn default_harness_component_version_set() -> Vec<HarnessComponentVersionBinding> {
    DEFAULT_HARNESS_FLOW
        .iter()
        .copied()
        .map(default_harness_component_spec)
        .map(|component| HarnessComponentVersionBinding {
            component_id: component.component_id,
            component_version: component.version,
        })
        .collect()
}

pub fn default_harness_worker_binding_registry_record() -> HarnessWorkerBindingRegistryRecord {
    let worker_binding = default_harness_worker_binding();
    HarnessWorkerBindingRegistryRecord {
        schema_version: "workflow.harness.worker-binding-registry.v1".to_string(),
        registry_record_id: format!(
            "harness-worker-binding-registry:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        ),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        activation_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        reviewed_package_snapshot_hash:
            "stable-fnv1a32:default-agent-harness-reviewed-package-projection".to_string(),
        reviewed_workflow_content_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        reviewed_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        reviewed_worker_binding_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_replay_fixture_refs: Vec::new(),
        reviewed_worker_handoff_node_attempt_ids: Vec::new(),
        reviewed_worker_handoff_receipt_ids: Vec::new(),
        reviewed_fork_mutation_canary_id: String::new(),
        reviewed_fork_mutation_canary_status: String::new(),
        reviewed_fork_mutation_canary_diff_hash: String::new(),
        reviewed_fork_mutation_canary_receipt_refs: Vec::new(),
        reviewed_fork_mutation_canary_replay_fixture_refs: Vec::new(),
        reviewed_fork_mutation_canary_node_attempt_ids: Vec::new(),
        reviewed_fork_mutation_canary_rollback_target: String::new(),
        reviewed_policy_posture: String::new(),
        component_version_set: default_harness_component_version_set(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        readiness_proof_id: String::new(),
        rollback_readiness_proof_id: String::new(),
        rollback_live_shadow_comparison_gate_id: String::new(),
        rollback_live_shadow_comparison_gate_ready: false,
        rollback_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        rollback_policy_decision: "block_default_harness_worker_rollback_from_live_shadow_gate"
            .to_string(),
        canary_result_id: "harness-canary-result:default-agent-harness:not-run".to_string(),
        policy_decision: "block_workflow_default_until_gates_pass".to_string(),
        binding_status: HarnessWorkerBindingStatus::Projection,
        blockers: vec!["worker_binding_registry_not_live".to_string()],
        required_invariant_ids: vec![
            DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string(),
        ],
        invariant_blockers: vec!["reviewed_import_activation_apply_not_live".to_string()],
        worker_binding,
    }
}

pub fn bound_default_harness_worker_binding_registry_record(
    selector_decision_id: impl Into<String>,
    default_dispatch_id: impl Into<String>,
    readiness_proof_id: impl Into<String>,
    policy_decision: impl Into<String>,
) -> HarnessWorkerBindingRegistryRecord {
    let selector_decision_id = selector_decision_id.into();
    let default_dispatch_id = default_dispatch_id.into();
    let readiness_proof_id = readiness_proof_id.into();
    let policy_decision = policy_decision.into();
    let mut worker_binding = default_harness_worker_binding();
    worker_binding.execution_mode = HarnessExecutionMode::Live;
    worker_binding.selector_decision_id = Some(selector_decision_id);
    worker_binding.default_dispatch_id = Some(default_dispatch_id.clone());
    worker_binding.authority_binding_ready = true;
    worker_binding.authority_binding_blockers.clear();
    worker_binding.live_promotion_readiness_proof_id = Some(readiness_proof_id.clone());
    worker_binding.live_shadow_comparison_gate_id =
        Some("p0-live-shadow-comparison-gate".to_string());
    worker_binding.live_shadow_comparison_gate_ready = true;
    worker_binding.rollback_policy_decision =
        Some("allow_default_harness_worker_rollback_from_live_shadow_gate".to_string());
    worker_binding.policy_decision = Some(policy_decision.clone());
    worker_binding.required_invariant_ids =
        vec![DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string()];
    worker_binding.invariant_blockers.clear();
    let mut record = HarnessWorkerBindingRegistryRecord {
        schema_version: "workflow.harness.worker-binding-registry.v1".to_string(),
        registry_record_id: format!(
            "harness-worker-binding-registry:{}:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            default_dispatch_id
        ),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        activation_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        reviewed_package_snapshot_hash:
            "stable-fnv1a32:default-agent-harness-reviewed-package-bound".to_string(),
        reviewed_workflow_content_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        reviewed_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        reviewed_worker_binding_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        reviewed_replay_fixture_refs: vec![format!(
            "harness-reviewed-package:fixture:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_worker_handoff_node_attempt_ids: vec![format!(
            "harness-reviewed-package:worker-attempt:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_worker_handoff_receipt_ids: vec![format!(
            "harness-reviewed-package:worker-receipt:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_fork_mutation_canary_id: format!(
            "harness-reviewed-package:fork-mutation-canary:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        ),
        reviewed_fork_mutation_canary_status: "passed".to_string(),
        reviewed_fork_mutation_canary_diff_hash:
            "stable-fnv1a32:default-reviewed-fork-mutation-canary".to_string(),
        reviewed_fork_mutation_canary_receipt_refs: vec![format!(
            "harness-reviewed-package:fork-mutation-canary-receipt:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_fork_mutation_canary_replay_fixture_refs: vec![format!(
            "harness-reviewed-package:fork-mutation-canary-fixture:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_fork_mutation_canary_node_attempt_ids: vec![format!(
            "harness-reviewed-package:fork-mutation-canary-attempt:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        )],
        reviewed_fork_mutation_canary_rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            .to_string(),
        reviewed_policy_posture: "canary".to_string(),
        component_version_set: default_harness_component_version_set(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_readiness_proof_id: readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: "p0-live-shadow-comparison-gate".to_string(),
        rollback_live_shadow_comparison_gate_ready: true,
        rollback_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        rollback_policy_decision: "allow_default_harness_worker_rollback_from_live_shadow_gate"
            .to_string(),
        readiness_proof_id,
        canary_result_id: "harness-canary-result:default-agent-harness:passed".to_string(),
        policy_decision,
        binding_status: HarnessWorkerBindingStatus::Bound,
        blockers: Vec::new(),
        required_invariant_ids: vec![
            DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string(),
        ],
        invariant_blockers: Vec::new(),
        worker_binding,
    };
    record.reviewed_package_snapshot_hash =
        harness_worker_binding_registry_reviewed_package_snapshot_hash(&record);
    record
}

pub fn default_harness_worker_attach_request(
    record: &HarnessWorkerBindingRegistryRecord,
    requested_status: HarnessWorkerAttachStatus,
) -> HarnessWorkerAttachRequest {
    HarnessWorkerAttachRequest {
        schema_version: "workflow.harness.worker-attach-request.v1".to_string(),
        request_id: format!(
            "harness-worker-attach-request:{}:{}:{}",
            record.workflow_id,
            record.activation_id,
            requested_status.as_str()
        ),
        worker_id: format!(
            "harness-worker:{}:{}",
            record.workflow_id, record.activation_id
        ),
        workflow_id: record.workflow_id.clone(),
        activation_id: record.activation_id.clone(),
        activation_hash: record.activation_hash.clone(),
        harness_hash: record.harness_hash.clone(),
        reviewed_package_snapshot_hash: record.reviewed_package_snapshot_hash.clone(),
        reviewed_workflow_content_hash: record.reviewed_workflow_content_hash.clone(),
        reviewed_activation_id: record.reviewed_activation_id.clone(),
        reviewed_harness_workflow_id: record.reviewed_harness_workflow_id.clone(),
        reviewed_worker_binding_activation_id: record.reviewed_worker_binding_activation_id.clone(),
        reviewed_rollback_target: record.reviewed_rollback_target.clone(),
        reviewed_replay_fixture_refs: record.reviewed_replay_fixture_refs.clone(),
        reviewed_worker_handoff_node_attempt_ids: record
            .reviewed_worker_handoff_node_attempt_ids
            .clone(),
        reviewed_worker_handoff_receipt_ids: record.reviewed_worker_handoff_receipt_ids.clone(),
        reviewed_fork_mutation_canary_id: record.reviewed_fork_mutation_canary_id.clone(),
        reviewed_fork_mutation_canary_status: record.reviewed_fork_mutation_canary_status.clone(),
        reviewed_fork_mutation_canary_diff_hash: record
            .reviewed_fork_mutation_canary_diff_hash
            .clone(),
        reviewed_fork_mutation_canary_receipt_refs: record
            .reviewed_fork_mutation_canary_receipt_refs
            .clone(),
        reviewed_fork_mutation_canary_replay_fixture_refs: record
            .reviewed_fork_mutation_canary_replay_fixture_refs
            .clone(),
        reviewed_fork_mutation_canary_node_attempt_ids: record
            .reviewed_fork_mutation_canary_node_attempt_ids
            .clone(),
        reviewed_fork_mutation_canary_rollback_target: record
            .reviewed_fork_mutation_canary_rollback_target
            .clone(),
        reviewed_policy_posture: record.reviewed_policy_posture.clone(),
        component_version_set: record.component_version_set.clone(),
        rollback_target: record.rollback_target.clone(),
        readiness_proof_id: record.readiness_proof_id.clone(),
        rollback_readiness_proof_id: record.rollback_readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: record
            .rollback_live_shadow_comparison_gate_id
            .clone(),
        rollback_live_shadow_comparison_gate_ready: record
            .rollback_live_shadow_comparison_gate_ready,
        rollback_activation_id: record.rollback_activation_id.clone(),
        rollback_harness_hash: record.rollback_harness_hash.clone(),
        rollback_policy_decision: record.rollback_policy_decision.clone(),
        required_invariant_ids: record.required_invariant_ids.clone(),
        requested_status,
    }
}

fn harness_component_version_sets_match(
    left: &[HarnessComponentVersionBinding],
    right: &[HarnessComponentVersionBinding],
) -> bool {
    let left = left
        .iter()
        .map(|binding| (&binding.component_id, &binding.component_version))
        .collect::<std::collections::BTreeMap<_, _>>();
    let right = right
        .iter()
        .map(|binding| (&binding.component_id, &binding.component_version))
        .collect::<std::collections::BTreeMap<_, _>>();
    left == right
}

pub(super) fn harness_required_invariant_ids_present(invariant_ids: &[String]) -> bool {
    invariant_ids
        .iter()
        .any(|id| id == DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)
}

pub(super) fn harness_invariant_sets_match(left: &[String], right: &[String]) -> bool {
    let left = left.iter().collect::<std::collections::BTreeSet<_>>();
    let right = right.iter().collect::<std::collections::BTreeSet<_>>();
    left == right
}

fn harness_stable_json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

pub(super) fn harness_stable_json_string_array(values: &[String]) -> String {
    let values = values
        .iter()
        .filter(|value| !value.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| harness_stable_json_string(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(super) fn harness_stable_fnv1a32(input: &str) -> String {
    let hash = input.as_bytes().iter().fold(0x811c9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    });
    format!("stable-fnv1a32:{hash:08x}")
}

pub fn harness_reviewed_package_snapshot_hash(
    reviewed_workflow_content_hash: &str,
    reviewed_activation_id: &str,
    reviewed_harness_workflow_id: &str,
    reviewed_worker_binding_activation_id: &str,
    reviewed_rollback_target: &str,
    reviewed_replay_fixture_refs: &[String],
    reviewed_worker_handoff_node_attempt_ids: &[String],
    reviewed_worker_handoff_receipt_ids: &[String],
    reviewed_fork_mutation_canary_id: &str,
    reviewed_fork_mutation_canary_status: &str,
    reviewed_fork_mutation_canary_diff_hash: &str,
    reviewed_fork_mutation_canary_receipt_refs: &[String],
    reviewed_fork_mutation_canary_replay_fixture_refs: &[String],
    reviewed_fork_mutation_canary_node_attempt_ids: &[String],
    reviewed_fork_mutation_canary_rollback_target: &str,
    reviewed_policy_posture: &str,
) -> String {
    let input = format!(
        "{{\"reviewedActivationId\":{},\"reviewedForkMutationCanaryDiffHash\":{},\"reviewedForkMutationCanaryId\":{},\"reviewedForkMutationCanaryNodeAttemptIds\":{},\"reviewedForkMutationCanaryReceiptRefs\":{},\"reviewedForkMutationCanaryReplayFixtureRefs\":{},\"reviewedForkMutationCanaryRollbackTarget\":{},\"reviewedForkMutationCanaryStatus\":{},\"reviewedHarnessWorkflowId\":{},\"reviewedPolicyPosture\":{},\"reviewedReplayFixtureRefs\":{},\"reviewedRollbackTarget\":{},\"reviewedWorkerBindingActivationId\":{},\"reviewedWorkerHandoffNodeAttemptIds\":{},\"reviewedWorkerHandoffReceiptIds\":{},\"reviewedWorkflowContentHash\":{},\"schemaVersion\":\"workflow.harness.reviewed-package-snapshot.v1\"}}",
        harness_stable_json_string(reviewed_activation_id),
        harness_stable_json_string(reviewed_fork_mutation_canary_diff_hash),
        harness_stable_json_string(reviewed_fork_mutation_canary_id),
        harness_stable_json_string_array(reviewed_fork_mutation_canary_node_attempt_ids),
        harness_stable_json_string_array(reviewed_fork_mutation_canary_receipt_refs),
        harness_stable_json_string_array(reviewed_fork_mutation_canary_replay_fixture_refs),
        harness_stable_json_string(reviewed_fork_mutation_canary_rollback_target),
        harness_stable_json_string(reviewed_fork_mutation_canary_status),
        harness_stable_json_string(reviewed_harness_workflow_id),
        harness_stable_json_string(reviewed_policy_posture),
        harness_stable_json_string_array(reviewed_replay_fixture_refs),
        harness_stable_json_string(reviewed_rollback_target),
        harness_stable_json_string(reviewed_worker_binding_activation_id),
        harness_stable_json_string_array(reviewed_worker_handoff_node_attempt_ids),
        harness_stable_json_string_array(reviewed_worker_handoff_receipt_ids),
        harness_stable_json_string(reviewed_workflow_content_hash),
    );
    harness_stable_fnv1a32(&input)
}

pub fn harness_worker_binding_registry_reviewed_package_snapshot_hash(
    record: &HarnessWorkerBindingRegistryRecord,
) -> String {
    harness_reviewed_package_snapshot_hash(
        &record.reviewed_workflow_content_hash,
        &record.reviewed_activation_id,
        &record.reviewed_harness_workflow_id,
        &record.reviewed_worker_binding_activation_id,
        &record.reviewed_rollback_target,
        &record.reviewed_replay_fixture_refs,
        &record.reviewed_worker_handoff_node_attempt_ids,
        &record.reviewed_worker_handoff_receipt_ids,
        &record.reviewed_fork_mutation_canary_id,
        &record.reviewed_fork_mutation_canary_status,
        &record.reviewed_fork_mutation_canary_diff_hash,
        &record.reviewed_fork_mutation_canary_receipt_refs,
        &record.reviewed_fork_mutation_canary_replay_fixture_refs,
        &record.reviewed_fork_mutation_canary_node_attempt_ids,
        &record.reviewed_fork_mutation_canary_rollback_target,
        &record.reviewed_policy_posture,
    )
}

pub fn harness_worker_attach_request_reviewed_package_snapshot_hash(
    request: &HarnessWorkerAttachRequest,
) -> String {
    harness_reviewed_package_snapshot_hash(
        &request.reviewed_workflow_content_hash,
        &request.reviewed_activation_id,
        &request.reviewed_harness_workflow_id,
        &request.reviewed_worker_binding_activation_id,
        &request.reviewed_rollback_target,
        &request.reviewed_replay_fixture_refs,
        &request.reviewed_worker_handoff_node_attempt_ids,
        &request.reviewed_worker_handoff_receipt_ids,
        &request.reviewed_fork_mutation_canary_id,
        &request.reviewed_fork_mutation_canary_status,
        &request.reviewed_fork_mutation_canary_diff_hash,
        &request.reviewed_fork_mutation_canary_receipt_refs,
        &request.reviewed_fork_mutation_canary_replay_fixture_refs,
        &request.reviewed_fork_mutation_canary_node_attempt_ids,
        &request.reviewed_fork_mutation_canary_rollback_target,
        &request.reviewed_policy_posture,
    )
}

pub fn resolve_harness_worker_binding(
    record: &HarnessWorkerBindingRegistryRecord,
    request: &HarnessWorkerAttachRequest,
) -> HarnessWorkerAttachReceipt {
    let mut blockers = Vec::<String>::new();
    if request.schema_version != "workflow.harness.worker-attach-request.v1" {
        blockers.push("worker_attach_request_schema_mismatch".to_string());
    }
    if validate_harness_worker_binding_registry_record(record).is_err() {
        blockers.push("worker_attach_registry_invalid".to_string());
    }
    if request.workflow_id.trim().is_empty() {
        blockers.push("worker_attach_workflow_missing".to_string());
    }
    if request.activation_id.trim().is_empty() {
        blockers.push("worker_attach_activation_missing".to_string());
    }
    if request.activation_hash.trim().is_empty() {
        blockers.push("worker_attach_activation_hash_missing".to_string());
    }
    if request.harness_hash.trim().is_empty() {
        blockers.push("worker_attach_harness_hash_missing".to_string());
    }
    if request.workflow_id != record.workflow_id {
        blockers.push("worker_attach_workflow_mismatch".to_string());
    }
    if request.activation_id != record.activation_id {
        blockers.push("worker_attach_activation_mismatch".to_string());
    }
    if request.activation_hash != record.activation_hash {
        blockers.push("worker_attach_activation_hash_mismatch".to_string());
    }
    if request.harness_hash != record.harness_hash {
        blockers.push("worker_attach_harness_hash_mismatch".to_string());
    }
    if record.reviewed_package_snapshot_hash.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_snapshot_hash_missing".to_string());
    }
    let expected_record_snapshot_hash =
        harness_worker_binding_registry_reviewed_package_snapshot_hash(record);
    if record.reviewed_package_snapshot_hash != expected_record_snapshot_hash {
        blockers.push("worker_attach_reviewed_package_snapshot_hash_mismatch".to_string());
    }
    let expected_request_snapshot_hash =
        harness_worker_attach_request_reviewed_package_snapshot_hash(request);
    if request.reviewed_package_snapshot_hash != expected_request_snapshot_hash {
        blockers.push("worker_attach_reviewed_package_snapshot_hash_mismatch".to_string());
    }
    if request.reviewed_package_snapshot_hash != record.reviewed_package_snapshot_hash {
        blockers.push("worker_attach_reviewed_package_snapshot_hash_mismatch".to_string());
    }
    if record.reviewed_workflow_content_hash.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_workflow_hash_missing".to_string());
    }
    if request.reviewed_workflow_content_hash != record.reviewed_workflow_content_hash {
        blockers.push("worker_attach_reviewed_package_workflow_hash_mismatch".to_string());
    }
    if record.reviewed_activation_id.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_activation_missing".to_string());
    }
    if record
        .reviewed_worker_binding_activation_id
        .trim()
        .is_empty()
    {
        blockers.push("worker_attach_reviewed_package_worker_binding_missing".to_string());
    }
    if record.reviewed_activation_id != record.reviewed_worker_binding_activation_id
        || request.reviewed_activation_id != record.reviewed_activation_id
        || request.reviewed_worker_binding_activation_id
            != record.reviewed_worker_binding_activation_id
    {
        blockers.push("worker_attach_reviewed_package_activation_mismatch".to_string());
    }
    if record.reviewed_harness_workflow_id.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_workflow_id_missing".to_string());
    }
    if request.reviewed_harness_workflow_id != record.reviewed_harness_workflow_id {
        blockers.push("worker_attach_reviewed_package_workflow_id_mismatch".to_string());
    }
    if record.reviewed_rollback_target.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_rollback_target_missing".to_string());
    }
    if record.reviewed_rollback_target != record.rollback_target
        || request.reviewed_rollback_target != record.reviewed_rollback_target
    {
        blockers.push("worker_attach_reviewed_package_rollback_target_mismatch".to_string());
    }
    if record.reviewed_replay_fixture_refs.is_empty() {
        blockers.push("worker_attach_reviewed_package_replay_fixture_missing".to_string());
    }
    if request.reviewed_replay_fixture_refs != record.reviewed_replay_fixture_refs {
        blockers.push("worker_attach_reviewed_package_replay_fixture_mismatch".to_string());
    }
    if record.reviewed_worker_handoff_node_attempt_ids.is_empty() {
        blockers.push("worker_attach_reviewed_package_worker_attempt_missing".to_string());
    }
    if request.reviewed_worker_handoff_node_attempt_ids
        != record.reviewed_worker_handoff_node_attempt_ids
    {
        blockers.push("worker_attach_reviewed_package_worker_attempt_mismatch".to_string());
    }
    if record.reviewed_worker_handoff_receipt_ids.is_empty() {
        blockers.push("worker_attach_reviewed_package_worker_receipt_missing".to_string());
    }
    if request.reviewed_worker_handoff_receipt_ids != record.reviewed_worker_handoff_receipt_ids {
        blockers.push("worker_attach_reviewed_package_worker_receipt_mismatch".to_string());
    }
    if record.reviewed_fork_mutation_canary_id.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_fork_mutation_canary_missing".to_string());
    }
    if request.reviewed_fork_mutation_canary_id != record.reviewed_fork_mutation_canary_id {
        blockers.push("worker_attach_reviewed_package_fork_mutation_canary_mismatch".to_string());
    }
    if record.reviewed_fork_mutation_canary_status != "passed" {
        blockers.push("worker_attach_reviewed_package_fork_mutation_canary_not_passed".to_string());
    }
    if request.reviewed_fork_mutation_canary_status != record.reviewed_fork_mutation_canary_status {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_status_mismatch".to_string(),
        );
    }
    if record
        .reviewed_fork_mutation_canary_diff_hash
        .trim()
        .is_empty()
    {
        blockers
            .push("worker_attach_reviewed_package_fork_mutation_canary_diff_missing".to_string());
    }
    if request.reviewed_fork_mutation_canary_diff_hash
        != record.reviewed_fork_mutation_canary_diff_hash
    {
        blockers
            .push("worker_attach_reviewed_package_fork_mutation_canary_diff_mismatch".to_string());
    }
    if record.reviewed_fork_mutation_canary_receipt_refs.is_empty() {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_receipt_missing".to_string(),
        );
    }
    if request.reviewed_fork_mutation_canary_receipt_refs
        != record.reviewed_fork_mutation_canary_receipt_refs
    {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_receipt_mismatch".to_string(),
        );
    }
    if record
        .reviewed_fork_mutation_canary_replay_fixture_refs
        .is_empty()
    {
        blockers
            .push("worker_attach_reviewed_package_fork_mutation_canary_replay_missing".to_string());
    }
    if request.reviewed_fork_mutation_canary_replay_fixture_refs
        != record.reviewed_fork_mutation_canary_replay_fixture_refs
    {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_replay_mismatch".to_string(),
        );
    }
    if record
        .reviewed_fork_mutation_canary_node_attempt_ids
        .is_empty()
    {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_attempt_missing".to_string(),
        );
    }
    if request.reviewed_fork_mutation_canary_node_attempt_ids
        != record.reviewed_fork_mutation_canary_node_attempt_ids
    {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_attempt_mismatch".to_string(),
        );
    }
    if record.reviewed_fork_mutation_canary_rollback_target != record.rollback_target
        || request.reviewed_fork_mutation_canary_rollback_target
            != record.reviewed_fork_mutation_canary_rollback_target
    {
        blockers.push(
            "worker_attach_reviewed_package_fork_mutation_canary_rollback_mismatch".to_string(),
        );
    }
    if record.reviewed_policy_posture.trim().is_empty() {
        blockers.push("worker_attach_reviewed_package_policy_posture_missing".to_string());
    }
    if request.reviewed_policy_posture != record.reviewed_policy_posture {
        blockers.push("worker_attach_reviewed_package_policy_posture_mismatch".to_string());
    }
    if !harness_component_version_sets_match(
        &request.component_version_set,
        &record.component_version_set,
    ) {
        blockers.push("worker_attach_component_version_set_mismatch".to_string());
    }
    if request.rollback_target.trim().is_empty() {
        blockers.push("worker_attach_rollback_target_missing".to_string());
    }
    if request.rollback_target != record.rollback_target {
        blockers.push("worker_attach_rollback_target_mismatch".to_string());
    }
    if request.readiness_proof_id.trim().is_empty() {
        blockers.push("worker_attach_readiness_proof_missing".to_string());
    }
    if request.readiness_proof_id != record.readiness_proof_id {
        blockers.push("worker_attach_readiness_proof_mismatch".to_string());
    }
    if request.rollback_readiness_proof_id.trim().is_empty() {
        blockers.push("worker_attach_rollback_readiness_proof_missing".to_string());
    }
    if request.rollback_readiness_proof_id != record.readiness_proof_id
        || record.rollback_readiness_proof_id != record.readiness_proof_id
    {
        blockers.push("worker_attach_rollback_readiness_proof_mismatch".to_string());
    }
    if request
        .rollback_live_shadow_comparison_gate_id
        .trim()
        .is_empty()
        || record
            .rollback_live_shadow_comparison_gate_id
            .trim()
            .is_empty()
    {
        blockers.push("worker_attach_rollback_live_shadow_gate_missing".to_string());
    }
    if request.rollback_live_shadow_comparison_gate_id
        != record.rollback_live_shadow_comparison_gate_id
        || record
            .worker_binding
            .live_shadow_comparison_gate_id
            .as_deref()
            != Some(record.rollback_live_shadow_comparison_gate_id.as_str())
    {
        blockers.push("worker_attach_rollback_live_shadow_gate_mismatch".to_string());
    }
    if !request.rollback_live_shadow_comparison_gate_ready
        || !record.rollback_live_shadow_comparison_gate_ready
        || !record.worker_binding.live_shadow_comparison_gate_ready
    {
        blockers.push("worker_attach_rollback_live_shadow_gate_not_ready".to_string());
    }
    if request.rollback_activation_id != record.activation_id
        || record.rollback_activation_id != record.activation_id
    {
        blockers.push("worker_attach_rollback_activation_mismatch".to_string());
    }
    if request.rollback_harness_hash != record.harness_hash
        || record.rollback_harness_hash != record.harness_hash
    {
        blockers.push("worker_attach_rollback_harness_hash_mismatch".to_string());
    }
    if request.rollback_policy_decision
        != "allow_default_harness_worker_rollback_from_live_shadow_gate"
        || record.rollback_policy_decision
            != "allow_default_harness_worker_rollback_from_live_shadow_gate"
        || record.worker_binding.rollback_policy_decision.as_deref()
            != Some("allow_default_harness_worker_rollback_from_live_shadow_gate")
    {
        blockers.push("worker_attach_rollback_policy_not_allowed".to_string());
    }
    if !harness_invariant_sets_match(
        &request.required_invariant_ids,
        &record.required_invariant_ids,
    ) {
        blockers.push("worker_attach_required_invariant_mismatch".to_string());
    }
    if !harness_required_invariant_ids_present(&record.required_invariant_ids) {
        blockers
            .push("worker_attach_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    if !record.invariant_blockers.is_empty() {
        blockers.push("worker_attach_invariant_blocked".to_string());
    }
    if record.binding_status != HarnessWorkerBindingStatus::Bound {
        blockers.push("worker_attach_registry_not_bound".to_string());
    }
    if !record.blockers.is_empty() {
        blockers.push("worker_attach_registry_blocked".to_string());
    }
    if !record.canary_result_id.ends_with(":passed") {
        blockers.push("worker_attach_canary_not_passed".to_string());
    }
    if record.worker_binding.execution_mode != HarnessExecutionMode::Live {
        blockers.push("worker_attach_worker_not_live".to_string());
    }
    if record.worker_binding.rollback_target.as_deref() != Some(record.rollback_target.as_str()) {
        blockers.push("worker_attach_worker_rollback_mismatch".to_string());
    }
    if !record.worker_binding.authority_binding_ready {
        blockers.push("worker_attach_authority_not_ready".to_string());
    }
    if !record.worker_binding.authority_binding_blockers.is_empty() {
        blockers.push("worker_attach_authority_blocked".to_string());
    }
    if record
        .worker_binding
        .live_promotion_readiness_proof_id
        .as_deref()
        != Some(record.readiness_proof_id.as_str())
    {
        blockers.push("worker_attach_worker_readiness_proof_mismatch".to_string());
    }
    if !harness_invariant_sets_match(
        &record.worker_binding.required_invariant_ids,
        &record.required_invariant_ids,
    ) {
        blockers.push("worker_attach_worker_invariant_mismatch".to_string());
    }
    if !record.worker_binding.invariant_blockers.is_empty() {
        blockers.push("worker_attach_worker_invariant_blocked".to_string());
    }
    blockers.sort();
    blockers.dedup();

    let accepted = blockers.is_empty();
    let attach_status = if accepted {
        match request.requested_status {
            HarnessWorkerAttachStatus::Resumed => HarnessWorkerAttachStatus::Resumed,
            HarnessWorkerAttachStatus::RolledBack => HarnessWorkerAttachStatus::RolledBack,
            _ => HarnessWorkerAttachStatus::Bound,
        }
    } else {
        match record.binding_status {
            HarnessWorkerBindingStatus::Projection => HarnessWorkerAttachStatus::Unbound,
            HarnessWorkerBindingStatus::Canary => HarnessWorkerAttachStatus::Canary,
            HarnessWorkerBindingStatus::Blocked | HarnessWorkerBindingStatus::Bound => {
                HarnessWorkerAttachStatus::Blocked
            }
        }
    };

    HarnessWorkerAttachReceipt {
        schema_version: "workflow.harness.worker-attach-receipt.v1".to_string(),
        receipt_id: format!(
            "harness-worker-attach-receipt:{}:{}:{}",
            request.worker_id,
            record.registry_record_id,
            attach_status.as_str()
        ),
        worker_id: request.worker_id.clone(),
        workflow_id: request.workflow_id.clone(),
        activation_id: request.activation_id.clone(),
        activation_hash: request.activation_hash.clone(),
        harness_hash: request.harness_hash.clone(),
        reviewed_package_snapshot_hash: request.reviewed_package_snapshot_hash.clone(),
        reviewed_workflow_content_hash: request.reviewed_workflow_content_hash.clone(),
        reviewed_activation_id: request.reviewed_activation_id.clone(),
        reviewed_harness_workflow_id: request.reviewed_harness_workflow_id.clone(),
        reviewed_worker_binding_activation_id: request
            .reviewed_worker_binding_activation_id
            .clone(),
        reviewed_rollback_target: request.reviewed_rollback_target.clone(),
        reviewed_replay_fixture_refs: request.reviewed_replay_fixture_refs.clone(),
        reviewed_worker_handoff_node_attempt_ids: request
            .reviewed_worker_handoff_node_attempt_ids
            .clone(),
        reviewed_worker_handoff_receipt_ids: request.reviewed_worker_handoff_receipt_ids.clone(),
        reviewed_fork_mutation_canary_id: request.reviewed_fork_mutation_canary_id.clone(),
        reviewed_fork_mutation_canary_status: request.reviewed_fork_mutation_canary_status.clone(),
        reviewed_fork_mutation_canary_diff_hash: request
            .reviewed_fork_mutation_canary_diff_hash
            .clone(),
        reviewed_fork_mutation_canary_receipt_refs: request
            .reviewed_fork_mutation_canary_receipt_refs
            .clone(),
        reviewed_fork_mutation_canary_replay_fixture_refs: request
            .reviewed_fork_mutation_canary_replay_fixture_refs
            .clone(),
        reviewed_fork_mutation_canary_node_attempt_ids: request
            .reviewed_fork_mutation_canary_node_attempt_ids
            .clone(),
        reviewed_fork_mutation_canary_rollback_target: request
            .reviewed_fork_mutation_canary_rollback_target
            .clone(),
        reviewed_policy_posture: request.reviewed_policy_posture.clone(),
        component_version_set: request.component_version_set.clone(),
        rollback_target: request.rollback_target.clone(),
        rollback_available: request.rollback_target == record.rollback_target
            && !record.rollback_target.trim().is_empty(),
        readiness_proof_id: request.readiness_proof_id.clone(),
        rollback_readiness_proof_id: request.rollback_readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: request
            .rollback_live_shadow_comparison_gate_id
            .clone(),
        rollback_live_shadow_comparison_gate_ready: request
            .rollback_live_shadow_comparison_gate_ready
            && record.rollback_live_shadow_comparison_gate_ready,
        rollback_activation_id: request.rollback_activation_id.clone(),
        rollback_harness_hash: request.rollback_harness_hash.clone(),
        rollback_policy_decision: request.rollback_policy_decision.clone(),
        registry_record_id: record.registry_record_id.clone(),
        binding_status: record.binding_status,
        attach_status,
        accepted,
        blockers,
        worker_binding: record.worker_binding.clone(),
        policy_decision: if accepted {
            "allow_harness_worker_attach".to_string()
        } else {
            "block_harness_worker_attach".to_string()
        },
        required_invariant_ids: record.required_invariant_ids.clone(),
        invariant_blockers: {
            let mut blockers = record.invariant_blockers.clone();
            blockers.extend(record.worker_binding.invariant_blockers.iter().cloned());
            blockers.sort();
            blockers.dedup();
            blockers
        },
        evidence_refs: vec![
            record.registry_record_id.clone(),
            record.readiness_proof_id.clone(),
            record.rollback_live_shadow_comparison_gate_id.clone(),
            record.rollback_activation_id.clone(),
            record.rollback_harness_hash.clone(),
            record.canary_result_id.clone(),
            record.reviewed_package_snapshot_hash.clone(),
            record.reviewed_workflow_content_hash.clone(),
            record.reviewed_activation_id.clone(),
            record.reviewed_harness_workflow_id.clone(),
            record.reviewed_worker_binding_activation_id.clone(),
            record.reviewed_rollback_target.clone(),
            record.reviewed_fork_mutation_canary_id.clone(),
            record.reviewed_fork_mutation_canary_status.clone(),
            record.reviewed_fork_mutation_canary_diff_hash.clone(),
            record.reviewed_fork_mutation_canary_rollback_target.clone(),
        ],
    }
}

pub fn default_harness_worker_attach_lifecycle_events(
    record: &HarnessWorkerBindingRegistryRecord,
) -> Vec<HarnessWorkerAttachLifecycleEvent> {
    [
        (
            HarnessWorkerAttachLifecyclePhase::Attach,
            HarnessWorkerAttachStatus::Bound,
        ),
        (
            HarnessWorkerAttachLifecyclePhase::Resume,
            HarnessWorkerAttachStatus::Resumed,
        ),
        (
            HarnessWorkerAttachLifecyclePhase::Rollback,
            HarnessWorkerAttachStatus::RolledBack,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (phase, status))| {
        let receipt = resolve_harness_worker_binding(
            record,
            &default_harness_worker_attach_request(record, status),
        );
        let attempt_id = format!(
            "harness-worker-attach:attempt:{}:{}:{}",
            phase.as_str(),
            record.workflow_id,
            record.activation_id
        );
        HarnessWorkerAttachLifecycleEvent {
            schema_version: "workflow.harness.worker-attach-lifecycle.v1".to_string(),
            event_id: format!(
                "harness-worker-attach-lifecycle:{}:{}:{}",
                phase.as_str(),
                record.workflow_id,
                record.activation_id
            ),
            sequence: index as u32,
            phase,
            attempt_id,
            workflow_node_id: HarnessComponentKind::HandoffBridge.workflow_node_id(),
            component_kind: HarnessComponentKind::HandoffBridge,
            attach_status: receipt.attach_status,
            receipt_id: receipt.receipt_id.clone(),
            registry_record_id: record.registry_record_id.clone(),
            accepted: receipt.accepted,
            rollback_available: receipt.rollback_available,
            rollback_readiness_proof_id: receipt.rollback_readiness_proof_id.clone(),
            rollback_live_shadow_comparison_gate_id: receipt
                .rollback_live_shadow_comparison_gate_id
                .clone(),
            rollback_live_shadow_comparison_gate_ready: receipt
                .rollback_live_shadow_comparison_gate_ready,
            rollback_activation_id: receipt.rollback_activation_id.clone(),
            rollback_harness_hash: receipt.rollback_harness_hash.clone(),
            rollback_policy_decision: receipt.rollback_policy_decision.clone(),
            policy_decision: receipt.policy_decision.clone(),
            blockers: receipt.blockers.clone(),
            required_invariant_ids: receipt.required_invariant_ids.clone(),
            invariant_blockers: receipt.invariant_blockers.clone(),
            evidence_refs: receipt.evidence_refs.clone(),
            receipt,
        }
    })
    .collect()
}

pub fn default_harness_worker_session_record(
    record: &HarnessWorkerBindingRegistryRecord,
    lifecycle: &[HarnessWorkerAttachLifecycleEvent],
    session_id: impl AsRef<str>,
) -> HarnessWorkerSessionRecord {
    let session_id = session_id.as_ref().to_string();
    let attach_event = lifecycle
        .iter()
        .find(|event| event.phase == HarnessWorkerAttachLifecyclePhase::Attach);
    let resume_event = lifecycle
        .iter()
        .find(|event| event.phase == HarnessWorkerAttachLifecyclePhase::Resume);
    let rollback_event = lifecycle
        .iter()
        .find(|event| event.phase == HarnessWorkerAttachLifecyclePhase::Rollback);
    let mut blockers = Vec::<String>::new();
    if lifecycle.len() < 3 {
        blockers.push("worker_session_lifecycle_incomplete".to_string());
    }
    if attach_event.map(|event| {
        event.accepted
            && event.blockers.is_empty()
            && event.attach_status == HarnessWorkerAttachStatus::Bound
    }) != Some(true)
    {
        blockers.push("worker_session_attach_not_bound".to_string());
    }
    if resume_event.map(|event| {
        event.accepted
            && event.blockers.is_empty()
            && event.attach_status == HarnessWorkerAttachStatus::Resumed
    }) != Some(true)
    {
        blockers.push("worker_session_resume_not_resolved".to_string());
    }
    if rollback_event.map(|event| {
        event.accepted
            && event.blockers.is_empty()
            && event.attach_status == HarnessWorkerAttachStatus::RolledBack
            && event.rollback_available
    }) != Some(true)
    {
        blockers.push("worker_session_rollback_not_ready".to_string());
    }
    for event in lifecycle {
        if event.registry_record_id != record.registry_record_id {
            blockers.push("worker_session_registry_record_mismatch".to_string());
        }
        if !event.accepted {
            blockers.push("worker_session_lifecycle_event_blocked".to_string());
        }
        blockers.extend(event.blockers.iter().cloned());
        blockers.extend(event.invariant_blockers.iter().cloned());
    }
    if !harness_required_invariant_ids_present(&record.required_invariant_ids) {
        blockers
            .push("worker_session_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    if record.rollback_readiness_proof_id != record.readiness_proof_id {
        blockers.push("worker_session_rollback_readiness_proof_mismatch".to_string());
    }
    if record
        .rollback_live_shadow_comparison_gate_id
        .trim()
        .is_empty()
    {
        blockers.push("worker_session_rollback_live_shadow_gate_missing".to_string());
    }
    if !record.rollback_live_shadow_comparison_gate_ready {
        blockers.push("worker_session_rollback_live_shadow_gate_not_ready".to_string());
    }
    if record.rollback_activation_id != record.activation_id {
        blockers.push("worker_session_rollback_activation_mismatch".to_string());
    }
    if record.rollback_harness_hash != record.harness_hash {
        blockers.push("worker_session_rollback_harness_hash_mismatch".to_string());
    }
    if record.rollback_policy_decision
        != "allow_default_harness_worker_rollback_from_live_shadow_gate"
    {
        blockers.push("worker_session_rollback_policy_not_allowed".to_string());
    }
    blockers.extend(record.invariant_blockers.iter().cloned());
    blockers.extend(record.worker_binding.invariant_blockers.iter().cloned());
    blockers.sort();
    blockers.dedup();

    let accepted = blockers.is_empty();
    let resumed = resume_event
        .map(|event| event.accepted && event.attach_status == HarnessWorkerAttachStatus::Resumed)
        .unwrap_or(false);
    let rollback_available = rollback_event
        .map(|event| event.accepted && event.rollback_available)
        .unwrap_or(false);
    let rollback_target_ready = rollback_available && record.rollback_target.trim().len() > 0;
    let current_status = if !accepted {
        HarnessWorkerSessionStatus::Blocked
    } else if rollback_target_ready {
        HarnessWorkerSessionStatus::RollbackReady
    } else if resumed {
        HarnessWorkerSessionStatus::Resumed
    } else {
        HarnessWorkerSessionStatus::Attached
    };
    let current_event = if rollback_target_ready {
        rollback_event
    } else if resumed {
        resume_event
    } else {
        attach_event
    };
    let worker_id = attach_event
        .or_else(|| lifecycle.first())
        .map(|event| event.receipt.worker_id.clone())
        .unwrap_or_else(|| {
            default_harness_worker_attach_request(record, HarnessWorkerAttachStatus::Bound)
                .worker_id
        });
    let lifecycle_event_ids = lifecycle
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let lifecycle_attempt_ids = lifecycle
        .iter()
        .map(|event| event.attempt_id.clone())
        .collect::<Vec<_>>();
    let receipt_ids = lifecycle
        .iter()
        .map(|event| event.receipt_id.clone())
        .collect::<Vec<_>>();
    let mut invariant_blockers = record.invariant_blockers.clone();
    invariant_blockers.extend(record.worker_binding.invariant_blockers.iter().cloned());
    for event in lifecycle {
        invariant_blockers.extend(event.invariant_blockers.iter().cloned());
    }
    invariant_blockers.sort();
    invariant_blockers.dedup();
    let lifecycle_statuses = lifecycle
        .iter()
        .map(|event| event.attach_status)
        .collect::<Vec<_>>();
    let mut evidence_refs = vec![
        record.registry_record_id.clone(),
        record.readiness_proof_id.clone(),
        record.rollback_readiness_proof_id.clone(),
        record.rollback_live_shadow_comparison_gate_id.clone(),
        record.rollback_activation_id.clone(),
        record.rollback_harness_hash.clone(),
    ];
    evidence_refs.extend(lifecycle_event_ids.iter().cloned());
    evidence_refs.extend(receipt_ids.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();

    let session_record_id = format!(
        "harness-worker-session:{}:{}:{}:{}:{}",
        record.workflow_id, record.activation_id, record.activation_hash, worker_id, session_id
    );
    let persistence_key = format!("agent::harness_worker_session::{}", session_id);
    let record_persistence_key = format!(
        "agent::harness_worker_session_record::{}",
        session_record_id
    );
    let persistence_blockers = if accepted {
        Vec::new()
    } else {
        blockers.clone()
    };
    let launch_authority_blockers = if accepted {
        vec!["worker_session_not_persisted".to_string()]
    } else {
        blockers.clone()
    };
    let rollback_handoff_blockers = if accepted {
        vec!["worker_session_not_persisted".to_string()]
    } else {
        blockers.clone()
    };

    HarnessWorkerSessionRecord {
        schema_version: "workflow.harness.worker-session.v1".to_string(),
        session_record_id,
        session_id,
        worker_id,
        workflow_id: record.workflow_id.clone(),
        activation_id: record.activation_id.clone(),
        activation_hash: record.activation_hash.clone(),
        harness_hash: record.harness_hash.clone(),
        component_version_set: record.component_version_set.clone(),
        rollback_target: record.rollback_target.clone(),
        readiness_proof_id: record.readiness_proof_id.clone(),
        rollback_readiness_proof_id: record.rollback_readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: record
            .rollback_live_shadow_comparison_gate_id
            .clone(),
        rollback_live_shadow_comparison_gate_ready: record
            .rollback_live_shadow_comparison_gate_ready,
        rollback_activation_id: record.rollback_activation_id.clone(),
        rollback_harness_hash: record.rollback_harness_hash.clone(),
        rollback_policy_decision: record.rollback_policy_decision.clone(),
        registry_record_id: record.registry_record_id.clone(),
        current_status,
        current_event_id: current_event.map(|event| event.event_id.clone()),
        current_attempt_id: current_event.map(|event| event.attempt_id.clone()),
        current_receipt_id: current_event.map(|event| event.receipt_id.clone()),
        attach_event_id: attach_event.map(|event| event.event_id.clone()),
        resume_event_id: resume_event.map(|event| event.event_id.clone()),
        rollback_event_id: rollback_event.map(|event| event.event_id.clone()),
        lifecycle_event_ids,
        lifecycle_attempt_ids,
        receipt_ids,
        lifecycle_statuses,
        resumed,
        rollback_available,
        rollback_target_ready,
        accepted,
        blockers,
        policy_decision: if accepted {
            "allow_harness_worker_session".to_string()
        } else {
            "block_harness_worker_session".to_string()
        },
        required_invariant_ids: record.required_invariant_ids.clone(),
        invariant_blockers: invariant_blockers.clone(),
        evidence_refs,
        persistence_key,
        record_persistence_key,
        persisted_in_runtime_checkpoint: false,
        restored_from_persisted_session: false,
        runtime_checkpoint_source: "runtime_state_access_harness_worker_session_record".to_string(),
        persistence_blockers,
        launch_authority_ready: false,
        launch_authority_blockers,
        launch_authority_invariant_ids: record.required_invariant_ids.clone(),
        launch_authority_invariant_blockers: invariant_blockers,
        launch_authority_source: "persisted_harness_worker_session_record".to_string(),
        rollback_handoff_ready: false,
        rollback_handoff_blockers,
        rollback_handoff_target: record.rollback_target.clone(),
    }
}

pub fn default_harness_worker_launch_envelope(
    record: &HarnessWorkerSessionRecord,
    phase: HarnessWorkerLaunchPhase,
) -> HarnessWorkerLaunchEnvelope {
    let mut blockers = Vec::<String>::new();
    if record.schema_version != "workflow.harness.worker-session.v1" {
        blockers.push("worker_launch_session_schema_mismatch".to_string());
    }
    if record.session_record_id.trim().is_empty() {
        blockers.push("worker_launch_session_record_missing".to_string());
    }
    if record.session_id.trim().is_empty() {
        blockers.push("worker_launch_session_id_missing".to_string());
    }
    if record.worker_id.trim().is_empty() {
        blockers.push("worker_launch_worker_id_missing".to_string());
    }
    if !record.accepted {
        blockers.push("worker_launch_session_not_accepted".to_string());
    }
    if !record.blockers.is_empty() {
        blockers.push("worker_launch_session_blocked".to_string());
    }
    if record.current_status == HarnessWorkerSessionStatus::Blocked {
        blockers.push("worker_launch_session_status_blocked".to_string());
    }
    if !record.persisted_in_runtime_checkpoint {
        blockers.push("worker_launch_session_not_persisted".to_string());
    }
    if !record.persistence_blockers.is_empty() {
        blockers.push("worker_launch_session_persistence_blocked".to_string());
    }
    if !record.launch_authority_ready {
        blockers.push("worker_launch_authority_not_ready".to_string());
    }
    if !record.launch_authority_blockers.is_empty() {
        blockers.push("worker_launch_authority_blocked".to_string());
    }
    if !harness_required_invariant_ids_present(&record.launch_authority_invariant_ids) {
        blockers
            .push("worker_launch_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    blockers.extend(record.launch_authority_invariant_blockers.iter().cloned());
    if record.launch_authority_source != "persisted_harness_worker_session_record" {
        blockers.push("worker_launch_authority_source_mismatch".to_string());
    }
    if record.rollback_readiness_proof_id != record.readiness_proof_id {
        blockers.push("worker_launch_rollback_readiness_proof_mismatch".to_string());
    }
    if record
        .rollback_live_shadow_comparison_gate_id
        .trim()
        .is_empty()
    {
        blockers.push("worker_launch_rollback_live_shadow_gate_missing".to_string());
    }
    if !record.rollback_live_shadow_comparison_gate_ready {
        blockers.push("worker_launch_rollback_live_shadow_gate_not_ready".to_string());
    }
    if record.rollback_activation_id != record.activation_id {
        blockers.push("worker_launch_rollback_activation_mismatch".to_string());
    }
    if record.rollback_harness_hash != record.harness_hash {
        blockers.push("worker_launch_rollback_harness_hash_mismatch".to_string());
    }
    if record.rollback_policy_decision
        != "allow_default_harness_worker_rollback_from_live_shadow_gate"
    {
        blockers.push("worker_launch_rollback_policy_not_allowed".to_string());
    }
    if matches!(
        phase,
        HarnessWorkerLaunchPhase::Resume | HarnessWorkerLaunchPhase::Rollback
    ) && !record.resumed
    {
        blockers.push("worker_launch_session_not_resumed".to_string());
    }
    if phase == HarnessWorkerLaunchPhase::Rollback {
        if !record.rollback_available {
            blockers.push("worker_launch_rollback_not_available".to_string());
        }
        if !record.rollback_target_ready {
            blockers.push("worker_launch_rollback_target_not_ready".to_string());
        }
        if !record.rollback_handoff_ready {
            blockers.push("worker_launch_rollback_handoff_not_ready".to_string());
        }
        if !record.rollback_handoff_blockers.is_empty() {
            blockers.push("worker_launch_rollback_handoff_blocked".to_string());
        }
        if record.rollback_handoff_target != record.rollback_target {
            blockers.push("worker_launch_rollback_handoff_target_mismatch".to_string());
        }
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let mut evidence_refs = record.evidence_refs.clone();
    evidence_refs.push(record.session_record_id.clone());
    evidence_refs.push(record.persistence_key.clone());
    evidence_refs.push(record.record_persistence_key.clone());
    evidence_refs.push(record.rollback_readiness_proof_id.clone());
    evidence_refs.push(record.rollback_live_shadow_comparison_gate_id.clone());
    evidence_refs.push(record.rollback_activation_id.clone());
    evidence_refs.push(record.rollback_harness_hash.clone());
    evidence_refs.sort();
    evidence_refs.dedup();
    HarnessWorkerLaunchEnvelope {
        schema_version: "workflow.harness.worker-launch-envelope.v1".to_string(),
        envelope_id: format!(
            "harness-worker-launch-envelope:{}:{}",
            phase.as_str(),
            record.session_record_id
        ),
        phase,
        workflow_node_id: HarnessComponentKind::HandoffBridge.workflow_node_id(),
        component_kind: HarnessComponentKind::HandoffBridge,
        session_record_id: record.session_record_id.clone(),
        session_id: record.session_id.clone(),
        worker_id: record.worker_id.clone(),
        workflow_id: record.workflow_id.clone(),
        activation_id: record.activation_id.clone(),
        activation_hash: record.activation_hash.clone(),
        harness_hash: record.harness_hash.clone(),
        component_version_set: record.component_version_set.clone(),
        registry_record_id: record.registry_record_id.clone(),
        readiness_proof_id: record.readiness_proof_id.clone(),
        rollback_readiness_proof_id: record.rollback_readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: record
            .rollback_live_shadow_comparison_gate_id
            .clone(),
        rollback_live_shadow_comparison_gate_ready: record
            .rollback_live_shadow_comparison_gate_ready,
        rollback_activation_id: record.rollback_activation_id.clone(),
        rollback_harness_hash: record.rollback_harness_hash.clone(),
        rollback_policy_decision: record.rollback_policy_decision.clone(),
        rollback_target: record.rollback_target.clone(),
        persistence_key: record.persistence_key.clone(),
        record_persistence_key: record.record_persistence_key.clone(),
        launch_authority_source: record.launch_authority_source.clone(),
        launch_authority_ready: record.launch_authority_ready,
        launch_authority_invariant_ids: record.launch_authority_invariant_ids.clone(),
        launch_authority_invariant_blockers: record.launch_authority_invariant_blockers.clone(),
        rollback_handoff_ready: record.rollback_handoff_ready,
        accepted,
        blockers,
        policy_decision: if accepted {
            "allow_harness_worker_launch_envelope".to_string()
        } else {
            "block_harness_worker_launch_envelope".to_string()
        },
        evidence_refs,
    }
}

pub fn resolve_harness_worker_handoff_receipt(
    record: &HarnessWorkerSessionRecord,
    envelope: &HarnessWorkerLaunchEnvelope,
) -> HarnessWorkerHandoffReceipt {
    let mut blockers = envelope.blockers.clone();
    if envelope.schema_version != "workflow.harness.worker-launch-envelope.v1" {
        blockers.push("worker_handoff_envelope_schema_mismatch".to_string());
    }
    if envelope.session_record_id != record.session_record_id {
        blockers.push("worker_handoff_session_record_mismatch".to_string());
    }
    if envelope.session_id != record.session_id {
        blockers.push("worker_handoff_session_id_mismatch".to_string());
    }
    if envelope.worker_id != record.worker_id {
        blockers.push("worker_handoff_worker_id_mismatch".to_string());
    }
    if envelope.registry_record_id != record.registry_record_id {
        blockers.push("worker_handoff_registry_record_mismatch".to_string());
    }
    if envelope.readiness_proof_id != record.readiness_proof_id {
        blockers.push("worker_handoff_readiness_proof_mismatch".to_string());
    }
    if envelope.rollback_readiness_proof_id != record.rollback_readiness_proof_id
        || record.rollback_readiness_proof_id != record.readiness_proof_id
    {
        blockers.push("worker_handoff_rollback_readiness_proof_mismatch".to_string());
    }
    if envelope.rollback_live_shadow_comparison_gate_id
        != record.rollback_live_shadow_comparison_gate_id
        || record
            .rollback_live_shadow_comparison_gate_id
            .trim()
            .is_empty()
    {
        blockers.push("worker_handoff_rollback_live_shadow_gate_mismatch".to_string());
    }
    if !envelope.rollback_live_shadow_comparison_gate_ready
        || !record.rollback_live_shadow_comparison_gate_ready
    {
        blockers.push("worker_handoff_rollback_live_shadow_gate_not_ready".to_string());
    }
    if envelope.rollback_activation_id != record.rollback_activation_id
        || record.rollback_activation_id != record.activation_id
    {
        blockers.push("worker_handoff_rollback_activation_mismatch".to_string());
    }
    if envelope.rollback_harness_hash != record.rollback_harness_hash
        || record.rollback_harness_hash != record.harness_hash
    {
        blockers.push("worker_handoff_rollback_harness_hash_mismatch".to_string());
    }
    if envelope.rollback_policy_decision != record.rollback_policy_decision
        || record.rollback_policy_decision
            != "allow_default_harness_worker_rollback_from_live_shadow_gate"
    {
        blockers.push("worker_handoff_rollback_policy_not_allowed".to_string());
    }
    if envelope.rollback_target != record.rollback_target {
        blockers.push("worker_handoff_rollback_target_mismatch".to_string());
    }
    if !envelope.accepted {
        blockers.push("worker_handoff_envelope_not_accepted".to_string());
    }
    if !record.launch_authority_ready {
        blockers.push("worker_handoff_launch_authority_not_ready".to_string());
    }
    if !harness_required_invariant_ids_present(&envelope.launch_authority_invariant_ids) {
        blockers
            .push("worker_handoff_reviewed_import_activation_apply_invariant_missing".to_string());
    }
    blockers.extend(envelope.launch_authority_invariant_blockers.iter().cloned());
    if envelope.phase == HarnessWorkerLaunchPhase::Rollback && !record.rollback_handoff_ready {
        blockers.push("worker_handoff_rollback_not_ready".to_string());
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let handoff_status = if !accepted {
        "blocked"
    } else {
        match envelope.phase {
            HarnessWorkerLaunchPhase::Launch => "launched",
            HarnessWorkerLaunchPhase::Resume => "resumed",
            HarnessWorkerLaunchPhase::Rollback => "rollback_handoff_ready",
        }
    };
    let mut evidence_refs = envelope.evidence_refs.clone();
    evidence_refs.push(envelope.envelope_id.clone());
    evidence_refs.push(envelope.rollback_readiness_proof_id.clone());
    evidence_refs.push(envelope.rollback_live_shadow_comparison_gate_id.clone());
    evidence_refs.push(envelope.rollback_activation_id.clone());
    evidence_refs.push(envelope.rollback_harness_hash.clone());
    evidence_refs.extend(record.receipt_ids.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();
    let mut receipt_refs = record.receipt_ids.clone();
    receipt_refs.push(envelope.envelope_id.clone());
    receipt_refs.sort();
    receipt_refs.dedup();
    HarnessWorkerHandoffReceipt {
        schema_version: "workflow.harness.worker-handoff-receipt.v1".to_string(),
        receipt_id: format!(
            "harness-worker-handoff-receipt:{}:{}",
            envelope.phase.as_str(),
            record.session_record_id
        ),
        envelope_id: envelope.envelope_id.clone(),
        phase: envelope.phase,
        workflow_node_id: envelope.workflow_node_id.clone(),
        component_kind: envelope.component_kind,
        session_record_id: record.session_record_id.clone(),
        session_id: record.session_id.clone(),
        worker_id: record.worker_id.clone(),
        workflow_id: record.workflow_id.clone(),
        activation_id: record.activation_id.clone(),
        activation_hash: record.activation_hash.clone(),
        harness_hash: record.harness_hash.clone(),
        registry_record_id: record.registry_record_id.clone(),
        readiness_proof_id: record.readiness_proof_id.clone(),
        rollback_readiness_proof_id: record.rollback_readiness_proof_id.clone(),
        rollback_live_shadow_comparison_gate_id: record
            .rollback_live_shadow_comparison_gate_id
            .clone(),
        rollback_live_shadow_comparison_gate_ready: record
            .rollback_live_shadow_comparison_gate_ready,
        rollback_activation_id: record.rollback_activation_id.clone(),
        rollback_harness_hash: record.rollback_harness_hash.clone(),
        rollback_policy_decision: record.rollback_policy_decision.clone(),
        rollback_target: record.rollback_target.clone(),
        rollback_available: record.rollback_available,
        launch_authority_source: record.launch_authority_source.clone(),
        accepted,
        handoff_status: handoff_status.to_string(),
        blockers,
        required_invariant_ids: envelope.launch_authority_invariant_ids.clone(),
        invariant_blockers: envelope.launch_authority_invariant_blockers.clone(),
        policy_decision: if accepted {
            "allow_harness_worker_handoff".to_string()
        } else {
            "block_harness_worker_handoff".to_string()
        },
        receipt_refs,
        evidence_refs,
    }
}

pub fn default_harness_node_attempt_for_worker_handoff_receipt(
    receipt: &HarnessWorkerHandoffReceipt,
    attempt_index: u32,
) -> HarnessNodeAttemptRecord {
    let component = default_harness_component_spec(HarnessComponentKind::HandoffBridge);
    let mut receipt_ids = receipt.receipt_refs.clone();
    receipt_ids.push(receipt.receipt_id.clone());
    receipt_ids.push(receipt.envelope_id.clone());
    receipt_ids.sort();
    receipt_ids.dedup();
    let mut replay = default_harness_replay_envelope(HarnessComponentKind::HandoffBridge);
    replay.captures_policy_decision = true;
    replay.fixture_ref = Some(format!(
        "harness-worker-handoff:fixture:{}:{}",
        receipt.phase.as_str(),
        receipt.session_record_id
    ));
    HarnessNodeAttemptRecord {
        attempt_id: format!(
            "harness-worker-handoff:attempt:{}:{}",
            receipt.phase.as_str(),
            receipt.session_record_id
        ),
        harness_workflow_id: receipt.workflow_id.clone(),
        harness_activation_id: receipt.activation_id.clone(),
        harness_hash: receipt.harness_hash.clone(),
        workflow_node_id: receipt.workflow_node_id.clone(),
        component_id: component.component_id,
        component_kind: HarnessComponentKind::HandoffBridge,
        execution_mode: HarnessExecutionMode::Live,
        readiness: component.readiness,
        attempt_index,
        status: if receipt.accepted {
            HarnessNodeAttemptStatus::Live
        } else {
            HarnessNodeAttemptStatus::Blocked
        },
        input_hash: Some(format!(
            "sha256:worker-handoff-input:{}:{}",
            receipt.phase.as_str(),
            receipt.session_record_id
        )),
        output_hash: receipt.accepted.then(|| {
            format!(
                "sha256:worker-handoff-output:{}:{}",
                receipt.phase.as_str(),
                receipt.session_record_id
            )
        }),
        error_class: (!receipt.accepted).then(|| "worker_handoff_blocked".to_string()),
        policy_decision: Some(receipt.policy_decision.clone()),
        started_at_ms: None,
        duration_ms: None,
        receipt_ids,
        evidence_refs: receipt.evidence_refs.clone(),
        replay,
    }
}
