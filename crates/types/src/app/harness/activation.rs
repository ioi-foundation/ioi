use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessLiveHandoffSelector {
    WorkflowRecoveryBlocked,
    BlessedWorkflowGated,
    BlessedWorkflowLiveCanary,
    BlessedWorkflowLiveDefault,
}

impl HarnessLiveHandoffSelector {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowRecoveryBlocked => "workflow_recovery_blocked",
            Self::BlessedWorkflowGated => "blessed_workflow_gated",
            Self::BlessedWorkflowLiveCanary => "blessed_workflow_live_canary",
            Self::BlessedWorkflowLiveDefault => "blessed_workflow_live_default",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessRecoveryMode {
    FailClosed,
    RestorePriorWorkflowActivation,
}

impl HarnessRecoveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::RestorePriorWorkflowActivation => "restore_prior_workflow_activation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentVersionBinding {
    pub component_id: String,
    pub component_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessDefaultPromotionGate {
    pub config_key: String,
    pub enabled: bool,
    pub eligible: bool,
    pub non_mutating_only: bool,
    pub selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub default_authority_transferred: bool,
    pub rollback_target: String,
    pub activation_blockers: Vec<String>,
    pub required_invariant_ids: Vec<String>,
    pub invariant_blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessReviewedImportActivationApplyGate {
    pub schema_version: String,
    pub gate_id: String,
    pub invariant_id: String,
    pub proof_present: bool,
    pub proof_passed: bool,
    pub proof_blockers: Vec<String>,
    pub activation_id: Option<String>,
    pub worker_binding_activation_id: Option<String>,
    pub rollback_target: Option<String>,
    pub reviewed_workflow_content_hash: Option<String>,
    pub reviewed_harness_workflow_id: Option<String>,
    pub reviewed_replay_fixture_refs: Vec<String>,
    pub reviewed_worker_handoff_node_attempt_ids: Vec<String>,
    pub reviewed_worker_handoff_receipt_ids: Vec<String>,
    pub reviewed_policy_posture: Option<String>,
    pub default_dispatch_activation_blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessCognitionNodeAuthorityGate {
    pub schema_version: String,
    pub gate_id: String,
    pub authority_mode: String,
    pub authoritative: bool,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub required_execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub adapter_mode: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub live_ready_component_kinds: Vec<HarnessComponentKind>,
    pub action_frame_ids: Vec<String>,
    pub attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessRoutingModelNodeAuthorityGate {
    pub schema_version: String,
    pub gate_id: String,
    pub authority_mode: String,
    pub authoritative: bool,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub required_execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub adapter_mode: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub shadow_ready_component_kinds: Vec<HarnessComponentKind>,
    pub action_frame_ids: Vec<String>,
    pub attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub shadow_attempt_ids: Vec<String>,
    pub shadow_receipt_ids: Vec<String>,
    pub shadow_replay_fixture_refs: Vec<String>,
    pub divergence_classes: Vec<HarnessDivergenceClass>,
    pub shadow_divergence_classes: Vec<HarnessDivergenceClass>,
    pub provider_canary_ready: bool,
    pub visible_output_selected: bool,
    pub visible_output_authority: String,
    pub read_only_capability_routing_ready: bool,
    pub rollback_available: bool,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessVerificationOutputNodeAuthorityGate {
    pub schema_version: String,
    pub gate_id: String,
    pub authority_mode: String,
    pub authoritative: bool,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub required_execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub adapter_mode: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub shadow_ready_component_kinds: Vec<HarnessComponentKind>,
    pub action_frame_ids: Vec<String>,
    pub attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub shadow_attempt_ids: Vec<String>,
    pub shadow_receipt_ids: Vec<String>,
    pub shadow_replay_fixture_refs: Vec<String>,
    pub divergence_classes: Vec<HarnessDivergenceClass>,
    pub shadow_divergence_classes: Vec<HarnessDivergenceClass>,
    pub output_writer_handoff_ready: bool,
    pub output_writer_materialization_canary_ready: bool,
    pub output_writer_staged_write_canary_ready: bool,
    pub output_writer_visible_write_ready: bool,
    pub output_writer_visible_write_committed: bool,
    pub rollback_available: bool,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessAuthorityToolingNodeAuthorityGate {
    pub schema_version: String,
    pub gate_id: String,
    pub authority_mode: String,
    pub authoritative: bool,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub required_execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub adapter_mode: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub shadow_ready_component_kinds: Vec<HarnessComponentKind>,
    pub action_frame_ids: Vec<String>,
    pub attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub shadow_attempt_ids: Vec<String>,
    pub shadow_receipt_ids: Vec<String>,
    pub shadow_replay_fixture_refs: Vec<String>,
    pub divergence_classes: Vec<HarnessDivergenceClass>,
    pub shadow_divergence_classes: Vec<HarnessDivergenceClass>,
    pub read_only_route_accepted: bool,
    pub destructive_route_denied: bool,
    pub mutating_tool_calls_blocked: bool,
    pub side_effects_executed: bool,
    pub policy_gate_ready: bool,
    pub tool_router_ready: bool,
    pub dry_run_simulator_ready: bool,
    pub approval_gate_ready: bool,
    pub gate_live_ready: bool,
    pub read_only_authority_canary_ready: bool,
    pub rollback_available: bool,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessLiveHandoffProof {
    pub schema_version: String,
    pub selector: HarnessLiveHandoffSelector,
    pub available_selectors: Vec<HarnessLiveHandoffSelector>,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub canary_status: String,
    pub canary_turn_routed_through_workflow: bool,
    pub execution_boundary_id: String,
    pub execution_boundary_ids: Vec<String>,
    pub execution_boundary_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub execution_boundary_status: String,
    pub execution_boundary_executor: String,
    pub default_authority_transferred: bool,
    pub runtime_authority: String,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub policy_decision: String,
    pub gated_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub node_timeline_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub live_promotion_readiness_proof: Option<HarnessLivePromotionReadinessProof>,
    pub live_promotion_readiness_ready: bool,
    pub live_promotion_readiness_blockers: Vec<String>,
    pub live_promotion_readiness_policy_decision: String,
    pub default_live_promotion_invariant_ids: Vec<String>,
    pub default_live_promotion_invariant_blockers: Vec<String>,
    pub reviewed_import_activation_apply_proof_present: bool,
    pub reviewed_import_activation_apply_proof_passed: bool,
    pub reviewed_import_activation_apply_proof_blockers: Vec<String>,
    pub reviewed_import_activation_apply_activation_id: Option<String>,
    pub activation_blockers: Vec<String>,
    pub default_promotion_gate: HarnessDefaultPromotionGate,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessRuntimeSelectorDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub requested_selector: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub canary_eligible: bool,
    pub canary_blockers: Vec<String>,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub actual_runtime_authority: String,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub policy_decision: String,
    pub route_reason: String,
    pub live_promotion_readiness_proof: Option<HarnessLivePromotionReadinessProof>,
    pub live_promotion_readiness_ready: bool,
    pub live_promotion_readiness_blockers: Vec<String>,
    pub live_promotion_readiness_policy_decision: String,
    pub default_live_promotion_invariant_ids: Vec<String>,
    pub default_live_promotion_invariant_blockers: Vec<String>,
    pub reviewed_import_activation_apply_proof_present: bool,
    pub reviewed_import_activation_apply_proof_passed: bool,
    pub reviewed_import_activation_apply_proof_blockers: Vec<String>,
    pub reviewed_import_activation_apply_activation_id: Option<String>,
    pub default_promotion_gate: HarnessDefaultPromotionGate,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessDefaultRuntimeDispatchProof {
    pub schema_version: String,
    pub dispatch_id: String,
    pub selector_decision_id: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub dispatch_scope: String,
    pub accepted_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub deferred_component_kinds: Vec<HarnessComponentKind>,
    pub handoff_validated_component_kinds: Vec<HarnessComponentKind>,
    pub materialization_canary_component_kinds: Vec<HarnessComponentKind>,
    pub source_boundary_ids: Vec<String>,
    pub dispatch_node_attempt_ids: Vec<String>,
    pub cognition_execution_attempt_ids: Vec<String>,
    pub cognition_execution_receipt_ids: Vec<String>,
    pub cognition_execution_replay_fixture_refs: Vec<String>,
    pub model_execution_attempt_ids: Vec<String>,
    pub model_execution_receipt_ids: Vec<String>,
    pub model_execution_replay_fixture_refs: Vec<String>,
    pub model_provider_canary_attempt_ids: Vec<String>,
    pub model_provider_canary_receipt_ids: Vec<String>,
    pub model_provider_canary_replay_fixture_refs: Vec<String>,
    pub model_provider_gated_visible_output_attempt_ids: Vec<String>,
    pub model_provider_gated_visible_output_receipt_ids: Vec<String>,
    pub model_provider_gated_visible_output_replay_fixture_refs: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_attempt_ids: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_receipt_ids: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_replay_fixture_refs: Vec<String>,
    pub read_only_capability_routing_attempt_ids: Vec<String>,
    pub read_only_capability_routing_receipt_ids: Vec<String>,
    pub read_only_capability_routing_replay_fixture_refs: Vec<String>,
    pub output_writer_handoff_attempt_ids: Vec<String>,
    pub output_writer_materialization_canary_attempt_ids: Vec<String>,
    pub output_writer_staged_write_canary_attempt_ids: Vec<String>,
    pub output_writer_visible_write_attempt_ids: Vec<String>,
    pub authority_tooling_live_dry_run_attempt_ids: Vec<String>,
    pub authority_tooling_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_policy_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_policy_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_policy_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_destructive_denial_live_attempt_ids: Vec<String>,
    pub authority_tooling_destructive_denial_live_receipt_ids: Vec<String>,
    pub authority_tooling_destructive_denial_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_approval_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_approval_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_approval_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_read_only_live_attempt_ids: Vec<String>,
    pub authority_tooling_read_only_receipt_ids: Vec<String>,
    pub authority_tooling_read_only_replay_fixture_refs: Vec<String>,
    pub authority_tooling_provider_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_provider_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_provider_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_connector_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_connector_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_connector_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_attempt_ids: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_receipt_ids: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs: Vec<String>,
    pub authority_tooling_read_only_component_kinds: Vec<HarnessComponentKind>,
    pub authority_tooling_mutation_deferred_component_kinds: Vec<HarnessComponentKind>,
    pub authority_tooling_denial_receipt_ids: Vec<String>,
    pub accepted_node_attempt_ids: Vec<String>,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub executor_kind: String,
    pub executor_ref: String,
    pub synchronous: bool,
    pub drives_runtime_decision: bool,
    pub activation_id_gate_click_proof_present: bool,
    pub activation_id_gate_click_proof_passed: bool,
    pub activation_id_gate_click_proof_blockers: Vec<String>,
    pub default_dispatch_activation_blockers: Vec<String>,
    pub default_live_promotion_invariant_ids: Vec<String>,
    pub default_live_promotion_invariant_blockers: Vec<String>,
    pub reviewed_import_activation_apply_proof_present: bool,
    pub reviewed_import_activation_apply_proof_passed: bool,
    pub reviewed_import_activation_apply_proof_blockers: Vec<String>,
    pub reviewed_import_activation_apply_activation_id: Option<String>,
    pub reviewed_import_activation_apply_gate: HarnessReviewedImportActivationApplyGate,
    pub cognition_node_authority_gate: HarnessCognitionNodeAuthorityGate,
    pub routing_model_node_authority_gate: HarnessRoutingModelNodeAuthorityGate,
    pub verification_output_node_authority_gate: HarnessVerificationOutputNodeAuthorityGate,
    pub authority_tooling_node_authority_gate: HarnessAuthorityToolingNodeAuthorityGate,
    pub cognition_execution_mode: String,
    pub cognition_execution_ready: bool,
    pub prompt_assembly_mode: String,
    pub prompt_assembly_prompt_hash: String,
    pub prompt_assembly_prompt_hash_matches: bool,
    pub model_execution_mode: String,
    pub model_execution_envelope_ready: bool,
    pub model_execution_binding_id: String,
    pub model_execution_binding_ready: bool,
    pub model_execution_prompt_hash: String,
    pub model_execution_prompt_hash_matches: bool,
    pub model_execution_output_hash: String,
    pub model_execution_output_hash_matches: bool,
    pub model_execution_provider_invocation_mode: String,
    pub model_execution_low_level_invocation_deferred: bool,
    pub model_execution_recovery_mode: HarnessRecoveryMode,
    pub model_execution_latency_ms: u64,
    pub model_provider_canary_mode: String,
    pub model_provider_canary_ready: bool,
    pub model_provider_canary_candidate_output_hash: String,
    pub model_provider_canary_prior_workflow_output_hash: String,
    pub model_provider_canary_output_hash_matches: bool,
    pub model_provider_canary_transcript_matches: bool,
    pub model_provider_canary_recovery_ready: bool,
    pub model_provider_canary_rollback_available: bool,
    pub model_provider_gated_visible_output_mode: String,
    pub model_provider_gated_visible_output_enabled: bool,
    pub model_provider_gated_visible_output_ready: bool,
    pub model_provider_gated_visible_output_selected: bool,
    pub model_provider_gated_visible_output_eligible: bool,
    pub model_provider_gated_visible_output_scenario: String,
    pub model_provider_gated_visible_output_cohort: String,
    pub model_provider_gated_visible_output_retained_read_only_no_tool: bool,
    pub model_provider_gated_visible_output_required_scenario_set: Vec<String>,
    pub model_provider_gated_visible_output_scenario_coverage_key: Option<String>,
    pub model_provider_gated_visible_output_activation_flag: String,
    pub model_provider_gated_visible_output_activation_id: String,
    pub model_provider_gated_visible_output_authority: String,
    pub model_provider_gated_visible_output_rollback_target: String,
    pub model_provider_gated_visible_output_rollback_available: bool,
    pub selected_visible_output_authority: String,
    pub selected_visible_output_hash: String,
    pub workflow_provider_visible_output_hash: String,
    pub prior_workflow_visible_output_hash: String,
    pub prior_workflow_visible_output_computed: bool,
    pub prior_workflow_visible_output_hash_matches_selected: bool,
    pub selected_visible_output_authority_matches_transcript: bool,
    pub visible_output_divergence_class: Option<String>,
    pub model_provider_gated_visible_output_rollback_drill_enabled: bool,
    pub model_provider_gated_visible_output_rollback_drill_ready: bool,
    pub model_provider_gated_visible_output_rollback_drill_failure_injected: bool,
    pub model_provider_gated_visible_output_rollback_drill_injected_output_hash: String,
    pub model_provider_gated_visible_output_rollback_drill_output_hash_diverges: bool,
    pub model_provider_gated_visible_output_rollback_drill_divergence_class: String,
    pub model_provider_gated_visible_output_rollback_drill_recovery_mode: HarnessRecoveryMode,
    pub model_provider_gated_visible_output_rollback_drill_selected_authority: String,
    pub model_provider_gated_visible_output_rollback_drill_transcript_unchanged: bool,
    pub model_provider_gated_visible_output_rollback_drill_rollback_executed: bool,
    pub model_provider_gated_visible_output_rollback_drill_activation_blockers: Vec<String>,
    pub read_only_capability_routing_mode: String,
    pub read_only_capability_routing_ready: bool,
    pub read_only_capability_routing_selected: bool,
    pub read_only_capability_routing_eligible: bool,
    pub read_only_capability_routing_scenario: String,
    pub read_only_capability_routing_required_scenario_set: Vec<String>,
    pub read_only_capability_routing_scenario_coverage_key: Option<String>,
    pub read_only_capability_routing_source_material_ready: bool,
    pub read_only_capability_routing_no_mutation_ready: bool,
    pub read_only_capability_routing_workflow_owned_node_kinds: Vec<HarnessComponentKind>,
    pub live_promotion_readiness_proof: HarnessLivePromotionReadinessProof,
    pub worker_binding_registry_record: HarnessWorkerBindingRegistryRecord,
    pub output_authority: String,
    pub output_writer_deferred: bool,
    pub output_writer_status: String,
    pub output_writer_handoff_ready: bool,
    pub output_writer_authority_transferred: bool,
    pub output_writer_materialization_mode: String,
    pub output_writer_materialization_canary_ready: bool,
    pub output_writer_materialization_committed: bool,
    pub output_writer_staged_write_mode: String,
    pub output_writer_staged_write_canary_ready: bool,
    pub output_writer_staged_write_persisted: bool,
    pub output_writer_staged_write_committed: bool,
    pub output_writer_staged_write_visible: bool,
    pub output_writer_staged_write_excluded_from_visible_transcript: bool,
    pub output_writer_staged_write_rollback_status: String,
    pub output_writer_staged_write_rollback_verified: bool,
    pub output_writer_visible_write_mode: String,
    pub output_writer_visible_write_ready: bool,
    pub output_writer_visible_write_persisted: bool,
    pub output_writer_visible_write_committed: bool,
    pub output_writer_visible_write_visible: bool,
    pub output_writer_visible_write_identity_checkpoint_persisted: bool,
    pub output_writer_visible_write_recovery_duplicate_suppressed: bool,
    pub authority_tooling_mode: String,
    pub authority_tooling_ready: bool,
    pub authority_tooling_policy_gate_ready: bool,
    pub authority_tooling_tool_router_ready: bool,
    pub authority_tooling_dry_run_simulator_ready: bool,
    pub authority_tooling_approval_gate_ready: bool,
    pub authority_tooling_gate_live_ready: bool,
    pub authority_tooling_policy_gate_live_ready: bool,
    pub authority_tooling_destructive_denial_live_ready: bool,
    pub authority_tooling_approval_gate_live_ready: bool,
    pub authority_tooling_read_only_route_accepted: bool,
    pub authority_tooling_destructive_route_denied: bool,
    pub authority_tooling_mutating_tool_calls_blocked: bool,
    pub authority_tooling_side_effects_executed: bool,
    pub authority_tooling_rollback_available: bool,
    pub workflow_transcript_recovery_authority_retained: bool,
    pub workflow_transcript_recovery_available: bool,
    pub proposed_visible_output_hash: String,
    pub actual_visible_output_hash: String,
    pub output_hash_algorithm: String,
    pub output_hash_matches: bool,
    pub output_hash_divergence: bool,
    pub output_hash_divergence_count: u32,
    pub transcript_materialization_content_hash_matches: bool,
    pub transcript_materialization_order_matches: bool,
    pub transcript_materialization_receipt_binding_matches: bool,
    pub transcript_materialization_target_matches: bool,
    pub transcript_materialization_matches: bool,
    pub transcript_materialization_divergence_count: u32,
    pub staged_transcript_write_content_hash_matches: bool,
    pub staged_transcript_write_order_matches: bool,
    pub staged_transcript_write_receipt_binding_matches: bool,
    pub staged_transcript_write_target_matches: bool,
    pub staged_transcript_write_matches: bool,
    pub staged_transcript_write_divergence_count: u32,
    pub visible_transcript_write_content_hash_matches: bool,
    pub visible_transcript_write_order_matches: bool,
    pub visible_transcript_write_receipt_binding_matches: bool,
    pub visible_transcript_write_target_matches: bool,
    pub visible_transcript_write_matches: bool,
    pub visible_transcript_write_divergence_count: u32,
    pub workflow_output_recovery_authority_retained: bool,
    pub workflow_output_recovery_available: bool,
    pub mutating_turns_blocked: bool,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub activation_blockers: Vec<String>,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessCanaryRollbackDrill {
    pub schema_version: String,
    pub drill_id: String,
    pub selector_decision_id: String,
    pub failure_injected: bool,
    pub failed_node_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub failure_class: String,
    pub observed_failure: bool,
    pub rollback_executed: bool,
    pub rollback_selector: HarnessLiveHandoffSelector,
    pub recovery_mode: HarnessRecoveryMode,
    pub recovery_target: String,
    pub recovery_available: bool,
    pub recovery_blockers: Vec<String>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub drill_status: String,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessCanaryExecutionBoundary {
    pub schema_version: String,
    pub boundary_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub selector_decision_id: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub executor_kind: String,
    pub executor_ref: String,
    pub synchronous: bool,
    pub enforced_before_visible_output: bool,
    pub canary_eligible: bool,
    pub status: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub executed_component_kinds: Vec<HarnessComponentKind>,
    pub workflow_node_ids: Vec<String>,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub activation_blockers: Vec<String>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub rollback_drill: HarnessCanaryRollbackDrill,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessForkMutationCanaryStatus {
    Passed,
    Blocked,
    NotRun,
}

impl HarnessForkMutationCanaryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Blocked => "blocked",
            Self::NotRun => "not_run",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessForkMutationKind {
    BudgetGateLimit,
    RetryBound,
    VerifierThreshold,
}

impl HarnessForkMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BudgetGateLimit => "budget_gate_limit",
            Self::RetryBound => "retry_bound",
            Self::VerifierThreshold => "verifier_threshold",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessForkMutationCanary {
    pub schema_version: String,
    pub canary_id: String,
    pub mutation_id: String,
    pub mutation_kind: HarnessForkMutationKind,
    pub mutation_scope: String,
    pub workflow_id: String,
    pub harness_workflow_id: String,
    pub component_id: String,
    pub workflow_node_id: String,
    pub target_path: String,
    pub before_value: String,
    pub after_value: String,
    pub diff_hash: String,
    pub proposal_id: String,
    pub status: HarnessForkMutationCanaryStatus,
    pub canary_status: HarnessForkMutationCanaryStatus,
    pub replay_fixture_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub node_attempt_ids: Vec<String>,
    #[serde(default)]
    pub node_attempts: Vec<HarnessNodeAttemptRecord>,
    pub evidence_refs: Vec<String>,
    pub policy_decision: String,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub blockers: Vec<String>,
    pub created_at_ms: u64,
}
pub fn default_blessed_live_handoff_proof(
    node_timeline_attempt_ids: Vec<String>,
    receipt_ids: Vec<String>,
    replay_fixture_refs: Vec<String>,
) -> HarnessLiveHandoffProof {
    HarnessLiveHandoffProof {
        schema_version: "workflow.harness.live-handoff.v1".to_string(),
        selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        available_selectors: vec![
            HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
            HarnessLiveHandoffSelector::BlessedWorkflowGated,
            HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        ],
        production_default_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        component_version_set: default_harness_component_version_set(),
        canary_status: "passed".to_string(),
        canary_turn_routed_through_workflow: true,
        execution_boundary_id: "harness-canary-boundary:default-agent-harness:verification_output"
            .to_string(),
        execution_boundary_ids: vec![
            "harness-canary-boundary:default-agent-harness:cognition".to_string(),
            "harness-canary-boundary:default-agent-harness:routing_model".to_string(),
            "harness-canary-boundary:default-agent-harness:verification_output".to_string(),
            "harness-canary-boundary:default-agent-harness:authority_tooling".to_string(),
        ],
        execution_boundary_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        execution_boundary_status: "passed".to_string(),
        execution_boundary_executor: "crate::project::execute_workflow_harness_canary_node"
            .to_string(),
        default_authority_transferred: false,
        runtime_authority: "blessed_workflow_activation_canary".to_string(),
        recovery_mode: HarnessRecoveryMode::FailClosed,
        recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        recovery_available: true,
        recovery_blockers: Vec::new(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        policy_decision: "allow_blessed_workflow_live_canary".to_string(),
        gated_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        node_timeline_attempt_ids,
        receipt_ids,
        replay_fixture_refs,
        live_promotion_readiness_proof: None,
        live_promotion_readiness_ready: false,
        live_promotion_readiness_blockers: Vec::new(),
        live_promotion_readiness_policy_decision: "not_required_for_canary_handoff".to_string(),
        default_live_promotion_invariant_ids: Vec::new(),
        default_live_promotion_invariant_blockers: Vec::new(),
        reviewed_import_activation_apply_proof_present: false,
        reviewed_import_activation_apply_proof_passed: false,
        reviewed_import_activation_apply_proof_blockers: Vec::new(),
        reviewed_import_activation_apply_activation_id: None,
        activation_blockers: Vec::new(),
        default_promotion_gate: HarnessDefaultPromotionGate {
            config_key: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION".to_string(),
            enabled: false,
            eligible: false,
            non_mutating_only: true,
            selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            production_default_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
            default_authority_transferred: false,
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            activation_blockers: vec!["promotion_gate_disabled".to_string()],
            required_invariant_ids: Vec::new(),
            invariant_blockers: Vec::new(),
            policy_decision: "block_workflow_default_until_gates_pass".to_string(),
        },
        evidence_refs: vec!["runtime-evidence:blessed-live-handoff-canary".to_string()],
    }
}

pub fn default_harness_runtime_selector_decision() -> HarnessRuntimeSelectorDecision {
    HarnessRuntimeSelectorDecision {
        schema_version: "workflow.harness.runtime-selector.v1".to_string(),
        decision_id: "harness-selector:default-agent-harness:canary".to_string(),
        requested_selector: "auto_canary".to_string(),
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        production_default_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
        canary_eligible: true,
        canary_blockers: Vec::new(),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        actual_runtime_authority: "blessed_workflow_activation_canary".to_string(),
        recovery_mode: HarnessRecoveryMode::FailClosed,
        recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        recovery_available: true,
        recovery_blockers: Vec::new(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        policy_decision: "allow_blessed_workflow_live_canary".to_string(),
        route_reason: "Turn is non-mutating and eligible for blessed workflow canary routing."
            .to_string(),
        live_promotion_readiness_proof: None,
        live_promotion_readiness_ready: false,
        live_promotion_readiness_blockers: Vec::new(),
        live_promotion_readiness_policy_decision: "not_required_for_canary_selector".to_string(),
        default_live_promotion_invariant_ids: Vec::new(),
        default_live_promotion_invariant_blockers: Vec::new(),
        reviewed_import_activation_apply_proof_present: false,
        reviewed_import_activation_apply_proof_passed: false,
        reviewed_import_activation_apply_proof_blockers: Vec::new(),
        reviewed_import_activation_apply_activation_id: None,
        default_promotion_gate: HarnessDefaultPromotionGate {
            config_key: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION".to_string(),
            enabled: false,
            eligible: false,
            non_mutating_only: true,
            selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            production_default_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
            default_authority_transferred: false,
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            activation_blockers: vec!["promotion_gate_disabled".to_string()],
            required_invariant_ids: Vec::new(),
            invariant_blockers: Vec::new(),
            policy_decision: "block_workflow_default_until_gates_pass".to_string(),
        },
        evidence_refs: vec!["runtime-evidence:selector-canary".to_string()],
    }
}

fn default_live_promotion_cluster_readiness(
    cluster_id: HarnessPromotionClusterId,
    component_kinds: Vec<HarnessComponentKind>,
    attempt_slugs: &[&str],
    rollback_target: &str,
) -> HarnessLivePromotionClusterReadiness {
    let attempt_ids = attempt_slugs
        .iter()
        .map(|slug| format!("harness-default-dispatch:attempt-{slug}"))
        .collect::<Vec<_>>();
    let receipt_refs = attempt_slugs
        .iter()
        .map(|slug| format!("harness-default-dispatch:receipt-{slug}"))
        .collect::<Vec<_>>();
    let replay_fixture_refs = attempt_slugs
        .iter()
        .map(|slug| format!("harness-default-dispatch:fixture-{slug}"))
        .collect::<Vec<_>>();
    let action_frame_ids = component_kinds
        .iter()
        .map(|kind| format!("harness.{}:{}", kind.as_str(), kind.component_id()))
        .collect::<Vec<_>>();

    HarnessLivePromotionClusterReadiness {
        cluster_id,
        label: cluster_id.label().to_string(),
        current_status: HarnessClusterPromotionStatus::Gated,
        target_execution_mode: HarnessExecutionMode::Live,
        component_kinds,
        readiness_ready: true,
        receipt_ready: !receipt_refs.is_empty(),
        replay_gate_ready: !replay_fixture_refs.is_empty(),
        canary_ready: true,
        rollback_ready: true,
        divergence_ready: true,
        blocking_divergence_count: 0,
        unclassified_divergence_count: 0,
        attempt_ids,
        receipt_refs,
        replay_fixture_refs,
        action_frame_ids,
        divergence_classes: vec![HarnessDivergenceClass::None],
        rollback_target: rollback_target.to_string(),
        blockers: Vec::new(),
        decision: "allow_default_harness_live_cluster_promotion".to_string(),
    }
}

pub fn default_harness_live_shadow_comparison_gate(
    evidence_ref: impl Into<String>,
) -> HarnessLiveShadowComparisonGate {
    let required_component_kinds = default_harness_live_shadow_comparison_gate_component_kinds();
    let required_comparison_count = required_component_kinds.len() as u32;
    HarnessLiveShadowComparisonGate {
        schema_version: "workflow.harness.live-shadow-comparison-gate.v1".to_string(),
        gate_id: "p0-live-shadow-comparison-gate".to_string(),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        target_execution_mode: HarnessExecutionMode::Live,
        required_component_kinds: required_component_kinds.clone(),
        component_kinds: required_component_kinds,
        comparison_count: required_comparison_count,
        required_comparison_count,
        all_required_components_present: true,
        receipt_ready: true,
        replay_ready: true,
        divergence_ready: true,
        blocking_divergence_count: 0,
        unclassified_divergence_count: 0,
        ready: true,
        policy_decision: "allow_default_harness_live_shadow_comparison_gate".to_string(),
        blockers: Vec::new(),
        evidence_refs: vec![
            evidence_ref.into(),
            format!(
                "harness-live-shadow-comparison-gate:{}",
                DEFAULT_AGENT_HARNESS_WORKFLOW_ID
            ),
        ],
    }
}

pub fn default_harness_live_promotion_readiness_proof(
    dispatch_id: impl Into<String>,
    activation_blockers: Vec<String>,
) -> HarnessLivePromotionReadinessProof {
    let dispatch_id = dispatch_id.into();
    let required_cluster_ids = vec![
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ];
    let cluster_readiness = vec![
        default_live_promotion_cluster_readiness(
            HarnessPromotionClusterId::Cognition,
            vec![
                HarnessComponentKind::Planner,
                HarnessComponentKind::PromptAssembler,
                HarnessComponentKind::TaskState,
                HarnessComponentKind::UncertaintyGate,
                HarnessComponentKind::BudgetGate,
                HarnessComponentKind::CapabilitySequencer,
            ],
            &[
                "planner_envelope",
                "prompt_assembler_envelope",
                "task_state_envelope",
                "uncertainty_gate_envelope",
                "budget_gate_envelope",
                "capability_sequencer_envelope",
            ],
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        ),
        default_live_promotion_cluster_readiness(
            HarnessPromotionClusterId::RoutingModel,
            vec![
                HarnessComponentKind::ModelRouter,
                HarnessComponentKind::ModelCall,
                HarnessComponentKind::ToolRouter,
            ],
            &[
                "routing_model_model_router_envelope",
                "routing_model_model_call_envelope",
                "routing_model_tool_router_envelope",
                "model_provider_call_canary",
                "model_provider_gated_visible_output",
                "model_provider_gated_visible_output_rollback_drill",
            ],
            "workflow_model_recovery_fail_closed",
        ),
        default_live_promotion_cluster_readiness(
            HarnessPromotionClusterId::VerificationOutput,
            vec![
                HarnessComponentKind::PostconditionSynthesizer,
                HarnessComponentKind::Verifier,
                HarnessComponentKind::CompletionGate,
                HarnessComponentKind::ReceiptWriter,
                HarnessComponentKind::QualityLedger,
                HarnessComponentKind::OutputWriter,
            ],
            &[
                "verification_output_postcondition_synthesizer_envelope",
                "verification_output_verifier_envelope",
                "verification_output_completion_gate_envelope",
                "verification_output_receipt_writer_envelope",
                "verification_output_quality_ledger_envelope",
                "verification_output_output_writer_envelope",
            ],
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        ),
        default_live_promotion_cluster_readiness(
            HarnessPromotionClusterId::AuthorityTooling,
            vec![
                HarnessComponentKind::PolicyGate,
                HarnessComponentKind::ApprovalGate,
                HarnessComponentKind::DryRunSimulator,
                HarnessComponentKind::McpProvider,
                HarnessComponentKind::McpToolCall,
                HarnessComponentKind::ToolCall,
                HarnessComponentKind::ConnectorCall,
                HarnessComponentKind::WalletCapability,
            ],
            &[
                "authority_tooling_policy_gate_envelope",
                "authority_tooling_approval_gate_envelope",
                "authority_tooling_dry_run_simulator_envelope",
                "authority_tooling_mcp_provider_envelope",
                "authority_tooling_mcp_tool_call_envelope",
                "authority_tooling_tool_call_envelope",
                "authority_tooling_connector_call_envelope",
                "authority_tooling_wallet_capability_envelope",
            ],
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        ),
    ];
    let all_clusters_ready = cluster_readiness
        .iter()
        .all(|cluster| cluster.blockers.is_empty());
    let live_shadow_comparison_gate =
        default_harness_live_shadow_comparison_gate(dispatch_id.clone());
    let live_shadow_comparison_gate_ready = live_shadow_comparison_gate.ready;
    let rollback_available = true;
    let invalid_fork_live_activation_blocked = true;
    let promotion_eligible = all_clusters_ready
        && live_shadow_comparison_gate_ready
        && activation_blockers.is_empty()
        && rollback_available
        && invalid_fork_live_activation_blocked;

    HarnessLivePromotionReadinessProof {
        schema_version: "workflow.harness.live-promotion-readiness.v1".to_string(),
        proof_id: format!(
            "harness-live-promotion-readiness:{}:{}",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID, DEFAULT_AGENT_HARNESS_ACTIVATION_ID
        ),
        dispatch_id: dispatch_id.clone(),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        target_execution_mode: HarnessExecutionMode::Live,
        required_cluster_ids,
        cluster_readiness,
        live_shadow_comparison_gate,
        live_shadow_comparison_gate_ready,
        all_clusters_ready,
        promotion_eligible,
        default_live_activation_ready: promotion_eligible,
        invalid_fork_live_activation_blocked,
        rollback_available,
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        activation_blockers,
        policy_decision: if promotion_eligible {
            "allow_default_harness_live_promotion_readiness".to_string()
        } else {
            "block_default_harness_live_promotion_readiness".to_string()
        },
        evidence_refs: vec![
            dispatch_id,
            format!(
                "harness-live-promotion-readiness:{}",
                DEFAULT_AGENT_HARNESS_WORKFLOW_ID
            ),
        ],
    }
}

pub fn default_harness_default_runtime_dispatch_proof() -> HarnessDefaultRuntimeDispatchProof {
    let dispatch_id = "harness-default-dispatch:default-agent-harness:readonly".to_string();
    let selector_decision_id = "harness-selector:default-agent-harness:default".to_string();
    let live_promotion_readiness_proof =
        default_harness_live_promotion_readiness_proof(dispatch_id.clone(), Vec::new());
    let worker_binding_registry_record = bound_default_harness_worker_binding_registry_record(
        selector_decision_id.clone(),
        dispatch_id.clone(),
        live_promotion_readiness_proof.proof_id.clone(),
        "promote_blessed_workflow_default_for_non_mutating_turn",
    );
    HarnessDefaultRuntimeDispatchProof {
        schema_version: "workflow.harness.default-runtime-dispatch.v1".to_string(),
        dispatch_id: dispatch_id.clone(),
        selector_decision_id,
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        production_default_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        runtime_authority: "blessed_workflow_activation_default".to_string(),
        dispatch_scope: "read_only_cognition_routing_verification_completion_authority_tooling"
            .to_string(),
        accepted_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        component_kinds: vec![
            HarnessComponentKind::Planner,
            HarnessComponentKind::PromptAssembler,
            HarnessComponentKind::TaskState,
            HarnessComponentKind::UncertaintyGate,
            HarnessComponentKind::BudgetGate,
            HarnessComponentKind::CapabilitySequencer,
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ModelCall,
            HarnessComponentKind::ToolRouter,
            HarnessComponentKind::PostconditionSynthesizer,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::CompletionGate,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::QualityLedger,
            HarnessComponentKind::OutputWriter,
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::DryRunSimulator,
            HarnessComponentKind::ApprovalGate,
        ],
        deferred_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        handoff_validated_component_kinds: vec![HarnessComponentKind::OutputWriter],
        materialization_canary_component_kinds: vec![HarnessComponentKind::OutputWriter],
        source_boundary_ids: vec![
            "harness-canary-boundary:default-agent-harness:cognition".to_string(),
            "harness-canary-boundary:default-agent-harness:routing_model".to_string(),
            "harness-canary-boundary:default-agent-harness:verification_output".to_string(),
            "harness-canary-boundary:default-agent-harness:authority_tooling".to_string(),
        ],
        dispatch_node_attempt_ids: vec![
            "harness-default-dispatch:attempt-cognition".to_string(),
            "harness-default-dispatch:attempt-routing_model".to_string(),
            "harness-default-dispatch:attempt-verification_output".to_string(),
            "harness-default-dispatch:attempt-authority_tooling".to_string(),
            "harness-default-dispatch:attempt-planner_envelope".to_string(),
            "harness-default-dispatch:attempt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:attempt-task_state_envelope".to_string(),
            "harness-default-dispatch:attempt-model_router_envelope".to_string(),
            "harness-default-dispatch:attempt-model_call_envelope".to_string(),
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
            "harness-default-dispatch:attempt-read_only_source_router".to_string(),
            "harness-default-dispatch:attempt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:attempt-read_only_tool_router".to_string(),
            "harness-default-dispatch:attempt-read_only_no_mutation_drill".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_router".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
            "harness-default-dispatch:attempt-output_writer_handoff".to_string(),
            "harness-default-dispatch:attempt-output_writer_materialization_canary".to_string(),
            "harness-default-dispatch:attempt-output_writer_staged_write_canary".to_string(),
            "harness-default-dispatch:attempt-output_writer_visible_write_commit".to_string(),
        ],
        cognition_execution_attempt_ids: vec![
            "harness-default-dispatch:attempt-planner_envelope".to_string(),
            "harness-default-dispatch:attempt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:attempt-task_state_envelope".to_string(),
        ],
        cognition_execution_receipt_ids: vec![
            "harness-default-dispatch:receipt-planner_envelope".to_string(),
            "harness-default-dispatch:receipt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:receipt-task_state_envelope".to_string(),
        ],
        cognition_execution_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-planner_envelope".to_string(),
            "harness-default-dispatch:fixture-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:fixture-task_state_envelope".to_string(),
        ],
        model_execution_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_router_envelope".to_string(),
            "harness-default-dispatch:attempt-model_call_envelope".to_string(),
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_execution_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_router_envelope".to_string(),
            "harness-default-dispatch:receipt-model_call_envelope".to_string(),
            "harness-default-dispatch:receipt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:receipt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_execution_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_router_envelope".to_string(),
            "harness-default-dispatch:fixture-model_call_envelope".to_string(),
            "harness-default-dispatch:fixture-model_provider_call_canary".to_string(),
            "harness-default-dispatch:fixture-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
        ],
        model_provider_canary_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_call_canary".to_string(),
        ],
        model_provider_canary_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_call_canary".to_string(),
        ],
        model_provider_gated_visible_output_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        read_only_capability_routing_attempt_ids: vec![
            "harness-default-dispatch:attempt-read_only_source_router".to_string(),
            "harness-default-dispatch:attempt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:attempt-read_only_tool_router".to_string(),
            "harness-default-dispatch:attempt-read_only_no_mutation_drill".to_string(),
        ],
        read_only_capability_routing_receipt_ids: vec![
            "harness-default-dispatch:receipt-read_only_source_router".to_string(),
            "harness-default-dispatch:receipt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:receipt-read_only_tool_router".to_string(),
            "harness-default-dispatch:receipt-read_only_no_mutation_drill".to_string(),
        ],
        read_only_capability_routing_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-read_only_source_router".to_string(),
            "harness-default-dispatch:fixture-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:fixture-read_only_tool_router".to_string(),
            "harness-default-dispatch:fixture-read_only_no_mutation_drill".to_string(),
        ],
        output_writer_handoff_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_handoff".to_string(),
        ],
        output_writer_materialization_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_materialization_canary".to_string(),
        ],
        output_writer_staged_write_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_staged_write_canary".to_string(),
        ],
        output_writer_visible_write_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_visible_write_commit".to_string(),
        ],
        authority_tooling_live_dry_run_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_router".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_destructive_denial_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_destructive_denial_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_destructive_denial_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_approval_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_approval_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_approval_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_read_only_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_provider_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_provider_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_provider_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_native_tool_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_native_tool_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_native_tool_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_connector_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_connector_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_connector_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        authority_tooling_mutation_deferred_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        authority_tooling_denial_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
        ],
        accepted_node_attempt_ids: vec!["harness-canary:attempt-planner".to_string()],
        node_attempt_ids: vec!["harness-default-dispatch:attempt-planner".to_string()],
        receipt_ids: vec!["harness-default-dispatch:receipt-planner".to_string()],
        replay_fixture_refs: vec!["harness-default-dispatch:fixture-planner".to_string()],
        executor_kind: "workflow_node_executor".to_string(),
        executor_ref: "crate::project::execute_workflow_harness_live_default_node".to_string(),
        synchronous: true,
        drives_runtime_decision: true,
        activation_id_gate_click_proof_present: true,
        activation_id_gate_click_proof_passed: true,
        activation_id_gate_click_proof_blockers: Vec::new(),
        default_dispatch_activation_blockers: Vec::new(),
        default_live_promotion_invariant_ids: vec![
            DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT.to_string(),
        ],
        default_live_promotion_invariant_blockers: Vec::new(),
        reviewed_import_activation_apply_proof_present: true,
        reviewed_import_activation_apply_proof_passed: true,
        reviewed_import_activation_apply_proof_blockers: Vec::new(),
        reviewed_import_activation_apply_activation_id: Some(
            DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        ),
        reviewed_import_activation_apply_gate: HarnessReviewedImportActivationApplyGate {
            schema_version:
                "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1"
                    .to_string(),
            gate_id: "reviewed-import-activation-apply".to_string(),
            invariant_id: DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
                .to_string(),
            proof_present: true,
            proof_passed: true,
            proof_blockers: Vec::new(),
            activation_id: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
            worker_binding_activation_id: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
            rollback_target: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
            reviewed_workflow_content_hash: Some(DEFAULT_AGENT_HARNESS_HASH.to_string()),
            reviewed_harness_workflow_id: Some(DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string()),
            reviewed_replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-planner".to_string()
            ],
            reviewed_worker_handoff_node_attempt_ids: vec![
                "harness-canary:attempt-planner".to_string()
            ],
            reviewed_worker_handoff_receipt_ids: vec![
                "harness-default-dispatch:receipt-planner".to_string()
            ],
            reviewed_policy_posture: Some("canary".to_string()),
            default_dispatch_activation_blockers: Vec::new(),
        },
        cognition_node_authority_gate: HarnessCognitionNodeAuthorityGate {
            schema_version: "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1"
                .to_string(),
            gate_id: "cognition-node-authority".to_string(),
            authority_mode: "node_authoritative".to_string(),
            authoritative: true,
            workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
            activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
            required_execution_mode: HarnessExecutionMode::Live,
            runtime_authority: "blessed_workflow_activation_default".to_string(),
            adapter_mode: "workflow_component_adapter_live".to_string(),
            component_kinds: vec![
                HarnessComponentKind::Planner,
                HarnessComponentKind::PromptAssembler,
                HarnessComponentKind::TaskState,
            ],
            live_ready_component_kinds: vec![
                HarnessComponentKind::Planner,
                HarnessComponentKind::PromptAssembler,
                HarnessComponentKind::TaskState,
            ],
            action_frame_ids: vec![
                "harness.planner:planner".to_string(),
                "harness.prompt_assembler:prompt_assembler".to_string(),
                "harness.task_state:task_state".to_string(),
            ],
            attempt_ids: vec![
                "harness-default-dispatch:attempt-planner_envelope".to_string(),
                "harness-default-dispatch:attempt-prompt_assembler_envelope".to_string(),
                "harness-default-dispatch:attempt-task_state_envelope".to_string(),
            ],
            receipt_ids: vec![
                "harness-default-dispatch:receipt-planner_envelope".to_string(),
                "harness-default-dispatch:receipt-prompt_assembler_envelope".to_string(),
                "harness-default-dispatch:receipt-task_state_envelope".to_string(),
            ],
            replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-planner_envelope".to_string(),
                "harness-default-dispatch:fixture-prompt_assembler_envelope".to_string(),
                "harness-default-dispatch:fixture-task_state_envelope".to_string(),
            ],
            recovery_mode: HarnessRecoveryMode::FailClosed,
            recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            recovery_available: true,
            recovery_blockers: Vec::new(),
            blockers: Vec::new(),
            policy_decision: "allow_node_authoritative_cognition".to_string(),
        },
        routing_model_node_authority_gate: HarnessRoutingModelNodeAuthorityGate {
            schema_version:
                "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1"
                    .to_string(),
            gate_id: "routing-model-node-authority".to_string(),
            authority_mode: "gated_node_authoritative".to_string(),
            authoritative: true,
            workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
            activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
            required_execution_mode: HarnessExecutionMode::Gated,
            runtime_authority: "blessed_workflow_activation_default".to_string(),
            adapter_mode: "workflow_component_adapter_gated".to_string(),
            component_kinds: vec![
                HarnessComponentKind::ModelRouter,
                HarnessComponentKind::ModelCall,
                HarnessComponentKind::ToolRouter,
            ],
            shadow_ready_component_kinds: vec![
                HarnessComponentKind::ModelRouter,
                HarnessComponentKind::ModelCall,
                HarnessComponentKind::ToolRouter,
            ],
            action_frame_ids: vec![
                "harness.model_router:ioi.agent-harness.model_router.v1".to_string(),
                "harness.model_call:ioi.agent-harness.model_call.v1".to_string(),
                "harness.tool_router:ioi.agent-harness.tool_router.v1".to_string(),
            ],
            attempt_ids: vec![
                "harness-default-dispatch:attempt-routing_model_model_router_envelope".to_string(),
                "harness-default-dispatch:attempt-routing_model_model_call_envelope".to_string(),
                "harness-default-dispatch:attempt-routing_model_tool_router_envelope".to_string(),
            ],
            receipt_ids: vec![
                "harness-default-dispatch:receipt-routing_model_model_router_envelope".to_string(),
                "harness-default-dispatch:receipt-routing_model_model_call_envelope".to_string(),
                "harness-default-dispatch:receipt-routing_model_tool_router_envelope".to_string(),
            ],
            replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-routing_model_model_router_envelope".to_string(),
                "harness-default-dispatch:fixture-routing_model_model_call_envelope".to_string(),
                "harness-default-dispatch:fixture-routing_model_tool_router_envelope".to_string(),
            ],
            shadow_attempt_ids: vec![
                "harness-default-dispatch:attempt-routing_model_model_router_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-routing_model_model_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-routing_model_tool_router_envelope_shadow"
                    .to_string(),
            ],
            shadow_receipt_ids: vec![
                "harness-default-dispatch:receipt-routing_model_model_router_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-routing_model_model_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-routing_model_tool_router_envelope_shadow"
                    .to_string(),
            ],
            shadow_replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-routing_model_model_router_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-routing_model_model_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-routing_model_tool_router_envelope_shadow"
                    .to_string(),
            ],
            divergence_classes: vec![HarnessDivergenceClass::None],
            shadow_divergence_classes: vec![HarnessDivergenceClass::None],
            provider_canary_ready: true,
            visible_output_selected: true,
            visible_output_authority: "workflow_model_provider_call".to_string(),
            read_only_capability_routing_ready: true,
            rollback_available: true,
            recovery_mode: HarnessRecoveryMode::FailClosed,
            recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            recovery_available: true,
            recovery_blockers: Vec::new(),
            blockers: Vec::new(),
            policy_decision: "allow_gated_node_authoritative_routing_model".to_string(),
        },
        verification_output_node_authority_gate: HarnessVerificationOutputNodeAuthorityGate {
            schema_version:
                "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1"
                    .to_string(),
            gate_id: "verification-output-node-authority".to_string(),
            authority_mode: "gated_node_authoritative".to_string(),
            authoritative: true,
            workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
            activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
            required_execution_mode: HarnessExecutionMode::Gated,
            runtime_authority: "blessed_workflow_activation_default".to_string(),
            adapter_mode: "workflow_component_adapter_gated".to_string(),
            component_kinds: vec![
                HarnessComponentKind::PostconditionSynthesizer,
                HarnessComponentKind::Verifier,
                HarnessComponentKind::CompletionGate,
                HarnessComponentKind::ReceiptWriter,
                HarnessComponentKind::QualityLedger,
                HarnessComponentKind::OutputWriter,
            ],
            shadow_ready_component_kinds: vec![
                HarnessComponentKind::PostconditionSynthesizer,
                HarnessComponentKind::Verifier,
                HarnessComponentKind::CompletionGate,
                HarnessComponentKind::ReceiptWriter,
                HarnessComponentKind::QualityLedger,
                HarnessComponentKind::OutputWriter,
            ],
            action_frame_ids: vec![
                "harness.postcondition_synthesizer:ioi.agent-harness.postcondition_synthesizer.v1"
                    .to_string(),
                "harness.verifier:ioi.agent-harness.verifier.v1".to_string(),
                "harness.completion_gate:ioi.agent-harness.completion_gate.v1".to_string(),
                "harness.receipt_writer:ioi.agent-harness.receipt_writer.v1".to_string(),
                "harness.quality_ledger:ioi.agent-harness.quality_ledger.v1".to_string(),
                "harness.output_writer:ioi.agent-harness.output_writer.v1".to_string(),
            ],
            attempt_ids: vec![
                "harness-default-dispatch:attempt-verification_output_postcondition_synthesizer_envelope".to_string(),
                "harness-default-dispatch:attempt-verification_output_verifier_envelope".to_string(),
                "harness-default-dispatch:attempt-verification_output_completion_gate_envelope".to_string(),
                "harness-default-dispatch:attempt-verification_output_receipt_writer_envelope".to_string(),
                "harness-default-dispatch:attempt-verification_output_quality_ledger_envelope".to_string(),
                "harness-default-dispatch:attempt-verification_output_output_writer_envelope".to_string(),
            ],
            receipt_ids: vec![
                "harness-default-dispatch:receipt-verification_output_postcondition_synthesizer_envelope".to_string(),
                "harness-default-dispatch:receipt-verification_output_verifier_envelope".to_string(),
                "harness-default-dispatch:receipt-verification_output_completion_gate_envelope".to_string(),
                "harness-default-dispatch:receipt-verification_output_receipt_writer_envelope".to_string(),
                "harness-default-dispatch:receipt-verification_output_quality_ledger_envelope".to_string(),
                "harness-default-dispatch:receipt-verification_output_output_writer_envelope".to_string(),
            ],
            replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-verification_output_postcondition_synthesizer_envelope".to_string(),
                "harness-default-dispatch:fixture-verification_output_verifier_envelope".to_string(),
                "harness-default-dispatch:fixture-verification_output_completion_gate_envelope".to_string(),
                "harness-default-dispatch:fixture-verification_output_receipt_writer_envelope".to_string(),
                "harness-default-dispatch:fixture-verification_output_quality_ledger_envelope".to_string(),
                "harness-default-dispatch:fixture-verification_output_output_writer_envelope".to_string(),
            ],
            shadow_attempt_ids: vec![
                "harness-default-dispatch:attempt-verification_output_postcondition_synthesizer_envelope_shadow".to_string(),
                "harness-default-dispatch:attempt-verification_output_verifier_envelope_shadow".to_string(),
                "harness-default-dispatch:attempt-verification_output_completion_gate_envelope_shadow".to_string(),
                "harness-default-dispatch:attempt-verification_output_receipt_writer_envelope_shadow".to_string(),
                "harness-default-dispatch:attempt-verification_output_quality_ledger_envelope_shadow".to_string(),
                "harness-default-dispatch:attempt-verification_output_output_writer_envelope_shadow".to_string(),
            ],
            shadow_receipt_ids: vec![
                "harness-default-dispatch:receipt-verification_output_postcondition_synthesizer_envelope_shadow".to_string(),
                "harness-default-dispatch:receipt-verification_output_verifier_envelope_shadow".to_string(),
                "harness-default-dispatch:receipt-verification_output_completion_gate_envelope_shadow".to_string(),
                "harness-default-dispatch:receipt-verification_output_receipt_writer_envelope_shadow".to_string(),
                "harness-default-dispatch:receipt-verification_output_quality_ledger_envelope_shadow".to_string(),
                "harness-default-dispatch:receipt-verification_output_output_writer_envelope_shadow".to_string(),
            ],
            shadow_replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-verification_output_postcondition_synthesizer_envelope_shadow".to_string(),
                "harness-default-dispatch:fixture-verification_output_verifier_envelope_shadow".to_string(),
                "harness-default-dispatch:fixture-verification_output_completion_gate_envelope_shadow".to_string(),
                "harness-default-dispatch:fixture-verification_output_receipt_writer_envelope_shadow".to_string(),
                "harness-default-dispatch:fixture-verification_output_quality_ledger_envelope_shadow".to_string(),
                "harness-default-dispatch:fixture-verification_output_output_writer_envelope_shadow".to_string(),
            ],
            divergence_classes: vec![HarnessDivergenceClass::None],
            shadow_divergence_classes: vec![HarnessDivergenceClass::None],
            output_writer_handoff_ready: true,
            output_writer_materialization_canary_ready: true,
            output_writer_staged_write_canary_ready: true,
            output_writer_visible_write_ready: true,
            output_writer_visible_write_committed: true,
            rollback_available: true,
            recovery_mode: HarnessRecoveryMode::FailClosed,
            recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            recovery_available: true,
            recovery_blockers: Vec::new(),
            blockers: Vec::new(),
            policy_decision: "allow_gated_node_authoritative_verification_output".to_string(),
        },
        authority_tooling_node_authority_gate: HarnessAuthorityToolingNodeAuthorityGate {
            schema_version:
                "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1"
                    .to_string(),
            gate_id: "authority-tooling-node-authority".to_string(),
            authority_mode: "gated_node_authoritative".to_string(),
            authoritative: true,
            workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
            activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
            required_execution_mode: HarnessExecutionMode::Gated,
            runtime_authority: "blessed_workflow_activation_default".to_string(),
            adapter_mode: "workflow_component_adapter_gated".to_string(),
            component_kinds: vec![
                HarnessComponentKind::PolicyGate,
                HarnessComponentKind::ApprovalGate,
                HarnessComponentKind::DryRunSimulator,
                HarnessComponentKind::McpProvider,
                HarnessComponentKind::McpToolCall,
                HarnessComponentKind::ToolCall,
                HarnessComponentKind::ConnectorCall,
                HarnessComponentKind::WalletCapability,
            ],
            shadow_ready_component_kinds: vec![
                HarnessComponentKind::PolicyGate,
                HarnessComponentKind::ApprovalGate,
                HarnessComponentKind::DryRunSimulator,
                HarnessComponentKind::McpProvider,
                HarnessComponentKind::McpToolCall,
                HarnessComponentKind::ToolCall,
                HarnessComponentKind::ConnectorCall,
                HarnessComponentKind::WalletCapability,
            ],
            action_frame_ids: vec![
                "harness.policy_gate:ioi.agent-harness.policy_gate.v1".to_string(),
                "harness.approval_gate:ioi.agent-harness.approval_gate.v1".to_string(),
                "harness.dry_run_simulator:ioi.agent-harness.dry_run_simulator.v1"
                    .to_string(),
                "harness.mcp_provider:ioi.agent-harness.mcp_provider.v1".to_string(),
                "harness.mcp_tool_call:ioi.agent-harness.mcp_tool_call.v1".to_string(),
                "harness.tool_call:ioi.agent-harness.tool_call.v1".to_string(),
                "harness.connector_call:ioi.agent-harness.connector_call.v1".to_string(),
                "harness.wallet_capability:ioi.agent-harness.wallet_capability.v1".to_string(),
            ],
            attempt_ids: vec![
                "harness-default-dispatch:attempt-authority_tooling_policy_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_approval_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_mcp_provider_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_connector_call_envelope"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_wallet_capability_envelope"
                    .to_string(),
            ],
            receipt_ids: vec![
                "harness-default-dispatch:receipt-authority_tooling_policy_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_approval_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_dry_run_simulator_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_mcp_provider_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_connector_call_envelope"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_wallet_capability_envelope"
                    .to_string(),
            ],
            replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-authority_tooling_policy_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_approval_gate_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_dry_run_simulator_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_mcp_provider_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_tool_call_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_connector_call_envelope"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_wallet_capability_envelope"
                    .to_string(),
            ],
            shadow_attempt_ids: vec![
                "harness-default-dispatch:attempt-authority_tooling_policy_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_approval_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_mcp_provider_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_connector_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:attempt-authority_tooling_wallet_capability_envelope_shadow"
                    .to_string(),
            ],
            shadow_receipt_ids: vec![
                "harness-default-dispatch:receipt-authority_tooling_policy_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_approval_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_dry_run_simulator_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_mcp_provider_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_connector_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:receipt-authority_tooling_wallet_capability_envelope_shadow"
                    .to_string(),
            ],
            shadow_replay_fixture_refs: vec![
                "harness-default-dispatch:fixture-authority_tooling_policy_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_approval_gate_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_dry_run_simulator_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_mcp_provider_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_tool_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_connector_call_envelope_shadow"
                    .to_string(),
                "harness-default-dispatch:fixture-authority_tooling_wallet_capability_envelope_shadow"
                    .to_string(),
            ],
            divergence_classes: vec![HarnessDivergenceClass::None],
            shadow_divergence_classes: vec![HarnessDivergenceClass::None],
            read_only_route_accepted: true,
            destructive_route_denied: true,
            mutating_tool_calls_blocked: true,
            side_effects_executed: false,
            policy_gate_ready: true,
            tool_router_ready: true,
            dry_run_simulator_ready: true,
            approval_gate_ready: true,
            gate_live_ready: true,
            read_only_authority_canary_ready: true,
            rollback_available: true,
            recovery_mode: HarnessRecoveryMode::FailClosed,
            recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            recovery_available: true,
            recovery_blockers: Vec::new(),
            blockers: Vec::new(),
            policy_decision: "allow_gated_node_authoritative_authority_tooling".to_string(),
        },
        cognition_execution_mode: "workflow_synchronous_envelope".to_string(),
        cognition_execution_ready: true,
        prompt_assembly_mode: "workflow_synchronous_envelope".to_string(),
        prompt_assembly_prompt_hash: "sha256:prompt-final".to_string(),
        prompt_assembly_prompt_hash_matches: true,
        model_execution_mode: "workflow_synchronous_envelope".to_string(),
        model_execution_envelope_ready: true,
        model_execution_binding_id:
            "model-binding:default-agent-harness:workflow-default-model-route".to_string(),
        model_execution_binding_ready: true,
        model_execution_prompt_hash: "sha256:prompt-final".to_string(),
        model_execution_prompt_hash_matches: true,
        model_execution_output_hash: "sha256:visible-output".to_string(),
        model_execution_output_hash_matches: true,
        model_execution_provider_invocation_mode: "workflow_provider_canary".to_string(),
        model_execution_low_level_invocation_deferred: false,
        model_execution_recovery_mode: HarnessRecoveryMode::FailClosed,
        model_execution_latency_ms: 0,
        model_provider_canary_mode: "workflow_provider_canary".to_string(),
        model_provider_canary_ready: true,
        model_provider_canary_candidate_output_hash: "sha256:visible-output".to_string(),
        model_provider_canary_prior_workflow_output_hash: "sha256:visible-output".to_string(),
        model_provider_canary_output_hash_matches: true,
        model_provider_canary_transcript_matches: true,
        model_provider_canary_recovery_ready: true,
        model_provider_canary_rollback_available: true,
        model_provider_gated_visible_output_mode: "workflow_provider_gated_visible_output"
            .to_string(),
        model_provider_gated_visible_output_enabled: true,
        model_provider_gated_visible_output_ready: true,
        model_provider_gated_visible_output_selected: true,
        model_provider_gated_visible_output_eligible: true,
        model_provider_gated_visible_output_scenario: "retained_no_tool_answer".to_string(),
        model_provider_gated_visible_output_cohort: "retained_read_only_no_tool".to_string(),
        model_provider_gated_visible_output_retained_read_only_no_tool: true,
        model_provider_gated_visible_output_required_scenario_set: vec![
            "retained_no_tool_answer".to_string(),
            "retained_repo_grounded_answer".to_string(),
            "retained_planning_without_mutation".to_string(),
            "retained_mermaid_rendering".to_string(),
            "retained_source_heavy_synthesis".to_string(),
            "retained_probe_behavior".to_string(),
            "retained_harness_dogfooding".to_string(),
        ],
        model_provider_gated_visible_output_scenario_coverage_key: Some(
            "retained_no_tool_answer".to_string(),
        ),
        model_provider_gated_visible_output_activation_flag:
            "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT".to_string(),
        model_provider_gated_visible_output_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            .to_string(),
        model_provider_gated_visible_output_authority: "workflow_model_provider_call".to_string(),
        model_provider_gated_visible_output_rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        model_provider_gated_visible_output_rollback_available: true,
        selected_visible_output_authority: "workflow_model_provider_call".to_string(),
        selected_visible_output_hash: "sha256:visible-output".to_string(),
        workflow_provider_visible_output_hash: "sha256:visible-output".to_string(),
        prior_workflow_visible_output_hash: "sha256:visible-output".to_string(),
        prior_workflow_visible_output_computed: true,
        prior_workflow_visible_output_hash_matches_selected: true,
        selected_visible_output_authority_matches_transcript: true,
        visible_output_divergence_class: None,
        model_provider_gated_visible_output_rollback_drill_enabled: true,
        model_provider_gated_visible_output_rollback_drill_ready: true,
        model_provider_gated_visible_output_rollback_drill_failure_injected: true,
        model_provider_gated_visible_output_rollback_drill_injected_output_hash:
            "sha256:provider-output-divergence".to_string(),
        model_provider_gated_visible_output_rollback_drill_output_hash_diverges: true,
        model_provider_gated_visible_output_rollback_drill_divergence_class:
            "provider_output_hash_divergence".to_string(),
        model_provider_gated_visible_output_rollback_drill_recovery_mode: HarnessRecoveryMode::FailClosed,
        model_provider_gated_visible_output_rollback_drill_selected_authority:
            "workflow_model_recovery_fail_closed".to_string(),
        model_provider_gated_visible_output_rollback_drill_transcript_unchanged: true,
        model_provider_gated_visible_output_rollback_drill_rollback_executed: true,
        model_provider_gated_visible_output_rollback_drill_activation_blockers: vec![
            "model_provider_output_hash_divergence".to_string(),
        ],
        read_only_capability_routing_mode: "workflow_read_only_capability_routing".to_string(),
        read_only_capability_routing_ready: true,
        read_only_capability_routing_selected: true,
        read_only_capability_routing_eligible: true,
        read_only_capability_routing_scenario: "retained_repo_grounded_answer".to_string(),
        read_only_capability_routing_required_scenario_set: vec![
            "retained_repo_grounded_answer".to_string(),
            "retained_source_heavy_synthesis".to_string(),
            "retained_probe_behavior".to_string(),
        ],
        read_only_capability_routing_scenario_coverage_key: Some(
            "retained_repo_grounded_answer".to_string(),
        ),
        read_only_capability_routing_source_material_ready: true,
        read_only_capability_routing_no_mutation_ready: true,
        read_only_capability_routing_workflow_owned_node_kinds: vec![
            HarnessComponentKind::MemoryRead,
            HarnessComponentKind::CapabilitySequencer,
            HarnessComponentKind::ToolRouter,
            HarnessComponentKind::DryRunSimulator,
        ],
        live_promotion_readiness_proof,
        worker_binding_registry_record,
        output_authority: "blessed_workflow_activation_default".to_string(),
        output_writer_deferred: false,
        output_writer_status: "visible_write_committed".to_string(),
        output_writer_handoff_ready: true,
        output_writer_authority_transferred: true,
        output_writer_materialization_mode: "workflow_visible_transcript_write".to_string(),
        output_writer_materialization_canary_ready: true,
        output_writer_materialization_committed: true,
        output_writer_staged_write_mode: "isolated_checkpoint_blob".to_string(),
        output_writer_staged_write_canary_ready: true,
        output_writer_staged_write_persisted: true,
        output_writer_staged_write_committed: true,
        output_writer_staged_write_visible: false,
        output_writer_staged_write_excluded_from_visible_transcript: true,
        output_writer_staged_write_rollback_status: "deleted".to_string(),
        output_writer_staged_write_rollback_verified: true,
        output_writer_visible_write_mode: "workflow_visible_transcript_write".to_string(),
        output_writer_visible_write_ready: true,
        output_writer_visible_write_persisted: true,
        output_writer_visible_write_committed: true,
        output_writer_visible_write_visible: true,
        output_writer_visible_write_identity_checkpoint_persisted: true,
        output_writer_visible_write_recovery_duplicate_suppressed: true,
        authority_tooling_mode: "workflow_live_dry_run".to_string(),
        authority_tooling_ready: true,
        authority_tooling_policy_gate_ready: true,
        authority_tooling_tool_router_ready: true,
        authority_tooling_dry_run_simulator_ready: true,
        authority_tooling_approval_gate_ready: true,
        authority_tooling_gate_live_ready: true,
        authority_tooling_policy_gate_live_ready: true,
        authority_tooling_destructive_denial_live_ready: true,
        authority_tooling_approval_gate_live_ready: true,
        authority_tooling_read_only_route_accepted: true,
        authority_tooling_destructive_route_denied: true,
        authority_tooling_mutating_tool_calls_blocked: true,
        authority_tooling_side_effects_executed: false,
        authority_tooling_rollback_available: true,
        workflow_transcript_recovery_authority_retained: false,
        workflow_transcript_recovery_available: true,
        proposed_visible_output_hash: "sha256:visible-output".to_string(),
        actual_visible_output_hash: "sha256:visible-output".to_string(),
        output_hash_algorithm: "runtime_prompt_hash:v1".to_string(),
        output_hash_matches: true,
        output_hash_divergence: false,
        output_hash_divergence_count: 0,
        transcript_materialization_content_hash_matches: true,
        transcript_materialization_order_matches: true,
        transcript_materialization_receipt_binding_matches: true,
        transcript_materialization_target_matches: true,
        transcript_materialization_matches: true,
        transcript_materialization_divergence_count: 0,
        staged_transcript_write_content_hash_matches: true,
        staged_transcript_write_order_matches: true,
        staged_transcript_write_receipt_binding_matches: true,
        staged_transcript_write_target_matches: true,
        staged_transcript_write_matches: true,
        staged_transcript_write_divergence_count: 0,
        visible_transcript_write_content_hash_matches: true,
        visible_transcript_write_order_matches: true,
        visible_transcript_write_receipt_binding_matches: true,
        visible_transcript_write_target_matches: true,
        visible_transcript_write_matches: true,
        visible_transcript_write_divergence_count: 0,
        workflow_output_recovery_authority_retained: false,
        workflow_output_recovery_available: true,
        mutating_turns_blocked: true,
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        activation_blockers: Vec::new(),
        policy_decision:
            "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write"
                .to_string(),
        evidence_refs: vec!["runtime-evidence:default-runtime-dispatch".to_string()],
    }
}

fn default_harness_canary_execution_boundary_for_cluster(
    cluster_id: HarnessPromotionClusterId,
) -> HarnessCanaryExecutionBoundary {
    let component_kinds = match cluster_id {
        HarnessPromotionClusterId::Cognition => vec![
            HarnessComponentKind::Planner,
            HarnessComponentKind::PromptAssembler,
            HarnessComponentKind::TaskState,
            HarnessComponentKind::UncertaintyGate,
            HarnessComponentKind::BudgetGate,
            HarnessComponentKind::CapabilitySequencer,
        ],
        HarnessPromotionClusterId::VerificationOutput => vec![
            HarnessComponentKind::PostconditionSynthesizer,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::CompletionGate,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::QualityLedger,
            HarnessComponentKind::OutputWriter,
        ],
        HarnessPromotionClusterId::RoutingModel => vec![
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ModelCall,
            HarnessComponentKind::ToolRouter,
        ],
        HarnessPromotionClusterId::AuthorityTooling => vec![
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::ApprovalGate,
            HarnessComponentKind::DryRunSimulator,
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
    };
    let cluster_slug = cluster_id.as_str();
    let failed_component = match cluster_id {
        HarnessPromotionClusterId::Cognition => HarnessComponentKind::TaskState,
        HarnessPromotionClusterId::VerificationOutput => HarnessComponentKind::Verifier,
        HarnessPromotionClusterId::RoutingModel => HarnessComponentKind::ModelRouter,
        HarnessPromotionClusterId::AuthorityTooling => HarnessComponentKind::PolicyGate,
    };
    HarnessCanaryExecutionBoundary {
        schema_version: "workflow.harness.canary-execution-boundary.v1".to_string(),
        boundary_id: format!("harness-canary-boundary:default-agent-harness:{cluster_slug}"),
        cluster_id,
        cluster_label: cluster_id.label().to_string(),
        selector_decision_id: "harness-selector:default-agent-harness:canary".to_string(),
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        production_default_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        runtime_authority: "blessed_workflow_activation_canary".to_string(),
        executor_kind: "workflow_node_executor".to_string(),
        executor_ref: "crate::project::execute_workflow_harness_canary_node".to_string(),
        synchronous: true,
        enforced_before_visible_output: true,
        canary_eligible: true,
        status: "passed".to_string(),
        component_kinds: component_kinds.clone(),
        executed_component_kinds: component_kinds.clone(),
        workflow_node_ids: component_kinds
            .iter()
            .map(|kind| format!("harness.{}", kind.as_str()))
            .collect(),
        node_attempt_ids: component_kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                format!(
                    "harness-canary:default:turn-1:{}:attempt-{}",
                    kind.as_str(),
                    index + 1
                )
            })
            .collect(),
        receipt_ids: component_kinds
            .iter()
            .map(|kind| format!("default:harness.{}:workflow-node-execution", kind.as_str()))
            .collect(),
        replay_fixture_refs: component_kinds
            .iter()
            .map(|kind| format!("runtime-evidence:default:canary-fixture:{}", kind.as_str()))
            .collect(),
        activation_blockers: Vec::new(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        rollback_drill: HarnessCanaryRollbackDrill {
            schema_version: "workflow.harness.canary-rollback-drill.v1".to_string(),
            drill_id: "harness-canary-rollback-drill:default".to_string(),
            selector_decision_id: "harness-selector:default-agent-harness:canary".to_string(),
            failure_injected: true,
            failed_node_id: format!("harness.{}.rollback_drill", failed_component.as_str()),
            cluster_id,
            failure_class: "deterministic_executor_failure".to_string(),
            observed_failure: true,
            rollback_executed: true,
            rollback_selector: HarnessLiveHandoffSelector::WorkflowRecoveryBlocked,
            recovery_mode: HarnessRecoveryMode::FailClosed,
            recovery_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            recovery_available: true,
            recovery_blockers: Vec::new(),
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            rollback_available: true,
            drill_status: "passed".to_string(),
            policy_decision: "fail_closed_workflow_recovery_on_workflow_executor_failure"
                .to_string(),
            evidence_refs: vec![
                "runtime-evidence:default".to_string(),
                format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}"),
            ],
        },
        policy_decision: "allow_synchronous_workflow_node_canary_boundary".to_string(),
        evidence_refs: vec![format!("runtime-evidence:canary-boundary:{cluster_slug}")],
    }
}

pub fn default_harness_canary_execution_boundary() -> HarnessCanaryExecutionBoundary {
    default_harness_canary_execution_boundary_for_cluster(
        HarnessPromotionClusterId::VerificationOutput,
    )
}

pub fn default_harness_canary_execution_boundaries() -> Vec<HarnessCanaryExecutionBoundary> {
    vec![
        default_harness_canary_execution_boundary_for_cluster(HarnessPromotionClusterId::Cognition),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::RoutingModel,
        ),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::VerificationOutput,
        ),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::AuthorityTooling,
        ),
    ]
}

pub fn validate_harness_worker_binding(
    binding: &HarnessWorkerBinding,
) -> Result<(), HarnessBindingError> {
    if binding.harness_workflow_id.trim().is_empty() {
        return Err(HarnessBindingError::MissingWorkflowId);
    }
    if binding
        .harness_activation_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(HarnessBindingError::MissingActivationId);
    }
    if binding.harness_hash.trim().is_empty() {
        return Err(HarnessBindingError::MissingHash);
    }
    Ok(())
}

pub fn validate_harness_worker_binding_registry_record(
    record: &HarnessWorkerBindingRegistryRecord,
) -> Result<(), HarnessBindingError> {
    if record.workflow_id.trim().is_empty() {
        return Err(HarnessBindingError::MissingWorkflowId);
    }
    if record.activation_id.trim().is_empty() {
        return Err(HarnessBindingError::MissingActivationId);
    }
    if record.activation_hash.trim().is_empty() {
        return Err(HarnessBindingError::MissingActivationHash);
    }
    if record.harness_hash.trim().is_empty() {
        return Err(HarnessBindingError::MissingHash);
    }
    if record.binding_status == HarnessWorkerBindingStatus::Bound
        && (record.reviewed_package_snapshot_hash.trim().is_empty()
            || record.reviewed_workflow_content_hash.trim().is_empty()
            || record.reviewed_activation_id.trim().is_empty()
            || record.reviewed_harness_workflow_id.trim().is_empty()
            || record
                .reviewed_worker_binding_activation_id
                .trim()
                .is_empty()
            || record.reviewed_activation_id != record.reviewed_worker_binding_activation_id
            || record.reviewed_rollback_target != record.rollback_target
            || record.reviewed_replay_fixture_refs.is_empty()
            || record.reviewed_worker_handoff_node_attempt_ids.is_empty()
            || record.reviewed_worker_handoff_receipt_ids.is_empty()
            || record.reviewed_fork_mutation_canary_id.trim().is_empty()
            || record.reviewed_fork_mutation_canary_status != "passed"
            || record
                .reviewed_fork_mutation_canary_diff_hash
                .trim()
                .is_empty()
            || record.reviewed_fork_mutation_canary_receipt_refs.is_empty()
            || record
                .reviewed_fork_mutation_canary_replay_fixture_refs
                .is_empty()
            || record
                .reviewed_fork_mutation_canary_node_attempt_ids
                .is_empty()
            || record.reviewed_fork_mutation_canary_rollback_target != record.rollback_target
            || record.reviewed_policy_posture.trim().is_empty())
    {
        return Err(HarnessBindingError::RegistryWorkerBindingMismatch);
    }
    validate_harness_worker_binding(&record.worker_binding)?;
    if record.worker_binding.harness_workflow_id != record.workflow_id
        || record.worker_binding.harness_activation_id.as_deref()
            != Some(record.activation_id.as_str())
        || record.worker_binding.harness_hash != record.harness_hash
    {
        return Err(HarnessBindingError::RegistryWorkerBindingMismatch);
    }
    if record.binding_status == HarnessWorkerBindingStatus::Bound
        && (record.readiness_proof_id.trim().is_empty()
            || record.rollback_readiness_proof_id != record.readiness_proof_id
            || record
                .rollback_live_shadow_comparison_gate_id
                .trim()
                .is_empty()
            || !record.rollback_live_shadow_comparison_gate_ready
            || record
                .worker_binding
                .live_shadow_comparison_gate_id
                .as_deref()
                != Some(record.rollback_live_shadow_comparison_gate_id.as_str())
            || !record.worker_binding.live_shadow_comparison_gate_ready
            || record.rollback_activation_id != record.activation_id
            || record.rollback_harness_hash != record.harness_hash
            || record.rollback_policy_decision
                != "allow_default_harness_worker_rollback_from_live_shadow_gate"
            || record.worker_binding.rollback_policy_decision.as_deref()
                != Some("allow_default_harness_worker_rollback_from_live_shadow_gate"))
    {
        return Err(HarnessBindingError::RegistryWorkerBindingMismatch);
    }
    if !harness_required_invariant_ids_present(&record.required_invariant_ids)
        || !harness_invariant_sets_match(
            &record.worker_binding.required_invariant_ids,
            &record.required_invariant_ids,
        )
    {
        return Err(HarnessBindingError::RegistryWorkerBindingMismatch);
    }
    if record.binding_status == HarnessWorkerBindingStatus::Bound
        && (!record.invariant_blockers.is_empty()
            || !record.worker_binding.invariant_blockers.is_empty())
    {
        return Err(HarnessBindingError::RegistryBlocked);
    }
    if record.binding_status == HarnessWorkerBindingStatus::Bound && !record.blockers.is_empty() {
        return Err(HarnessBindingError::RegistryBlocked);
    }
    Ok(())
}
