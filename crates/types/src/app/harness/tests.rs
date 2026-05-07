use super::*;
use crate::app::events::{
    RoutingEffectiveToolSurface, RoutingPostStateSummary, RoutingRouteDecision, RoutingStateSummary,
};

fn routing_receipt(policy_decision: &str, gate_state: &str) -> RoutingReceiptEvent {
    RoutingReceiptEvent {
        session_id: [7; 32],
        step_index: 3,
        intent_hash: "intent-hash".to_string(),
        policy_decision: policy_decision.to_string(),
        tool_name: "shell__run".to_string(),
        tool_version: "1".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "running".to_string(),
            tier: "foreground".to_string(),
            step_index: 2,
            consecutive_failures: 0,
            target_hint: None,
        },
        action_json: "{}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "paused".to_string(),
            tier: "foreground".to_string(),
            step_index: 3,
            consecutive_failures: 0,
            success: false,
            verification_checks: vec![],
        },
        artifacts: vec![],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: "tool".to_string(),
        incident_id: "incident".to_string(),
        incident_stage: "policy".to_string(),
        strategy_name: "default".to_string(),
        strategy_node: "gate".to_string(),
        gate_state: gate_state.to_string(),
        resolution_action: "wait_for_user".to_string(),
        stop_condition_hit: false,
        escalation_path: None,
        lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "policy-binding".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
        route_decision: RoutingRouteDecision {
            route_family: "tool".to_string(),
            direct_answer_allowed: false,
            direct_answer_blockers: vec![],
            currentness_override: false,
            connector_candidate_count: 0,
            selected_provider_family: None,
            selected_provider_route_label: None,
            connector_first_preference: false,
            narrow_tool_preference: true,
            file_output_intent: false,
            artifact_output_intent: false,
            inline_visual_intent: false,
            skill_prep_required: false,
            output_intent: "tool".to_string(),
            effective_tool_surface: RoutingEffectiveToolSurface::default(),
        },
    }
}

fn shadow_attempt_for_component(
    component_kind: HarnessComponentKind,
    attempt_index: u32,
) -> HarnessNodeAttemptRecord {
    let component = default_harness_component_spec(component_kind);
    let mut replay = default_harness_replay_envelope(component_kind);
    replay.fixture_ref = Some(format!("fixture:{}", component_kind.as_str()));
    HarnessNodeAttemptRecord {
        attempt_id: format!("shadow:{}:{attempt_index}", component_kind.as_str()),
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        workflow_node_id: component_kind.workflow_node_id(),
        component_id: component_kind.component_id(),
        component_kind,
        execution_mode: HarnessExecutionMode::Shadow,
        readiness: component.readiness,
        attempt_index,
        status: HarnessNodeAttemptStatus::Shadow,
        input_hash: Some(format!("input:{attempt_index}")),
        output_hash: Some(format!("output:{attempt_index}")),
        error_class: None,
        policy_decision: None,
        started_at_ms: None,
        duration_ms: Some(0),
        receipt_ids: vec![format!(
            "receipt:{}:{attempt_index}",
            component_kind.as_str()
        )],
        evidence_refs: vec![format!("evidence:{}", component_kind.as_str())],
        replay,
    }
}

#[test]
fn default_harness_components_have_complete_contracts() {
    let components = default_agent_harness_components();
    assert!(components.len() >= 30);
    assert!(components
        .iter()
        .any(|component| component.kind == HarnessComponentKind::McpProvider));
    assert!(components
        .iter()
        .any(|component| component.kind == HarnessComponentKind::McpToolCall));
    for required in [
        HarnessComponentKind::TaskState,
        HarnessComponentKind::UncertaintyGate,
        HarnessComponentKind::ProbeRunner,
        HarnessComponentKind::BudgetGate,
        HarnessComponentKind::CapabilitySequencer,
        HarnessComponentKind::DryRunSimulator,
        HarnessComponentKind::SemanticImpactAnalyzer,
        HarnessComponentKind::PostconditionSynthesizer,
        HarnessComponentKind::DriftDetector,
        HarnessComponentKind::QualityLedger,
        HarnessComponentKind::HandoffBridge,
        HarnessComponentKind::GuiHarnessValidator,
    ] {
        assert!(
            components
                .iter()
                .any(|component| component.kind == required),
            "missing {required:?}"
        );
    }
    for component in components {
        assert!(component.component_id.starts_with("ioi.agent-harness."));
        assert_eq!(component.version, HARNESS_COMPONENT_VERSION_V1);
        assert_eq!(component.input_schema, HARNESS_INPUT_SCHEMA_ID);
        assert_eq!(component.output_schema, HARNESS_OUTPUT_SCHEMA_ID);
        assert_eq!(component.error_schema, HARNESS_ERROR_SCHEMA_ID);
        assert!(!component.kernel_ref.is_empty());
        assert!(!component.required_capability_scope.is_empty());
        assert!(!component.emitted_events.is_empty());
        assert!(!component.evidence.is_empty());
        assert!(component.timeout.timeout_ms > 0);
        assert!(component.retry.max_attempts >= 1);
    }
    assert_eq!(
        default_harness_component_spec(HarnessComponentKind::TaskState).readiness,
        HarnessComponentReadiness::ShadowReady
    );
    assert_eq!(
        default_harness_component_spec(HarnessComponentKind::McpToolCall).readiness,
        HarnessComponentReadiness::ShadowReady
    );
}

#[test]
fn default_harness_action_frames_are_workflow_addressable() {
    let frames = default_agent_harness_action_frames();
    assert!(frames.len() >= 30);
    assert!(frames.iter().all(|frame| {
        frame.workflow_id == DEFAULT_AGENT_HARNESS_WORKFLOW_ID
            && frame.workflow_hash == DEFAULT_AGENT_HARNESS_HASH
            && frame.execution_mode == HarnessExecutionMode::Projection
            && frame.node_id.starts_with("harness.")
            && frame.replay.captures_input
            && frame.replay.captures_output
    }));
    let tool_frame = frames
        .iter()
        .find(|frame| frame.component_kind == HarnessComponentKind::ToolCall)
        .expect("tool call frame");
    assert_eq!(tool_frame.slot_ids, vec!["slot.tool-grants"]);
    assert!(!tool_frame.deterministic_envelope);
    assert_eq!(
        tool_frame.replay.determinism,
        HarnessReplayDeterminism::Nondeterministic
    );

    let task_state_frame = frames
        .iter()
        .find(|frame| frame.component_kind == HarnessComponentKind::TaskState)
        .expect("task state frame");
    assert_eq!(task_state_frame.slot_ids, vec!["slot.state-policy"]);
    assert_eq!(
        task_state_frame.readiness,
        HarnessComponentReadiness::ShadowReady
    );
    assert!(task_state_frame.deterministic_envelope);

    let gui_frame = frames
        .iter()
        .find(|frame| frame.component_kind == HarnessComponentKind::GuiHarnessValidator)
        .expect("gui validator frame");
    assert_eq!(gui_frame.slot_ids, vec!["slot.output-policy"]);
}

#[test]
fn receipt_binding_can_be_projected_into_node_attempt_and_shadow_comparison() {
    let binding = default_harness_receipt_binding_for_routing(&routing_receipt(
        "REQUIRE_APPROVAL",
        "Pending",
    ));
    let live = default_harness_node_attempt_for_receipt(
        &binding,
        HarnessExecutionMode::Live,
        1,
        HarnessNodeAttemptStatus::Live,
    );
    let shadow = default_harness_node_attempt_for_receipt(
        &binding,
        HarnessExecutionMode::Shadow,
        1,
        HarnessNodeAttemptStatus::Shadow,
    );

    assert_eq!(live.workflow_node_id, "harness.approval_gate");
    assert_eq!(live.policy_decision.as_deref(), Some("REQUIRE_APPROVAL"));
    assert_eq!(live.readiness, HarnessComponentReadiness::ShadowReady);

    let comparison = compare_harness_live_shadow_attempts(&live, &shadow);
    assert_eq!(comparison.divergence, HarnessDivergenceClass::None);
    assert!(!comparison.blocking);

    let run = default_harness_shadow_run_for_attempts(
        "shadow-run-test",
        Some("session-test".to_string()),
        Some("turn-1".to_string()),
        vec![shadow],
        vec![comparison],
        vec!["runtime_evidence_projection".to_string()],
    );
    assert_eq!(run.execution_mode, HarnessExecutionMode::Shadow);
    assert_eq!(run.blocking_divergence_count, 0);
    assert!(!run.promotion_blocked);
}

#[test]
fn cognition_cluster_can_be_promoted_to_gated_from_shadow_run() {
    let clusters = default_harness_promotion_clusters();
    let cognition = clusters
        .iter()
        .find(|cluster| cluster.cluster_id == HarnessPromotionClusterId::Cognition)
        .expect("cognition cluster");
    assert_eq!(cognition.activation_order, 1);
    assert!(cognition
        .component_kinds
        .contains(&HarnessComponentKind::PromptAssembler));
    assert_eq!(
        cognition.required_execution_mode,
        HarnessExecutionMode::Gated
    );

    let attempts = cognition
        .component_kinds
        .iter()
        .enumerate()
        .map(|(index, component_kind)| {
            shadow_attempt_for_component(*component_kind, (index + 1) as u32)
        })
        .collect::<Vec<_>>();
    let shadow_run = default_harness_shadow_run_for_attempts(
        "shadow-run-cognition",
        Some("session-cognition".to_string()),
        Some("turn-1".to_string()),
        attempts,
        Vec::new(),
        vec!["runtime_evidence_projection".to_string()],
    );
    let gated = default_harness_gated_cluster_run_for_shadow_run(
        HarnessPromotionClusterId::Cognition,
        &shadow_run,
    );

    assert_eq!(gated.execution_mode, HarnessExecutionMode::Gated);
    assert_eq!(gated.status, HarnessClusterPromotionStatus::Gated);
    assert_eq!(gated.component_kinds.len(), cognition.component_kinds.len());
    assert!(gated.activation_blockers.is_empty());
    assert_eq!(gated.gate_decision, "allow_live_runtime_passthrough");
    assert_eq!(gated.rollback_target, "shadow");
    assert_eq!(gated.canary_status, "passed");
    assert!(!gated.promotion_blocked);
}

#[test]
fn routing_model_cluster_can_be_promoted_to_gated_from_shadow_run() {
    let clusters = default_harness_promotion_clusters();
    let routing_model = clusters
        .iter()
        .find(|cluster| cluster.cluster_id == HarnessPromotionClusterId::RoutingModel)
        .expect("routing/model cluster");
    assert_eq!(routing_model.activation_order, 2);
    assert_eq!(
        routing_model.component_kinds,
        vec![
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ModelCall,
            HarnessComponentKind::ToolRouter,
        ]
    );
    assert_eq!(
        routing_model.required_execution_mode,
        HarnessExecutionMode::Gated
    );

    let attempts = routing_model
        .component_kinds
        .iter()
        .enumerate()
        .map(|(index, component_kind)| {
            shadow_attempt_for_component(*component_kind, (index + 1) as u32)
        })
        .collect::<Vec<_>>();
    let shadow_run = default_harness_shadow_run_for_attempts(
        "shadow-run-routing-model",
        Some("session-routing-model".to_string()),
        Some("turn-1".to_string()),
        attempts,
        Vec::new(),
        vec!["runtime_evidence_projection".to_string()],
    );
    let gated = default_harness_gated_cluster_run_for_shadow_run(
        HarnessPromotionClusterId::RoutingModel,
        &shadow_run,
    );

    assert_eq!(gated.cluster_id, HarnessPromotionClusterId::RoutingModel);
    assert_eq!(gated.status, HarnessClusterPromotionStatus::Gated);
    assert_eq!(
        gated.node_attempt_ids.len(),
        routing_model.component_kinds.len()
    );
    assert!(gated.activation_blockers.is_empty());
    assert_eq!(gated.canary_status, "passed");
    assert!(!gated.promotion_blocked);
}

#[test]
fn verification_output_cluster_can_be_promoted_to_gated_from_shadow_run() {
    let clusters = default_harness_promotion_clusters();
    let verification_output = clusters
        .iter()
        .find(|cluster| cluster.cluster_id == HarnessPromotionClusterId::VerificationOutput)
        .expect("verification/output cluster");
    assert_eq!(verification_output.activation_order, 3);
    assert_eq!(
        verification_output.component_kinds,
        vec![
            HarnessComponentKind::PostconditionSynthesizer,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::CompletionGate,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::QualityLedger,
            HarnessComponentKind::OutputWriter,
        ]
    );
    assert_eq!(
        verification_output.required_execution_mode,
        HarnessExecutionMode::Gated
    );

    let attempts = verification_output
        .component_kinds
        .iter()
        .enumerate()
        .map(|(index, component_kind)| {
            shadow_attempt_for_component(*component_kind, (index + 1) as u32)
        })
        .collect::<Vec<_>>();
    let shadow_run = default_harness_shadow_run_for_attempts(
        "shadow-run-verification-output",
        Some("session-verification-output".to_string()),
        Some("turn-1".to_string()),
        attempts,
        Vec::new(),
        vec!["runtime_evidence_projection".to_string()],
    );
    let gated = default_harness_gated_cluster_run_for_shadow_run(
        HarnessPromotionClusterId::VerificationOutput,
        &shadow_run,
    );

    assert_eq!(
        gated.cluster_id,
        HarnessPromotionClusterId::VerificationOutput
    );
    assert_eq!(gated.status, HarnessClusterPromotionStatus::Gated);
    assert_eq!(
        gated.node_attempt_ids.len(),
        verification_output.component_kinds.len()
    );
    assert!(gated.activation_blockers.is_empty());
    assert_eq!(gated.canary_status, "passed");
    assert!(!gated.promotion_blocked);
}

#[test]
fn authority_tooling_cluster_can_be_promoted_to_gated_from_shadow_run() {
    let clusters = default_harness_promotion_clusters();
    let authority_tooling = clusters
        .iter()
        .find(|cluster| cluster.cluster_id == HarnessPromotionClusterId::AuthorityTooling)
        .expect("authority/tooling cluster");
    assert_eq!(authority_tooling.activation_order, 4);
    assert_eq!(
        authority_tooling.component_kinds,
        vec![
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::ApprovalGate,
            HarnessComponentKind::DryRunSimulator,
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ]
    );
    assert_eq!(
        authority_tooling.required_execution_mode,
        HarnessExecutionMode::Gated
    );

    let attempts = authority_tooling
        .component_kinds
        .iter()
        .enumerate()
        .map(|(index, component_kind)| {
            shadow_attempt_for_component(*component_kind, (index + 1) as u32)
        })
        .collect::<Vec<_>>();
    let shadow_run = default_harness_shadow_run_for_attempts(
        "shadow-run-authority-tooling",
        Some("session-authority-tooling".to_string()),
        Some("turn-1".to_string()),
        attempts,
        Vec::new(),
        vec!["runtime_evidence_projection".to_string()],
    );
    let gated = default_harness_gated_cluster_run_for_shadow_run(
        HarnessPromotionClusterId::AuthorityTooling,
        &shadow_run,
    );

    assert_eq!(
        gated.cluster_id,
        HarnessPromotionClusterId::AuthorityTooling
    );
    assert_eq!(gated.status, HarnessClusterPromotionStatus::Gated);
    assert_eq!(
        gated.node_attempt_ids.len(),
        authority_tooling.component_kinds.len()
    );
    assert!(gated.activation_blockers.is_empty());
    assert_eq!(gated.canary_status, "passed");
    assert!(!gated.promotion_blocked);
}

#[test]
fn gated_cluster_blocks_when_shadow_fixture_or_receipt_is_missing() {
    let mut attempt = shadow_attempt_for_component(HarnessComponentKind::Planner, 1);
    attempt.replay.fixture_ref = None;
    attempt.receipt_ids.clear();
    let shadow_run = default_harness_shadow_run_for_attempts(
        "shadow-run-blocked",
        Some("session-blocked".to_string()),
        Some("turn-1".to_string()),
        vec![attempt],
        Vec::new(),
        vec!["runtime_evidence_projection".to_string()],
    );

    let gated = default_harness_gated_cluster_run_for_shadow_run(
        HarnessPromotionClusterId::Cognition,
        &shadow_run,
    );
    assert_eq!(gated.status, HarnessClusterPromotionStatus::Blocked);
    assert!(gated.promotion_blocked);
    assert!(gated
        .activation_blockers
        .iter()
        .any(|blocker| blocker == "missing_replay_fixture:planner"));
    assert!(gated
        .activation_blockers
        .iter()
        .any(|blocker| blocker == "missing_receipt:planner"));
    assert!(gated
        .activation_blockers
        .iter()
        .any(|blocker| blocker == "missing_attempt:prompt_assembler"));
}

#[test]
fn routing_receipts_map_policy_and_approval_gates() {
    let policy = default_harness_receipt_binding_for_routing(&routing_receipt("ALLOW", "None"));
    assert_eq!(policy.component_kind, HarnessComponentKind::PolicyGate);
    assert_eq!(policy.workflow_node_id, "harness.policy_gate");

    let approval = default_harness_receipt_binding_for_routing(&routing_receipt(
        "REQUIRE_APPROVAL",
        "Pending",
    ));
    assert_eq!(approval.component_kind, HarnessComponentKind::ApprovalGate);
    assert_eq!(approval.workflow_node_id, "harness.approval_gate");
    assert!(approval
        .evidence_refs
        .iter()
        .any(|item| item == "policy_decision:REQUIRE_APPROVAL"));
}

#[test]
fn tool_names_and_action_targets_componentize_native_mcp_connector_and_model_calls() {
    assert_eq!(
        harness_component_kind_for_action_target(&ActionTarget::ModelRespond),
        HarnessComponentKind::ModelCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("mcp__filesystem__read"),
        HarnessComponentKind::McpToolCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("gmail__send_email"),
        HarnessComponentKind::ConnectorCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("memory__save"),
        HarnessComponentKind::MemoryWrite
    );
    assert_eq!(
        harness_component_kind_for_tool_name("shell__run"),
        HarnessComponentKind::ToolCall
    );
}

#[test]
fn worker_binding_requires_activation_identity() {
    let binding = default_harness_worker_binding();
    validate_harness_worker_binding(&binding).expect("default binding is valid");

    let missing_activation = HarnessWorkerBinding {
        harness_activation_id: None,
        ..binding
    };
    assert_eq!(
        validate_harness_worker_binding(&missing_activation),
        Err(HarnessBindingError::MissingActivationId)
    );
}

#[test]
fn blessed_live_handoff_proof_selects_workflow_canary_with_rollback() {
    let proof = default_blessed_live_handoff_proof(
        vec!["attempt-planner".to_string()],
        vec!["receipt-planner".to_string()],
        vec!["fixture-planner".to_string()],
    );

    assert_eq!(
        proof.selector,
        HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary
    );
    assert_eq!(
        proof.production_default_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert_eq!(proof.workflow_id, DEFAULT_AGENT_HARNESS_WORKFLOW_ID);
    assert_eq!(proof.activation_id, DEFAULT_AGENT_HARNESS_ACTIVATION_ID);
    assert_eq!(proof.harness_hash, DEFAULT_AGENT_HARNESS_HASH);
    assert_eq!(proof.canary_status, "passed");
    assert!(proof.canary_turn_routed_through_workflow);
    assert_eq!(proof.execution_boundary_status, "passed");
    assert!(proof
        .execution_boundary_cluster_ids
        .contains(&HarnessPromotionClusterId::Cognition));
    assert!(proof
        .execution_boundary_cluster_ids
        .contains(&HarnessPromotionClusterId::RoutingModel));
    assert!(proof
        .execution_boundary_cluster_ids
        .contains(&HarnessPromotionClusterId::VerificationOutput));
    assert!(proof
        .execution_boundary_cluster_ids
        .contains(&HarnessPromotionClusterId::AuthorityTooling));
    assert_eq!(proof.execution_boundary_ids.len(), 4);
    assert_eq!(
        proof.execution_boundary_executor,
        "crate::project::execute_workflow_harness_canary_node"
    );
    assert!(!proof.default_authority_transferred);
    assert_eq!(
        proof.fallback_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert_eq!(proof.rollback_target, DEFAULT_AGENT_HARNESS_ACTIVATION_ID);
    assert!(proof.rollback_available);
    assert!(proof.activation_blockers.is_empty());
    assert!(proof
        .gated_cluster_ids
        .contains(&HarnessPromotionClusterId::AuthorityTooling));
    assert!(!proof.node_timeline_attempt_ids.is_empty());
    assert!(!proof.receipt_ids.is_empty());
    assert!(!proof.replay_fixture_refs.is_empty());
}

#[test]
fn runtime_selector_decision_keeps_legacy_default_while_routing_canary() {
    let decision = default_harness_runtime_selector_decision();

    assert_eq!(
        decision.schema_version,
        "workflow.harness.runtime-selector.v1"
    );
    assert_eq!(
        decision.selected_selector,
        HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary
    );
    assert_eq!(
        decision.production_default_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert!(decision.canary_eligible);
    assert!(decision.canary_blockers.is_empty());
    assert_eq!(decision.execution_mode, HarnessExecutionMode::Live);
    assert_eq!(
        decision.actual_runtime_authority,
        "blessed_workflow_activation_canary"
    );
    assert_eq!(
        decision.fallback_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert_eq!(
        decision.rollback_target,
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID
    );
    assert!(decision.rollback_available);
}

#[test]
fn default_runtime_dispatch_proof_accepts_readonly_default_with_provider_visible_output_authority()
{
    let dispatch = default_harness_default_runtime_dispatch_proof();

    assert_eq!(
        dispatch.schema_version,
        "workflow.harness.default-runtime-dispatch.v1"
    );
    assert_eq!(
        dispatch.selected_selector,
        HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault
    );
    assert_eq!(
        dispatch.production_default_selector,
        HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault
    );
    assert_eq!(dispatch.execution_mode, HarnessExecutionMode::Live);
    assert_eq!(
        dispatch.runtime_authority,
        "blessed_workflow_activation_default"
    );
    assert_eq!(
        dispatch.dispatch_scope,
        "read_only_cognition_routing_verification_completion_authority_tooling"
    );
    assert!(dispatch
        .accepted_cluster_ids
        .contains(&HarnessPromotionClusterId::Cognition));
    assert!(dispatch
        .accepted_cluster_ids
        .contains(&HarnessPromotionClusterId::RoutingModel));
    assert!(dispatch
        .accepted_cluster_ids
        .contains(&HarnessPromotionClusterId::VerificationOutput));
    assert!(dispatch
        .accepted_cluster_ids
        .contains(&HarnessPromotionClusterId::AuthorityTooling));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::Planner));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::ModelRouter));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::Verifier));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::CompletionGate));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::OutputWriter));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::PolicyGate));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::DryRunSimulator));
    assert!(dispatch
        .component_kinds
        .contains(&HarnessComponentKind::ApprovalGate));
    assert!(dispatch
        .deferred_component_kinds
        .contains(&HarnessComponentKind::ToolCall));
    assert!(dispatch
        .deferred_component_kinds
        .contains(&HarnessComponentKind::ConnectorCall));
    assert!(dispatch
        .deferred_component_kinds
        .contains(&HarnessComponentKind::WalletCapability));
    assert!(dispatch
        .handoff_validated_component_kinds
        .contains(&HarnessComponentKind::OutputWriter));
    assert!(dispatch
        .materialization_canary_component_kinds
        .contains(&HarnessComponentKind::OutputWriter));
    assert!(!dispatch
        .output_writer_materialization_canary_attempt_ids
        .is_empty());
    assert!(!dispatch
        .output_writer_staged_write_canary_attempt_ids
        .is_empty());
    assert!(!dispatch.output_writer_visible_write_attempt_ids.is_empty());
    assert!(!dispatch
        .authority_tooling_live_dry_run_attempt_ids
        .is_empty());
    assert!(!dispatch.authority_tooling_denial_receipt_ids.is_empty());
    assert!(dispatch.cognition_execution_attempt_ids.len() >= 3);
    assert!(dispatch.cognition_execution_receipt_ids.len() >= 3);
    assert!(dispatch.cognition_execution_replay_fixture_refs.len() >= 3);
    assert!(dispatch.model_execution_attempt_ids.len() >= 5);
    assert!(dispatch.model_execution_receipt_ids.len() >= 5);
    assert!(dispatch.model_execution_replay_fixture_refs.len() >= 5);
    assert!(!dispatch.model_provider_canary_attempt_ids.is_empty());
    assert!(!dispatch.model_provider_canary_receipt_ids.is_empty());
    assert!(!dispatch
        .model_provider_canary_replay_fixture_refs
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_attempt_ids
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_receipt_ids
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_replay_fixture_refs
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_rollback_drill_attempt_ids
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_rollback_drill_receipt_ids
        .is_empty());
    assert!(!dispatch
        .model_provider_gated_visible_output_rollback_drill_replay_fixture_refs
        .is_empty());
    assert!(dispatch.read_only_capability_routing_attempt_ids.len() >= 4);
    assert!(dispatch.read_only_capability_routing_receipt_ids.len() >= 4);
    assert!(
        dispatch
            .read_only_capability_routing_replay_fixture_refs
            .len()
            >= 4
    );
    assert!(dispatch.drives_runtime_decision);
    assert_eq!(
        dispatch.cognition_execution_mode,
        "workflow_synchronous_envelope"
    );
    assert!(dispatch.cognition_execution_ready);
    assert_eq!(
        dispatch.prompt_assembly_mode,
        "workflow_synchronous_envelope"
    );
    assert!(!dispatch.prompt_assembly_prompt_hash.is_empty());
    assert!(dispatch.prompt_assembly_prompt_hash_matches);
    assert_eq!(
        dispatch.model_execution_mode,
        "workflow_synchronous_envelope"
    );
    assert!(dispatch.model_execution_envelope_ready);
    assert!(!dispatch.model_execution_binding_id.is_empty());
    assert!(dispatch.model_execution_binding_ready);
    assert!(!dispatch.model_execution_prompt_hash.is_empty());
    assert!(dispatch.model_execution_prompt_hash_matches);
    assert!(!dispatch.model_execution_output_hash.is_empty());
    assert!(dispatch.model_execution_output_hash_matches);
    assert_eq!(
        dispatch.model_execution_provider_invocation_mode,
        "workflow_provider_canary"
    );
    assert!(!dispatch.model_execution_low_level_invocation_deferred);
    assert_eq!(
        dispatch.model_execution_fallback_selector,
        "legacy_runtime_model_invocation"
    );
    assert_eq!(
        dispatch.model_provider_canary_mode,
        "workflow_provider_canary"
    );
    assert!(dispatch.model_provider_canary_ready);
    assert_eq!(
        dispatch.model_provider_canary_candidate_output_hash,
        dispatch.model_provider_canary_legacy_output_hash
    );
    assert!(dispatch.model_provider_canary_output_hash_matches);
    assert!(dispatch.model_provider_canary_transcript_matches);
    assert!(dispatch.model_provider_canary_fallback_retained);
    assert!(dispatch.model_provider_canary_rollback_available);
    assert_eq!(
        dispatch.model_provider_gated_visible_output_mode,
        "workflow_provider_gated_visible_output"
    );
    assert!(dispatch.model_provider_gated_visible_output_enabled);
    assert!(dispatch.model_provider_gated_visible_output_ready);
    assert!(dispatch.model_provider_gated_visible_output_selected);
    assert!(dispatch.model_provider_gated_visible_output_eligible);
    assert_eq!(
        dispatch.model_provider_gated_visible_output_scenario,
        "retained_no_tool_answer"
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_cohort,
        "retained_read_only_no_tool"
    );
    assert!(dispatch.model_provider_gated_visible_output_retained_read_only_no_tool);
    assert_eq!(
        dispatch
            .model_provider_gated_visible_output_scenario_coverage_key
            .as_deref(),
        Some("retained_no_tool_answer")
    );
    assert_eq!(
        dispatch
            .model_provider_gated_visible_output_required_scenario_set
            .as_slice(),
        [
            "retained_no_tool_answer",
            "retained_repo_grounded_answer",
            "retained_planning_without_mutation",
            "retained_mermaid_rendering",
            "retained_source_heavy_synthesis",
            "retained_probe_behavior",
            "retained_harness_dogfooding",
        ]
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_activation_flag,
        "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT"
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_activation_id,
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_authority,
        "workflow_model_provider_call"
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_rollback_target,
        "legacy_runtime_model_invocation"
    );
    assert!(dispatch.model_provider_gated_visible_output_rollback_available);
    assert_eq!(
        dispatch.selected_visible_output_authority,
        "workflow_model_provider_call"
    );
    assert_eq!(
        dispatch.selected_visible_output_hash,
        dispatch.workflow_provider_visible_output_hash
    );
    assert_eq!(
        dispatch.legacy_visible_output_hash,
        dispatch.selected_visible_output_hash
    );
    assert!(dispatch.legacy_visible_output_computed);
    assert!(dispatch.legacy_visible_output_hash_matches_selected);
    assert!(dispatch.selected_visible_output_authority_matches_transcript);
    assert!(dispatch.visible_output_divergence_class.is_none());
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_enabled);
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_ready);
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_failure_injected);
    assert_ne!(
        dispatch.model_provider_gated_visible_output_rollback_drill_injected_output_hash,
        dispatch.legacy_visible_output_hash
    );
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_output_hash_diverges);
    assert_eq!(
        dispatch.model_provider_gated_visible_output_rollback_drill_divergence_class,
        "provider_output_hash_divergence"
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_rollback_drill_fallback_authority,
        "legacy_runtime_model_invocation"
    );
    assert_eq!(
        dispatch.model_provider_gated_visible_output_rollback_drill_selected_authority,
        "legacy_runtime_model_invocation"
    );
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_transcript_unchanged);
    assert!(dispatch.model_provider_gated_visible_output_rollback_drill_rollback_executed);
    assert!(dispatch
        .model_provider_gated_visible_output_rollback_drill_activation_blockers
        .contains(&"model_provider_output_hash_divergence".to_string()));
    assert_eq!(
        dispatch.read_only_capability_routing_mode,
        "workflow_read_only_capability_routing"
    );
    assert!(dispatch.read_only_capability_routing_ready);
    assert!(dispatch.read_only_capability_routing_selected);
    assert!(dispatch.read_only_capability_routing_eligible);
    assert_eq!(
        dispatch.read_only_capability_routing_scenario,
        "retained_repo_grounded_answer"
    );
    assert_eq!(
        dispatch
            .read_only_capability_routing_scenario_coverage_key
            .as_deref(),
        Some("retained_repo_grounded_answer")
    );
    assert_eq!(
        dispatch
            .read_only_capability_routing_required_scenario_set
            .as_slice(),
        [
            "retained_repo_grounded_answer",
            "retained_source_heavy_synthesis",
            "retained_probe_behavior",
        ]
    );
    assert!(dispatch.read_only_capability_routing_source_material_ready);
    assert!(dispatch.read_only_capability_routing_no_mutation_ready);
    assert!(dispatch
        .read_only_capability_routing_workflow_owned_node_kinds
        .contains(&HarnessComponentKind::MemoryRead));
    assert!(dispatch
        .read_only_capability_routing_workflow_owned_node_kinds
        .contains(&HarnessComponentKind::CapabilitySequencer));
    assert!(dispatch
        .read_only_capability_routing_workflow_owned_node_kinds
        .contains(&HarnessComponentKind::ToolRouter));
    assert!(dispatch
        .read_only_capability_routing_workflow_owned_node_kinds
        .contains(&HarnessComponentKind::DryRunSimulator));
    assert_eq!(
        dispatch.output_authority,
        "blessed_workflow_activation_default"
    );
    assert!(!dispatch.output_writer_deferred);
    assert_eq!(dispatch.output_writer_status, "visible_write_committed");
    assert!(dispatch.output_writer_handoff_ready);
    assert!(dispatch.output_writer_authority_transferred);
    assert_eq!(
        dispatch.output_writer_materialization_mode,
        "workflow_visible_transcript_write"
    );
    assert!(dispatch.output_writer_materialization_canary_ready);
    assert!(dispatch.output_writer_materialization_committed);
    assert_eq!(
        dispatch.output_writer_staged_write_mode,
        "isolated_checkpoint_blob"
    );
    assert!(dispatch.output_writer_staged_write_canary_ready);
    assert!(dispatch.output_writer_staged_write_persisted);
    assert!(dispatch.output_writer_staged_write_committed);
    assert!(!dispatch.output_writer_staged_write_visible);
    assert!(dispatch.output_writer_staged_write_excluded_from_visible_transcript);
    assert_eq!(
        dispatch.output_writer_staged_write_rollback_status,
        "deleted"
    );
    assert!(dispatch.output_writer_staged_write_rollback_verified);
    assert_eq!(
        dispatch.output_writer_visible_write_mode,
        "workflow_visible_transcript_write"
    );
    assert!(dispatch.output_writer_visible_write_ready);
    assert!(dispatch.output_writer_visible_write_persisted);
    assert!(dispatch.output_writer_visible_write_committed);
    assert!(dispatch.output_writer_visible_write_visible);
    assert!(dispatch.output_writer_visible_write_identity_checkpoint_persisted);
    assert!(dispatch.output_writer_visible_write_legacy_duplicate_suppressed);
    assert_eq!(dispatch.authority_tooling_mode, "workflow_live_dry_run");
    assert!(dispatch.authority_tooling_ready);
    assert!(dispatch.authority_tooling_policy_gate_ready);
    assert!(dispatch.authority_tooling_tool_router_ready);
    assert!(dispatch.authority_tooling_dry_run_simulator_ready);
    assert!(dispatch.authority_tooling_approval_gate_ready);
    assert!(dispatch.authority_tooling_read_only_route_accepted);
    assert!(dispatch.authority_tooling_destructive_route_denied);
    assert!(dispatch.authority_tooling_mutating_tool_calls_blocked);
    assert!(!dispatch.authority_tooling_side_effects_executed);
    assert!(dispatch.authority_tooling_rollback_available);
    assert!(!dispatch.legacy_transcript_authority_retained);
    assert!(dispatch.legacy_transcript_fallback_available);
    assert_eq!(
        dispatch.proposed_visible_output_hash,
        dispatch.actual_visible_output_hash
    );
    assert_eq!(dispatch.output_hash_algorithm, "runtime_prompt_hash:v1");
    assert!(dispatch.output_hash_matches);
    assert!(!dispatch.output_hash_divergence);
    assert_eq!(dispatch.output_hash_divergence_count, 0);
    assert!(dispatch.transcript_materialization_content_hash_matches);
    assert!(dispatch.transcript_materialization_order_matches);
    assert!(dispatch.transcript_materialization_receipt_binding_matches);
    assert!(dispatch.transcript_materialization_target_matches);
    assert!(dispatch.transcript_materialization_matches);
    assert_eq!(dispatch.transcript_materialization_divergence_count, 0);
    assert!(dispatch.staged_transcript_write_content_hash_matches);
    assert!(dispatch.staged_transcript_write_order_matches);
    assert!(dispatch.staged_transcript_write_receipt_binding_matches);
    assert!(dispatch.staged_transcript_write_target_matches);
    assert!(dispatch.staged_transcript_write_matches);
    assert_eq!(dispatch.staged_transcript_write_divergence_count, 0);
    assert!(dispatch.visible_transcript_write_content_hash_matches);
    assert!(dispatch.visible_transcript_write_order_matches);
    assert!(dispatch.visible_transcript_write_receipt_binding_matches);
    assert!(dispatch.visible_transcript_write_target_matches);
    assert!(dispatch.visible_transcript_write_matches);
    assert_eq!(dispatch.visible_transcript_write_divergence_count, 0);
    assert!(!dispatch.legacy_output_authority_retained);
    assert!(dispatch.legacy_output_fallback_available);
    assert!(dispatch.mutating_turns_blocked);
    assert_eq!(
        dispatch.executor_ref,
        "crate::project::execute_workflow_harness_live_default_node"
    );
    assert!(dispatch.rollback_available);
    assert!(dispatch.activation_blockers.is_empty());
}

#[test]
fn canary_execution_boundary_uses_workflow_node_executor_with_rollback_drill() {
    let boundary = default_harness_canary_execution_boundary();

    assert_eq!(
        boundary.schema_version,
        "workflow.harness.canary-execution-boundary.v1"
    );
    assert_eq!(
        boundary.cluster_id,
        HarnessPromotionClusterId::VerificationOutput
    );
    assert_eq!(
        boundary.selected_selector,
        HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary
    );
    assert_eq!(
        boundary.production_default_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert_eq!(boundary.execution_mode, HarnessExecutionMode::Live);
    assert_eq!(boundary.executor_kind, "workflow_node_executor");
    assert!(boundary.synchronous);
    assert!(boundary.enforced_before_visible_output);
    assert_eq!(boundary.status, "passed");
    assert_eq!(boundary.component_kinds, boundary.executed_component_kinds);
    assert!(boundary
        .component_kinds
        .contains(&HarnessComponentKind::CompletionGate));
    assert_eq!(boundary.workflow_node_ids.len(), 6);
    assert_eq!(boundary.node_attempt_ids.len(), 6);
    assert!(boundary.activation_blockers.is_empty());
    assert!(boundary.rollback_available);
    assert!(boundary.rollback_drill.failure_injected);
    assert_eq!(
        boundary.rollback_drill.cluster_id,
        HarnessPromotionClusterId::VerificationOutput
    );
    assert!(boundary.rollback_drill.observed_failure);
    assert!(boundary.rollback_drill.rollback_executed);
    assert_eq!(
        boundary.rollback_drill.rollback_selector,
        HarnessLiveHandoffSelector::LegacyRuntime
    );
    assert_eq!(
        boundary.rollback_drill.fallback_authority,
        "existing_runtime_service"
    );
    assert_eq!(boundary.rollback_drill.drill_status, "passed");

    let boundaries = default_harness_canary_execution_boundaries();
    assert_eq!(boundaries.len(), 4);
    assert!(boundaries.iter().any(|boundary| boundary.cluster_id
        == HarnessPromotionClusterId::Cognition
        && boundary
            .component_kinds
            .contains(&HarnessComponentKind::CapabilitySequencer)));
    assert!(boundaries.iter().any(|boundary| boundary.cluster_id
        == HarnessPromotionClusterId::RoutingModel
        && boundary
            .component_kinds
            .contains(&HarnessComponentKind::ToolRouter)));
    assert!(boundaries.iter().any(|boundary| boundary.cluster_id
        == HarnessPromotionClusterId::VerificationOutput
        && boundary
            .component_kinds
            .contains(&HarnessComponentKind::CompletionGate)));
    assert!(boundaries.iter().any(|boundary| boundary.cluster_id
        == HarnessPromotionClusterId::AuthorityTooling
        && boundary
            .component_kinds
            .contains(&HarnessComponentKind::WalletCapability)));
    for boundary in boundaries {
        assert_eq!(boundary.execution_mode, HarnessExecutionMode::Live);
        assert_eq!(boundary.executor_kind, "workflow_node_executor");
        assert_eq!(boundary.status, "passed");
        assert_eq!(boundary.component_kinds, boundary.executed_component_kinds);
        assert_eq!(
            boundary.node_attempt_ids.len(),
            boundary.component_kinds.len()
        );
        assert_eq!(boundary.rollback_drill.cluster_id, boundary.cluster_id);
        assert!(boundary.rollback_drill.failure_injected);
        assert!(boundary.rollback_drill.rollback_executed);
        assert_eq!(boundary.rollback_drill.drill_status, "passed");
    }
}
