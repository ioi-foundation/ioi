//! Default agent harness projection and receipt correlation adapters.
//!
//! This module deliberately does not replace the live runtime executor. It lifts the
//! existing runtime kernels into stable, workflow-addressable component frames so
//! policy, receipts, replay, and UI projection can share one substrate.

pub use ioi_types::app::{
    compare_harness_live_shadow_attempts, default_agent_harness_action_frames,
    default_agent_harness_components, default_agent_harness_slots,
    default_harness_action_frame_for_component, default_harness_component_spec,
    default_harness_gated_cluster_run_for_shadow_run, default_harness_node_attempt_for_receipt,
    default_harness_promotion_clusters, default_harness_receipt_binding_for_execution_contract,
    default_harness_receipt_binding_for_plan, default_harness_receipt_binding_for_routing,
    default_harness_receipt_binding_for_workload, default_harness_shadow_run_for_attempts,
    default_harness_worker_binding, harness_component_kind_for_action_target,
    harness_component_kind_for_policy_decision, harness_component_kind_for_tool_name,
    validate_harness_worker_binding, HarnessActionFrame, HarnessApprovalSemantics,
    HarnessBindingError, HarnessClusterPromotionStatus, HarnessComponentAdapterResult,
    HarnessComponentInvocation, HarnessComponentKind, HarnessComponentReadiness,
    HarnessComponentSpec, HarnessDivergenceClass, HarnessExecutionMode, HarnessGatedClusterRun,
    HarnessNodeAttemptRecord, HarnessNodeAttemptStatus, HarnessPromotionCluster,
    HarnessPromotionClusterId, HarnessReceiptBinding, HarnessReplayDeterminism,
    HarnessReplayEnvelope, HarnessRetryBehavior, HarnessShadowComparison, HarnessShadowRun,
    HarnessSlotKind, HarnessSlotSpec, HarnessTimeoutBehavior, HarnessWorkerBinding,
    DEFAULT_AGENT_HARNESS_ACTIVATION_ID, DEFAULT_AGENT_HARNESS_HASH, DEFAULT_AGENT_HARNESS_VERSION,
    DEFAULT_AGENT_HARNESS_WORKFLOW_ID, HARNESS_COMPONENT_VERSION_V1, HARNESS_ERROR_SCHEMA_ID,
    HARNESS_INPUT_SCHEMA_ID, HARNESS_OUTPUT_SCHEMA_ID,
};

use ioi_types::app::KernelEvent;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HarnessComponentAdapterError {
    #[error("harness component invocation id is missing")]
    MissingInvocationId,
}

fn readiness_allows_mode(
    readiness: HarnessComponentReadiness,
    execution_mode: HarnessExecutionMode,
) -> bool {
    match execution_mode {
        HarnessExecutionMode::Projection => true,
        HarnessExecutionMode::Shadow => matches!(
            readiness,
            HarnessComponentReadiness::Simulated
                | HarnessComponentReadiness::ShadowReady
                | HarnessComponentReadiness::LiveReady
        ),
        HarnessExecutionMode::Gated => matches!(
            readiness,
            HarnessComponentReadiness::ShadowReady | HarnessComponentReadiness::LiveReady
        ),
        HarnessExecutionMode::Live => matches!(readiness, HarnessComponentReadiness::LiveReady),
    }
}

fn invocation_error_class(invocation: &HarnessComponentInvocation) -> Option<String> {
    invocation
        .evidence_refs
        .iter()
        .find_map(|entry| entry.strip_prefix("error_class:").map(str::to_string))
}

fn status_for_invocation(
    invocation: &HarnessComponentInvocation,
    readiness: HarnessComponentReadiness,
) -> HarnessNodeAttemptStatus {
    if !readiness_allows_mode(readiness, invocation.execution_mode) {
        return HarnessNodeAttemptStatus::Blocked;
    }
    if invocation_error_class(invocation).is_some() {
        return HarnessNodeAttemptStatus::Failed;
    }
    match invocation.execution_mode {
        HarnessExecutionMode::Projection => HarnessNodeAttemptStatus::Projection,
        HarnessExecutionMode::Shadow => HarnessNodeAttemptStatus::Shadow,
        HarnessExecutionMode::Gated => HarnessNodeAttemptStatus::Gated,
        HarnessExecutionMode::Live => HarnessNodeAttemptStatus::Live,
    }
}

fn stable_adapter_output_hash(
    invocation: &HarnessComponentInvocation,
    frame: &HarnessActionFrame,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(invocation.invocation_id.as_bytes());
    hasher.update(frame.component_id.as_bytes());
    hasher.update(invocation.component_kind.as_str().as_bytes());
    hasher.update(invocation.execution_mode.as_str().as_bytes());
    if let Some(input_hash) = &invocation.input_hash {
        hasher.update(input_hash.as_bytes());
    }
    if let Some(policy_decision) = &invocation.policy_decision {
        hasher.update(policy_decision.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn invoke_default_harness_component(
    invocation: HarnessComponentInvocation,
) -> Result<HarnessComponentAdapterResult, HarnessComponentAdapterError> {
    if invocation.invocation_id.trim().is_empty() {
        return Err(HarnessComponentAdapterError::MissingInvocationId);
    }
    let frame = default_harness_action_frame_for_component(
        invocation.component_kind,
        invocation.execution_mode,
    );
    let readiness = frame.readiness;
    let status = status_for_invocation(&invocation, readiness);
    let not_ready = status == HarnessNodeAttemptStatus::Blocked;
    let error_class = if not_ready {
        Some("harness_component_not_ready_for_mode".to_string())
    } else {
        invocation_error_class(&invocation)
    };
    let mut replay = frame.replay.clone();
    replay.fixture_ref = invocation.replay_fixture_ref.clone();
    let result_hash = if not_ready {
        None
    } else {
        Some(
            invocation
                .output_hash
                .clone()
                .unwrap_or_else(|| stable_adapter_output_hash(&invocation, &frame)),
        )
    };
    let node_attempt = HarnessNodeAttemptRecord {
        attempt_id: format!("{}:{}", frame.node_id, invocation.invocation_id),
        harness_workflow_id: frame.workflow_id.clone(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: frame.workflow_hash.clone(),
        workflow_node_id: frame.node_id.clone(),
        component_id: frame.component_id.clone(),
        component_kind: frame.component_kind,
        execution_mode: invocation.execution_mode,
        readiness,
        attempt_index: invocation.attempt_index,
        status,
        input_hash: invocation.input_hash.clone(),
        output_hash: result_hash.clone(),
        error_class: error_class.clone(),
        policy_decision: invocation.policy_decision.clone(),
        started_at_ms: invocation.started_at_ms,
        duration_ms: invocation.duration_ms,
        receipt_ids: invocation.receipt_ids.clone(),
        evidence_refs: invocation.evidence_refs.clone(),
        replay: replay.clone(),
    };
    Ok(HarnessComponentAdapterResult {
        schema_version: "workflow.harness.component-adapter-result.v1".to_string(),
        invocation_id: invocation.invocation_id,
        action_frame: frame.clone(),
        node_attempt,
        slot_ids: frame.slot_ids,
        result_hash,
        error_class,
        readiness,
        receipt_ids: invocation.receipt_ids,
        replay,
    })
}

pub fn default_harness_node_attempt_for_kernel_event(
    event: &KernelEvent,
    execution_mode: HarnessExecutionMode,
    attempt_index: u32,
) -> Option<HarnessNodeAttemptRecord> {
    let binding = match event {
        KernelEvent::PlanReceipt(receipt) => default_harness_receipt_binding_for_plan(receipt),
        KernelEvent::RoutingReceipt(receipt) => {
            default_harness_receipt_binding_for_routing(receipt)
        }
        KernelEvent::WorkloadReceipt(receipt) => {
            default_harness_receipt_binding_for_workload(receipt)
        }
        KernelEvent::ExecutionContractReceipt(receipt) => {
            default_harness_receipt_binding_for_execution_contract(receipt)
        }
        _ => return None,
    };
    let status = match execution_mode {
        HarnessExecutionMode::Projection => HarnessNodeAttemptStatus::Projection,
        HarnessExecutionMode::Shadow => HarnessNodeAttemptStatus::Shadow,
        HarnessExecutionMode::Gated => HarnessNodeAttemptStatus::Gated,
        HarnessExecutionMode::Live => HarnessNodeAttemptStatus::Live,
    };
    Some(default_harness_node_attempt_for_receipt(
        &binding,
        execution_mode,
        attempt_index,
        status,
    ))
}

pub fn default_harness_shadow_attempts_for_events(
    events: &[KernelEvent],
) -> Vec<HarnessNodeAttemptRecord> {
    events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            default_harness_node_attempt_for_kernel_event(
                event,
                HarnessExecutionMode::Shadow,
                (index + 1) as u32,
            )
        })
        .collect()
}

pub fn default_harness_shadow_run_for_events(
    run_id: impl Into<String>,
    source_session_id: Option<String>,
    live_turn_id: Option<String>,
    events: &[KernelEvent],
) -> HarnessShadowRun {
    let attempts = default_harness_shadow_attempts_for_events(events);
    default_harness_shadow_run_for_attempts(
        run_id,
        source_session_id,
        live_turn_id,
        attempts,
        Vec::new(),
        vec!["KernelEvent stream shadow projection".to_string()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::adapter::{AdapterKind, AdapterReceipt};
    use ioi_types::app::events::{WorkloadReceipt, WorkloadReceiptEvent};
    use ioi_types::app::KernelEvent;

    #[test]
    fn runtime_component_contracts_cover_required_harness_kernels() {
        let components = default_agent_harness_components();
        let kinds: Vec<_> = components.iter().map(|component| component.kind).collect();
        for required in [
            HarnessComponentKind::Planner,
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ToolRouter,
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::ApprovalGate,
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::CompletionGate,
        ] {
            assert!(kinds.contains(&required), "missing {required:?}");
        }
    }

    #[test]
    fn default_component_adapter_invokes_gated_cognition_components() {
        let cluster = default_harness_promotion_clusters()
            .into_iter()
            .find(|cluster| cluster.cluster_id == HarnessPromotionClusterId::Cognition)
            .expect("cognition cluster");

        for (index, component_kind) in cluster.component_kinds.iter().enumerate() {
            let result = invoke_default_harness_component(HarnessComponentInvocation {
                invocation_id: format!("cognition-adapter-{index}"),
                component_kind: *component_kind,
                execution_mode: HarnessExecutionMode::Gated,
                attempt_index: (index + 1) as u32,
                input_hash: Some(format!("input:{index}")),
                output_hash: None,
                policy_decision: Some("allow_non_mutating_component".to_string()),
                receipt_ids: vec![format!("receipt:{index}")],
                evidence_refs: vec![format!("evidence:{}", component_kind.as_str())],
                replay_fixture_ref: Some(format!("fixture:{}", component_kind.as_str())),
                started_at_ms: Some(10),
                duration_ms: Some(2),
            })
            .expect("adapter invocation should be accepted");

            assert_eq!(
                result.action_frame.execution_mode,
                HarnessExecutionMode::Gated
            );
            assert_eq!(result.action_frame.component_kind, *component_kind);
            assert_eq!(
                result.node_attempt.workflow_node_id,
                component_kind.workflow_node_id()
            );
            assert_eq!(result.node_attempt.status, HarnessNodeAttemptStatus::Gated);
            assert_eq!(
                result.node_attempt.policy_decision.as_deref(),
                Some("allow_non_mutating_component")
            );
            assert_eq!(
                result.node_attempt.replay.fixture_ref.as_deref(),
                Some(format!("fixture:{}", component_kind.as_str()).as_str())
            );
            assert!(result
                .result_hash
                .as_deref()
                .unwrap_or("")
                .starts_with("sha256:"));
            assert!(!result.slot_ids.is_empty());
            assert_eq!(result.receipt_ids, vec![format!("receipt:{index}")]);
        }
    }

    #[test]
    fn default_component_adapter_blocks_unready_modes_without_side_effects() {
        let projection_only = invoke_default_harness_component(HarnessComponentInvocation {
            invocation_id: "projection-only-gated".to_string(),
            component_kind: HarnessComponentKind::MemoryRead,
            execution_mode: HarnessExecutionMode::Gated,
            attempt_index: 1,
            input_hash: Some("input:memory".to_string()),
            output_hash: None,
            policy_decision: None,
            receipt_ids: vec![],
            evidence_refs: vec![],
            replay_fixture_ref: None,
            started_at_ms: None,
            duration_ms: None,
        })
        .expect("adapter returns a blocked attempt for unready mode");

        assert_eq!(
            projection_only.node_attempt.status,
            HarnessNodeAttemptStatus::Blocked
        );
        assert_eq!(
            projection_only.error_class.as_deref(),
            Some("harness_component_not_ready_for_mode")
        );
        assert!(projection_only.result_hash.is_none());

        let live_before_ready = invoke_default_harness_component(HarnessComponentInvocation {
            invocation_id: "planner-live".to_string(),
            component_kind: HarnessComponentKind::Planner,
            execution_mode: HarnessExecutionMode::Live,
            attempt_index: 1,
            input_hash: Some("input:planner".to_string()),
            output_hash: None,
            policy_decision: None,
            receipt_ids: vec![],
            evidence_refs: vec![],
            replay_fixture_ref: None,
            started_at_ms: None,
            duration_ms: None,
        })
        .expect("live mode blocks until component is live-ready");

        assert_eq!(
            live_before_ready.node_attempt.status,
            HarnessNodeAttemptStatus::Blocked
        );
        assert_eq!(
            live_before_ready.action_frame.execution_mode,
            HarnessExecutionMode::Live
        );
    }

    #[test]
    fn default_component_adapter_rejects_missing_invocation_id() {
        let error = invoke_default_harness_component(HarnessComponentInvocation {
            invocation_id: String::new(),
            component_kind: HarnessComponentKind::Planner,
            execution_mode: HarnessExecutionMode::Projection,
            attempt_index: 1,
            input_hash: None,
            output_hash: None,
            policy_decision: None,
            receipt_ids: vec![],
            evidence_refs: vec![],
            replay_fixture_ref: None,
            started_at_ms: None,
            duration_ms: None,
        })
        .expect_err("empty invocation id should be invalid");

        assert_eq!(error, HarnessComponentAdapterError::MissingInvocationId);
    }

    #[test]
    fn runtime_mcp_adapter_receipt_maps_to_mcp_tool_component() {
        let event = WorkloadReceiptEvent {
            session_id: [9; 32],
            step_index: 8,
            workload_id: "mcp-call-1".to_string(),
            timestamp_ms: 42,
            receipt: WorkloadReceipt::Adapter(AdapterReceipt {
                adapter_id: "mcp.filesystem".to_string(),
                tool_name: "mcp__filesystem__read".to_string(),
                kind: AdapterKind::Mcp,
                invocation_id: "invoke-1".to_string(),
                idempotency_key: "idem-1".to_string(),
                action_target: "fs::read".to_string(),
                request_hash: "request-hash".to_string(),
                response_hash: Some("response-hash".to_string()),
                success: true,
                error_class: None,
                artifact_pointers: vec![],
                redaction: None,
                replay_classification: None,
            }),
        };

        let binding = default_harness_receipt_binding_for_workload(&event);
        assert_eq!(binding.component_kind, HarnessComponentKind::McpToolCall);
        assert_eq!(binding.workflow_node_id, "harness.mcp_tool_call");
        assert!(binding
            .evidence_refs
            .iter()
            .any(|item| item == "workload_id:mcp-call-1"));
    }

    #[test]
    fn runtime_connector_adapter_receipt_maps_to_connector_component() {
        let event = WorkloadReceiptEvent {
            session_id: [10; 32],
            step_index: 5,
            workload_id: "gmail-send".to_string(),
            timestamp_ms: 84,
            receipt: WorkloadReceipt::Adapter(AdapterReceipt {
                adapter_id: "gmail".to_string(),
                tool_name: "gmail__send_email".to_string(),
                kind: AdapterKind::Connector,
                invocation_id: "invoke-2".to_string(),
                idempotency_key: "idem-2".to_string(),
                action_target: "connector::send".to_string(),
                request_hash: "request-hash".to_string(),
                response_hash: Some("response-hash".to_string()),
                success: true,
                error_class: None,
                artifact_pointers: vec![],
                redaction: None,
                replay_classification: None,
            }),
        };

        let binding = default_harness_receipt_binding_for_workload(&event);
        assert_eq!(binding.component_kind, HarnessComponentKind::ConnectorCall);
        assert_eq!(binding.workflow_node_id, "harness.connector_call");
    }

    #[test]
    fn runtime_kernel_events_project_to_shadow_node_attempts() {
        let event = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [11; 32],
            step_index: 2,
            workload_id: "mcp-call-shadow".to_string(),
            timestamp_ms: 128,
            receipt: WorkloadReceipt::Adapter(AdapterReceipt {
                adapter_id: "mcp.filesystem".to_string(),
                tool_name: "mcp__filesystem__read".to_string(),
                kind: AdapterKind::Mcp,
                invocation_id: "invoke-shadow".to_string(),
                idempotency_key: "idem-shadow".to_string(),
                action_target: "fs::read".to_string(),
                request_hash: "request-hash".to_string(),
                response_hash: Some("response-hash".to_string()),
                success: true,
                error_class: None,
                artifact_pointers: vec![],
                redaction: None,
                replay_classification: None,
            }),
        });

        let attempts = default_harness_shadow_attempts_for_events(&[event]);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].workflow_node_id, "harness.mcp_tool_call");
        assert_eq!(attempts[0].execution_mode, HarnessExecutionMode::Shadow);
        assert_eq!(attempts[0].status, HarnessNodeAttemptStatus::Shadow);
        assert_eq!(
            attempts[0].replay.determinism,
            HarnessReplayDeterminism::Nondeterministic
        );
    }

    #[test]
    fn runtime_kernel_events_project_to_shadow_run() {
        let event = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [12; 32],
            step_index: 4,
            workload_id: "connector-shadow".to_string(),
            timestamp_ms: 256,
            receipt: WorkloadReceipt::Adapter(AdapterReceipt {
                adapter_id: "gmail".to_string(),
                tool_name: "gmail__draft".to_string(),
                kind: AdapterKind::Connector,
                invocation_id: "invoke-shadow-run".to_string(),
                idempotency_key: "idem-shadow-run".to_string(),
                action_target: "connector::draft".to_string(),
                request_hash: "request-hash".to_string(),
                response_hash: Some("response-hash".to_string()),
                success: true,
                error_class: None,
                artifact_pointers: vec![],
                redaction: None,
                replay_classification: None,
            }),
        });

        let run = default_harness_shadow_run_for_events(
            "shadow-run-1",
            Some("session-1".to_string()),
            Some("turn-4".to_string()),
            &[event],
        );
        assert_eq!(run.execution_mode, HarnessExecutionMode::Shadow);
        assert_eq!(run.node_attempts.len(), 1);
        assert_eq!(
            run.node_attempts[0].component_kind,
            HarnessComponentKind::ConnectorCall
        );
        assert!(!run.promotion_blocked);
    }

    #[test]
    fn runtime_exports_default_promotion_clusters() {
        let clusters = default_harness_promotion_clusters();
        assert_eq!(clusters.len(), 4);
        assert_eq!(clusters[0].cluster_id, HarnessPromotionClusterId::Cognition);
        assert!(clusters[0]
            .component_kinds
            .contains(&HarnessComponentKind::PromptAssembler));
        assert_eq!(
            clusters[0].required_execution_mode,
            HarnessExecutionMode::Gated
        );
    }
}
