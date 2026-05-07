//! Default agent harness projection and receipt correlation adapters.
//!
//! This module deliberately does not replace the live runtime executor. It lifts the
//! existing runtime kernels into stable, workflow-addressable component frames so
//! policy, receipts, replay, and UI projection can share one substrate.

pub use ioi_types::app::{
    compare_harness_live_shadow_attempts, default_agent_harness_action_frames,
    default_agent_harness_components, default_agent_harness_slots, default_harness_component_spec,
    default_harness_gated_cluster_run_for_shadow_run, default_harness_node_attempt_for_receipt,
    default_harness_promotion_clusters, default_harness_receipt_binding_for_execution_contract,
    default_harness_receipt_binding_for_plan, default_harness_receipt_binding_for_routing,
    default_harness_receipt_binding_for_workload, default_harness_shadow_run_for_attempts,
    default_harness_worker_binding, harness_component_kind_for_action_target,
    harness_component_kind_for_policy_decision, harness_component_kind_for_tool_name,
    validate_harness_worker_binding, HarnessActionFrame, HarnessApprovalSemantics,
    HarnessBindingError, HarnessClusterPromotionStatus, HarnessComponentKind,
    HarnessComponentReadiness, HarnessComponentSpec, HarnessDivergenceClass, HarnessExecutionMode,
    HarnessGatedClusterRun, HarnessNodeAttemptRecord, HarnessNodeAttemptStatus,
    HarnessPromotionCluster, HarnessPromotionClusterId, HarnessReceiptBinding,
    HarnessReplayDeterminism, HarnessReplayEnvelope, HarnessRetryBehavior, HarnessShadowComparison,
    HarnessShadowRun, HarnessSlotKind, HarnessSlotSpec, HarnessTimeoutBehavior,
    HarnessWorkerBinding, DEFAULT_AGENT_HARNESS_ACTIVATION_ID, DEFAULT_AGENT_HARNESS_HASH,
    DEFAULT_AGENT_HARNESS_VERSION, DEFAULT_AGENT_HARNESS_WORKFLOW_ID, HARNESS_COMPONENT_VERSION_V1,
    HARNESS_ERROR_SCHEMA_ID, HARNESS_INPUT_SCHEMA_ID, HARNESS_OUTPUT_SCHEMA_ID,
};

use ioi_types::app::KernelEvent;

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
