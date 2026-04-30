//! Default agent harness projection and receipt correlation adapters.
//!
//! This module deliberately does not replace the live runtime executor. It lifts the
//! existing runtime kernels into stable, workflow-addressable component frames so
//! policy, receipts, replay, and UI projection can share one substrate.

pub use ioi_types::app::{
    default_agent_harness_action_frames, default_agent_harness_components,
    default_agent_harness_slots, default_harness_component_spec,
    default_harness_receipt_binding_for_execution_contract,
    default_harness_receipt_binding_for_plan, default_harness_receipt_binding_for_routing,
    default_harness_receipt_binding_for_workload, default_harness_worker_binding,
    harness_component_kind_for_action_target, harness_component_kind_for_policy_decision,
    harness_component_kind_for_tool_name, validate_harness_worker_binding, HarnessActionFrame,
    HarnessApprovalSemantics, HarnessBindingError, HarnessComponentKind, HarnessComponentSpec,
    HarnessReceiptBinding, HarnessRetryBehavior, HarnessSlotKind, HarnessSlotSpec,
    HarnessTimeoutBehavior, HarnessWorkerBinding, DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    DEFAULT_AGENT_HARNESS_HASH, DEFAULT_AGENT_HARNESS_VERSION, DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    HARNESS_COMPONENT_VERSION_V1, HARNESS_ERROR_SCHEMA_ID, HARNESS_INPUT_SCHEMA_ID,
    HARNESS_OUTPUT_SCHEMA_ID,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::adapter::{AdapterKind, AdapterReceipt};
    use ioi_types::app::events::{WorkloadReceipt, WorkloadReceiptEvent};

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
}
