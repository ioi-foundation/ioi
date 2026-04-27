use super::{summarize_workload_receipt, WorkloadReceiptKind};
use ioi_ipc::public::{WorkloadParentPlaybookReceipt, WorkloadReceipt};

#[test]
fn parent_playbook_summary_preserves_explicit_decision_record_fields() {
    let receipt = WorkloadReceipt {
        session_id: "session-1".to_string(),
        workload_id: "workload-1".to_string(),
        step_index: 7,
        timestamp_ms: 1_763_000_000_000,
        receipt: Some(WorkloadReceiptKind::ParentPlaybook(
            WorkloadParentPlaybookReceipt {
                tool_name: "agent__await".to_string(),
                phase: "completed".to_string(),
                parent_session_id: "parent-1".to_string(),
                playbook_id: "citation_grounded_brief".to_string(),
                playbook_label: "Citation Grounded Brief".to_string(),
                status: "completed".to_string(),
                success: true,
                route_family: "research".to_string(),
                topology: "planner_specialist_verifier".to_string(),
                planner_authority: "kernel".to_string(),
                verifier_state: "passed".to_string(),
                verifier_role: "citation_verifier".to_string(),
                verifier_outcome: "pass".to_string(),
                summary: "Parent playbook completed.".to_string(),
                ..WorkloadParentPlaybookReceipt::default()
            },
        )),
    };

    let summary = summarize_workload_receipt(&receipt).expect("summary");
    assert_eq!(summary.kind, "parent_playbook");
    assert_eq!(summary.digest["planner_authority"], "kernel");
    assert_eq!(summary.digest["verifier_role"], "citation_verifier");
    assert_eq!(summary.digest["verifier_outcome"], "pass");
    assert_eq!(summary.details["planner_authority"], "kernel");
    assert_eq!(summary.details["verifier_role"], "citation_verifier");
    assert_eq!(summary.details["verifier_outcome"], "pass");
}
