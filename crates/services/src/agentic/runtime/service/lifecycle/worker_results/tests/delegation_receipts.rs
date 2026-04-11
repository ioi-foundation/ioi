use super::*;

#[tokio::test(flavor = "current_thread")]
async fn delegated_verifier_playbook_flows_through_result_artifact_and_merge_receipts() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state();

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x46; 32],
        "Verify whether the parser regression fix satisfies the postcondition.",
        8,
        None,
        Some("verifier"),
        Some("postcondition_audit"),
        None,
        None,
        None,
        None,
        5,
        0,
    )
    .await
    .expect("delegated child should spawn");
    let child_session_id = spawned.child_session_id;
    assert_eq!(spawned.assignment.budget, 8);
    assert_eq!(
        spawned.assignment.workflow_id.as_deref(),
        Some("postcondition_audit")
    );
    assert_eq!(spawned.assignment.max_retries, 0);
    assert!(spawned
        .assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "model__rerank"));
    assert!(spawned
        .assignment
        .allowed_tools
        .iter()
        .all(|tool| tool != "model__responses"));

    let child_key = get_state_key(&child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child state lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(child_state.goal.contains("return a pass/fail audit"));

    child_state.status = AgentStatus::Completed(Some(
            "Verdict: pass\nEvidence: Receipt 42 and reranked memory fragments both confirm the parser regression path now returns the expected token stream.\nResidual risk: Full parser fuzz coverage still has not been rerun."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        6,
        0,
        &hex::encode(child_session_id),
    )
    .await
    .expect("await result should merge");

    assert!(merged.contains("Worker evidence"));
    assert!(merged.contains("Playbook: Postcondition Audit (postcondition_audit)"));
    assert!(merged.contains("Verdict: pass"));

    let result = load_worker_session_result(&state, child_session_id)
        .expect("worker result load should succeed")
        .expect("worker result artifact should exist");
    assert_eq!(result.workflow_id.as_deref(), Some("postcondition_audit"));
    assert_eq!(result.budget, 8);
    assert_eq!(
        result.completion_contract.merge_mode,
        WorkerMergeMode::AppendAsEvidence
    );
    assert_eq!(result.merged_step_index, Some(6));
    assert!(result.merged_at_ms.is_some());
    assert!(result
        .merged_output
        .contains("Playbook: Postcondition Audit (postcondition_audit)"));

    let mut completion_saw_workflow = false;
    let mut merge_saw_workflow = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                match receipt.phase.as_str() {
                    "completed" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("postcondition_audit"));
                        assert_eq!(receipt.merge_mode, "append_as_evidence");
                        completion_saw_workflow = true;
                    }
                    "merged" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("postcondition_audit"));
                        assert_eq!(receipt.merge_mode, "append_as_evidence");
                        merge_saw_workflow = true;
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(
        completion_saw_workflow,
        "completion receipt should preserve verifier workflow id"
    );
    assert!(
        merge_saw_workflow,
        "merge receipt should preserve verifier workflow id"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn delegated_coder_playbook_flows_through_result_artifact_and_merge_receipts() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state();

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x45; 32],
        "Patch the parser regression, run focused verification, and summarize the outcome.",
        8,
        Some("evidence_audited_patch"),
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
        6,
        0,
    )
    .await
    .expect("delegated child should spawn");
    let child_session_id = spawned.child_session_id;
    assert_eq!(spawned.assignment.budget, 8);
    assert_eq!(
        spawned.assignment.playbook_id.as_deref(),
        Some("evidence_audited_patch")
    );
    assert_eq!(
        spawned.assignment.workflow_id.as_deref(),
        Some("patch_build_verify")
    );
    assert!(spawned
        .assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__edit"));
    assert!(spawned
        .assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "shell__start"));
    assert!(spawned
        .assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "agent__complete"));

    let child_key = get_state_key(&child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child state lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(child_state.goal.contains(
        "Patch the parser regression, run focused verification, and summarize the outcome."
    ));
    assert!(child_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(child_state
        .goal
        .contains("- delegated_task_contract: Parent orchestration goal"));

    child_state.status = AgentStatus::Completed(Some(
            "Touched files: crates/services/src/parser.rs\nVerification: cargo test -p ioi-services parser_regression -- --nocapture (passed)\nResidual risk: broader parser edge cases still need coverage."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        7,
        0,
        &hex::encode(child_session_id),
    )
    .await
    .expect("await result should merge");

    assert!(merged.contains("Playbook: Patch, Build, Verify (patch_build_verify)"));
    assert!(merged.contains("Parent playbook: evidence_audited_patch"));
    assert!(merged.contains("Touched files: crates/services/src/parser.rs"));
    assert!(merged.contains("cargo test -p ioi-services parser_regression"));

    let result = load_worker_session_result(&state, child_session_id)
        .expect("worker result load should succeed")
        .expect("worker result artifact should exist");
    assert_eq!(
        result.playbook_id.as_deref(),
        Some("evidence_audited_patch")
    );
    assert_eq!(result.workflow_id.as_deref(), Some("patch_build_verify"));
    assert_eq!(result.budget, 8);
    assert_eq!(
        result.completion_contract.merge_mode,
        WorkerMergeMode::AppendSummaryToParent
    );
    assert_eq!(result.merged_step_index, Some(7));
    assert!(result.merged_at_ms.is_some());
    assert!(result
        .merged_output
        .contains("Parent playbook: evidence_audited_patch"));
    assert!(result
        .merged_output
        .contains("Playbook: Patch, Build, Verify (patch_build_verify)"));

    let mut completion_saw_workflow = false;
    let mut merge_saw_workflow = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                match receipt.phase.as_str() {
                    "completed" => {
                        assert_eq!(
                            receipt.playbook_id.as_deref(),
                            Some("evidence_audited_patch")
                        );
                        assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                        assert_eq!(receipt.merge_mode, "append_summary_to_parent");
                        completion_saw_workflow = true;
                    }
                    "merged" => {
                        assert_eq!(
                            receipt.playbook_id.as_deref(),
                            Some("evidence_audited_patch")
                        );
                        assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                        assert_eq!(receipt.merge_mode, "append_summary_to_parent");
                        merge_saw_workflow = true;
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(
        completion_saw_workflow,
        "completion receipt should preserve coder workflow id"
    );
    assert!(
        merge_saw_workflow,
        "merge receipt should preserve coder workflow id"
    );
}
