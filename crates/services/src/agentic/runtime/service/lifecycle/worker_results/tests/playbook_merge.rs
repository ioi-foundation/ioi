use super::*;

#[test]
fn resolve_researcher_assignment_uses_template_defaults() {
    let assignment = resolve_worker_assignment(
        [0x11; 32],
        4,
        120,
        "Research latest grounding evidence",
        None,
        Some("researcher"),
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(assignment.role.as_deref(), Some("Research Worker"));
    assert_eq!(
        assignment.workflow_id.as_deref(),
        Some("live_research_brief")
    );
    assert_eq!(
        assignment.completion_contract.merge_mode,
        WorkerMergeMode::AppendSummaryToParent
    );
    assert!(assignment
        .goal
        .contains("using current web and local memory evidence"));
    assert!(assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "web__search"));
}

#[test]
fn append_as_evidence_merge_renders_stable_handoff() {
    let mut assignment = resolve_worker_assignment(
        [0x22; 32],
        2,
        40,
        "Verify whether the parent claim is supported",
        None,
        Some("verifier"),
        None,
        None,
        None,
        Some("append_as_evidence"),
        None,
    );
    assignment.completion_contract.verification_hint =
        Some("Check whether the cited evidence satisfies the claim.".to_string());

    let merged = merged_worker_output(
        &assignment,
        true,
        Some("The claim is supported by two matching primary sources."),
        None,
    );

    assert!(merged.contains("Worker evidence"));
    assert!(merged.contains("parent claim is supported"));
    assert!(merged.contains("The claim is supported by two matching primary sources."));
    assert!(merged.contains("Verification hint"));
}

#[test]
fn context_worker_playbook_merge_preserves_playbook_identity() {
    let assignment = resolve_worker_assignment(
        [0x33; 32],
        3,
        64,
        "Capture repo context for the routing regression.",
        Some("evidence_audited_patch"),
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
    );

    let merged = merged_worker_output(
            &assignment,
            true,
            Some("Likely files: crates/services/src/router.rs\nTargeted checks: cargo test -p ioi-services routing_contracts -- --nocapture"),
            None,
        );

    assert!(merged.contains("Parent playbook: evidence_audited_patch"));
    assert!(merged.contains("Playbook: Repo Context Brief (repo_context_brief)"));
    assert!(merged.contains("Likely files: crates/services/src/router.rs"));
}

#[test]
fn verifier_playbook_overrides_budget_retries_and_tools() {
    let assignment = resolve_worker_assignment(
        [0x34; 32],
        5,
        120,
        "Verify whether the receipt proves the postcondition.",
        None,
        Some("verifier"),
        Some("postcondition_audit"),
        None,
        None,
        None,
        None,
    );

    assert_eq!(
        assignment.workflow_id.as_deref(),
        Some("postcondition_audit")
    );
    assert_eq!(assignment.budget, 48);
    assert_eq!(assignment.max_retries, 0);
    assert!(assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "model__rerank"));
    assert!(assignment
        .allowed_tools
        .iter()
        .all(|tool| tool != "model__responses"));
    assert_eq!(
        assignment.completion_contract.merge_mode,
        WorkerMergeMode::AppendAsEvidence
    );
}

#[test]
fn citation_audit_assignment_uses_research_specific_contract() {
    let assignment = resolve_worker_assignment(
        [0x35; 32],
        5,
        120,
        "Verify whether the cited brief is fresh and quote-grounded.",
        Some("citation_grounded_brief"),
        Some("verifier"),
        Some("citation_audit"),
        None,
        None,
        None,
        None,
    );

    assert_eq!(assignment.workflow_id.as_deref(), Some("citation_audit"));
    assert_eq!(assignment.budget, 48);
    assert_eq!(assignment.max_retries, 0);
    assert!(assignment
        .completion_contract
        .expected_output
        .contains("Citation verifier scorecard"));
    assert!(assignment
        .completion_contract
        .verification_hint
        .as_deref()
        .is_some_and(|hint| hint.contains("freshness")));
}

#[test]
fn coder_playbook_overrides_budget_retries_and_tools() {
    let assignment = resolve_worker_assignment(
        [0x35; 32],
        6,
        140,
        "Patch the parser regression, run focused verification, and summarize the outcome.",
        None,
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
    );

    assert_eq!(
        assignment.workflow_id.as_deref(),
        Some("patch_build_verify")
    );
    assert_eq!(assignment.budget, 96);
    assert_eq!(assignment.max_retries, 1);
    assert!(assignment
        .goal
        .contains("run focused verification commands"));
    assert!(!assignment.goal.contains("Implement Implement"));
    assert!(assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__edit"));
    assert!(assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "shell__start"));
    assert!(assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "agent__complete"));
    assert!(assignment
        .allowed_tools
        .iter()
        .all(|tool| tool != "model__responses"));
    assert_eq!(
        assignment.completion_contract.merge_mode,
        WorkerMergeMode::AppendSummaryToParent
    );
}
