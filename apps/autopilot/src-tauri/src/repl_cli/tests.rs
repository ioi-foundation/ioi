use super::{
    apply_authority_override, apply_authority_profile, build_repl_authority_recommendation,
    build_repl_delegated_runs, compaction_policy_from_flags, resolve_authority_profile_id,
    select_attachable_target, select_target, selector_and_compaction_policy, DataHandlingMode,
    LocalEngineAgentPlaybookRecord, LocalEngineParentPlaybookReceiptRecord,
    LocalEngineParentPlaybookRunRecord, PolicyDecisionMode, ReplSessionTarget,
};
use crate::models::{
    LocalEngineAgentPlaybookStepRecord, LocalEngineParentPlaybookStepRunRecord,
    LocalEngineWorkerCompletionContract, SessionHookReceiptSummary, SessionHookRecord,
    SessionHookSnapshot,
};
use std::collections::BTreeMap;

fn target(session_id: &str, workspace_root: Option<&str>) -> ReplSessionTarget {
    ReplSessionTarget {
        session_id: session_id.to_string(),
        title: format!("Session {session_id}"),
        timestamp: 0,
        phase: None,
        current_step: None,
        resume_hint: None,
        workspace_root: workspace_root.map(ToOwned::to_owned),
        has_local_task: true,
    }
}

fn hook_snapshot(
    active_hook_count: usize,
    disabled_hook_count: usize,
    runtime_receipt_count: usize,
    approval_receipt_count: usize,
) -> SessionHookSnapshot {
    let mut hooks = Vec::new();
    for index in 0..active_hook_count {
        hooks.push(SessionHookRecord {
            hook_id: format!("active-hook-{index}"),
            entry_id: None,
            label: format!("Active hook {index}"),
            owner_label: "Owner".to_string(),
            source_label: "Source".to_string(),
            source_kind: "extension".to_string(),
            source_uri: None,
            contribution_path: None,
            trigger_label: "Trigger".to_string(),
            enabled: true,
            status_label: "Enabled".to_string(),
            trust_posture: "contained_local".to_string(),
            governed_profile: "automation_bridge".to_string(),
            authority_tier_label: "Automation bridge".to_string(),
            availability_label: "Ready".to_string(),
            session_scope_label: "Matches current workspace".to_string(),
            why_active: "Test hook".to_string(),
        });
    }
    for index in 0..disabled_hook_count {
        hooks.push(SessionHookRecord {
            hook_id: format!("disabled-hook-{index}"),
            entry_id: None,
            label: format!("Disabled hook {index}"),
            owner_label: "Owner".to_string(),
            source_label: "Source".to_string(),
            source_kind: "extension".to_string(),
            source_uri: None,
            contribution_path: None,
            trigger_label: "Trigger".to_string(),
            enabled: false,
            status_label: "Disabled".to_string(),
            trust_posture: "contained_local".to_string(),
            governed_profile: "automation_bridge".to_string(),
            authority_tier_label: "Automation bridge".to_string(),
            availability_label: "Disabled".to_string(),
            session_scope_label: "Matches current workspace".to_string(),
            why_active: "Test hook".to_string(),
        });
    }
    SessionHookSnapshot {
        generated_at_ms: 0,
        session_id: Some("session-a".to_string()),
        workspace_root: Some("/tmp/a".to_string()),
        active_hook_count,
        disabled_hook_count,
        runtime_receipt_count,
        approval_receipt_count,
        hooks,
        recent_receipts: Vec::new(),
    }
}

fn remembered_approvals(
    active_decision_count: usize,
    recent_receipt_count: usize,
) -> crate::kernel::connectors::ShieldRememberedApprovalSnapshot {
    crate::kernel::connectors::ShieldRememberedApprovalSnapshot {
        generated_at_ms: 0,
        active_decision_count,
        recent_receipt_count,
        decisions: Vec::new(),
        recent_receipts: Vec::new(),
    }
}

fn sample_playbook() -> LocalEngineAgentPlaybookRecord {
    LocalEngineAgentPlaybookRecord {
        playbook_id: "evidence_audited_patch".to_string(),
        label: "Evidence-Audited Patch".to_string(),
        summary: "Patch flow".to_string(),
        goal_template: "Close {topic}".to_string(),
        route_family: "coding".to_string(),
        topology: "planner_specialist_verifier".to_string(),
        trigger_intents: vec!["workspace.ops".to_string()],
        recommended_for: vec!["Patch work".to_string()],
        default_budget: 196,
        completion_contract: LocalEngineWorkerCompletionContract {
            success_criteria: "Return a verified patch summary.".to_string(),
            expected_output: "Patch handoff".to_string(),
            merge_mode: "append summary".to_string(),
            verification_hint: None,
        },
        steps: vec![
            LocalEngineAgentPlaybookStepRecord {
                step_id: "context".to_string(),
                label: "Capture repo context".to_string(),
                summary: "Gather repo context.".to_string(),
                worker_template_id: "context_worker".to_string(),
                worker_workflow_id: "repo_context_brief".to_string(),
                goal_template: "Gather context".to_string(),
                depends_on: Vec::new(),
            },
            LocalEngineAgentPlaybookStepRecord {
                step_id: "implement".to_string(),
                label: "Patch the workspace".to_string(),
                summary: "Apply the patch.".to_string(),
                worker_template_id: "coder".to_string(),
                worker_workflow_id: "patch_build_verify".to_string(),
                goal_template: "Patch the repo".to_string(),
                depends_on: vec!["context".to_string()],
            },
            LocalEngineAgentPlaybookStepRecord {
                step_id: "verify".to_string(),
                label: "Verify targeted tests".to_string(),
                summary: "Run targeted verification.".to_string(),
                worker_template_id: "verifier".to_string(),
                worker_workflow_id: "targeted_test_audit".to_string(),
                goal_template: "Verify the patch".to_string(),
                depends_on: vec!["implement".to_string()],
            },
        ],
    }
}

fn sample_run() -> LocalEngineParentPlaybookRunRecord {
    LocalEngineParentPlaybookRunRecord {
        run_id: "run-1".to_string(),
        parent_session_id: "session-a".to_string(),
        playbook_id: "evidence_audited_patch".to_string(),
        playbook_label: "Evidence-Audited Patch".to_string(),
        status: "running".to_string(),
        latest_phase: "step_spawned".to_string(),
        summary: "Delegated patch flow is in flight.".to_string(),
        current_step_id: Some("implement".to_string()),
        current_step_label: Some("Patch the workspace".to_string()),
        active_child_session_id: Some("worker-2".to_string()),
        started_at_ms: 1,
        updated_at_ms: 2,
        completed_at_ms: None,
        error_class: None,
        steps: vec![
            LocalEngineParentPlaybookStepRunRecord {
                step_id: "context".to_string(),
                label: "Capture repo context".to_string(),
                summary: "Context brief captured.".to_string(),
                status: "completed".to_string(),
                child_session_id: Some("worker-1".to_string()),
                template_id: Some("context_worker".to_string()),
                workflow_id: Some("repo_context_brief".to_string()),
                updated_at_ms: Some(1),
                completed_at_ms: Some(1),
                error_class: None,
                receipts: vec![LocalEngineParentPlaybookReceiptRecord {
                    event_id: "event-1".to_string(),
                    timestamp_ms: 1,
                    phase: "step_completed".to_string(),
                    status: "completed".to_string(),
                    success: true,
                    summary: "Context brief captured.".to_string(),
                    receipt_ref: Some("receipt-1".to_string()),
                    child_session_id: Some("worker-1".to_string()),
                    template_id: Some("context_worker".to_string()),
                    workflow_id: Some("repo_context_brief".to_string()),
                    error_class: None,
                    artifact_ids: vec!["artifact-1".to_string()],
                }],
            },
            LocalEngineParentPlaybookStepRunRecord {
                step_id: "implement".to_string(),
                label: "Patch the workspace".to_string(),
                summary: "Patch worker is still running.".to_string(),
                status: "running".to_string(),
                child_session_id: Some("worker-2".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                updated_at_ms: Some(2),
                completed_at_ms: None,
                error_class: None,
                receipts: Vec::new(),
            },
            LocalEngineParentPlaybookStepRunRecord {
                step_id: "verify".to_string(),
                label: "Verify targeted tests".to_string(),
                summary: "Verification is still pending.".to_string(),
                status: "pending".to_string(),
                child_session_id: None,
                template_id: Some("verifier".to_string()),
                workflow_id: Some("targeted_test_audit".to_string()),
                updated_at_ms: None,
                completed_at_ms: None,
                error_class: None,
                receipts: Vec::new(),
            },
        ],
    }
}

#[test]
fn latest_attachable_target_prefers_first_target_with_workspace_root() {
    let targets = vec![
        target("session-a", None),
        target("session-b", Some("/tmp/repo")),
    ];
    let selected = select_attachable_target(&targets, Some("latest")).expect("attach target");
    assert_eq!(selected.session_id, "session-b");
}

#[test]
fn explicit_target_selection_returns_exact_session() {
    let targets = vec![
        target("session-a", Some("/tmp/a")),
        target("session-b", Some("/tmp/b")),
    ];
    let selected = select_target(&targets, Some("session-b")).expect("selected target");
    assert_eq!(selected.session_id, "session-b");
}

#[test]
fn explicit_attach_requires_workspace_root() {
    let targets = vec![target("session-a", None)];
    let error = select_attachable_target(&targets, Some("session-a")).expect_err("missing root");
    assert!(error.contains("workspace root"));
}

#[test]
fn compaction_flags_parse_into_policy() {
    let policy = compaction_policy_from_flags(&[
        "--pinned-only".to_string(),
        "--drop-background".to_string(),
        "--aggressive-pruning".to_string(),
    ])
    .expect("policy parse")
    .expect("changed policy");

    assert!(policy.carry_pinned_only);
    assert!(!policy.preserve_background_tasks);
    assert!(policy.aggressive_transcript_pruning);
    assert!(policy.preserve_checklist_state);
}

#[test]
fn selector_and_policy_parser_supports_selector_plus_flags() {
    let targets = vec![
        target("session-a", Some("/tmp/a")),
        target("session-b", Some("/tmp/b")),
    ];
    let (selector, policy) = selector_and_compaction_policy(
        vec![
            "session-b".to_string(),
            "--drop-output".to_string(),
            "--drop-blockers".to_string(),
        ],
        &targets,
    )
    .expect("selector and policy");

    let policy = policy.expect("changed policy");
    assert_eq!(selector.as_deref(), Some("session-b"));
    assert!(!policy.preserve_latest_output_excerpt);
    assert!(!policy.preserve_governance_blockers);
}

#[test]
fn authority_profile_resolution_matches_guided_default() {
    let profile_id =
        resolve_authority_profile_id(&crate::kernel::connectors::ShieldPolicyState::default());
    assert_eq!(profile_id.as_deref(), Some("guided_default"));
}

#[test]
fn authority_profile_apply_replaces_global_defaults() {
    let updated = apply_authority_profile(
        crate::kernel::connectors::ShieldPolicyState::default(),
        "safer_review",
    )
    .expect("profile apply");

    assert_eq!(
        resolve_authority_profile_id(&updated).as_deref(),
        Some("safer_review")
    );
}

#[test]
fn authority_override_apply_sets_connector_specific_profile() {
    let updated = apply_authority_override(
        crate::kernel::connectors::ShieldPolicyState::default(),
        "gmail",
        "autonomous",
    )
    .expect("override apply");

    let override_state = updated.overrides.get("gmail").expect("gmail override");
    assert!(!override_state.inherit_global);
    assert_eq!(override_state.reads, PolicyDecisionMode::Auto);
    assert_eq!(override_state.writes, PolicyDecisionMode::Auto);
    assert_eq!(
        override_state.data_handling,
        DataHandlingMode::LocalRedacted
    );
}

#[test]
fn authority_override_apply_can_reset_to_inherit() {
    let seeded = apply_authority_override(
        crate::kernel::connectors::ShieldPolicyState::default(),
        "gmail",
        "safer_review",
    )
    .expect("seeded override");
    let updated = apply_authority_override(seeded, "gmail", "inherit").expect("reset override");

    assert!(!updated.overrides.contains_key("gmail"));
}

#[test]
fn authority_recommendation_tightens_when_approval_receipts_exist() {
    let plan = build_repl_authority_recommendation(
        Some("guided_default"),
        &hook_snapshot(1, 0, 0, 1),
        &remembered_approvals(1, 1),
        0,
    );

    assert_eq!(plan.recommended_profile_id.as_deref(), Some("safer_review"));
    assert_eq!(plan.action_kind, "apply_profile");
}

#[test]
fn authority_recommendation_widens_back_to_guided_default_when_safe() {
    let mut snapshot = hook_snapshot(1, 0, 2, 0);
    snapshot.hooks.push(SessionHookRecord {
        hook_id: "hook-1".to_string(),
        entry_id: None,
        label: "Hook".to_string(),
        owner_label: "Owner".to_string(),
        source_label: "Source".to_string(),
        source_kind: "extension".to_string(),
        source_uri: None,
        contribution_path: None,
        trigger_label: "Trigger".to_string(),
        enabled: true,
        status_label: "Enabled".to_string(),
        trust_posture: "contained_local".to_string(),
        governed_profile: "automation_bridge".to_string(),
        authority_tier_label: "Automation bridge".to_string(),
        availability_label: "Ready".to_string(),
        session_scope_label: "Matches current workspace".to_string(),
        why_active: "Test hook".to_string(),
    });
    snapshot.recent_receipts.push(SessionHookReceiptSummary {
        title: "Hook".to_string(),
        timestamp_ms: 0,
        tool_name: "hook_worker".to_string(),
        status: "success".to_string(),
        summary: "Worker hook ran".to_string(),
    });

    let plan = build_repl_authority_recommendation(
        Some("safer_review"),
        &snapshot,
        &remembered_approvals(1, 1),
        0,
    );

    assert_eq!(
        plan.recommended_profile_id.as_deref(),
        Some("guided_default")
    );
    assert_eq!(plan.action_kind, "apply_profile");
}

#[test]
fn delegated_run_view_marks_dependency_satisfied_pending_step_as_startable() {
    let playbook = sample_playbook();
    let playbooks = BTreeMap::from([(playbook.playbook_id.clone(), playbook)]);
    let mut run = sample_run();
    run.steps[1].status = "completed".to_string();
    run.steps[1]
        .receipts
        .push(LocalEngineParentPlaybookReceiptRecord {
            event_id: "event-2".to_string(),
            timestamp_ms: 2,
            phase: "step_completed".to_string(),
            status: "completed".to_string(),
            success: true,
            summary: "Patch landed.".to_string(),
            receipt_ref: Some("receipt-2".to_string()),
            child_session_id: Some("worker-2".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            error_class: None,
            artifact_ids: Vec::new(),
        });
    run.current_step_id = Some("verify".to_string());
    run.current_step_label = Some("Verify targeted tests".to_string());

    let (summary, runs) = build_repl_delegated_runs(&[run], &playbooks);
    let verify_step = runs[0]
        .steps
        .iter()
        .find(|step| step.step_id == "verify")
        .expect("verify step");

    assert_eq!(summary.status_label, "Delegated work is ready to advance");
    assert!(verify_step.can_start);
    assert_eq!(verify_step.dependency_status, "Ready now");
}

#[test]
fn delegated_run_summary_prioritizes_blocked_steps() {
    let playbook = sample_playbook();
    let playbooks = BTreeMap::from([(playbook.playbook_id.clone(), playbook)]);
    let mut run = sample_run();
    run.status = "blocked".to_string();
    run.steps[1].status = "blocked".to_string();
    run.steps[1].error_class = Some("approval_required".to_string());

    let (summary, runs) = build_repl_delegated_runs(&[run], &playbooks);

    assert_eq!(summary.status_label, "Delegated work needs review");
    assert_eq!(summary.blocked_step_count, 1);
    assert!(summary.detail.contains("Patch the workspace"));
    assert_eq!(runs[0].blocked_step_count, 1);
}
