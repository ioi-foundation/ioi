use super::{
    duplicate_skip_execution_label, has_prior_successful_duplicate_action,
    is_active_web_pipeline_chat_reply_duplicate, is_duplicate_non_command_noop_allowed,
    is_mail_read_latest_tool, is_mail_reply_tool, is_non_command_duplicate_noop_tool,
    is_read_only_filesystem_tool, maybe_terminalize_duplicate_worker_noop,
    queue_browser_snapshot_verification, synthesize_repo_context_brief_from_duplicate,
    worker_duplicate_noop_summary, worker_duplicate_refresh_read_allowed,
    worker_duplicate_requires_recovery_error, workspace_duplicate_noop_summary,
};
use crate::agentic::runtime::service::lifecycle::persist_worker_assignment;
use crate::agentic::runtime::service::step::action::{
    mark_action_fingerprint_executed_at_step, record_execution_evidence_with_value,
};
use crate::agentic::runtime::service::step::helpers::default_safe_policy;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, PendingSearchCompletion,
    WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
use ioi_types::app::ActionTarget;
use std::collections::BTreeMap;
use tempfile::tempdir;

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

#[test]
fn read_only_filesystem_tools_are_noop_safe() {
    assert!(is_read_only_filesystem_tool("file__list"));
    assert!(is_read_only_filesystem_tool("file__read"));
    assert!(is_read_only_filesystem_tool("file__info"));
    assert!(is_read_only_filesystem_tool("file__search"));
    assert!(!is_read_only_filesystem_tool("file__move"));
}

#[test]
fn noop_allowlist_includes_read_only_filesystem_tools() {
    assert!(is_non_command_duplicate_noop_tool("file__list"));
    assert!(is_non_command_duplicate_noop_tool("mail__read_latest"));
    assert!(is_non_command_duplicate_noop_tool("mail__reply"));
    assert!(!is_non_command_duplicate_noop_tool("file__create_dir"));
}

#[test]
fn active_web_pipeline_chat_reply_duplicates_are_noop_safe() {
    let mut agent_state = test_agent_state();
    agent_state.pending_search_completion = Some(PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: None,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    });

    assert!(is_active_web_pipeline_chat_reply_duplicate(
        "chat__reply",
        &agent_state
    ));
    assert!(!is_active_web_pipeline_chat_reply_duplicate(
        "file__read",
        &agent_state
    ));
}

#[test]
fn workspace_package_read_duplicate_summary_requires_chat_reply() {
    let mut agent_state = test_agent_state();
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: "workspace.lookup".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    });

    let summary = workspace_duplicate_noop_summary(
        &agent_state,
        &AgentTool::FsRead {
            path: "./package.json".to_string(),
        },
        "Skipped immediate replay of 'file__read'.".to_string(),
    );

    assert!(summary.contains("chat__reply"));
    assert!(summary.contains("package.json"));
}

#[test]
fn mail_tool_duplicate_helpers_match_expected_tools() {
    assert!(is_mail_read_latest_tool("wallet_network__mail_read_latest"));
    assert!(is_mail_reply_tool("wallet_network__mail_reply"));
    assert!(is_mail_reply_tool("mail__reply"));
    assert!(is_mail_reply_tool("connector__google__gmail_send_email"));
    assert!(is_mail_reply_tool("connector__google__gmail_draft_email"));
    assert!(!is_mail_reply_tool("wallet_network__mail_read_latest"));
}

#[test]
fn prior_successful_duplicate_action_is_detected() {
    let mut agent_state = test_agent_state();
    mark_action_fingerprint_executed_at_step(
        &mut agent_state.tool_execution_log,
        "fp",
        3,
        "success",
    );
    mark_action_fingerprint_executed_at_step(
        &mut agent_state.tool_execution_log,
        "fp-noop",
        4,
        "success_duplicate_skip",
    );

    assert!(has_prior_successful_duplicate_action(&agent_state, "fp"));
    assert!(has_prior_successful_duplicate_action(
        &agent_state,
        "fp-noop"
    ));
    assert!(!has_prior_successful_duplicate_action(
        &agent_state,
        "missing"
    ));
}

#[test]
fn browser_snapshot_verification_is_queued_once() {
    let mut agent_state = test_agent_state();

    assert!(queue_browser_snapshot_verification(
        &mut agent_state,
        [7u8; 32]
    ));
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert_eq!(
        agent_state.execution_queue[0].target,
        ActionTarget::BrowserInspect
    );
    assert!(!queue_browser_snapshot_verification(
        &mut agent_state,
        [7u8; 32]
    ));
    assert_eq!(agent_state.execution_queue.len(), 1);
}

#[test]
fn browser_snapshot_duplicate_is_not_noop_safe_after_prior_success() {
    assert!(!is_duplicate_non_command_noop_allowed(
        "browser__inspect",
        true,
        false
    ));
    assert_eq!(
        duplicate_skip_execution_label(true, false),
        "duplicate_skip"
    );
}

#[test]
fn synthesized_repo_context_brief_uses_goal_files_and_targeted_command() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    let tests_dir = repo_root.join("tests");
    std::fs::create_dir_all(&tests_dir).expect("tests dir should exist");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path():\n    pass\n",
    )
    .expect("source file should exist");
    std::fs::write(
        tests_dir.join("test_path_utils.py"),
        "def test_normalize_fixture_path():\n    pass\n",
    )
    .expect("test file should exist");

    let goal = format!(
        "Inspect repo context for the patch in \"{}\". Patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and run `python3 -m unittest tests.test_path_utils -v` first.",
        repo_root.display()
    );
    let tool = AgentTool::FsStat {
        path: repo_root.to_string_lossy().to_string(),
    };

    let summary = synthesize_repo_context_brief_from_duplicate(&goal, &tool)
        .expect("repo context brief should synthesize");
    assert!(summary.contains("path_utils.py"));
    assert!(summary.contains("tests/test_path_utils.py"));
    assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
}

#[test]
fn duplicate_repo_context_worker_noop_terminalizes_with_fallback_brief() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    let tests_dir = repo_root.join("tests");
    std::fs::create_dir_all(&tests_dir).expect("tests dir should exist");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path():\n    pass\n",
    )
    .expect("source file should exist");
    std::fs::write(
        tests_dir.join("test_path_utils.py"),
        "def test_normalize_fixture_path():\n    pass\n",
    )
    .expect("test file should exist");

    let session_id = [7u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:repo".to_string(),
        budget: 24,
        goal: format!(
            "Inspect repo context for the patch in \"{}\". Patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and run `python3 -m unittest tests.test_path_utils -v` first.",
            repo_root.display()
        ),
        success_criteria: "Return a deterministic repo context brief.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("context_worker".to_string()),
        workflow_id: Some("repo_context_brief".to_string()),
        role: Some("Context Worker".to_string()),
        allowed_tools: vec![
            "file__info".to_string(),
            "file__search".to_string(),
            "file__read".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a deterministic repo context brief.".to_string(),
            expected_output: "Repo context brief.".to_string(),
            merge_mode: WorkerMergeMode::AppendAsEvidence,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.parent_session_id = Some([9u8; 32]);
    let mut verification_checks = Vec::new();
    let tool = AgentTool::FsStat {
        path: repo_root.to_string_lossy().to_string(),
    };

    let completion = maybe_terminalize_duplicate_worker_noop(
        &state,
        &mut agent_state,
        &default_safe_policy(),
        &tool,
        session_id,
        &mut verification_checks,
    )
    .expect("duplicate repo-context noop should terminalize");

    assert!(matches!(agent_state.status, AgentStatus::Completed(_)));
    assert!(completion.contains("path_utils.py"));
    assert!(completion.contains("tests/test_path_utils.py"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "duplicate_repo_context_worker_terminalized=true"));
}

#[test]
fn patch_build_verify_duplicate_read_guidance_runs_focused_verifier_before_patch() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [8u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` first.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let summary = worker_duplicate_noop_summary(
        &state,
        &test_agent_state(),
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        },
        "fallback".to_string(),
    );

    assert!(summary.contains("path_utils.py"));
    assert!(summary.contains("before patching"));
    assert!(summary.contains("shell__start"));
    assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
    assert!(summary.contains("file__edit"));
    assert!(summary.contains("file__edit"));
    assert!(summary.contains("file__replace_line"));
}

#[test]
fn patch_build_verify_duplicate_read_requires_recovery_error() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [9u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    assert!(worker_duplicate_requires_recovery_error(
        &state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
    assert!(worker_duplicate_requires_recovery_error(
        &state,
        session_id,
        &AgentTool::FsList {
            path: repo_root.to_string_lossy().to_string(),
        }
    ));
    assert!(!worker_duplicate_requires_recovery_error(
        &state,
        session_id,
        &AgentTool::FsPatch {
            path: source_path.to_string_lossy().to_string(),
            search: "before".to_string(),
            replace: "after".to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_stays_blocked_before_command_history() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [11u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec![
        "attempt::NoEffectAfterAction::first".to_string(),
        "attempt::UnexpectedState::second".to_string(),
    ];

    assert!(!worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_is_allowed_after_command_history_unexpected_state() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [12u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec![
        "attempt::NoEffectAfterAction::first".to_string(),
        "attempt::UnexpectedState::second".to_string(),
    ];
    agent_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 1,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1,
        step_index: 0,
    });

    assert!(worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_is_allowed_after_workspace_edit_receipt() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [0x6d; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\", patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and rerun `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display(),
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_edit_applied",
        format!("step=7;tool=file__write;path={}", source_path.display()),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        format!("step=3;tool=file__read;path={}", source_path.display()),
    );

    assert!(worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_is_allowed_after_patch_miss_receipt() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [0x70; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display(),
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
        format!(
            "step=7;tool=file__edit;path={};reason=search_block_not_found",
            source_path.display()
        ),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        format!("step=3;tool=file__read;path={}", source_path.display()),
    );

    assert!(worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_stays_blocked_after_post_edit_refresh_read() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [0x6e; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display(),
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_edit_applied",
        format!("step=7;tool=file__write;path={}", source_path.display()),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        format!("step=8;tool=file__read;path={}", source_path.display()),
    );

    assert!(!worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_refresh_read_stays_blocked_when_post_edit_verifier_rerun_is_due() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [0x72; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
            repo_root.display(),
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec!["attempt::UnexpectedState::first".to_string()];
    agent_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 1,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1,
        step_index: 4,
    });
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_edit_applied",
        format!("step=7;tool=file__write;path={}", source_path.display()),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        format!("step=3;tool=file__read;path={}", source_path.display()),
    );

    assert!(!worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));

    let summary = worker_duplicate_noop_summary(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        },
        "fallback".to_string(),
    );
    assert!(summary.contains("The edit already landed after a failing focused verification run."));
    assert!(summary.contains("shell__start"));
    assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
}

#[test]
fn patch_build_verify_refresh_read_stays_blocked_after_patch_miss_refresh_read() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    let source_path = repo_root.join("path_utils.py");
    std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
        .expect("source file should exist");

    let session_id = [0x71; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and rerun the focused verification command after the edit.",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let mut agent_state = test_agent_state();
    agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
        format!(
            "step=7;tool=file__edit;path={};reason=search_block_not_found",
            source_path.display()
        ),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "workspace_read_observed",
        format!("step=8;tool=file__read;path={}", source_path.display()),
    );

    assert!(!worker_duplicate_refresh_read_allowed(
        &state,
        &agent_state,
        session_id,
        &AgentTool::FsRead {
            path: source_path.to_string_lossy().to_string(),
        }
    ));
}

#[test]
fn patch_build_verify_duplicate_root_probe_guidance_points_to_direct_file_read() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(&repo_root).expect("repo root should exist");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path():\n    pass\n",
    )
    .expect("source file should exist");

    let session_id = [10u8; 32];
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let assignment = WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: format!(
            "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py",
            repo_root.display()
        ),
        success_criteria: "Return a bounded implementation handoff.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some(session_id),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__list".to_string(),
            "file__edit".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: WorkerCompletionContract {
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            expected_output: "Patch/build/test handoff.".to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        },
    };
    persist_worker_assignment(&mut state, session_id, &assignment)
        .expect("worker assignment should persist");

    let summary = worker_duplicate_noop_summary(
        &state,
        &test_agent_state(),
        session_id,
        &AgentTool::FsList {
            path: repo_root.to_string_lossy().to_string(),
        },
        "fallback".to_string(),
    );

    assert!(summary.contains("repo-root probe"));
    assert!(summary.contains("path_utils.py"));
    assert!(summary.contains("file__read"));
    assert!(summary.contains("shell__start"));
    assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
}
