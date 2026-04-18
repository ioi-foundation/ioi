use super::bootstrap::{
    delegated_child_preset_resolved_intent, delegated_research_bootstrap_query,
    delegated_research_query_contract, seed_delegated_child_execution_queue,
};
use super::goal::{
    enrich_delegated_child_goal_with_prep, enrich_patch_build_verify_goal_with_parent_context,
    infer_delegated_child_working_directory, resolve_worker_name, resolve_worker_role,
};
use super::prep::{delegated_prep_mode, DelegatedChildPrepBundle, DelegatedPrepMode};
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, WorkerAssignment,
};
use crate::agentic::runtime::worker_context::PARENT_PLAYBOOK_CONTEXT_MARKER;
use ioi_types::app::agentic::{CapabilityId, InstructionSideEffectMode, IntentScopeProfile};
use ioi_types::app::ActionTarget;
use tempfile::tempdir;

fn test_agent_state(goal: &str) -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: goal.to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 90,
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
        tool_execution_log: Default::default(),
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

fn research_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:0:abcd".to_string(),
        budget: 90,
        goal: goal.to_string(),
        success_criteria: "Return a cited research brief.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some([1u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("citation_grounded_brief".to_string()),
        template_id: Some("researcher".to_string()),
        workflow_id: Some("live_research_brief".to_string()),
        role: Some("Research Worker".to_string()),
        allowed_tools: vec![
            "web__search".to_string(),
            "web__read".to_string(),
            "agent__complete".to_string(),
            "agent__await".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn citation_audit_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:1:beef".to_string(),
        budget: 48,
        goal: goal.to_string(),
        success_criteria: "Return a verifier scorecard.".to_string(),
        max_retries: 0,
        retries_used: 0,
        assigned_session_id: Some([2u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("citation_grounded_brief".to_string()),
        template_id: Some("verifier".to_string()),
        workflow_id: Some("citation_audit".to_string()),
        role: Some("Verification Worker".to_string()),
        allowed_tools: vec![
            "memory__read".to_string(),
            "agent__complete".to_string(),
            "agent__await".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn patch_build_verify_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:2:cafe".to_string(),
        budget: 96,
        goal: goal.to_string(),
        success_criteria:
            "Return a deterministic implementation handoff with verification results.".to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some([3u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coder".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__list".to_string(),
            "file__search".to_string(),
            "file__edit".to_string(),
            "file__replace_line".to_string(),
            "file__write".to_string(),
            "shell__cd".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn targeted_test_audit_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:3:feed".to_string(),
        budget: 56,
        goal: goal.to_string(),
        success_criteria: "Return a deterministic coding verifier scorecard.".to_string(),
        max_retries: 0,
        retries_used: 0,
        assigned_session_id: Some([4u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("verifier".to_string()),
        workflow_id: Some("targeted_test_audit".to_string()),
        role: Some("Verification Worker".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__list".to_string(),
            "file__search".to_string(),
            "memory__read".to_string(),
            "memory__search".to_string(),
            "shell__cd".to_string(),
            "shell__start".to_string(),
            "agent__complete".to_string(),
            "agent__await".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn patch_synthesis_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:4:fade".to_string(),
        budget: 40,
        goal: goal.to_string(),
        success_criteria:
            "Return a deterministic patch synthesis summary with touched files and residual risk."
                .to_string(),
        max_retries: 0,
        retries_used: 0,
        assigned_session_id: Some([5u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("patch_synthesizer".to_string()),
        workflow_id: Some("patch_synthesis_handoff".to_string()),
        role: Some("Patch Synthesizer".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__list".to_string(),
            "file__search".to_string(),
            "memory__read".to_string(),
            "memory__search".to_string(),
            "agent__complete".to_string(),
            "agent__await".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn browser_postcondition_pass_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:5:babe".to_string(),
        budget: 72,
        goal: goal.to_string(),
        success_criteria:
            "Return a deterministic browser execution handoff with the observed postcondition."
                .to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some([6u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("browser_postcondition_gate".to_string()),
        template_id: Some("browser_operator".to_string()),
        workflow_id: Some("browser_postcondition_pass".to_string()),
        role: Some("Browser Operator".to_string()),
        allowed_tools: vec![
            "browser__navigate".to_string(),
            "browser__inspect".to_string(),
            "browser__click".to_string(),
            "browser__click_at".to_string(),
            "browser__type".to_string(),
            "browser__wait".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

fn artifact_generate_repair_assignment(goal: &str) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:6:face".to_string(),
        budget: 108,
        goal: goal.to_string(),
        success_criteria:
            "Return a deterministic artifact handoff with produced files and presentation status."
                .to_string(),
        max_retries: 1,
        retries_used: 0,
        assigned_session_id: Some([7u8; 32]),
        status: "running".to_string(),
        playbook_id: Some("artifact_generation_gate".to_string()),
        template_id: Some("artifact_builder".to_string()),
        workflow_id: Some("artifact_generate_repair".to_string()),
        role: Some("Artifact Builder".to_string()),
        allowed_tools: vec![
            "file__read".to_string(),
            "file__list".to_string(),
            "file__search".to_string(),
            "file__edit".to_string(),
            "file__write".to_string(),
            "shell__cd".to_string(),
            "shell__start".to_string(),
            "model__responses".to_string(),
            "agent__complete".to_string(),
        ],
        completion_contract: Default::default(),
    }
}

#[test]
fn researcher_template_defaults_to_research_worker_role() {
    assert_eq!(
        resolve_worker_role(Some("researcher"), None),
        "Research Worker"
    );
    assert_eq!(
        resolve_worker_role(Some("researcher"), Some("")),
        "Research Worker"
    );
    assert_eq!(
        resolve_worker_role(Some("researcher"), Some("Source Analyst")),
        "Source Analyst"
    );
}

#[test]
fn worker_name_uses_role_prefix_when_available() {
    let child_session_id = [0xabu8; 32];
    let name = resolve_worker_name("Research Worker", &child_session_id);
    assert!(name.starts_with("Research-Worker-"));
}

#[test]
fn delegated_child_working_directory_prefers_explicit_repo_path_from_goal() {
    let temp = tempdir().expect("tempdir should exist");
    let repo_root = temp.path().join("fixture-repo");
    std::fs::create_dir_all(&repo_root).expect("fixture repo should exist");

    let goal = format!(
        "Inspect repo context for the coding task in \"{}\" and keep `tests/test_path_utils.py` unchanged.",
        repo_root.display()
    );

    let inferred = infer_delegated_child_working_directory(".", &goal);
    assert_eq!(inferred, repo_root.to_string_lossy());
}

#[test]
fn delegated_child_working_directory_falls_back_to_parent_directory() {
    let inferred = infer_delegated_child_working_directory(
        "/tmp/parent-workspace",
        "Research the current blockers and summarize them.",
    );

    assert_eq!(inferred, "/tmp/parent-workspace");
}

#[test]
fn delegated_research_bootstrap_query_strips_worker_template_suffixes() {
    let query = delegated_research_bootstrap_query(
        "Research the latest NIST post-quantum cryptography standards using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.",
    )
    .expect("query should be derived");

    assert_eq!(query, "the latest NIST post-quantum cryptography standards");
}

#[test]
fn delegated_research_bootstrap_query_ignores_parent_context_and_briefing_clause() {
    let query = delegated_research_bootstrap_query(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- prep_summary: Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
    )
    .expect("query should be derived");

    assert_eq!(query, "the latest NIST post-quantum cryptography standards");
}

#[test]
fn delegated_research_query_contract_ignores_parent_context() {
    let contract = delegated_research_query_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- prep_summary: Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
    )
    .expect("contract should be derived");

    assert_eq!(
        contract,
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks."
    );
}

#[test]
fn live_research_worker_starts_with_seeded_web_search() {
    let goal = "Research the latest NIST post-quantum cryptography standards using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let mut child_state = test_agent_state(goal);
    let assignment = research_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [1u8; 32], &assignment)
        .expect("seed should succeed");

    assert_eq!(child_state.execution_queue.len(), 1);
    assert_eq!(
        child_state.execution_queue[0].target,
        ActionTarget::WebRetrieve
    );
    let args: serde_json::Value = serde_json::from_slice(&child_state.execution_queue[0].params)
        .expect("seeded search params should decode");
    assert_eq!(
        args.get("query").and_then(|value| value.as_str()),
        Some("the latest NIST post-quantum cryptography standards")
    );
    assert_eq!(
        args.get("query_contract").and_then(|value| value.as_str()),
        Some(goal)
    );
}

#[test]
fn live_research_worker_seeded_search_ignores_parent_context() {
    let goal = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- prep_summary: Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let mut child_state = test_agent_state(goal);
    let assignment = research_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [1u8; 32], &assignment)
        .expect("seed should succeed");

    assert_eq!(child_state.execution_queue.len(), 1);
    let args: serde_json::Value = serde_json::from_slice(&child_state.execution_queue[0].params)
        .expect("seeded search params should decode");
    assert_eq!(
        args.get("query").and_then(|value| value.as_str()),
        Some("the latest NIST post-quantum cryptography standards")
    );
    assert_eq!(
        args.get("query_contract").and_then(|value| value.as_str()),
        Some(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks."
        )
    );
}

#[test]
fn citation_audit_worker_does_not_seed_memory_search() {
    let goal = "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources, then return a citation verifier scorecard with blockers and next checks.";
    let mut child_state = test_agent_state(goal);
    let assignment = citation_audit_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [2u8; 32], &assignment)
        .expect("seed should succeed");

    assert!(child_state.execution_queue.is_empty());
}

#[test]
fn citation_audit_worker_completes_immediately_when_handoff_is_auditable() {
    let goal = "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and sufficiently independent, then return a citation verifier scorecard with blockers and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- Gather current sources full_handoff (research_full): Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-04-01T05:16:29Z UTC)\n\nWhat happened:\n- NIST's NCCoE draft migration practice guide remains a current public authority source for PQC migration activity.\n\nKey evidence:\n- NCCoE published the draft migration practice guide and IBM summarized the NIST cybersecurity framework updates.\n\nCitations:\n- Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards | https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf | 2026-04-01T05:16:29Z | retrieved_utc\n- IBM NIST cybersecurity framework summary | https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2 | 2026-04-01T05:16:29Z | retrieved_utc\n\nRun date (UTC): 2026-04-01\nRun timestamp (UTC): 2026-04-01T05:16:29Z\nOverall confidence: medium";
    let mut child_state = test_agent_state(goal);
    let assignment = citation_audit_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [2u8; 32], &assignment)
        .expect("seed should succeed");

    assert!(child_state.execution_queue.is_empty());
    let result = match &child_state.status {
        AgentStatus::Completed(Some(result)) => result.as_str(),
        other => panic!("expected completed verifier bootstrap, got {:?}", other),
    };
    assert!(result.contains("- verdict: passed"));
    assert!(result.contains("- freshness_status: passed"));
    assert!(result.contains("- quote_grounding_status: passed"));
    assert!(result.contains("distinct_domains=2"));
    assert!(result.contains("https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"));
}

#[test]
fn citation_audit_worker_bootstraps_to_delegation_intent() {
    let assignment = citation_audit_assignment("Verify the cited brief.");

    let resolved =
        delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

    assert_eq!(resolved.intent_id, "delegation.task");
    assert_eq!(resolved.scope, IntentScopeProfile::Delegation);
    assert_eq!(
        resolved.required_capabilities,
        vec![CapabilityId::from("memory.access")]
    );
    let contract = resolved
        .instruction_contract
        .as_ref()
        .expect("verifier child contract should be seeded");
    assert_eq!(contract.operation, "verify");
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("citation_grounded_brief")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("verifier")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("citation_audit")
    );
}

#[test]
fn targeted_test_audit_worker_completes_immediately_when_handoff_is_auditable() {
    let goal = "Verify the coding result for Port the path-normalization parity fix by running targeted checks first, widen only if needed, and return a coding verifier scorecard with blockers and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- Implement patch (implement): Worker evidence\nTouched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.\nVerification: Parent checks the concrete diff, verifies the named build or test commands, and confirms the delegated implementation slice is actually closed.";
    let mut child_state = test_agent_state(goal);
    let assignment = targeted_test_audit_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [4u8; 32], &assignment)
        .expect("seed should succeed");

    assert!(child_state.execution_queue.is_empty());
    let result = match &child_state.status {
        AgentStatus::Completed(Some(result)) => result.as_str(),
        other => panic!("expected completed verifier bootstrap, got {:?}", other),
    };
    assert!(result.contains("- verdict: passed"));
    assert!(result.contains("- targeted_command_count: 1"));
    assert!(result.contains("- targeted_pass_count: 1"));
    assert!(result.contains("- widening_status: not_needed"));
    assert!(result.contains("- regression_status: clear"));
    assert!(result.contains("python3 -m unittest tests.test_path_utils -v (passed)"));
    assert!(!result.contains("Parent checks the concrete diff"));
}

#[test]
fn targeted_test_audit_worker_bootstraps_to_read_only_workspace_verifier_intent() {
    let assignment = targeted_test_audit_assignment(
        "Verify the coding result for the path normalizer by running targeted checks first.",
    );

    let resolved =
        delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

    assert_eq!(resolved.intent_id, "workspace.ops");
    assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("filesystem.read")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("command.exec")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("command.probe")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("memory.access")));
    let contract = resolved
        .instruction_contract
        .as_ref()
        .expect("verifier child contract should be seeded");
    assert_eq!(contract.operation, "verify");
    assert_eq!(
        contract.side_effect_mode,
        InstructionSideEffectMode::ReadOnly
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("evidence_audited_patch")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("verifier")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("targeted_test_audit")
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "shell__start",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "file__read",
        )
    );
    assert!(
        !crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "file__write",
        )
    );
}

#[test]
fn patch_synthesis_handoff_worker_bootstraps_to_read_only_workspace_synthesizer_intent() {
    let assignment = patch_synthesis_assignment(
        "Synthesize the verified patch for the path normalizer into a final handoff.",
    );

    let resolved =
        delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

    assert_eq!(resolved.intent_id, "workspace.ops");
    assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("filesystem.read")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("memory.access")));
    let contract = resolved
        .instruction_contract
        .as_ref()
        .expect("patch synthesizer contract should be seeded");
    assert_eq!(contract.operation, "synthesize");
    assert_eq!(
        contract.side_effect_mode,
        InstructionSideEffectMode::ReadOnly
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("evidence_audited_patch")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("patch_synthesizer")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("patch_synthesis_handoff")
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "file__read",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "memory__read",
        )
    );
    assert!(
        !crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "shell__start",
        )
    );
}

#[test]
fn live_research_worker_bootstraps_to_web_research_intent() {
    let assignment = research_assignment("Research the latest standards.");

    let resolved =
        delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("web.retrieve")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("memory.access")));
    let contract = resolved
        .instruction_contract
        .as_ref()
        .expect("research child contract should be seeded");
    assert_eq!(contract.operation, "web.research");
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("citation_grounded_brief")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("researcher")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("live_research_brief")
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "web__search",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "web__read",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "memory__search",
        )
    );
}

#[test]
fn patch_build_verify_worker_bootstraps_to_workspace_ops_with_exec_capabilities() {
    let assignment = patch_build_verify_assignment(
        "Patch the parser regression, run focused verification, and summarize the outcome.",
    );

    let resolved =
        delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

    assert_eq!(resolved.intent_id, "workspace.ops");
    assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("filesystem.read")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("filesystem.write")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("command.exec")));
    assert!(resolved
        .required_capabilities
        .contains(&CapabilityId::from("command.probe")));
    let contract = resolved
        .instruction_contract
        .as_ref()
        .expect("coding child contract should be seeded");
    assert_eq!(contract.operation, "workspace.ops");
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("evidence_audited_patch")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("coder")
    );
    assert_eq!(
        contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .and_then(|binding| binding.value.as_deref()),
        Some("patch_build_verify")
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "shell__start",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "file__edit",
        )
    );
    assert!(
        crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution(
            Some(&resolved),
            "file__write",
        )
    );
}

#[test]
fn patch_synthesis_handoff_worker_completes_immediately_when_verifier_context_is_auditable() {
    let goal = "Synthesize the verified patch for the path normalizer into a final handoff.\n\n[PARENT PLAYBOOK CONTEXT]\n- Patch the workspace (implement): Coding Worker handoff\nTouched files: path_utils.py; tests/test_path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.\n- Verify targeted tests (verify): Worker evidence\n- verdict: passed\n- targeted_command_count: 1\n- targeted_pass_count: 1\n- widening_status: not_needed\n- regression_status: clear\n- notes: Focused unittest verification passed without widening.";
    let mut child_state = test_agent_state(goal);
    let assignment = patch_synthesis_assignment(goal);

    seed_delegated_child_execution_queue(&mut child_state, [5u8; 32], &assignment)
        .expect("seed should succeed");

    assert!(child_state.execution_queue.is_empty());
    let result = match &child_state.status {
        AgentStatus::Completed(Some(result)) => result.as_str(),
        other => panic!("expected completed synth bootstrap, got {:?}", other),
    };
    assert!(result.contains("- status: ready"));
    assert!(result.contains("- touched_file_count: 2"));
    assert!(result.contains("- verification_ready: yes"));
    assert!(result.contains("Focused unittest verification passed without widening."));
    assert!(result.contains("Focused verification passed; broader checks were not rerun."));
}

#[test]
fn patch_build_verify_goal_enrichment_inherits_parent_contract_and_checks() {
    let parent_goal = concat!(
        "Port the path-normalization parity fix into the repo at \"/tmp/example\". Work inside that repo root, patch only `path_utils.py`, ",
        "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it converts backslashes to forward slashes, ",
        "collapses duplicate separators, and preserves a leading `./` or `/`. Run the focused verification command ",
        "`python3 -m unittest tests.test_path_utils -v` first, widen only if needed, verify the final postcondition, ",
        "and report the touched files plus command results."
    );
    let raw_goal =
        "Edit the code in the specified file to match the regex pattern for replacing text blocks.";

    let enriched = enrich_patch_build_verify_goal_with_parent_context(parent_goal, raw_goal);

    assert!(enriched.starts_with(raw_goal));
    assert!(enriched.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(enriched.contains("delegated_task_contract: Port the path-normalization parity fix"));
    assert!(enriched.contains("- likely_files: path_utils.py; tests/test_path_utils.py"));
    assert!(enriched.contains("- targeted_checks: python3 -m unittest tests.test_path_utils -v"));
    assert!(enriched.contains("converts backslashes to forward slashes"));
    assert!(enriched.contains("preserves a leading `./` or `/`"));
}

#[test]
fn delegated_worker_execution_and_context_prep_modes_cover_remaining_guided_lanes() {
    assert!(matches!(
        delegated_prep_mode(&patch_build_verify_assignment(
            "Patch the parser regression."
        )),
        Some(DelegatedPrepMode::Coding)
    ));
    assert!(matches!(
        delegated_prep_mode(&artifact_generate_repair_assignment(
            "Generate the launch page artifact."
        )),
        Some(DelegatedPrepMode::Artifact)
    ));
    assert!(matches!(
        delegated_prep_mode(&browser_postcondition_pass_assignment(
            "Click the confirmation button."
        )),
        Some(DelegatedPrepMode::ComputerUse)
    ));
    assert!(delegated_prep_mode(&targeted_test_audit_assignment(
        "Verify the coding result with targeted checks."
    ))
    .is_none());
}

#[test]
fn patch_build_verify_goal_enrichment_inherits_selected_skills_and_prep_summary() {
    let parent_goal =
        "Patch the workspace in \"/tmp/example\" and run `python3 -m unittest tests.test_path_utils -v`.";
    let raw_goal = "Implement the path-normalization fix as a narrow workspace patch.";
    let prep_bundle = DelegatedChildPrepBundle {
        selected_skills: vec![
            "coding__repo_diff_minimizer".to_string(),
            "coding__targeted_test_first".to_string(),
        ],
        prep_summary: Some(
            "Repo memory highlights the path-normalizer tests and a narrow string-normalization helper."
                .to_string(),
        ),
    };

    let enriched = enrich_delegated_child_goal_with_prep(
        parent_goal,
        raw_goal,
        Some("patch_build_verify"),
        &prep_bundle,
    );

    assert!(enriched.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(enriched
        .contains("- selected_skills: coding__repo_diff_minimizer, coding__targeted_test_first"));
    assert!(enriched.contains("- prep_summary: Repo memory highlights the path-normalizer tests"));
    assert!(enriched.contains("- targeted_checks: python3 -m unittest tests.test_path_utils -v"));
}

#[test]
fn artifact_generate_repair_goal_enrichment_adds_artifact_prep_hints() {
    let prep_bundle = DelegatedChildPrepBundle {
        selected_skills: vec!["artifact__frontend_validation_spine".to_string()],
        prep_summary: Some(
            "Artifact memory favors a restrained editorial hero with a single dominant CTA."
                .to_string(),
        ),
    };

    let enriched = enrich_delegated_child_goal_with_prep(
        "Create an editorial launch page for the new release.",
        "Generate the launch page artifact and retain the important output files.",
        Some("artifact_generate_repair"),
        &prep_bundle,
    );

    assert!(enriched.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(enriched.contains("- selected_skills: artifact__frontend_validation_spine"));
    assert!(enriched.contains(
        "- prep_summary: Artifact memory favors a restrained editorial hero with a single dominant CTA."
    ));
}

#[test]
fn browser_postcondition_pass_goal_enrichment_preserves_existing_context_and_adds_ui_prep() {
    let prep_bundle = DelegatedChildPrepBundle {
        selected_skills: vec!["computer_use__button_targeting".to_string()],
        prep_summary: Some(
            "UI memory suggests the primary confirmation button sits below the explanatory copy."
                .to_string(),
        ),
    };
    let raw_goal = concat!(
        "Carry out the confirmation click in the browser.\n\n",
        "[PARENT PLAYBOOK CONTEXT]\n",
        "- next_action: click the primary confirmation button\n",
        "- approval_risk: low"
    );

    let enriched = enrich_delegated_child_goal_with_prep(
        "Confirm the action in the current browser tab.",
        raw_goal,
        Some("browser_postcondition_pass"),
        &prep_bundle,
    );

    assert!(enriched.contains("- next_action: click the primary confirmation button"));
    assert!(enriched.contains("- approval_risk: low"));
    assert!(enriched.contains("- selected_skills: computer_use__button_targeting"));
    assert!(enriched.contains(
        "- prep_summary: UI memory suggests the primary confirmation button sits below the explanatory copy."
    ));
}
