use super::{
    capability_route_label, compose_terminal_chat_reply, contract_requires_evidence_with_rules,
    contract_requires_success_condition_with_rules, enrich_command_scope_summary,
    execution_contract_violation_error, is_command_execution_provider_tool,
    missing_completion_evidence_with_rules, record_verification_evidence,
    synthesize_allowlisted_timer_notification_tool, timer_payload_requires_allowlisted_scheduler,
    VERIFICATION_COMMIT_EVIDENCE, WEB_PIPELINE_TERMINAL_EVIDENCE,
};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::step::action::support::{
    record_execution_evidence, record_success_condition,
};
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ToolCallStatus,
};
use ioi_types::app::agentic::{AgentTool, CapabilityId};
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
use std::collections::{BTreeMap, VecDeque};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "Run a command".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 16,
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
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn resolved_intent(intent_id: &str, scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.92,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
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
    }
}

fn command_scope_intent(intent_id: &str) -> ResolvedIntentState {
    resolved_intent(intent_id, IntentScopeProfile::CommandExecution)
}

fn record_ledger_receipt(state: &mut AgentState, receipt: &str, value: &str) {
    state.execution_ledger.record_evidence(None, receipt, value);
    if receipt == "verification" {
        state.execution_ledger.record_verification_evidence(
            None,
            "test_verification_evidence",
            "present",
        );
    }
}

#[test]
fn execution_contract_violation_error_uses_contract_violation_as_primary_class() {
    let error = execution_contract_violation_error("evidence::verification=true");
    assert!(error.starts_with("ERROR_CLASS=ExecutionContractViolation "));
    assert!(error.contains("detail_class=VerificationMissing"));
}

#[test]
fn install_package_is_treated_as_command_execution_provider_tool() {
    let install = AgentTool::SysInstallPackage {
        package: "vlc".to_string(),
        manager: None,
    };
    assert!(is_command_execution_provider_tool(&install));
}

#[test]
fn install_package_verification_receipts_emit_commit() {
    let mut log = BTreeMap::<String, ToolCallStatus>::new();
    let mut checks = Vec::<String>::new();
    let tool = AgentTool::SysInstallPackage {
        package: "vlc".to_string(),
        manager: Some("apt-get".to_string()),
    };

    record_verification_evidence(&mut log, &mut checks, &tool, None);

    assert!(super::has_execution_evidence(&log, "verification"));
    let commit = super::execution_evidence_value(&log, VERIFICATION_COMMIT_EVIDENCE)
        .expect("verification commit receipt should be present for install package");
    assert!(commit.starts_with("sha256:"));
    assert!(checks
        .iter()
        .any(|check| check == "evidence::verification=true"));
}

#[test]
fn terminal_reply_composer_formats_dense_pdf_path_output() {
    let summary = "/home/heathledger/Documents/ioi/one.pdf/home/heathledger/Documents/ioi/two.pdf /home/heathledger/Pictures/news at DuckDuckGo.pdf Run timestamp (UTC): 2026-02-27T17:55:09.632Z";
    let outcome = compose_terminal_chat_reply(summary);

    assert!(outcome.applied);
    assert!(outcome.validator_passed);
    assert!(outcome
        .output
        .contains("- `/home/heathledger/Documents/ioi/one.pdf`"));
    assert!(outcome
        .output
        .contains("- `/home/heathledger/Documents/ioi/two.pdf`"));
    assert!(outcome
        .output
        .contains("- `/home/heathledger/Pictures/news at DuckDuckGo.pdf`"));
    assert!(outcome
        .output
        .contains("Run timestamp (UTC): 2026-02-27T17:55:09.632Z"));
}

#[test]
fn enrich_summary_preserves_terse_message_and_appends_timestamp() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(command_scope_intent("command.exec"));
    record_execution_evidence(&mut state.tool_execution_log, "execution");
    record_success_condition(&mut state.tool_execution_log, "execution_artifact");
    state.command_history.push_back(CommandExecution {
        command: "bash -s".to_string(),
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1_772_304_000_000,
        step_index: 1,
    });

    let enriched = enrich_command_scope_summary("phone-preview.mp4", &state);
    assert!(enriched.contains("phone-preview.mp4"));
    assert!(enriched.contains("Run timestamp (UTC):"));
}

#[test]
fn enrich_summary_preserves_non_terse_message() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(command_scope_intent("command.exec"));
    record_execution_evidence(&mut state.tool_execution_log, "execution");
    record_success_condition(&mut state.tool_execution_log, "execution_artifact");
    state.command_history.push_back(CommandExecution {
        command: "bash -s".to_string(),
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1_772_304_000_000,
        step_index: 1,
    });

    let summary = "Completed command run with expected output.";
    let enriched = enrich_command_scope_summary(summary, &state);
    assert!(enriched.contains(summary));
}

#[test]
fn enrich_summary_normalizes_runtime_home_paths_for_non_command_scope() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(resolved_intent(
        "workspace.ops",
        IntentScopeProfile::WorkspaceOps,
    ));
    let previous_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", "/tmp/ioi-fixture/home");

    let enriched = enrich_command_scope_summary(
        "Moved files to ~/Downloads/ioi_lowercase_123 and /home/Downloads/ioi_lowercase_123",
        &state,
    );
    let expected = "/tmp/ioi-fixture/home/Downloads/ioi_lowercase_123";
    assert_eq!(enriched.matches(expected).count(), 2);
    assert!(!enriched.contains("~/Downloads/ioi_lowercase_123"));

    if let Some(value) = previous_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }
}

#[test]
fn enrich_summary_does_not_duplicate_existing_runtime_home_paths() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(resolved_intent(
        "workspace.ops",
        IntentScopeProfile::WorkspaceOps,
    ));
    let previous_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", "/tmp/ioi-fixture/home");

    let input = "/tmp/ioi-fixture/home/Documents/report.pdf";
    let enriched = enrich_command_scope_summary(input, &state);
    assert_eq!(enriched, input);

    if let Some(value) = previous_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }
}

#[test]
fn command_probe_rrs_does_not_require_topology_receipts() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(command_scope_intent("command.probe"));
    record_ledger_receipt(&mut state, "execution", "true");
    record_ledger_receipt(&mut state, "verification", "true");

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);

    assert!(
        missing.is_empty(),
        "expected no missing markers, got {missing:?}"
    );
}

#[test]
fn app_launch_rrs_requires_topology_receipts() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(resolved_intent("app.launch", IntentScopeProfile::AppLaunch));
    record_ledger_receipt(&mut state, "execution", "true");
    record_ledger_receipt(&mut state, "verification", "true");

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);

    assert!(missing.contains(&"evidence::host_discovery=true".to_string()));
    assert!(missing.contains(&"evidence::provider_selection=true".to_string()));
}

#[test]
fn chat_reply_uses_native_integration_route_label() {
    let tool = AgentTool::ChatReply {
        message: "done".to_string(),
    };

    assert_eq!(
        capability_route_label(&tool, "chat__reply").as_deref(),
        Some("native_integration")
    );
}

#[test]
fn filesystem_copy_uses_native_integration_route_label() {
    let tool = AgentTool::FsCopy {
        source_path: "/tmp/source".to_string(),
        destination_path: "/tmp/destination".to_string(),
        overwrite: true,
    };

    assert_eq!(
        capability_route_label(&tool, "file__copy").as_deref(),
        Some("native_integration")
    );
}

#[test]
fn rrsa_network_domain_enforces_domain_binding_at_completion_gate() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(command_scope_intent("command.probe"));
    record_ledger_receipt(&mut state, "execution", "true");
    record_ledger_receipt(&mut state, "verification", "true");
    record_ledger_receipt(&mut state, "rrsa_request_binding", "sha256:abc");
    record_ledger_receipt(&mut state, "rrsa_firewall_decision", "sha256:def");
    record_ledger_receipt(&mut state, "rrsa_domain", "network_web");
    record_ledger_receipt(&mut state, "rrsa_output_commitment", "sha256:123");

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);
    assert!(missing.contains(&"evidence::rrsa_domain_binding=true".to_string()));
}

#[test]
fn resolved_mail_reply_contract_requires_grounding_receipt() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(resolved_intent(
        "mail.reply",
        IntentScopeProfile::Conversation,
    ));

    let rules = ActionRules::default();
    assert!(contract_requires_evidence_with_rules(
        &state,
        &rules,
        "grounding"
    ));
}

#[test]
fn resolved_mail_reply_contract_requires_reply_postcondition() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(resolved_intent(
        "mail.reply",
        IntentScopeProfile::Conversation,
    ));

    let rules = ActionRules::default();
    assert!(contract_requires_success_condition_with_rules(
        &state,
        &rules,
        "mail.reply.completed"
    ));
}

#[test]
fn capability_metadata_does_not_supply_contract_authority() {
    let mut state = test_agent_state();
    let mut resolved = resolved_intent("gmail.draft_email", IntentScopeProfile::Conversation);
    resolved.required_capabilities = vec![CapabilityId::from("mail.reply")];
    state.resolved_intent = Some(resolved);

    let rules = ActionRules::default();
    assert!(!contract_requires_evidence_with_rules(
        &state,
        &rules,
        "grounding"
    ));
    assert!(!contract_requires_success_condition_with_rules(
        &state,
        &rules,
        "mail.reply.completed"
    ));
}

#[test]
fn rrsa_wallet_domain_enforces_tx_approval_and_eei_bindings() {
    let mut state = test_agent_state();
    state.resolved_intent = Some(command_scope_intent("command.probe"));
    record_ledger_receipt(&mut state, "execution", "true");
    record_ledger_receipt(&mut state, "verification", "true");
    record_ledger_receipt(&mut state, "rrsa_request_binding", "sha256:abc");
    record_ledger_receipt(&mut state, "rrsa_firewall_decision", "sha256:def");
    record_ledger_receipt(&mut state, "rrsa_domain", "wallet");
    record_ledger_receipt(&mut state, "rrsa_tx_hash_binding", "sha256:tx");

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);
    assert!(missing.contains(&"evidence::rrsa_approval_grant_ref=true".to_string()));
    assert!(missing.contains(&"evidence::rrsa_eei_bundle_commitment=true".to_string()));
}

#[test]
fn pending_web_pipeline_requires_terminal_receipt_at_completion_gate() {
    let mut state = test_agent_state();
    state.pending_search_completion = Some(Default::default());

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);

    assert!(missing.contains(&format!(
        "evidence::{}=true",
        WEB_PIPELINE_TERMINAL_EVIDENCE
    )));
}

#[test]
fn pending_web_pipeline_terminal_receipt_clears_completion_gate_requirement() {
    let mut state = test_agent_state();
    state.pending_search_completion = Some(Default::default());
    record_ledger_receipt(&mut state, WEB_PIPELINE_TERMINAL_EVIDENCE, "true");

    let rules = ActionRules::default();
    let missing = missing_completion_evidence_with_rules(&state, &rules);

    assert!(
        !missing.contains(&format!(
            "evidence::{}=true",
            WEB_PIPELINE_TERMINAL_EVIDENCE
        )),
        "unexpected missing markers: {missing:?}"
    );
}

#[test]
fn timer_payload_scheduler_rewrite_covers_foreground_sleep_notify_chain() {
    let tool = AgentTool::SysExecSession {
        command: "sleep 900 && notify-send 'Timer' '15 minutes are up!'".to_string(),
        args: vec![],
        stdin: None,
        wait_ms_before_async: None,
    };

    assert!(timer_payload_requires_allowlisted_scheduler(&tool));
    let rewritten = synthesize_allowlisted_timer_notification_tool(&tool)
        .expect("sleep-backed timer chain should synthesize a scheduler-backed payload");

    match rewritten {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "systemd-run");
            assert!(args.iter().any(|arg| arg == "--user"));
            assert!(args.iter().any(|arg| arg == "--on-active=900s"));
            assert!(args.iter().any(|arg| arg == "notify-send"));
        }
        other => panic!("unexpected rewritten tool: {other:?}"),
    }
}

#[test]
fn detached_deferred_sleep_timer_does_not_require_scheduler_rewrite() {
    let tool = AgentTool::SysExec {
        command: "bash".to_string(),
        args: vec![
            "-lc".to_string(),
            "nohup sh -c 'sleep 900 && notify-send Timer Done' &".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: true,
    };

    assert!(!timer_payload_requires_allowlisted_scheduler(&tool));
}
