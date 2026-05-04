use super::{
    browser_route_owns_dedicated_surface, duplicate_prior_success_noop,
    install_already_satisfied_operator_reply, install_already_satisfied_terminal_reason,
    install_resolution_terminal_block_reason, maybe_enqueue_workspace_package_manifest_recovery,
    maybe_terminalize_workspace_package_manifest_read, observe_terminal_chat_reply_shape,
    select_manifest_script_recovery_candidate, should_release_browser_after_terminal_reply,
    terminal_chat_reply_layout_profile, workspace_goal_prefers_package_manifest_recovery,
    FailureClass, ManifestScriptRecoveryCandidate, TerminalChatReplyLayoutProfile,
};
use crate::agentic::runtime::service::queue::queue_action_request_to_tool;
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use ioi_types::app::agentic::{
    AgentTool, CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    RuntimeRouteFrame,
};
use ioi_types::app::ActionRequest;
use std::collections::{BTreeMap, VecDeque};

fn workspace_ops_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("filesystem.read")],
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

fn browser_interact_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "browser.interact".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("browser.navigate")],
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

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "test".to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
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
        execution_queue: Vec::<ActionRequest>::new(),
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn browser_terminal_reply_completion_releases_dedicated_browser_surface() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("The page title is Example Domain.".into()));
    agent_state.resolved_intent = Some(browser_interact_intent());

    assert!(browser_route_owns_dedicated_surface(&agent_state));
    assert!(should_release_browser_after_terminal_reply(
        &agent_state,
        "browser__navigate",
        Some("The page title is Example Domain."),
    ));
}

#[test]
fn browser_release_predicate_uses_typed_route_frame_fallback() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("done".into()));
    agent_state.runtime_route_frame = Some(RuntimeRouteFrame {
        intent_id: "browser.interact".to_string(),
        route_family: "tool_first".to_string(),
        output_intent: "browser__navigate".to_string(),
        direct_answer_allowed: false,
        target: "https://example.com".to_string(),
        target_kind: Some("url".to_string()),
        host_mutation: false,
        required_capabilities: vec!["browser.navigate".to_string()],
        typed_evidence: vec![],
        typed_required_capabilities: vec![],
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    });

    assert!(browser_route_owns_dedicated_surface(&agent_state));
    assert!(should_release_browser_after_terminal_reply(
        &agent_state,
        "browser__navigate",
        Some("done"),
    ));
}

#[test]
fn non_browser_terminal_reply_does_not_release_browser_surface() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("done".into()));
    agent_state.resolved_intent = Some(workspace_ops_intent());

    assert!(!browser_route_owns_dedicated_surface(&agent_state));
    assert!(!should_release_browser_after_terminal_reply(
        &agent_state,
        "file__read",
        Some("done"),
    ));
}

#[test]
fn terminal_chat_reply_shape_detects_story_collection_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\n- Example\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
    );

    assert!(!facts.heading_present);
    assert_eq!(facts.story_header_count, 1);
    assert_eq!(facts.comparison_label_count, 1);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::StoryCollection
    );
}

#[test]
fn terminal_chat_reply_shape_detects_document_briefing_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nWhat happened: NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- NIST finalized the first three standards.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
    );

    assert!(facts.heading_present);
    assert_eq!(facts.story_header_count, 0);
    assert_eq!(facts.comparison_label_count, 0);
    assert!(facts.run_date_present);
    assert!(facts.run_timestamp_present);
    assert!(facts.overall_confidence_present);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::DocumentBriefing
    );
}

#[test]
fn terminal_chat_reply_shape_detects_single_snapshot_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high",
    );

    assert!(!facts.heading_present);
    assert!(facts.single_snapshot_heading_present);
    assert_eq!(facts.story_header_count, 0);
    assert_eq!(facts.comparison_label_count, 0);
    assert!(facts.run_date_present);
    assert!(facts.run_timestamp_present);
    assert!(facts.overall_confidence_present);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::SingleSnapshot
    );
}

#[test]
fn duplicate_prior_success_noop_detects_retry_boundary() {
    assert!(duplicate_prior_success_noop(&[
        "duplicate_action_fingerprint_non_command_noop=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
    ]));
    assert!(!duplicate_prior_success_noop(&[
        "duplicate_action_fingerprint_non_command_noop=true".to_string(),
    ]));
}

#[test]
fn install_resolution_blocker_is_terminalized_from_receipt() {
    let checks = vec!["software_install_blocked_before_approval=true".to_string()];
    let reason = install_resolution_terminal_block_reason(
        &checks,
        Some(
            "ERROR_CLASS=InstallerResolutionRequired No verified install mapping exists for 'snorflepaint'.",
        ),
        None,
        None,
    )
    .expect("resolver blocker should terminalize");

    assert!(reason.contains("InstallerResolutionRequired"));
    assert!(reason.contains("snorflepaint"));
}

#[test]
fn non_install_failure_is_not_terminalized_as_install_blocker() {
    let checks = vec!["policy_decision=allowed".to_string()];

    assert!(install_resolution_terminal_block_reason(
        &checks,
        Some("ERROR_CLASS=UnexpectedState unrelated failure"),
        None,
        None,
    )
    .is_none());
}

#[test]
fn already_satisfied_install_is_terminalized_as_completion() {
    let checks = vec!["install_already_satisfied_before_approval=true".to_string()];
    let reason = install_already_satisfied_terminal_reason(
        &checks,
        Some("Already installed: 'LM Studio' is present before host mutation."),
        None,
    )
    .expect("verified installed target should terminalize");

    assert!(reason.contains("Already installed"));
    assert!(reason.contains("LM Studio"));
}

#[test]
fn already_satisfied_install_reply_hides_raw_receipt_tokens() {
    let reply = install_already_satisfied_operator_reply(
        r#"{"kind":"install_final_receipt","install_final_receipt":{"status":"already_installed_verified","display_name":"LM Studio","verification":{"passed":true,"command":"lms --version","observed_version":null,"evidence":[]}}}"#,
    );

    assert!(reply.contains("LM Studio is already installed"));
    assert!(reply.contains("`lms --version`"));
    assert!(!reply.contains("install_final_receipt"));
}

#[test]
fn workspace_goal_prefers_package_manifest_recovery_for_desktop_script_queries() {
    assert!(workspace_goal_prefers_package_manifest_recovery(
        "What npm script launches the desktop app in this repo?"
    ));
    assert!(!workspace_goal_prefers_package_manifest_recovery(
        "What does the README say about the desktop app?"
    ));
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_unique_desktop_script() {
    let manifest = r#"{
      "scripts": {
        "dev": "vite",
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "test": "vitest"
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_launch_oriented_desktop_match() {
    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "start:desktop": "electron ."
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_primary_desktop_script_over_variants() {
    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "dev:desktop:wayland": "bash apps/autopilot/scripts/dev-desktop.sh wayland",
        "dryrun:desktop": "bash apps/autopilot/scripts/dry-run-desktop.sh x11"
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn manifest_read_terminalization_emits_desktop_script_reply() {
    let mut agent_state = test_agent_state();
    agent_state.goal = "What npm script launches the desktop app in this repo?".to_string();
    agent_state.resolved_intent = Some(workspace_ops_intent());

    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "dev:desktop:wayland": "bash apps/autopilot/scripts/dev-desktop.sh wayland"
      }
    }"#;

    assert_eq!(
        maybe_terminalize_workspace_package_manifest_read(
            &agent_state,
            "file__read",
            Some(manifest),
        ),
        Some(
            "In `package.json`, the npm script that launches the desktop app is `dev:desktop`. It runs `bash apps/autopilot/scripts/dev-desktop.sh x11`.".to_string()
        )
    );
}

#[test]
fn workspace_package_manifest_recovery_enqueues_read_then_reply_on_first_no_effect() {
    let dir = std::env::temp_dir().join(format!(
        "ioi-package-manifest-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be available")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    std::fs::write(
        dir.join("package.json"),
        r#"{
          "scripts": {
            "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11"
          }
        }"#,
    )
    .expect("package.json should be written");

    let mut agent_state = test_agent_state();
    agent_state.goal = "What npm script launches the desktop app in this repo?".to_string();
    agent_state.resolved_intent = Some(workspace_ops_intent());
    agent_state.working_directory = dir.to_string_lossy().to_string();

    let queued = maybe_enqueue_workspace_package_manifest_recovery(
        &mut agent_state,
        [7u8; 32],
        FailureClass::NoEffectAfterAction,
        "file__list",
    )
    .expect("recovery enqueue should succeed");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 2);

    let read_tool = queue_action_request_to_tool(&agent_state.execution_queue[0])
        .expect("queued read should decode");
    let reply_tool = queue_action_request_to_tool(&agent_state.execution_queue[1])
        .expect("queued reply should decode");

    match read_tool {
        AgentTool::FsRead { path } => assert_eq!(path, "./package.json"),
        other => panic!("expected FsRead recovery tool, got {:?}", other),
    }
    match reply_tool {
        AgentTool::ChatReply { message } => {
            assert!(message.contains("`dev:desktop`"));
            assert!(message.contains("dev-desktop.sh x11"));
        }
        other => panic!("expected ChatReply recovery tool, got {:?}", other),
    }

    let _ = std::fs::remove_file(dir.join("package.json"));
    let _ = std::fs::remove_dir(dir);
}
