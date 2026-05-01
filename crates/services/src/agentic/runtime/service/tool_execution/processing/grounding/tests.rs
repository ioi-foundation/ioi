use super::*;
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::lifecycle::persist_worker_assignment;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookStatus, WorkerAssignment,
    WorkerCompletionContract, WorkerMergeMode,
};
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::tempdir;

fn slot(slot: &str, protected_slot_kind: ProtectedSlotKind) -> InstructionSlotBinding {
    InstructionSlotBinding {
        slot: slot.to_string(),
        binding_kind: InstructionBindingKind::UserLiteral,
        value: None,
        origin: ioi_types::app::agentic::ArgumentOrigin::UserSpan,
        protected_slot_kind,
    }
}

fn resolved_without_contract() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "mail.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "test".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        constrained: false,
        required_evidence: vec!["grounding".to_string()],
        success_conditions: vec!["mail.reply.completed".to_string()],
        instruction_contract: None,
    }
}

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
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
        command_history: Default::default(),
    }
}

fn patch_build_verify_assignment(session_id: [u8; 32]) -> WorkerAssignment {
    WorkerAssignment {
        step_key: "delegate:0:patch".to_string(),
        budget: 48,
        goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string(),
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
            "file__write".to_string(),
            "file__replace_line".to_string(),
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
    }
}

struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

#[test]
fn query_attests_explicit_email_literals_only_when_present() {
    let binding = slot("to", ProtectedSlotKind::EmailAddress);
    assert!(query_attests_protected_literal(
        "Draft an email to ioifoundationhl@gmail.com and do not send it.",
        &binding,
        "ioifoundationhl@gmail.com"
    ));
    assert!(!query_attests_protected_literal(
        "Draft an email to my connected Google address and do not send it.",
        &binding,
        "your-connected-email@example.com"
    ));
}

#[test]
fn query_attests_symbolic_alias_phrases_for_protected_email_slots() {
    let binding = slot("to", ProtectedSlotKind::EmailAddress);
    assert!(query_attests_protected_literal(
        "Draft an email to my connected Google address with the subject hello.",
        &binding,
        "my connected Google address"
    ));
}

#[test]
fn redacted_email_placeholder_recovers_single_explicit_query_email() {
    let binding = slot("to", ProtectedSlotKind::EmailAddress);
    assert_eq!(
        recover_redacted_protected_literal_from_query(
            "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM.",
            &binding,
            "<REDACTED:email>"
        )
        .as_deref(),
        Some("team@ioi.network")
    );
}

#[test]
fn protected_slot_metadata_synthesizes_missing_bindings_for_google_tools() {
    let resolved = resolved_without_contract();
    let arguments = json!({
        "to": "your-connected-email@example.com",
        "subject": "hello",
        "body": "world"
    });
    let bindings = protected_slot_bindings_by_name(
        &resolved,
        Some("connector__google__gmail_draft_email"),
        arguments.as_object().expect("arguments object"),
    );
    let to = bindings.get("to").expect("protected slot binding");
    assert_eq!(to.binding_kind, InstructionBindingKind::UserLiteral);
    assert_eq!(to.origin, ArgumentOrigin::ModelInferred);
    assert_eq!(to.protected_slot_kind, ProtectedSlotKind::EmailAddress);
    assert_eq!(
        to.value.as_deref(),
        Some("your-connected-email@example.com")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn delegate_template_binding_applies_without_grounding_receipt() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Research the latest kernel scheduler benchmarks.".to_string();
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "web.research".to_string();
    resolved.scope = IntentScopeProfile::WebResearch;
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::ReadOnly,
        slot_bindings: vec![
            ioi_types::app::agentic::InstructionSlotBinding {
                slot: "template_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("researcher".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
            ioi_types::app::agentic::InstructionSlotBinding {
                slot: "workflow_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("live_research_brief".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::AgentDelegate {
            goal: "Find the most recent benchmarks and summarize them.".to_string(),
            budget: 1,
            playbook_id: None,
            template_id: None,
            workflow_id: None,
            role: None,
            success_criteria: None,
            merge_mode: None,
            expected_output: None,
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "web.research",
        None,
        &mut verification_checks,
    )
    .await
    .expect("delegate template grounding should succeed");

    let AgentTool::AgentDelegate {
        playbook_id,
        template_id,
        workflow_id,
        ..
    } = grounded
    else {
        panic!("expected grounded delegate tool");
    };
    assert_eq!(playbook_id.as_deref(), None);
    assert_eq!(template_id.as_deref(), Some("researcher"));
    assert_eq!(workflow_id.as_deref(), Some("live_research_brief"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "grounding_slot=template_id::user_literal"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "grounding_slot=workflow_id::user_literal"));
    assert!(
        !agent_state.tool_execution_log.contains_key("grounding"),
        "non-grounding delegate template injection should not fabricate a grounding receipt"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn root_workspace_playbook_synthesizes_delegate_before_direct_tool_use() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Port the repo fix, verify the targeted test first, and report the touched files."
            .to_string();
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "workspace.ops".to_string();
    resolved.scope = IntentScopeProfile::WorkspaceOps;
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::Update,
        slot_bindings: vec![
            InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("evidence_audited_patch".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
            InstructionSlotBinding {
                slot: "template_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("context_worker".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
            InstructionSlotBinding {
                slot: "workflow_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("repo_context_brief".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsStat {
            path: "/tmp/project".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("root delegate synthesis should succeed");

    let AgentTool::AgentDelegate {
        budget,
        playbook_id,
        template_id,
        workflow_id,
        ..
    } = grounded
    else {
        panic!("expected grounded tool to become agent__delegate");
    };
    assert_eq!(budget, 0);
    assert_eq!(playbook_id.as_deref(), Some("evidence_audited_patch"));
    assert_eq!(template_id.as_deref(), Some("context_worker"));
    assert_eq!(workflow_id.as_deref(), Some("repo_context_brief"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "root_playbook_delegate_synthesized=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn root_workspace_playbook_rewrites_malformed_delegate_before_playbook_start() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Port the repo fix, verify the targeted test first, and report the touched files."
            .to_string();
    agent_state.child_session_ids = vec![[0x11; 32]];
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "workspace.ops".to_string();
    resolved.scope = IntentScopeProfile::WorkspaceOps;
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::Update,
        slot_bindings: vec![
            InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("evidence_audited_patch".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
            InstructionSlotBinding {
                slot: "template_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("context_worker".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
            InstructionSlotBinding {
                slot: "workflow_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("repo_context_brief".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::AgentDelegate {
            goal: "Update the code in 'src/lib.rs' to normalize quotes.".to_string(),
            budget: 100,
            playbook_id: Some("patch_build_verify".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: None,
            role: None,
            success_criteria: Some(
                "All string literals in 'src/lib.rs' are updated to use double quotes.".to_string(),
            ),
            merge_mode: None,
            expected_output: None,
        },
        &ActionRules::default(),
        [0u8; 32],
        2,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("malformed root delegate should be rewritten to the playbook kickoff");

    let AgentTool::AgentDelegate {
        goal,
        budget,
        playbook_id,
        template_id,
        workflow_id,
        ..
    } = grounded
    else {
        panic!("expected grounded tool to remain agent__delegate");
    };
    assert_eq!(goal, agent_state.goal);
    assert_eq!(budget, 0);
    assert_eq!(playbook_id.as_deref(), Some("evidence_audited_patch"));
    assert_eq!(template_id.as_deref(), Some("context_worker"));
    assert_eq!(workflow_id.as_deref(), Some("repo_context_brief"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "root_playbook_delegate_synthesized=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn active_parent_playbook_synthesizes_await_before_direct_tool_use() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Port the repo fix, verify the targeted test first, and report the touched files."
            .to_string();
    agent_state.child_session_ids = vec![[0x44; 32]];
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "workspace.ops".to_string();
    resolved.scope = IntentScopeProfile::WorkspaceOps;
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::Update,
        slot_bindings: vec![InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: Some("evidence_audited_patch".to_string()),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: ProtectedSlotKind::Unknown,
        }],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    agent_state.resolved_intent = Some(resolved);

    let run = ParentPlaybookRun {
        parent_session_id: agent_state.session_id,
        playbook_id: "evidence_audited_patch".to_string(),
        playbook_label: "Evidence-Audited Patch".to_string(),
        topic: agent_state.goal.clone(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some([0x44; 32]),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: Vec::new(),
    };
    state
        .insert(
            &get_parent_playbook_run_key(&agent_state.session_id, "evidence_audited_patch"),
            &codec::to_bytes_canonical(&run).expect("parent playbook run should encode"),
        )
        .expect("parent playbook run should persist");

    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsStat {
            path: "/tmp/project".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        1,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("active parent playbook should synthesize await");

    let AgentTool::AgentAwait {
        child_session_id_hex,
    } = grounded
    else {
        panic!("expected grounded tool to become agent__await");
    };
    assert_eq!(child_session_id_hex, hex::encode([0x44; 32]));
    assert!(verification_checks
        .iter()
        .any(|check| check == "parent_playbook_await_synthesized=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn delegated_child_intent_keeps_direct_tool_when_playbook_is_already_active() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Inspect the repo root and summarize likely touched files.".to_string();
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "delegation.task".to_string();
    resolved.scope = IntentScopeProfile::WorkspaceOps;
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::ReadOnly,
        slot_bindings: vec![InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: Some("evidence_audited_patch".to_string()),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: ProtectedSlotKind::Unknown,
        }],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsStat {
            path: "/tmp/project".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "delegation.task",
        None,
        &mut verification_checks,
    )
    .await
    .expect("delegated child should keep direct tool");

    let AgentTool::FsStat { path } = grounded else {
        panic!("delegated child should keep direct filesystem tool");
    };
    assert_eq!(path, "/tmp/project");
    assert!(!verification_checks
        .iter()
        .any(|check| check == "root_playbook_delegate_synthesized=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn delegated_workspace_child_keeps_direct_tool_when_parent_exists() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.parent_session_id = Some([0x44; 32]);
    agent_state.goal =
        "Patch the workspace, run the focused verification command, and report the touched files."
            .to_string();
    let mut resolved = resolved_without_contract();
    resolved.intent_id = "workspace.ops".to_string();
    resolved.scope = IntentScopeProfile::WorkspaceOps;
    resolved.required_evidence = vec!["execution".to_string(), "verification".to_string()];
    resolved.instruction_contract = Some(ioi_types::app::agentic::InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::ReadOnly,
        slot_bindings: vec![InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: Some("evidence_audited_patch".to_string()),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: ProtectedSlotKind::Unknown,
        }],
        negative_constraints: vec![],
        success_criteria: vec![],
    });
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsRead {
            path: "/tmp/project/path_utils.py".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("delegated workspace child should keep direct tool");

    let AgentTool::FsRead { path } = grounded else {
        panic!("delegated workspace child should keep direct filesystem tool");
    };
    assert_eq!(path, "/tmp/project/path_utils.py");
    assert!(!verification_checks
        .iter()
        .any(|check| check == "root_playbook_delegate_synthesized=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn filesystem_read_directory_rewrites_to_list_directory() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let repo = tempdir().expect("tempdir should succeed");
    let repo_root = repo.path().join("repo");
    std::fs::create_dir_all(repo_root.join("nested")).expect("nested directory should be created");

    let mut agent_state = test_agent_state();
    agent_state.working_directory = repo_root.to_string_lossy().to_string();
    let mut resolved = resolved_without_contract();
    resolved.required_evidence.clear();
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsRead {
            path: "nested".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("directory reads should canonicalize to list_directory");

    let AgentTool::FsList { path } = grounded else {
        panic!("expected directory read to become list_directory");
    };
    assert_eq!(path, "nested");
    assert!(verification_checks
        .iter()
        .any(|check| { check == "filesystem_read_directory_rewritten_to_list_directory=true" }));
    assert!(verification_checks.iter().any(|check| {
        check.as_str()
            == format!(
                "filesystem_read_directory_target={}",
                repo_root.join("nested").display()
            )
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn filesystem_read_file_keeps_regular_file() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let repo = tempdir().expect("tempdir should succeed");
    let repo_root = repo.path().join("repo");
    std::fs::create_dir_all(&repo_root).expect("repo root should be created");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path(path):\n    return path\n",
    )
    .expect("fixture file should be written");

    let mut agent_state = test_agent_state();
    agent_state.working_directory = repo_root.to_string_lossy().to_string();
    let mut resolved = resolved_without_contract();
    resolved.required_evidence.clear();
    agent_state.resolved_intent = Some(resolved);

    let state = IAVLTree::new(HashCommitmentScheme::new());
    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsRead {
            path: "path_utils.py".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("regular file reads should stay read_file");

    let AgentTool::FsRead { path } = grounded else {
        panic!("expected regular file read to stay read_file");
    };
    assert_eq!(path, "path_utils.py");
    assert!(!verification_checks
        .iter()
        .any(|check| { check == "filesystem_read_directory_rewritten_to_list_directory=true" }));
}

#[tokio::test(flavor = "current_thread")]
async fn patch_build_verify_directory_read_redirects_to_first_likely_file() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let repo = tempdir().expect("tempdir should succeed");
    let repo_root = repo.path().join("repo");
    let tests_root = repo_root.join("tests");
    std::fs::create_dir_all(&tests_root).expect("tests directory should be created");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path(path):\n    return path\n",
    )
    .expect("fixture file should be written");
    std::fs::write(repo_root.join("README.md"), "# fixture\n").expect("readme should exist");
    std::fs::write(
        tests_root.join("test_path_utils.py"),
        "def test_placeholder():\n    assert True\n",
    )
    .expect("test fixture should be written");

    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x44; 32];
    agent_state.working_directory = repo_root.to_string_lossy().to_string();
    let mut resolved = resolved_without_contract();
    resolved.required_evidence.clear();
    agent_state.resolved_intent = Some(resolved);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    persist_worker_assignment(
        &mut state,
        agent_state.session_id,
        &patch_build_verify_assignment(agent_state.session_id),
    )
    .expect("worker assignment should persist");

    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsRead {
            path: repo_root.to_string_lossy().to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("repo-root reads should redirect to likely file");

    let AgentTool::FsRead { path } = grounded else {
        panic!("expected likely-file redirect to stay read_file");
    };
    assert_eq!(path, "path_utils.py");
    assert!(verification_checks
        .iter()
        .any(|check| check == "filesystem_read_redirected_to_likely_file=true"));
    assert!(verification_checks.iter().any(|check| {
        check.as_str() == format!("filesystem_read_redirect_source={}", repo_root.display())
    }));
    assert!(verification_checks
        .iter()
        .any(|check| { check.as_str() == "filesystem_read_redirect_target=path_utils.py" }));
    assert!(!verification_checks
        .iter()
        .any(|check| { check == "filesystem_read_directory_rewritten_to_list_directory=true" }));
}

#[tokio::test(flavor = "current_thread")]
async fn patch_build_verify_stray_file_read_redirects_to_first_likely_file() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference = Arc::new(MockInferenceRuntime);
    let service = RuntimeAgentService::new(gui, terminal, browser, inference);

    let repo = tempdir().expect("tempdir should succeed");
    let repo_root = repo.path().join("repo");
    let tests_root = repo_root.join("tests");
    std::fs::create_dir_all(&tests_root).expect("tests directory should be created");
    std::fs::write(
        repo_root.join("path_utils.py"),
        "def normalize_fixture_path(path):\n    return path\n",
    )
    .expect("fixture file should be written");
    std::fs::write(repo_root.join("README.md"), "# fixture\n").expect("readme should exist");
    std::fs::write(
        tests_root.join("test_path_utils.py"),
        "def test_placeholder():\n    assert True\n",
    )
    .expect("test fixture should be written");

    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x55; 32];
    agent_state.working_directory = repo_root.to_string_lossy().to_string();
    let mut resolved = resolved_without_contract();
    resolved.required_evidence.clear();
    agent_state.resolved_intent = Some(resolved);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    persist_worker_assignment(
        &mut state,
        agent_state.session_id,
        &patch_build_verify_assignment(agent_state.session_id),
    )
    .expect("worker assignment should persist");

    let mut verification_checks = Vec::new();
    let grounded = apply_instruction_contract_grounding(
        &state,
        &service,
        &mut agent_state,
        AgentTool::FsRead {
            path: "README.md".to_string(),
        },
        &ActionRules::default(),
        [0u8; 32],
        0,
        "workspace.ops",
        None,
        &mut verification_checks,
    )
    .await
    .expect("non-likely reads should redirect to likely file");

    let AgentTool::FsRead { path } = grounded else {
        panic!("expected likely-file redirect to stay read_file");
    };
    assert_eq!(path, "path_utils.py");
    assert!(verification_checks
        .iter()
        .any(|check| check == "filesystem_read_redirected_to_likely_file=true"));
    assert!(verification_checks.iter().any(|check| {
        check.as_str()
            == format!(
                "filesystem_read_redirect_source={}",
                repo_root.join("README.md").display()
            )
    }));
}

#[test]
fn delegate_playbook_binding_applies_for_workspace_port_task() {
    let mut arguments = Map::new();
    let mut bindings = BTreeMap::from([
        (
            "playbook_id".to_string(),
            InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("evidence_audited_patch".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ),
        (
            "template_id".to_string(),
            InstructionSlotBinding {
                slot: "template_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("researcher".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ),
        (
            "workflow_id".to_string(),
            InstructionSlotBinding {
                slot: "workflow_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some("live_research_brief".to_string()),
                origin: ArgumentOrigin::ModelInferred,
                protected_slot_kind: ProtectedSlotKind::Unknown,
            },
        ),
    ]);
    let mut grounded_slots = Vec::new();
    let mut verification_checks = Vec::new();

    let applied = apply_delegate_template_binding(
        Some("agent__delegate"),
        &mut arguments,
        &mut bindings,
        &mut grounded_slots,
        &mut verification_checks,
    );

    assert!(applied);
    assert_eq!(
        arguments.get("playbook_id").and_then(Value::as_str),
        Some("evidence_audited_patch")
    );
    assert_eq!(
        arguments.get("template_id").and_then(Value::as_str),
        Some("researcher")
    );
    assert_eq!(
        arguments.get("workflow_id").and_then(Value::as_str),
        Some("live_research_brief")
    );
    assert!(verification_checks
        .iter()
        .any(|check| check == "grounding_slot=playbook_id::user_literal"));
}
