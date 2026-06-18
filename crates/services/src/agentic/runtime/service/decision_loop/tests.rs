use super::{
    ensure_agent_running_or_resume_retry_pause, handle_step, maybe_direct_inline_author_tool_call,
    maybe_fail_step_resource_limits, maybe_run_optimizer_recovery,
    maybe_typed_runtime_browser_navigate_tool_call, maybe_typed_runtime_file_write_tool_call,
    maybe_typed_runtime_install_resolve_tool_call, maybe_typed_runtime_shell_run_tool_call,
    maybe_typed_runtime_web_search_tool_call, maybe_typed_runtime_workspace_context_tool_call,
    queue_parent_playbook_await_request, queue_root_playbook_delegate_request,
    should_clear_stale_canonical_pending, typed_runtime_route_resolved_intent,
};
use crate::agentic::runtime::keys::{get_parent_playbook_run_key, get_state_key};
use crate::agentic::runtime::service::decision_loop::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::service::tool_execution::{
    execution_evidence_value, record_execution_evidence_with_value,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookRun, ParentPlaybookStatus,
    StepAgentParams,
};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{
    ArgumentOrigin, BrowserActionPlanRef, CapabilityId, CommandExecutionPlanRef,
    FileMutationPlanRef, InferenceOptions, InstructionBindingKind, InstructionContract,
    InstructionSlotBinding, IntentConfidenceBand, IntentScopeProfile, RequiredCapability,
    ResolvedIntentState, RuntimeActionFrame, RuntimeIntentEvidence, RuntimeRouteFrame,
    SoftwareInstallRequestFrame,
};
use ioi_types::app::{
    AccountId, ActionContext, ActionRequest, ActionTarget, ChainId, ContextSlice,
};
use ioi_types::codec;
use ioi_types::error::{StateError, VmError};
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        runtime_route_frame: None,
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
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

fn typed_install_frame(target: &str) -> RuntimeRouteFrame {
    RuntimeRouteFrame {
        intent_id: "software.install".to_string(),
        route_family: "command_execution".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: target.to_string(),
        target_kind: Some("desktop_app".to_string()),
        host_mutation: true,
        required_capabilities: vec!["software.install.resolve".to_string()],
        typed_evidence: vec![],
        typed_required_capabilities: vec![],
        host_mutation_scope: None,
        runtime_action: None,
        install_request: Some(SoftwareInstallRequestFrame {
            target_text: target.to_string(),
            target_kind: Some("desktop_app".to_string()),
            manager_preference: Some("apt".to_string()),
            launch_after_install: None,
            provenance: Some("test".to_string()),
        }),
        provenance: Some("test".to_string()),
    }
}

fn typed_runtime_action_frame(intent_id: &str, target_kind: &str) -> RuntimeRouteFrame {
    let runtime_action = match intent_id {
        "browser.interact" => Some(RuntimeActionFrame {
            intent_class: "local_runtime_action".to_string(),
            action_family: "browser".to_string(),
            target_text: "test runtime action".to_string(),
            target_kind: target_kind.to_string(),
            host_mutation: false,
            required_capabilities: vec![RequiredCapability {
                capability_id: "browser.interact".to_string(),
                reason: Some("test".to_string()),
            }],
            browser_plan: Some(BrowserActionPlanRef {
                plan_ref: "browser.navigate:https://example.com".to_string(),
                action: "navigate".to_string(),
                url: "https://example.com".to_string(),
                observation_required: true,
                observation_ref: None,
                coordinate_space_id: None,
                semantic_id: None,
            }),
            command_plan: None,
            file_plan: None,
            provenance: Some("test".to_string()),
        }),
        "command.exec" => Some(RuntimeActionFrame {
            intent_class: "local_runtime_action".to_string(),
            action_family: "shell".to_string(),
            target_text: "Run `echo typed-shell` in the terminal.".to_string(),
            target_kind: target_kind.to_string(),
            host_mutation: false,
            required_capabilities: vec![RequiredCapability {
                capability_id: "command.exec".to_string(),
                reason: Some("test".to_string()),
            }],
            browser_plan: None,
            command_plan: Some(CommandExecutionPlanRef {
                plan_ref: "command.exec:test".to_string(),
                argv: vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "echo typed-shell".to_string(),
                ],
                shell_policy: "bounded".to_string(),
                cwd: Some(".".to_string()),
                env: Vec::new(),
                approval_scope: None,
                expected_receipt: Some("command_receipt".to_string()),
            }),
            file_plan: None,
            provenance: Some("test".to_string()),
        }),
        _ => None,
    };
    RuntimeRouteFrame {
        intent_id: intent_id.to_string(),
        route_family: if intent_id == "command.exec" {
            "command_execution".to_string()
        } else {
            "browser".to_string()
        },
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: "test runtime action".to_string(),
        target_kind: Some(target_kind.to_string()),
        host_mutation: false,
        required_capabilities: Vec::new(),
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "normalized_request".to_string(),
            value: "runtime_action".to_string(),
            source: "test".to_string(),
            confidence: Some(95),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action,
        install_request: None,
        provenance: Some("test".to_string()),
    }
}

fn typed_workspace_frame_with_evidence(evidence_kind: &str, value: &str) -> RuntimeRouteFrame {
    RuntimeRouteFrame {
        intent_id: "workspace.context".to_string(),
        route_family: "workspace".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: true,
        target: value.to_string(),
        target_kind: Some("workspace_context".to_string()),
        host_mutation: false,
        required_capabilities: vec![
            "prim:file.search".to_string(),
            "prim:file.read".to_string(),
            "prim:workspace.read".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: evidence_kind.to_string(),
            value: value.to_string(),
            source: "test".to_string(),
            confidence: Some(92),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    }
}

fn typed_file_write_frame(path: &str, content: &str) -> RuntimeRouteFrame {
    RuntimeRouteFrame {
        intent_id: "workspace.mutate".to_string(),
        route_family: "workspace".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: path.to_string(),
        target_kind: Some("workspace_path".to_string()),
        host_mutation: true,
        required_capabilities: vec!["filesystem.write".to_string()],
        typed_evidence: vec![
            RuntimeIntentEvidence {
                evidence_kind: "workspace_path".to_string(),
                value: path.to_string(),
                source: "test".to_string(),
                confidence: Some(95),
            },
            RuntimeIntentEvidence {
                evidence_kind: "file_write_content".to_string(),
                value: content.to_string(),
                source: "test".to_string(),
                confidence: Some(90),
            },
        ],
        typed_required_capabilities: vec![RequiredCapability {
            capability_id: "filesystem.write".to_string(),
            reason: Some("test".to_string()),
        }],
        host_mutation_scope: None,
        runtime_action: Some(RuntimeActionFrame {
            intent_class: "workspace.mutate".to_string(),
            action_family: "file".to_string(),
            target_text: path.to_string(),
            target_kind: "workspace_path".to_string(),
            host_mutation: true,
            required_capabilities: vec![RequiredCapability {
                capability_id: "filesystem.write".to_string(),
                reason: Some("test".to_string()),
            }],
            browser_plan: None,
            command_plan: None,
            file_plan: Some(FileMutationPlanRef {
                plan_ref: "file.write:test".to_string(),
                path: path.to_string(),
                observed_hash: String::new(),
                mutation_kind: "write".to_string(),
                verification_command: None,
            }),
            provenance: Some("test".to_string()),
        }),
        install_request: None,
        provenance: Some("test".to_string()),
    }
}

fn typed_web_research_frame(
    route_family: &str,
    evidence_kind: &str,
    value: &str,
) -> RuntimeRouteFrame {
    RuntimeRouteFrame {
        intent_id: "retrieval.answer".to_string(),
        route_family: route_family.to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: value.to_string(),
        target_kind: Some("source_grounding".to_string()),
        host_mutation: false,
        required_capabilities: vec![
            "prim:conversation.reply".to_string(),
            "prim:web.search".to_string(),
            "prim:web.read".to_string(),
            "prim:source_grounding".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: evidence_kind.to_string(),
            value: value.to_string(),
            source: "test".to_string(),
            confidence: Some(92),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    }
}

#[test]
fn typed_runtime_install_route_dispatches_resolver_from_structured_frame() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_install_frame("lmstudio"));

    let tool_call =
        maybe_typed_runtime_install_resolve_tool_call(&mut state).expect("tool call should route");
    assert!(tool_call.contains("\"name\":\"software_install__resolve\""));
    assert!(tool_call.contains("\"request\""));
    assert!(state.recent_actions.iter().any(|action| {
        action.starts_with("runtime_route_frame_dispatch:software_install__resolve")
    }));

    assert!(maybe_typed_runtime_install_resolve_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_action_frames_seed_tool_scoped_intents() {
    let browser = typed_runtime_route_resolved_intent(&typed_runtime_action_frame(
        "browser.interact",
        "browser_action",
    ))
    .expect("browser route frame should seed intent");
    assert_eq!(browser.intent_id, "browser.interact");
    assert_eq!(browser.scope, IntentScopeProfile::UiInteraction);
    assert!(browser
        .required_capabilities
        .contains(&CapabilityId::from("browser.interact")));

    let shell = typed_runtime_route_resolved_intent(&typed_runtime_action_frame(
        "command.exec",
        "shell_command",
    ))
    .expect("shell route frame should seed intent");
    assert_eq!(shell.intent_id, "command.exec");
    assert_eq!(shell.scope, IntentScopeProfile::CommandExecution);
    assert!(shell
        .required_capabilities
        .contains(&CapabilityId::from("command.exec")));
}

#[test]
fn typed_runtime_studio_context_frames_seed_tool_scoped_intents() {
    let web = typed_runtime_route_resolved_intent(&RuntimeRouteFrame {
        intent_id: "retrieval.answer".to_string(),
        route_family: "web_research".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: "post-quantum computers".to_string(),
        target_kind: Some("source_grounding".to_string()),
        host_mutation: false,
        required_capabilities: vec![
            "prim:conversation.reply".to_string(),
            "prim:web.search".to_string(),
            "prim:web.read".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "studio_intent_frame".to_string(),
            value: "agent".to_string(),
            source: "test".to_string(),
            confidence: Some(92),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    })
    .expect("retrieval route frame should seed web research intent");
    assert_eq!(web.intent_id, "retrieval.answer");
    assert_eq!(web.scope, IntentScopeProfile::WebResearch);
    assert!(web
        .required_capabilities
        .contains(&CapabilityId::from("web.retrieve")));
    assert!(is_tool_allowed_for_resolution(Some(&web), "web__search"));
    assert!(is_tool_allowed_for_resolution(Some(&web), "web__read"));
    assert!(!is_tool_allowed_for_resolution(Some(&web), "file__read"));

    let workspace = typed_runtime_route_resolved_intent(&RuntimeRouteFrame {
        intent_id: "workspace.context".to_string(),
        route_family: "workspace".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: true,
        target: "local/native model providers".to_string(),
        target_kind: Some("workspace_context".to_string()),
        host_mutation: false,
        required_capabilities: vec![
            "prim:conversation.reply".to_string(),
            "prim:file.search".to_string(),
            "prim:file.read".to_string(),
            "prim:workspace.read".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "studio_intent_frame".to_string(),
            value: "agent".to_string(),
            source: "test".to_string(),
            confidence: Some(92),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    })
    .expect("workspace route frame should seed workspace intent despite direct flag");
    assert_eq!(workspace.intent_id, "workspace.context");
    assert_eq!(workspace.scope, IntentScopeProfile::WorkspaceOps);
    assert!(workspace
        .required_capabilities
        .contains(&CapabilityId::from("file.read")));
    assert!(is_tool_allowed_for_resolution(
        Some(&workspace),
        "file__read"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&workspace),
        "file__search"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&workspace),
        "file__write"
    ));
}

#[test]
fn typed_runtime_source_backed_artifact_frame_preserves_web_and_file_caps() {
    let resolved = typed_runtime_route_resolved_intent(&RuntimeRouteFrame {
        intent_id: "retrieval.answer".to_string(),
        route_family: "web_research".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: "photonic quantum computing".to_string(),
        target_kind: Some("source_backed_artifact".to_string()),
        host_mutation: true,
        required_capabilities: vec![
            "conversation.reply".to_string(),
            "web.retrieve".to_string(),
            "sys.time.read".to_string(),
            "filesystem.read".to_string(),
            "filesystem.write".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "retrieval_query".to_string(),
            value: "photonic quantum computing".to_string(),
            source: "test".to_string(),
            confidence: Some(92),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    })
    .expect("source-backed artifact frame should seed a tool-scoped intent");

    assert_eq!(resolved.intent_id, "retrieval.answer");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "web__search"
    ));
    assert!(is_tool_allowed_for_resolution(Some(&resolved), "web__read"));
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__write"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__read"
    ));
}

#[test]
fn typed_runtime_web_research_frame_dispatches_web_search_before_cognition() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_web_research_frame(
        "web_research",
        "web_search",
        "Which is a better investment right now, Akash or Filecoin?",
    ));

    let tool_call = maybe_typed_runtime_web_search_tool_call(&mut state)
        .expect("web research route frame should dispatch web__search");
    assert!(tool_call.contains("\"name\":\"web__search\""));
    assert!(tool_call.contains("Akash or Filecoin"));
    assert!(state
        .recent_actions
        .iter()
        .any(|action| action.starts_with("runtime_route_frame_dispatch:web__search")));

    assert!(maybe_typed_runtime_web_search_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_web_research_frame_ignores_studio_mode_labels_for_query() {
    let mut state = test_agent_state();
    let mut frame = typed_web_research_frame(
        "web_research",
        "normalized_request",
        "Which is a better investment right now, Akash or Filecoin?",
    );
    frame.typed_evidence.insert(
        0,
        RuntimeIntentEvidence {
            evidence_kind: "web_search".to_string(),
            value: "agent".to_string(),
            source: "test".to_string(),
            confidence: Some(95),
        },
    );
    frame.typed_evidence.insert(
        1,
        RuntimeIntentEvidence {
            evidence_kind: "query".to_string(),
            value: "studio_intent_frame".to_string(),
            source: "test".to_string(),
            confidence: Some(95),
        },
    );
    state.runtime_route_frame = Some(frame);

    let tool_call = maybe_typed_runtime_web_search_tool_call(&mut state)
        .expect("web research route frame should dispatch web__search");
    assert!(tool_call.contains("\"name\":\"web__search\""));
    assert!(tool_call.contains("Akash or Filecoin"));
    assert!(!tool_call.contains("\"query\":\"agent\""));
    assert!(!tool_call.contains("studio_intent_frame"));
}

#[test]
fn typed_runtime_research_family_frame_dispatches_web_search() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_web_research_frame(
        "research",
        "retrieval_query",
        "Find current sources for today's top local AI model runtime issue.",
    ));

    let tool_call = maybe_typed_runtime_web_search_tool_call(&mut state)
        .expect("generic research route family should still dispatch web__search");
    assert!(tool_call.contains("\"name\":\"web__search\""));
    assert!(tool_call.contains("local AI model runtime issue"));
}

#[test]
fn typed_runtime_browser_frame_dispatches_explicit_url_navigation() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_runtime_action_frame(
        "browser.interact",
        "browser_action",
    ));

    let tool_call = maybe_typed_runtime_browser_navigate_tool_call(&mut state)
        .expect("browser route frame with url should dispatch navigation");
    assert!(tool_call.contains("\"name\":\"browser__navigate\""));
    assert!(tool_call.contains("https://example.com"));
    assert!(state
        .recent_actions
        .iter()
        .any(|action| { action.starts_with("runtime_route_frame_dispatch:browser__navigate") }));
    assert_eq!(
        execution_evidence_value(
            &state.tool_execution_log,
            "runtime_route_frame_dispatch.browser_navigate_url"
        ),
        Some("https://example.com")
    );

    assert!(maybe_typed_runtime_browser_navigate_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_browser_frame_does_not_replay_after_recent_actions_clear() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_runtime_action_frame(
        "browser.interact",
        "browser_action",
    ));

    let tool_call = maybe_typed_runtime_browser_navigate_tool_call(&mut state)
        .expect("browser route frame should dispatch the first navigation");
    assert!(tool_call.contains("\"name\":\"browser__navigate\""));

    state.recent_actions.clear();

    assert!(maybe_typed_runtime_browser_navigate_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_shell_frame_dispatches_explicit_command_plan() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_runtime_action_frame("command.exec", "shell_command"));

    let tool_call = maybe_typed_runtime_shell_run_tool_call(&mut state)
        .expect("shell route frame with command plan should dispatch shell__run");
    assert!(tool_call.contains("\"name\":\"shell__run\""));
    assert!(tool_call.contains("\"command\":\"bash\""));
    assert!(tool_call.contains("echo typed-shell"));
    assert!(state
        .recent_actions
        .iter()
        .any(|action| { action.starts_with("runtime_route_frame_dispatch:shell__run") }));

    assert!(maybe_typed_runtime_shell_run_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_shell_frame_supersedes_stale_pending_shell_call() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_runtime_action_frame("command.exec", "shell_command"));
    state.pending_tool_call = Some(
        r#"{"name":"shell__run","arguments":{"command":"systemd-run","args":["--user","notify-send","Timer Complete"]}}"#
            .to_string(),
    );
    state.pending_tool_jcs = Some(vec![1, 2, 3]);
    state.pending_tool_hash = Some([7u8; 32]);
    state.pending_request_nonce = Some(99);
    state.pending_visual_hash = Some([8u8; 32]);
    state
        .recent_actions
        .push("runtime_route_frame_dispatch:shell__run:old-command".to_string());

    let tool_call = maybe_typed_runtime_shell_run_tool_call(&mut state)
        .expect("current typed command should supersede stale pending shell call");

    assert!(tool_call.contains("\"name\":\"shell__run\""));
    assert!(tool_call.contains("\"command\":\"bash\""));
    assert!(tool_call.contains("echo typed-shell"));
    assert!(state.pending_tool_call.is_none());
    assert!(state.pending_tool_jcs.is_none());
    assert!(state.pending_tool_hash.is_none());
    assert!(state.pending_request_nonce.is_none());
    assert!(state.pending_visual_hash.is_none());
    assert!(state
        .recent_actions
        .iter()
        .any(|action| action == "runtime_route_frame_dispatch:shell__run:command.exec:test"));
}

#[test]
fn typed_runtime_shell_frame_abstains_for_retained_lifecycle_controls() {
    let mut state = test_agent_state();
    state.goal = [
        "Start a disposable retained Node.js helper that waits for stdin and echoes a status line.",
        "Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and answer.",
    ]
    .join(" ");
    state.runtime_route_frame = Some(typed_runtime_action_frame("command.exec", "shell_command"));

    assert!(maybe_typed_runtime_shell_run_tool_call(&mut state).is_none());
    assert!(state
        .recent_actions
        .iter()
        .all(|action| !action.starts_with("runtime_route_frame_dispatch:shell__run")));
}

#[test]
fn typed_runtime_file_write_frame_dispatches_file_write_before_shell() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_file_write_frame(
        "/tmp/user-repo-sibling/outside-write.txt",
        "stage4-sibling-write-should-not-exist",
    ));

    let resolved = typed_runtime_route_resolved_intent(
        state
            .runtime_route_frame
            .as_ref()
            .expect("route frame should be present"),
    )
    .expect("file write route frame should seed mutation intent");
    assert_eq!(resolved.intent_id, "workspace.mutate");
    assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
    assert_eq!(
        resolved.required_evidence,
        vec!["policy_result".to_string()]
    );
    assert_eq!(
        resolved.success_conditions,
        vec!["action_report".to_string()]
    );
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__write"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__read"
    ));

    let tool_call = maybe_typed_runtime_file_write_tool_call(&mut state)
        .expect("file write route frame should dispatch file__write");
    assert!(tool_call.contains("\"name\":\"file__write\""));
    assert!(tool_call.contains("/tmp/user-repo-sibling/outside-write.txt"));
    assert!(tool_call.contains("stage4-sibling-write-should-not-exist"));
    assert!(state
        .recent_actions
        .iter()
        .any(|action| action.starts_with("runtime_route_frame_dispatch:file__write")));

    assert!(maybe_typed_runtime_file_write_tool_call(&mut state).is_none());
    assert!(maybe_typed_runtime_shell_run_tool_call(&mut state).is_none());
    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_workspace_frame_dispatches_explicit_path_read() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_path",
        ".internal/plans/example-master-guide.md",
    ));

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("workspace path route frame should dispatch file__read");
    assert!(tool_call.contains("\"name\":\"file__read\""));
    assert!(tool_call.contains(".internal/plans/example-master-guide.md"));
    assert!(state
        .recent_actions
        .iter()
        .any(|action| action.starts_with("runtime_route_frame_dispatch:workspace_context")));

    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_workspace_search_with_explicit_path_dispatches_read_not_search() {
    let mut state = test_agent_state();
    state.goal =
        "Try to read `/etc/passwd` through the governed file tool and summarize whether it blocks."
            .to_string();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Try to read `/etc/passwd` through the governed file tool",
    ));

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("explicit path read should dispatch file__read before workspace search fallback");
    assert!(tool_call.contains("\"name\":\"file__read\""));
    assert!(tool_call.contains("/etc/passwd"));
    assert!(!tool_call.contains("\"name\":\"file__search\""));
}

#[test]
fn typed_runtime_workspace_search_with_explicit_dotfile_path_dispatches_read_not_search() {
    let mut state = test_agent_state();
    state.goal =
        "Try to read `.autopilot-stage73-outside-link` through the governed file tool and summarize whether the daemon blocks it."
            .to_string();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Try to read `.autopilot-stage73-outside-link` through the governed file tool",
    ));

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state).expect(
        "explicit dotfile path read should dispatch file__read before workspace search fallback",
    );
    assert!(tool_call.contains("\"name\":\"file__read\""));
    assert!(tool_call.contains(".autopilot-stage73-outside-link"));
    assert!(!tool_call.contains("\"name\":\"file__search\""));
}

#[test]
fn typed_runtime_workspace_frame_stops_after_context_evidence() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Where are local/native model providers registered in this repo?",
    ));
    record_execution_evidence_with_value(
        &mut state.tool_execution_log,
        "file_context",
        "step=1;tool=file__search;path=.;regex=local|native|model|providers|registered;file_pattern=*"
            .to_string(),
    );

    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_workspace_frame_does_not_reuse_previous_path_context_for_search() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Where are local/native model providers registered in this repo?",
    ));
    record_execution_evidence_with_value(
        &mut state.tool_execution_log,
        "file_context",
        "step=1;tool=file__read;path=.internal/plans/example-master-guide.md".to_string(),
    );
    state.recent_actions.push(
        "runtime_route_frame_dispatch:workspace_context:file__read:.internal/plans/example-master-guide.md"
            .to_string(),
    );

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("a new workspace search target should not be suppressed by previous path context");
    assert!(tool_call.contains("\"name\":\"file__search\""));
    assert!(tool_call.contains("local|native|model|providers|registered"));
}

#[test]
fn typed_runtime_workspace_frame_does_not_reuse_previous_search_context_for_new_target() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Explain how Hypervisor Workbench decides between Ask and Agent mode in this repo.",
    ));
    record_execution_evidence_with_value(
        &mut state.tool_execution_log,
        "file_context",
        "step=1;tool=file__search;path=.;regex=local|native|model|providers|registered;file_pattern=*"
            .to_string(),
    );
    state.recent_actions.push(
        "runtime_route_frame_dispatch:workspace_context:file__search:local|native|model|providers|registered"
            .to_string(),
    );

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("a different workspace search target should get its own search");
    assert!(tool_call.contains("\"name\":\"file__search\""));
    assert!(tool_call.contains("Hypervisor|Workbench|decides|Ask|Agent|mode"));
}

#[test]
fn typed_runtime_workspace_frame_dispatches_bounded_search() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Where are local/native model providers registered in this repo?",
    ));

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("workspace search route frame should dispatch file__search");
    assert!(tool_call.contains("\"name\":\"file__search\""));
    assert!(tool_call.contains("local|native|model|providers|registered"));
    assert!(tool_call.contains("\"path\":\".\""));

    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_stage5_repair_frame_skips_workspace_context_prefetch() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(RuntimeRouteFrame {
        intent_id: "workspace.repair".to_string(),
        route_family: "workspace".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: "ARP_P0_007_PROOF_TOKEN repair loop for normalizeStatusLabel".to_string(),
        target_kind: Some("repair_loop".to_string()),
        host_mutation: true,
        required_capabilities: vec![
            "command.exec".to_string(),
            "filesystem.read".to_string(),
            "filesystem.write".to_string(),
            "conversation.reply".to_string(),
        ],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "stage5_stop_hook_repair_proof".to_string(),
            value: "model_tool_loop".to_string(),
            source: "test".to_string(),
            confidence: Some(96),
        }],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    });

    let resolved = typed_runtime_route_resolved_intent(
        state
            .runtime_route_frame
            .as_ref()
            .expect("route frame should be present"),
    )
    .expect("Stage 5 route frame should still seed a workspace-capable intent");
    assert_eq!(resolved.intent_id, "workspace.repair");
    assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
    assert!(resolved.required_evidence.is_empty());
    assert!(resolved.success_conditions.is_empty());
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__read"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__edit"
    ));
    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_workspace_frame_keeps_code_domain_search_terms() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Explain how Hypervisor Workbench decides between Ask and Agent mode in this repo.",
    ));

    let tool_call = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("workspace search route frame should dispatch file__search");
    assert!(tool_call.contains("\"name\":\"file__search\""));
    assert!(tool_call.contains("Hypervisor|Workbench|decides|Ask|Agent|mode"));
    assert!(!tool_call.contains("and|"));
}

#[test]
fn typed_runtime_workspace_overview_frame_reads_readme_after_structure_search() {
    let mut state = test_agent_state();
    state.runtime_route_frame = Some(typed_workspace_frame_with_evidence(
        "workspace_search",
        "Explore this repository and summarize the architecture.",
    ));

    let search = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("repo overview should begin with a structure search");
    assert!(search.contains("\"name\":\"file__search\""));
    assert!(search.contains("README|package"));
    record_execution_evidence_with_value(
        &mut state.tool_execution_log,
        "file_context",
        "step=1;tool=file__search;path=.;regex=README|package|Cargo|pyproject|go\\.mod|src|app|lib|crates|packages|export|import|function|class|test|config|script|dependency;file_pattern=*"
            .to_string(),
    );

    let read = maybe_typed_runtime_workspace_context_tool_call(&mut state)
        .expect("repo overview should read the README after the structure search");
    assert!(read.contains("\"name\":\"file__read\""));
    assert!(read.contains("README.md"));
    record_execution_evidence_with_value(
        &mut state.tool_execution_log,
        "file_context",
        "step=2;tool=file__read;path=README.md".to_string(),
    );

    assert!(maybe_typed_runtime_workspace_context_tool_call(&mut state).is_none());
}

#[test]
fn typed_runtime_install_route_does_not_parse_user_text_without_frame() {
    let mut state = test_agent_state();
    state.goal = "CHAT ARTIFACT ROUTE CONTRACT:\n- selected_route: install lmstudio\n- route_family: command_execution\n- output_intent: tool_execution\n- direct_answer_allowed: false\n- primary_tools: host_discovery, software_install_resolver, software_install__execute_plan, app__launch\nRUNTIME_ROUTE_FRAME_JSON:{\"intent_id\":\"software.install\"}\nUSER REQUEST:\ninstall lmstudio".to_string();

    assert!(maybe_typed_runtime_install_resolve_tool_call(&mut state).is_none());
}

#[test]
fn source_invariant_runtime_route_frames_are_not_prompt_dispatched() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let production_files = [
        repo_root.join("crates/api/src/chat/domain_topology/projection.rs"),
        repo_root.join("crates/services/src/agentic/runtime/service/decision_loop/mod.rs"),
    ];
    for path in production_files {
        let source = std::fs::read_to_string(&path).expect("source file readable");
        assert!(
            !source.contains("RUNTIME_ROUTE_FRAME_JSON"),
            "{} must not embed route frames in prompts",
            path.display()
        );
        assert!(
            !source.contains("typed_runtime_route_tool_call"),
            "{} must not use legacy route-frame tool-call markers",
            path.display()
        );
        assert!(
            !source.contains("typed_runtime_route_frame_from_goal"),
            "{} must not parse route frames from goal text",
            path.display()
        );
        assert!(
            !source.contains("first_http_url"),
            "{} must not extract executable browser targets from prompt text",
            path.display()
        );
    }
}

#[test]
fn source_invariant_browser_completion_uses_observation_receipts_not_title_strings() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let production_files = [
        repo_root.join("crates/services/src/agentic/runtime/execution/browser/handler.rs"),
        repo_root.join("crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/tool_outcome.rs"),
    ];
    for path in production_files {
        let source = std::fs::read_to_string(&path).expect("source file readable");
        assert!(
            !source.contains("Page title:"),
            "{} must not use browser title prose as an executable receipt",
            path.display()
        );
        assert!(
            !source.contains("split_once(\"Page title"),
            "{} must not parse browser title from arbitrary output strings",
            path.display()
        );
    }
}

#[test]
fn source_invariant_legacy_file_line_alias_is_not_advertised_or_executable() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let production_files = [
        repo_root.join("crates/services/src/agentic/runtime/tools/contracts.rs"),
        repo_root.join("crates/services/src/agentic/runtime/tools/builtins/filesystem_chat.rs"),
        repo_root.join("crates/services/src/agentic/runtime/worker_templates.rs"),
        repo_root
            .join("crates/services/src/agentic/runtime/service/decision_loop/cognition/mod.rs"),
        repo_root.join("crates/services/src/agentic/runtime/service/decision_loop/worker.rs"),
        repo_root.join("crates/services/src/agentic/runtime/execution/filesystem/handler.rs"),
    ];
    for path in production_files {
        let source = std::fs::read_to_string(&path).expect("source file readable");
        assert!(
            !source.contains("file__replace_line"),
            "{} must not advertise or execute the legacy line-edit alias",
            path.display()
        );
    }
}

#[test]
fn workspace_search_regex_uses_project_structure_terms_for_broad_repo_summaries() {
    let regex =
        super::workspace_search_regex("Explore this repository and summarize the architecture.");

    assert!(regex.contains("README"), "{regex}");
    assert!(regex.contains("package"), "{regex}");
    assert!(regex.contains("export"), "{regex}");
    assert!(!regex.contains("explore|architecture"), "{regex}");
}

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = image::ImageBuffer::<image::Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {error}")))?;
        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".to_string())
    }

    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root/>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_test_service() -> RuntimeAgentService {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let runtime = Arc::new(MockInferenceRuntime);
    RuntimeAgentService::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime,
    )
}

fn build_test_service_hybrid(
    fast_inference: Arc<dyn InferenceRuntime>,
    reasoning_inference: Arc<dyn InferenceRuntime>,
) -> RuntimeAgentService {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_inference,
        reasoning_inference,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn typed_runtime_install_bypasses_intent_inference_before_resolution() {
    let runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This inference output should never be consumed.",
    ]));
    let memory_path = std::env::temp_dir().join(format!(
        "ioi_typed_runtime_install_bypass_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos())
    ));
    let memory_runtime =
        MemoryRuntime::open_sqlite(&memory_path).expect("memory runtime should initialize");
    let service = build_test_service_hybrid(runtime.clone(), runtime.clone())
        .with_memory_runtime(Arc::new(memory_runtime));
    let mut state = MockState::default();
    let session_id = [0x64; 32];
    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.runtime_route_frame = Some(typed_install_frame("ffmpeg"));
    let key = get_state_key(&session_id);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("agent state encodes"),
        )
        .expect("state insert succeeds");

    let services = ServiceDirectory::default();
    let mut ctx = TxContext {
        block_height: 7,
        block_timestamp: 1_750_000_000_000_000_000,
        chain_id: ChainId(0),
        signer_account_id: AccountId([9u8; 32]),
        services: &services,
        simulation: false,
        is_internal: false,
    };

    handle_step(
        &service,
        &mut state,
        StepAgentParams { session_id },
        &mut ctx,
    )
    .await
    .expect("typed install resolver step should process");

    let second_step = handle_step(
        &service,
        &mut state,
        StepAgentParams { session_id },
        &mut ctx,
    )
    .await;
    if let Err(error) = &second_step {
        assert!(
            error
                .to_string()
                .contains("Awaiting install approval: ffmpeg"),
            "unexpected second-step error: {error}"
        );
    }

    let updated: AgentState = codec::from_bytes_canonical(
        &state
            .get(&key)
            .expect("state get succeeds")
            .expect("agent state remains persisted"),
    )
    .expect("updated state decodes");
    assert!(
        matches!(
        updated.status,
        AgentStatus::Paused(ref reason)
            if reason.contains("Awaiting install approval: ffmpeg")
        ),
        "unexpected status after typed install handoff: status={:?} pending_tool_call={:?} queue_len={} log={:?}",
        updated.status,
        updated.pending_tool_call,
        updated.execution_queue.len(),
        updated.tool_execution_log
    );
    let _ = std::fs::remove_file(memory_path);
}

#[derive(Debug, Default)]
struct RecordingInferenceRuntime {
    outputs: Mutex<Vec<Vec<u8>>>,
    seen_inputs: Mutex<Vec<String>>,
}

impl RecordingInferenceRuntime {
    fn with_outputs<I>(outputs: I) -> Self
    where
        I: IntoIterator<Item = &'static str>,
    {
        let mut queued = outputs
            .into_iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        queued.reverse();
        Self {
            outputs: Mutex::new(queued),
            seen_inputs: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl InferenceRuntime for RecordingInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .push(String::from_utf8_lossy(input_context).to_string());
        self.outputs
            .lock()
            .expect("outputs mutex poisoned")
            .pop()
            .ok_or_else(|| VmError::HostError("no mock output queued".to_string()))
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn resolved_web_intent_with_playbook(playbook_id: &str) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "web.research".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent-query-norm-v1".to_string(),
        intent_catalog_source_hash: [4u8; 32],
        evidence_requirements_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: Some(InstructionContract {
            operation: "web.research".to_string(),
            side_effect_mode: Default::default(),
            slot_bindings: vec![InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some(playbook_id.to_string()),
                origin: ArgumentOrigin::default(),
                protected_slot_kind: Default::default(),
            }],
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }
}

fn resolved_conversation_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "conversation.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent-query-norm-v1".to_string(),
        intent_catalog_source_hash: [4u8; 32],
        evidence_requirements_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn stale_canonical_pending_requires_cleanup_without_approval_or_runtime_retry() {
    let mut state = test_agent_state();
    state.pending_tool_jcs = Some(vec![1, 2, 3]);
    assert!(should_clear_stale_canonical_pending(&state, false));
}

#[test]
fn canonical_pending_is_not_stale_when_runtime_retry_is_expected() {
    let mut state = test_agent_state();
    state.pending_tool_jcs = Some(vec![1, 2, 3]);
    assert!(!should_clear_stale_canonical_pending(&state, true));
}

#[test]
fn retry_blocked_pause_auto_resumes_and_clears_recent_actions() {
    let mut state = test_agent_state();
    state.status =
        AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".to_string());
    state.recent_actions = vec!["file__read".to_string()];

    ensure_agent_running_or_resume_retry_pause(&mut state).expect("retry pause should resume");

    assert_eq!(state.status, AgentStatus::Running);
    assert!(state.recent_actions.is_empty());
}

#[test]
fn non_retry_pause_is_rejected_by_step_resumption_gate() {
    let mut state = test_agent_state();
    state.status = AgentStatus::Paused("Waiting for human approval".to_string());

    let error = ensure_agent_running_or_resume_retry_pause(&mut state)
        .expect_err("non-retry pause should not auto-resume");

    assert!(error
        .to_string()
        .contains("Agent not running: Paused(\"Waiting for human approval\")"));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_generates_chat_reply_for_conversation_route() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "The Pythagorean theorem states that in a right triangle, a^2 + b^2 = c^2.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x61; 32];
    agent_state.goal = "What is the Pythagorean theorem?".to_string();
    agent_state.resolved_intent = Some(resolved_conversation_intent());

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("direct inline authoring should succeed");

    let tool_call = tool_call.expect("conversation route should synthesize chat reply");
    let payload: serde_json::Value =
        serde_json::from_str(&tool_call).expect("tool call should decode");
    assert_eq!(
        payload.get("name").and_then(|value| value.as_str()),
        Some("chat__reply")
    );
    assert_eq!(
        payload
            .get("arguments")
            .and_then(|arguments| arguments.get("message"))
            .and_then(|value| value.as_str()),
        Some("The Pythagorean theorem states that in a right triangle, a^2 + b^2 = c^2.")
    );

    let seen_inputs = fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned");
    assert_eq!(seen_inputs.len(), 1);
    assert!(seen_inputs[0].contains("Return ONLY the final user-facing answer text."));
    assert!(seen_inputs[0].contains("What is the Pythagorean theorem?"));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_routes_lightweight_conversation_through_model() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "Hi. What would you like to work on?",
        "You're welcome.",
        "Got it.",
        "I'm doing fine and ready to help.",
        "You're welcome.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let cases = [
        ("hiya bot", "Hi. What would you like to work on?"),
        ("thanks dearie", "You're welcome."),
        ("sounds good", "Got it."),
        ("how are you?", "I'm doing fine and ready to help."),
    ];

    for (idx, (goal, expected_message)) in cases.iter().enumerate() {
        let mut agent_state = test_agent_state();
        let session_byte = 0x67_u8 + idx as u8;
        agent_state.session_id = [session_byte; 32];
        agent_state.goal = (*goal).to_string();
        agent_state.resolved_intent = Some(resolved_conversation_intent());

        let tool_call = maybe_direct_inline_author_tool_call(
            &service,
            &state,
            &agent_state,
            agent_state.session_id,
            ExecutionTier::DomHeadless,
        )
        .await
        .expect("lightweight conversation should evaluate")
        .expect("lightweight conversation should synthesize chat reply");

        let payload: serde_json::Value =
            serde_json::from_str(&tool_call).expect("tool call should decode");
        assert_eq!(
            payload.get("name").and_then(|value| value.as_str()),
            Some("chat__reply")
        );
        assert_eq!(
            payload
                .get("arguments")
                .and_then(|arguments| arguments.get("message"))
                .and_then(|value| value.as_str()),
            Some(*expected_message)
        );
    }

    let mut unknown_agent_state = test_agent_state();
    unknown_agent_state.session_id = [0x6c; 32];
    unknown_agent_state.goal = "thanks".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "unknown".to_string();
    intent.scope = IntentScopeProfile::Unknown;
    intent.required_capabilities.clear();
    unknown_agent_state.resolved_intent = Some(intent);
    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &unknown_agent_state,
        unknown_agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("unknown lightweight conversation should evaluate")
    .expect("unknown lightweight conversation should synthesize chat reply");
    let payload: serde_json::Value =
        serde_json::from_str(&tool_call).expect("tool call should decode");
    assert_eq!(
        payload
            .get("arguments")
            .and_then(|arguments| arguments.get("message"))
            .and_then(|value| value.as_str()),
        Some("You're welcome.")
    );

    let seen_inputs = fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned");
    assert_eq!(seen_inputs.len(), 5);
    for (goal, _) in cases {
        assert!(
            seen_inputs.iter().any(|input| input.contains(goal)),
            "expected model prompt for lightweight utterance: {goal}"
        );
    }
    assert!(seen_inputs.iter().any(|input| input.contains("thanks")));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_handles_plain_unknown_chat_utterance() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "Mm. They can only ignore it for so long.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x64; 32];
    agent_state.goal = "they can only ignore it for so long".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "unknown".to_string();
    intent.scope = IntentScopeProfile::Unknown;
    intent.required_capabilities.clear();
    agent_state.resolved_intent = Some(intent);

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("plain unknown utterance should evaluate");

    let payload: serde_json::Value =
        serde_json::from_str(&tool_call.expect("plain utterance should synthesize chat reply"))
            .expect("tool call should decode");
    assert_eq!(
        payload
            .get("arguments")
            .and_then(|arguments| arguments.get("message"))
            .and_then(|value| value.as_str()),
        Some("Mm. They can only ignore it for so long.")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_unknown_file_or_repo_requests() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x65; 32];
    agent_state.goal =
        "what does progress look like per .internal/plans/runtime-guide.md".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "unknown".to_string();
    intent.scope = IntentScopeProfile::Unknown;
    intent.required_capabilities.clear();
    agent_state.resolved_intent = Some(intent);

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("unknown repo-like request should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_unknown_currentness_requests() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x66; 32];
    agent_state.goal = "Is AKT or Filecoin a better investment right now?".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "unknown".to_string();
    intent.scope = IntentScopeProfile::Unknown;
    intent.required_capabilities.clear();
    agent_state.resolved_intent = Some(intent);

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("unknown currentness request should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_conversation_currentness_requests() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x67; 32];
    agent_state.goal = "Which is a better investment right now, Akash or Filecoin?".to_string();
    agent_state.resolved_intent = Some(resolved_conversation_intent());

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("conversation currentness request should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_research_routes() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x62; 32];
    agent_state.goal = "What is the weather in Boston today?".to_string();
    agent_state.resolved_intent =
        Some(resolved_web_intent_with_playbook("citation_grounded_brief"));

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("research route should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_delegation_routes() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x63; 32];
    agent_state.goal = "Wait for the child worker result".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "delegation.task".to_string();
    intent.scope = IntentScopeProfile::Delegation;
    intent.required_capabilities = vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("delegation.manage"),
    ];
    agent_state.resolved_intent = Some(intent);

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("delegation route should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn optimizer_recovery_is_skipped_without_optimizer_configuration() {
    let service = build_test_service();
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x44; 32];
    agent_state.consecutive_failures = 3;
    let session_id = agent_state.session_id;
    let key = get_state_key(&session_id);

    let triggered =
        maybe_run_optimizer_recovery(&service, &mut state, &mut agent_state, session_id, &key, 7)
            .await
            .expect("optimizer gate should evaluate");

    assert!(!triggered);
    assert_eq!(agent_state.consecutive_failures, 3);
    assert!(agent_state.active_skill_hash.is_none());
}

#[test]
fn zero_budget_does_not_trip_retry_limit_before_failure_ceiling() {
    let service = build_test_service();
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x51; 32];
    agent_state.budget = 0;
    agent_state.consecutive_failures = 4;
    let key = get_state_key(&agent_state.session_id);

    let failed = maybe_fail_step_resource_limits(&service, &mut state, &mut agent_state, &key)
        .expect("resource limit guard should evaluate");

    assert!(!failed);
    assert_eq!(agent_state.status, AgentStatus::Running);
    assert!(state
        .get(&key)
        .expect("state lookup should succeed")
        .is_none());
}

#[test]
fn retry_limit_terminalizes_after_failure_ceiling_even_with_zero_budget() {
    let service = build_test_service();
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x52; 32];
    agent_state.budget = 0;
    agent_state.consecutive_failures = 5;
    let key = get_state_key(&agent_state.session_id);

    let failed = maybe_fail_step_resource_limits(&service, &mut state, &mut agent_state, &key)
        .expect("resource limit guard should evaluate");

    assert!(failed);
    assert_eq!(
        agent_state.status,
        AgentStatus::Failed("Resources/Retry limit exceeded".to_string())
    );
    assert!(state
        .get(&key)
        .expect("state lookup should succeed")
        .is_some());
}

#[test]
fn root_playbook_delegate_is_queued_without_cognition() {
    let session_id = [6u8; 32];
    let playbook_id = "citation_grounded_brief";
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.goal = "Research the latest NIST PQC standards.".to_string();
    agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));

    let queued = queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
        .expect("queue delegate request");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert_eq!(
        agent_state.execution_queue[0].target,
        ActionTarget::Custom("agent__delegate".to_string())
    );
    let args: serde_json::Value = serde_json::from_slice(&agent_state.execution_queue[0].params)
        .expect("delegate params should decode");
    assert_eq!(
        args.get("goal").and_then(|value| value.as_str()),
        Some("Research the latest NIST PQC standards.")
    );
    assert_eq!(
        args.get("playbook_id").and_then(|value| value.as_str()),
        Some(playbook_id)
    );

    let run = ParentPlaybookRun {
        parent_session_id: session_id,
        playbook_id: playbook_id.to_string(),
        playbook_label: "Citation-Grounded Brief".to_string(),
        topic: "latest NIST PQC standards".to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some([9u8; 32]),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: vec![],
    };
    state
        .insert(
            &get_parent_playbook_run_key(&session_id, playbook_id),
            &codec::to_bytes_canonical(&run).expect("playbook bytes"),
        )
        .expect("persist playbook run");
    agent_state.execution_queue.clear();

    let queued_again = queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
        .expect("queue delegate request after kickoff");

    assert!(!queued_again);
    assert!(agent_state.execution_queue.is_empty());
    state
        .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
        .expect("delete playbook run");

    let child_session_id = [10u8; 32];
    let mut child_state = test_agent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some(session_id);
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist child state");
    agent_state.child_session_ids.push(child_session_id);

    let queued_with_child =
        queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
            .expect("queue delegate request after child spawn");

    assert!(!queued_with_child);
    assert!(agent_state.execution_queue.is_empty());
}

#[test]
fn active_parent_playbook_child_gets_single_startup_await_without_cognition() {
    let session_id = [7u8; 32];
    let child_session_id = [8u8; 32];
    let playbook_id = "citation_grounded_brief";
    let mut state = MockState::default();
    let run = ParentPlaybookRun {
        parent_session_id: session_id,
        playbook_id: playbook_id.to_string(),
        playbook_label: "Citation-Grounded Brief".to_string(),
        topic: "latest NIST PQC standards".to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some(child_session_id),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: vec![],
    };
    state
        .insert(
            &get_parent_playbook_run_key(&session_id, playbook_id),
            &codec::to_bytes_canonical(&run).expect("playbook bytes"),
        )
        .expect("persist playbook run");

    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
    let mut child_state = test_agent_state();
    child_state.session_id = child_session_id;
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist child state");

    let queued = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert_eq!(
        agent_state.execution_queue[0].target,
        ActionTarget::Custom("agent__await".to_string())
    );
    let args: serde_json::Value = serde_json::from_slice(&agent_state.execution_queue[0].params)
        .expect("await params should decode");
    assert_eq!(
        args.get("child_session_id_hex")
            .and_then(|value| value.as_str()),
        Some(hex::encode(child_session_id).as_str())
    );

    child_state.step_count = 1;
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist updated child state");
    agent_state.execution_queue.clear();

    let queued_again = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child start");

    assert!(queued_again);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();

    child_state.status = AgentStatus::Completed(Some(
        "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)"
            .to_string(),
    ));
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist completed child state");

    let queued_terminal = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child completion");

    assert!(queued_terminal);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();
    child_state.status = AgentStatus::Running;
    child_state.pending_tool_call =
        Some("{\"name\":\"agent__complete\",\"arguments\":{\"result\":\"done\"}}".to_string());
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist pending child state");

    let queued_pending = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child pending tool");

    assert!(queued_pending);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();
    child_state.pending_tool_call = None;

    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::Custom("web__read".to_string()),
        params: serde_jcs::to_vec(&serde_json::json!({
            "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
        }))
        .expect("queued child params"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(child_session_id),
            window_id: None,
        },
        nonce: 1,
    });
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist queued child state");

    let queued_followup = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request for queued child follow-up");

    assert!(queued_followup);
    assert_eq!(agent_state.execution_queue.len(), 1);
    state
        .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
        .expect("delete playbook run");

    let fallback_child_session_id = [9u8; 32];
    let mut fallback_agent_state = test_agent_state();
    fallback_agent_state.session_id = session_id;
    fallback_agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
    fallback_agent_state
        .child_session_ids
        .push(fallback_child_session_id);
    let mut fallback_child_state = test_agent_state();
    fallback_child_state.session_id = fallback_child_session_id;
    fallback_child_state.parent_session_id = Some(session_id);
    state
        .insert(
            &get_state_key(&fallback_child_session_id),
            &codec::to_bytes_canonical(&fallback_child_state).expect("fallback child bytes"),
        )
        .expect("persist fallback child state");

    let fallback_queued =
        queue_parent_playbook_await_request(&state, &mut fallback_agent_state, session_id)
            .expect("queue await request from child fallback");

    assert!(fallback_queued);
    assert_eq!(fallback_agent_state.execution_queue.len(), 1);
    let fallback_args: serde_json::Value =
        serde_json::from_slice(&fallback_agent_state.execution_queue[0].params)
            .expect("fallback await params should decode");
    assert_eq!(
        fallback_args
            .get("child_session_id_hex")
            .and_then(|value| value.as_str()),
        Some(hex::encode(fallback_child_session_id).as_str())
    );
}
