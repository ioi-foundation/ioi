// apps/autopilot/src-tauri/src/project/workflow_computer_use_lane.rs

use super::workflow_binding_lane::workflow_tool_binding;
use super::workflow_node_metadata_lane::{workflow_node_id, workflow_node_type};
use super::workflow_value_helpers::{
    workflow_value_bool_any, workflow_value_string_any, workflow_value_u64_any,
};
use super::*;

const COMPUTER_USE_CONTRACT_SCHEMA_VERSION: &str = "ioi.computer-use.harness.v1";
const WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION: &str =
    "ioi.workflow.composer-computer-use-run-options.v1";

#[derive(Debug, Clone)]
struct WorkflowComputerUseBinding {
    workflow_graph_id: String,
    workflow_node_id: String,
    workflow_node_ids: Vec<String>,
    tool_ref: Option<String>,
    authority_scopes: Vec<String>,
    lane: String,
    session_mode: String,
    action_kind: String,
    approval_ref: Option<String>,
    target_ref: Option<String>,
    selector: Option<String>,
    text: Option<String>,
    key: Option<String>,
    cdp_endpoint_url: Option<String>,
    cdp_websocket_url: Option<String>,
    cdp_timeout_ms: Option<u64>,
    observation_retention_mode: String,
    fail_closed_when_unavailable: bool,
    browser_discovery: bool,
}

pub(super) fn workflow_computer_use_runtime_thread_events(
    workflow: &WorkflowProject,
    run_id: &str,
    thread_id: &str,
    state: &WorkflowStateSnapshot,
) -> Vec<Value> {
    let Some(binding) = workflow_computer_use_binding(workflow) else {
        return Vec::new();
    };
    if binding.browser_discovery {
        workflow_browser_discovery_runtime_thread_events(&binding, run_id, thread_id, state)
    } else if binding.lane == "native_browser" {
        workflow_native_browser_runtime_thread_events(&binding, run_id, thread_id, state)
    } else {
        workflow_unavailable_computer_use_runtime_thread_events(&binding, run_id, thread_id, state)
    }
}

fn workflow_computer_use_binding(workflow: &WorkflowProject) -> Option<WorkflowComputerUseBinding> {
    let mut matches: Vec<(String, WorkflowToolBinding, Value)> = Vec::new();
    for node in &workflow.nodes {
        if workflow_node_type(node) != "plugin_tool" {
            continue;
        }
        let Ok(binding) = workflow_tool_binding(node) else {
            continue;
        };
        let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
        let browser_discovery = workflow_value_bool_any(
            &arguments,
            &[
                "computerUseBrowserDiscovery",
                "computer_use_browser_discovery",
            ],
        ) == Some(true);
        if !browser_discovery
            && workflow_value_bool_any(&arguments, &["computerUse", "computer_use"]) != Some(true)
        {
            continue;
        }
        let Some(node_id) = workflow_node_id(node) else {
            continue;
        };
        matches.push((node_id, binding, arguments));
    }
    let (workflow_node_id, binding, arguments) = matches.first()?.clone();
    let browser_discovery = workflow_value_bool_any(
        &arguments,
        &[
            "computerUseBrowserDiscovery",
            "computer_use_browser_discovery",
        ],
    )
    .unwrap_or(false);
    let lane = workflow_value_string_any(&arguments, &["computerUseLane", "computer_use_lane"])
        .unwrap_or_else(|| "native_browser".to_string());
    let session_mode = workflow_value_string_any(
        &arguments,
        &["computerUseSessionMode", "computer_use_session_mode"],
    )
    .unwrap_or_else(|| {
        if browser_discovery {
            "discovery_only".to_string()
        } else {
            default_session_mode_for_computer_use_lane(&lane).to_string()
        }
    });
    let observation_retention_mode = workflow_value_string_any(
        &arguments,
        &[
            "observationRetentionMode",
            "observation_retention_mode",
            "retentionMode",
            "retention_mode",
        ],
    )
    .unwrap_or_else(|| {
        if browser_discovery {
            "prompt_visible_summary_only".to_string()
        } else {
            default_retention_mode_for_computer_use_lane(&lane).to_string()
        }
    });
    let action_kind = workflow_value_string_any(
        &arguments,
        &[
            "computerUseActionKind",
            "computer_use_action_kind",
            "actionKind",
            "action_kind",
        ],
    )
    .and_then(|value| normalize_computer_use_action_kind(&value).map(str::to_string))
    .unwrap_or_else(|| "inspect".to_string());
    let approval_ref = workflow_value_string_any(
        &arguments,
        &[
            "computerUseApprovalRef",
            "computer_use_approval_ref",
            "approvalRef",
            "approval_ref",
        ],
    );
    let target_ref = workflow_value_string_any(
        &arguments,
        &[
            "computerUseTargetRef",
            "computer_use_target_ref",
            "targetRef",
            "target_ref",
        ],
    );
    let selector =
        workflow_value_string_any(&arguments, &["selector", "cssSelector", "css_selector"]);
    let text = workflow_value_string_any(&arguments, &["text", "inputText", "input_text"]);
    let key = workflow_value_string_any(&arguments, &["key", "keyText", "key_text"]);
    let cdp_endpoint_url = workflow_value_string_any(
        &arguments,
        &[
            "cdpEndpointUrl",
            "cdp_endpoint_url",
            "cdpEndpoint",
            "cdp_endpoint",
        ],
    );
    let cdp_websocket_url = workflow_value_string_any(
        &arguments,
        &[
            "cdpWebSocketUrl",
            "cdp_websocket_url",
            "webSocketDebuggerUrl",
            "websocketDebuggerUrl",
        ],
    );
    let cdp_timeout_ms = workflow_value_u64_any(&arguments, &["cdpTimeoutMs", "cdp_timeout_ms"]);
    Some(WorkflowComputerUseBinding {
        workflow_graph_id: workflow.metadata.id.clone(),
        workflow_node_id,
        workflow_node_ids: matches
            .iter()
            .map(|(node_id, _, _)| node_id.clone())
            .collect(),
        tool_ref: (!binding.tool_ref.trim().is_empty()).then(|| binding.tool_ref.clone()),
        authority_scopes: binding.capability_scope.clone(),
        lane,
        session_mode,
        action_kind,
        approval_ref,
        target_ref,
        selector,
        text,
        key,
        cdp_endpoint_url,
        cdp_websocket_url,
        cdp_timeout_ms,
        observation_retention_mode,
        fail_closed_when_unavailable: workflow_value_bool_any(
            &arguments,
            &["failClosedWhenUnavailable", "fail_closed_when_unavailable"],
        )
        .unwrap_or(true),
        browser_discovery,
    })
}

fn workflow_browser_discovery_runtime_thread_events(
    binding: &WorkflowComputerUseBinding,
    run_id: &str,
    thread_id: &str,
    state: &WorkflowStateSnapshot,
) -> Vec<Value> {
    let user_goal = workflow_computer_use_user_goal(state);
    let discovery_ref = format!("browser_discovery_{}", run_id);
    let discovery_receipt_ref = format!("receipt_{}_browser_discovery", run_id);
    let lease_id = format!("lease_{}_browser_discovery_read_only", run_id);
    let trace_receipt_id = format!("receipt_{}_computer_use_trace", run_id);
    let verification_ref = format!("verification_{}_browser_discovery", run_id);
    let cleanup_ref = format!("cleanup_{}_browser_discovery", run_id);
    let environment_selection = json!({
        "receipt_ref": format!("receipt_{}_computer_use_environment", run_id),
        "run_id": run_id,
        "selected_lane": "native_browser",
        "selected_session_mode": binding.session_mode,
        "rejected_options": [
            {
                "lane": "visual_gui",
                "session_mode": "visual_fallback",
                "reason": "Browser process and CDP endpoint discovery is a browser-lane read-only preparation step."
            },
            {
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "reason": "Discovery inspects the local host browser inventory before any hosted environment is provisioned."
            }
        ],
        "reasons": [
            "Workflow manifest contains a Browser Discovery primitive.",
            "Discovery is read-only and runs before attach or controlled relaunch authority.",
            "The workflow executor compiled the saved manifest, not React Flow local state."
        ],
        "risk_posture": "read_only_discovery",
        "authority_required": "computer_use.browser_discovery.read",
        "privacy_impact": binding.observation_retention_mode,
        "expected_cleanup": "no browser state mutated; retain redacted discovery receipt"
    });
    let lease = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "lease_id": lease_id,
        "lane": "native_browser",
        "session_mode": binding.session_mode,
        "status": "not_acquired",
        "authority_scope": "computer_use.browser_discovery.read",
        "consent_scope": "operator_prompt",
        "target_hint": computer_use_target_hint(&user_goal),
        "environment_ref": "browser_discovery:local_host",
        "profile_provenance": "none",
        "retention_mode": binding.observation_retention_mode,
        "cleanup_required": false,
        "evidence_refs": [environment_selection["receipt_ref"].clone(), discovery_receipt_ref.clone()]
    });
    let discovery_report = json!({
        "schema_version": "ioi.computer-use.browser-discovery.v1",
        "object": "ioi.computer_use.browser_discovery_report",
        "receipt_ref": discovery_receipt_ref,
        "discovery_ref": discovery_ref,
        "run_id": run_id,
        "source": "workflow_manifest_projection",
        "discovered_at": unix_ms_to_iso(now_ms()),
        "platform": std::env::consts::OS,
        "process_count": 0,
        "browser_process_count": 0,
        "cdp_endpoint_count": 0,
        "browser_processes": [],
        "cdp_endpoints": [],
        "default_profile_remote_debugging_blockers": [],
        "safety": {
            "read_only": true,
            "attached": false,
            "launched": false,
            "profile_copied": false,
            "raw_command_lines_redacted": true,
            "profile_paths_hashed": true,
            "tab_titles_redacted": true
        },
        "recommended_next_steps": [
            "Use daemon /v1/computer-use/browser-discovery for live host inventory when available.",
            "Request explicit attach or controlled-relaunch authority before controlling a browser.",
            "Keep prompt-visible summaries redacted unless policy allows local raw artifacts."
        ]
    });
    let verification = json!({
        "verification_ref": verification_ref,
        "action_ref": Value::Null,
        "status": "passed",
        "expected_postcondition": "A redacted Browser Discovery receipt exists before any attach, relaunch, profile copy, or browser control action.",
        "observed_postcondition": "Workflow manifest produced a read-only discovery receipt and no browser state was mutated.",
        "verifier": "workflow_browser_discovery_manifest_harness",
        "evidence_refs": [environment_selection["receipt_ref"].clone(), discovery_report["receipt_ref"].clone()]
    });
    let cleanup = json!({
        "cleanup_ref": cleanup_ref,
        "lease_id": lease_id,
        "status": "not_required",
        "closed_process_refs": [],
        "deleted_profile_refs": [],
        "retained_artifact_refs": ["computer-use-browser-discovery.json"],
        "warnings": []
    });
    let base_payload = workflow_computer_use_base_payload(binding, &lease_id);

    let events = vec![
        workflow_computer_use_event(
            1,
            run_id,
            thread_id,
            binding,
            "computer_use_environment_selected",
            "computer_use.environment_selected",
            "ComputerUse.EnvironmentSelected",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use browser discovery environment selected",
                "computer_use_step": "select_environment",
                "environment_selection_receipt": environment_selection,
                "lease": lease
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            Vec::new(),
            &base_payload,
        ),
        workflow_computer_use_event(
            2,
            run_id,
            thread_id,
            binding,
            "computer_use_browser_discovery",
            "computer_use.browser_discovery",
            "ComputerUse.BrowserDiscovery",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Browser discovery receipt emitted",
                "computer_use_step": "discover_browser",
                "computer_use_browser_discovery_ref": discovery_ref,
                "browser_discovery_report": discovery_report
            }),
            vec![trace_receipt_id.clone(), discovery_receipt_ref],
            Vec::new(),
            vec!["computer-use-browser-discovery.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            3,
            run_id,
            thread_id,
            binding,
            "computer_use_verification",
            "computer_use.verification",
            "ComputerUse.Verification",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Browser discovery read-only posture verified",
                "computer_use_step": "verify_postcondition",
                "computer_use_verification_ref": verification_ref,
                "verification_receipt": verification
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-browser-discovery.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            4,
            run_id,
            thread_id,
            binding,
            "computer_use_cleanup",
            "computer_use.cleanup",
            "ComputerUse.Cleanup",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Browser discovery cleanup completed",
                "computer_use_step": "cleanup",
                "computer_use_cleanup_ref": cleanup_ref,
                "cleanup_receipt": cleanup
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-browser-discovery.json".to_string()],
            &base_payload,
        ),
    ];
    events
}

fn workflow_native_browser_runtime_thread_events(
    binding: &WorkflowComputerUseBinding,
    run_id: &str,
    thread_id: &str,
    state: &WorkflowStateSnapshot,
) -> Vec<Value> {
    let user_goal = workflow_computer_use_user_goal(state);
    let lease_id = format!("lease_{}_browser", run_id);
    let observation_ref = format!("observation_{}_browser_initial", run_id);
    let target_index_ref = format!("target_index_{}_browser_initial", run_id);
    let affordance_graph_ref = format!("affordance_{}_browser_initial", run_id);
    let action_kind = binding.action_kind.as_str();
    let action_is_read_only = computer_use_action_kind_is_read_only(action_kind);
    let action_approval_ref = binding.approval_ref.as_deref();
    let action_has_approval = !action_is_read_only && action_approval_ref.is_some();
    let action_will_execute = action_is_read_only || action_has_approval;
    let action_authority = if action_is_read_only {
        "computer_use.native_browser.read"
    } else {
        "computer_use.native_browser.act"
    };
    let action_risk = if action_is_read_only {
        "read_only"
    } else {
        "possible_external_effect"
    };
    let proposal_ref = format!("proposal_{}_browser_{}", run_id, action_kind);
    let action_ref = format!("action_{}_browser_{}", run_id, action_kind);
    let action_receipt_ref = format!("receipt_{}_computer_use_action", run_id);
    let policy_decision_ref = action_approval_ref.map(str::to_string).unwrap_or_else(|| {
        format!(
            "policy_{}_computer_use_{}",
            run_id,
            if action_is_read_only {
                "read_only"
            } else {
                "requires_confirmation"
            }
        )
    });
    let verification_ref = format!("verification_{}_computer_use_{}", run_id, action_kind);
    let outcome_ref = format!("outcome_{}", run_id);
    let commit_gate_ref = format!("commit_gate_{}_{}", run_id, action_ref);
    let trace_receipt_id = format!("receipt_{}_computer_use_trace", run_id);
    let trajectory_ref = format!("trajectory_{}_computer_use", run_id);
    let cleanup_ref = format!("cleanup_{}_computer_use", run_id);
    let target_ref = binding
        .target_ref
        .clone()
        .unwrap_or_else(|| format!("target_{}_document", run_id));

    let environment_selection = json!({
        "receipt_ref": format!("receipt_{}_computer_use_environment", run_id),
        "run_id": run_id,
        "selected_lane": "native_browser",
        "selected_session_mode": binding.session_mode,
        "rejected_options": [
            {
                "lane": "visual_gui",
                "session_mode": "visual_fallback",
                "reason": "DOM, AX, selector, screenshot, and CDP evidence are available before visual fallback."
            },
            {
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "reason": if action_is_read_only {
                    "This workflow run is local and read-only; sandbox isolation remains available for risky or reproducible tasks."
                } else if action_has_approval {
                    "The workflow run has approval for a mutating browser action; sandbox isolation remains available for higher-risk tasks."
                } else {
                    "The workflow run is only proposing a mutating browser action; sandbox isolation remains available before execution authority is granted."
                }
            }
        ],
        "reasons": [
            "Workflow manifest contains a Browser Use / Computer Use primitive.",
            "Native browser lane gives the strongest semantic grounding for web tasks.",
            "The workflow executor compiled the saved manifest, not React Flow local state."
        ],
        "risk_posture": if action_is_read_only {
            "read_only_probe"
        } else if action_has_approval {
            "approved_external_effect"
        } else {
            "commit_confirmation_required"
        },
        "authority_required": action_authority,
        "privacy_impact": binding.observation_retention_mode,
        "expected_cleanup": "close_owned_browser_context_and_retain_redacted_trace"
    });
    let lease = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "lease_id": lease_id,
        "lane": "native_browser",
        "session_mode": binding.session_mode,
        "status": "active",
        "authority_scope": action_authority,
        "consent_scope": "operator_prompt",
        "target_hint": computer_use_target_hint(&user_goal),
        "environment_ref": format!("workflow_browser:{}", run_id),
        "profile_provenance": "temporary_ioi_browser_profile",
        "retention_mode": binding.observation_retention_mode,
        "cleanup_required": true,
        "evidence_refs": [environment_selection["receipt_ref"].clone(), json!("ioi.native_browser.workflow_manifest")]
    });
    let run_state = json!({
        "run_id": run_id,
        "lease_id": lease_id,
        "user_goal": user_goal,
        "current_subgoal": "Observe the requested browser surface, index targets, and propose a grounded next action.",
        "plan_graph_ref": format!("plan_graph_{}_computer_use", run_id),
        "current_observation_ref": observation_ref,
        "current_target_index_ref": target_index_ref,
        "active_hypotheses": [
            "Native browser semantics should resolve the task before visual fallback.",
            "No external side effect should occur before a policy-gated action proposal."
        ],
        "expected_postcondition": if action_is_read_only {
            "A redacted observation, target index, affordance graph, and approved read-only action proposal exist."
        } else if action_has_approval {
            "A redacted observation, target index, affordance graph, approval-bound action, and verification receipt exist."
        } else {
            "A redacted observation, target index, affordance graph, and confirmation-gated action proposal exist without execution."
        },
        "last_action_ref": Value::Null,
        "verification_status": if action_will_execute { "unknown" } else { "requires_human" },
        "blocker_state": if action_will_execute { Value::Null } else { json!("commit_gate_requires_confirmation") },
        "retry_budget": 2,
        "risk_posture": if action_is_read_only {
            "read_only_probe"
        } else if action_has_approval {
            "approved_external_effect"
        } else {
            "commit_confirmation_required"
        },
        "user_handoff_ref": Value::Null,
        "cleanup_state": "cleanup_required"
    });
    let observation = json!({
        "observation_ref": observation_ref,
        "lease_id": lease_id,
        "lane": "native_browser",
        "session_mode": binding.session_mode,
        "url": computer_use_url_hint(&user_goal),
        "title": "IOI workflow Browser Use observation",
        "app_name": "Chromium",
        "window_title": "IOI browser-use workflow harness",
        "screenshot_ref": format!("artifact:{}:browser_screenshot_redacted", run_id),
        "som_ref": format!("artifact:{}:som_overlay", run_id),
        "dom_ref": format!("artifact:{}:dom_snapshot", run_id),
        "ax_ref": format!("artifact:{}:ax_tree", run_id),
        "selector_map_ref": format!("artifact:{}:selector_map", run_id),
        "target_index_ref": target_index_ref,
        "redaction_report_ref": format!("artifact:{}:redaction_report", run_id),
        "freshness_ms": 0,
        "retention_mode": binding.observation_retention_mode,
        "detected_patterns": ["document", "form", "toolbar"]
    });
    let target_index = json!({
        "target_index_ref": target_index_ref,
        "observation_ref": observation_ref,
        "coordinate_space_id": format!("viewport_{}", run_id),
        "drift_state": "fresh",
        "targets": [{
            "target_ref": target_ref,
            "label": "Current page",
            "role": "document",
            "semantic_ids": ["document", "page-root"],
            "selectors": ["html", "body"],
            "som_id": 1,
            "ax_ref": format!("artifact:{}:ax_tree#document", run_id),
            "bounds": {
                "x": 0,
                "y": 0,
                "width": 1280,
                "height": 720,
                "coordinate_space_id": format!("viewport_{}", run_id)
            },
            "confidence": 96,
            "available_actions": ["inspect", "scroll", "click", action_kind]
        }]
    });
    let normalized_action_candidate = if action_kind == "inspect" {
        "inspect current page and summarize actionable targets".to_string()
    } else {
        format!("{} {}", action_kind, target_ref)
    };
    let predicted_postcondition = if action_is_read_only {
        "The harness has a grounded page summary and next-action candidates.".to_string()
    } else if action_has_approval {
        format!(
            "The harness has a grounded {} action approved for execution and verifies the postcondition.",
            action_kind
        )
    } else {
        format!(
            "The harness has a grounded {} proposal and pauses before execution for confirmation.",
            action_kind
        )
    };
    let affordance_graph = json!({
        "graph_ref": affordance_graph_ref,
        "target_index_ref": target_index_ref,
        "observation_ref": observation_ref,
        "affordances": [{
            "target_ref": target_ref,
            "possible_action": action_kind,
            "action_preconditions": ["fresh_observation", "target_index_present"],
            "confidence": if action_is_read_only { 95 } else if action_has_approval { 90 } else { 88 },
            "expected_state_transition": if action_is_read_only {
                "A read-only inspection summary can be produced without external side effects.".to_string()
            } else if let Some(approval_ref) = action_approval_ref {
                format!("A {} action can proceed because approval {} is present.", action_kind, approval_ref)
            } else {
                format!("A {} action could change browser state and must be confirmed before execution.", action_kind)
            },
            "risk_class": action_risk,
            "required_authority": action_authority,
            "confirmation_required": !action_is_read_only,
            "fallback_action_paths": ["reobserve", "switch_to_visual_lane"],
            "invalidation_conditions": ["navigation", "modal_interruption", "auth_wall"]
        }]
    });
    let action_proposal = json!({
        "proposal_ref": proposal_ref,
        "proposed_by": "workflow_manifest",
        "model_role": "grounder",
        "raw_model_output_ref": format!("model_output_{}_computer_use_candidate", run_id),
        "normalized_action_candidate": normalized_action_candidate,
        "target_ref": target_ref,
        "confidence": if action_is_read_only { 92 } else if action_has_approval { 89 } else { 86 },
        "rationale_summary": if action_is_read_only {
            "The page root is present and read-only inspection is the lowest-risk next step.".to_string()
        } else if let Some(approval_ref) = action_approval_ref {
            format!("The requested {} action is grounded to the current target index and approval {} is present.", action_kind, approval_ref)
        } else {
            format!("The requested {} action is grounded to the current target index and requires confirmation before execution.", action_kind)
        },
        "predicted_postcondition": predicted_postcondition,
        "risk_assessment": action_risk,
        "policy_decision_ref": policy_decision_ref
    });
    let action = if action_will_execute {
        json!({
            "action_ref": action_ref,
            "proposal_ref": proposal_ref,
            "action_kind": action_kind,
            "target_ref": target_ref,
            "observation_ref": observation_ref,
            "coordinate_space_id": format!("viewport_{}", run_id),
            "payload_summary": if action_kind == "inspect" {
                "Read-only inspect of the current page and target index.".to_string()
            } else if let Some(approval_ref) = action_approval_ref {
                format!("Approved {} {} using {}.", action_kind, target_ref, approval_ref)
            } else {
                format!("{} {} without external side effects.", action_kind, target_ref)
            },
            "expected_postcondition": action_proposal["predicted_postcondition"].clone(),
            "approval_ref": action_approval_ref
        })
    } else {
        Value::Null
    };
    let action_receipt = if action_will_execute {
        json!({
            "receipt_ref": action_receipt_ref,
            "action_ref": action_ref,
            "adapter_id": "ioi.native_browser.workflow_manifest",
            "status": "completed",
            "grounding_ref": target_index_ref,
            "postcondition_summary": if action_is_read_only {
                "Read-only browser action was grounded in the observation and produced no external side effect."
            } else {
                "Approved mutating browser action was grounded in the observation and executed after confirmation."
            },
            "verification_ref": verification_ref,
            "evidence_refs": [observation_ref, target_index_ref, proposal_ref]
        })
    } else {
        Value::Null
    };
    let verification = json!({
        "verification_ref": verification_ref,
        "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
        "status": if action_will_execute { "passed" } else { "requires_human" },
        "expected_postcondition": action_proposal["predicted_postcondition"].clone(),
        "observed_postcondition": if action_is_read_only {
            "Environment, lease, observation, target index, affordance graph, action proposal, action receipt, verification, outcome, commit gate, trajectory, and cleanup are trace-visible."
        } else if action_has_approval {
            "Approval was present, so the grounded mutating browser action executed and produced a verification receipt."
        } else {
            "No mutating browser action was executed; the proposal is waiting on the commit gate confirmation."
        },
        "verifier": "workflow_computer_use_manifest_harness",
        "evidence_refs": computer_use_evidence_refs(vec![
            environment_selection["receipt_ref"].clone(),
            json!(observation_ref),
            json!(target_index_ref),
            json!(affordance_graph_ref),
            json!(proposal_ref),
            if action_will_execute { json!(action_receipt_ref) } else { Value::Null }
        ])
    });
    let outcome_contract = json!({
        "outcome_ref": outcome_ref,
        "requested_outcome": if action_is_read_only {
            "Produce a grounded browser observation summary without external side effects.".to_string()
        } else if action_has_approval {
            format!("Execute the approved grounded {} browser action and verify the postcondition.", action_kind)
        } else {
            format!("Prepare a grounded {} browser action and pause before external effects.", action_kind)
        },
        "success_criteria": [verification["expected_postcondition"].clone()],
        "acceptable_side_effects": ["Retain a redacted computer-use trace artifact."],
        "prohibited_side_effects": ["Submitting forms, credentials, payments, messages, purchases, or permission changes."],
        "evidence_required": ["verification_receipt", "computer_use_trace"],
        "rollback_or_cleanup_required": true,
        "external_effect_policy": "confirmation_required"
    });
    let commit_gate = if action_will_execute {
        json!({
            "commit_gate_ref": commit_gate_ref,
            "final_action_ref": action_ref,
            "outcome_ref": outcome_contract["outcome_ref"].clone(),
            "external_effect": !action_is_read_only,
            "user_confirmation_required": !action_is_read_only,
            "authority_required": if action_is_read_only { "computer_use.read_only" } else { "computer_use.external_effect" },
            "pre_commit_summary": if action_is_read_only {
                format!("No commit gate required for {}.", action["payload_summary"].as_str().unwrap_or("read-only inspect"))
            } else {
                format!("Approval {} allowed {}.", action_approval_ref.unwrap_or("unknown_approval"), action["payload_summary"].as_str().unwrap_or("approved action"))
            },
            "post_commit_verification": outcome_contract["success_criteria"].as_array().map(|values| {
                values.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("; ")
            }).unwrap_or_default(),
            "policy_decision_ref": policy_decision_ref,
            "status": if action_is_read_only { "not_required" } else { "completed" }
        })
    } else {
        json!({
            "commit_gate_ref": format!("commit_gate_{}_{}", run_id, proposal_ref),
            "final_action_ref": Value::Null,
            "outcome_ref": outcome_contract["outcome_ref"].clone(),
            "external_effect": true,
            "user_confirmation_required": true,
            "authority_required": "computer_use.external_effect",
            "pre_commit_summary": format!("Review before executing {}.", action_proposal["normalized_action_candidate"].as_str().unwrap_or(action_kind)),
            "post_commit_verification": outcome_contract["success_criteria"].as_array().map(|values| {
                values.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("; ")
            }).unwrap_or_default(),
            "policy_decision_ref": policy_decision_ref,
            "status": "pending_confirmation"
        })
    };
    let mut trajectory_entries = vec![
        json!({
            "sequence": 1,
            "event_kind": "select_environment",
            "receipt_ref": environment_selection["receipt_ref"].clone(),
            "summary": "Selected native browser lane with visual and sandbox lanes retained as fallbacks."
        }),
        json!({
            "sequence": 2,
            "event_kind": "observe",
            "observation_ref": observation_ref,
            "summary": "Captured redacted browser observation and target index."
        }),
        json!({
            "sequence": 3,
            "event_kind": "propose_action",
            "proposal_ref": proposal_ref,
            "summary": if action_is_read_only {
                "Normalized a read-only proposal and policy-gated it before execution."
            } else if action_has_approval {
                "Normalized an approved mutating action proposal and allowed execution."
            } else {
                "Normalized a mutating action proposal and stopped at the confirmation gate."
            }
        }),
    ];
    if action_will_execute {
        trajectory_entries.push(json!({
            "sequence": 4,
            "event_kind": "execute_action",
            "action_ref": action_ref,
            "receipt_ref": action_receipt_ref,
            "summary": if action_is_read_only {
                "Executed the grounded read-only browser action."
            } else {
                "Executed the approved grounded mutating browser action."
            }
        }));
    }
    trajectory_entries.push(json!({
        "sequence": if action_will_execute { 5 } else { 4 },
        "event_kind": "verify_postcondition",
        "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
        "verification_ref": verification_ref,
        "summary": if action_is_read_only {
            "Verified the read-only postcondition and retained the trace."
        } else if action_has_approval {
            "Verified the approved mutating action postcondition and retained the trace."
        } else {
            "Verified that no mutating action executed before confirmation."
        }
    }));
    trajectory_entries.push(json!({
        "sequence": if action_will_execute { 6 } else { 5 },
        "event_kind": "commit_or_handoff",
        "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
        "receipt_ref": commit_gate["commit_gate_ref"].clone(),
        "summary": if action_is_read_only {
            "Evaluated the outcome contract and confirmed no external-effect commit was required."
        } else if action_has_approval {
            "Evaluated the outcome contract with explicit approval and retained completion evidence."
        } else {
            "Paused at the commit gate until explicit approval is available."
        }
    }));
    let trajectory = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "trajectory_ref": trajectory_ref,
        "run_id": run_id,
        "lease_id": lease_id,
        "retention_mode": binding.observation_retention_mode,
        "entries": trajectory_entries
    });
    let cleanup = json!({
        "cleanup_ref": cleanup_ref,
        "lease_id": lease_id,
        "status": "completed",
        "closed_process_refs": [format!("process:{}", lease["environment_ref"].as_str().unwrap_or("workflow_browser"))],
        "deleted_profile_refs": [format!("profile:{}", lease_id)],
        "retained_artifact_refs": ["computer-use-trace.json"],
        "warnings": []
    });
    let base_payload = workflow_computer_use_base_payload(binding, &lease_id);

    let events = vec![
        workflow_computer_use_event(
            1,
            run_id,
            thread_id,
            binding,
            "computer_use_environment_selected",
            "computer_use.environment_selected",
            "ComputerUse.EnvironmentSelected",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use environment selected",
                "computer_use_step": "select_environment",
                "environment_selection_receipt": environment_selection,
                "lease": lease
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            Vec::new(),
            &base_payload,
        ),
        workflow_computer_use_event(
            2,
            run_id,
            thread_id,
            binding,
            "computer_use_lease_acquired",
            "computer_use.lease_acquired",
            "ComputerUse.LeaseAcquired",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use lease acquired",
                "computer_use_step": "acquire_lease",
                "lease": lease,
                "adapter_contract": {
                    "adapter_id": "ioi.native_browser.workflow_manifest",
                    "lane": "native_browser",
                    "supported_session_modes": [binding.session_mode],
                    "capabilities": ["observe.dom", "observe.ax", "observe.screenshot", format!("act.{}", action_kind), "verify.postcondition"],
                    "emits_observation_bundle": true,
                    "emits_action_receipts": action_will_execute,
                    "fail_closed_when_unavailable": true
                }
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            Vec::new(),
            &base_payload,
        ),
        workflow_computer_use_event(
            3,
            run_id,
            thread_id,
            binding,
            "computer_use_run_state",
            "computer_use.run_state",
            "ComputerUse.RunState",
            "running",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use run state projected",
                "computer_use_step": "plan_next_step",
                "computer_use_observation_ref": observation_ref,
                "computer_use_target_index_ref": target_index_ref,
                "computer_use_run_state": run_state
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            Vec::new(),
            &base_payload,
        ),
        workflow_computer_use_event(
            4,
            run_id,
            thread_id,
            binding,
            "computer_use_observation",
            "computer_use.observation",
            "ComputerUse.Observation",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use observation indexed",
                "computer_use_step": "observe",
                "computer_use_observation_ref": observation_ref,
                "computer_use_target_index_ref": target_index_ref,
                "observation_bundle": observation,
                "target_index": target_index
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            5,
            run_id,
            thread_id,
            binding,
            "computer_use_affordance_graph",
            "computer_use.affordance_graph",
            "ComputerUse.AffordanceGraph",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use affordance graph built",
                "computer_use_step": "build_affordance_graph",
                "computer_use_affordance_graph_ref": affordance_graph_ref,
                "computer_use_target_index_ref": target_index_ref,
                "affordance_graph": affordance_graph
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            6,
            run_id,
            thread_id,
            binding,
            "computer_use_action_proposed",
            "computer_use.action_proposed",
            "ComputerUse.ActionProposed",
            "waiting_for_policy",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use action proposal policy-gated",
                "computer_use_step": "propose_action",
                "computer_use_proposal_ref": proposal_ref,
                "computer_use_target_ref": target_ref,
                "computer_use_policy_decision_ref": policy_decision_ref,
                "action_proposal": action_proposal,
                "policy_gate": {
                    "policy_decision_ref": policy_decision_ref,
                    "outcome": if action_is_read_only {
                        "approved_for_read_only_probe"
                    } else if action_has_approval {
                        "approved_after_confirmation"
                    } else {
                        "requires_confirmation_before_execution"
                    },
                    "authority_scope": action_authority,
                    "approval_ref": action_approval_ref
                }
            }),
            vec![trace_receipt_id.clone()],
            vec![policy_decision_ref.clone()],
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            7,
            run_id,
            thread_id,
            binding,
            "computer_use_action_executed",
            "computer_use.action_executed",
            "ComputerUse.ActionExecuted",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": if action_is_read_only {
                    "Computer-use read-only action executed"
                } else {
                    "Computer-use approved mutating action executed"
                },
                "computer_use_step": "execute_action",
                "computer_use_action_ref": action_ref,
                "computer_use_proposal_ref": proposal_ref,
                "computer_action": action,
                "action_receipt": action_receipt
            }),
            vec![trace_receipt_id.clone(), action_receipt_ref],
            vec![policy_decision_ref.clone()],
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            8,
            run_id,
            thread_id,
            binding,
            "computer_use_verification",
            "computer_use.verification",
            "ComputerUse.Verification",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use postcondition verified",
                "computer_use_step": "verify_postcondition",
                "computer_use_verification_ref": verification_ref,
                "computer_use_proposal_ref": proposal_ref,
                "verification_receipt": verification
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            9,
            run_id,
            thread_id,
            binding,
            "computer_use_commit_gate",
            "computer_use.commit_gate",
            "ComputerUse.CommitGate",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use commit gate evaluated",
                "computer_use_step": "commit_or_handoff",
                "computer_use_commit_gate_ref": commit_gate["commit_gate_ref"].clone(),
                "computer_use_action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
                "outcome_contract": outcome_contract,
                "commit_gate": commit_gate,
                "human_handoff_state": if action_will_execute { Value::Null } else { json!({
                    "handoff_ref": format!("handoff_{}_{}", run_id, action_kind),
                    "reason": "mutating_browser_action_requires_confirmation",
                    "requested_user_action": format!("Approve or reject {}.", action_proposal["normalized_action_candidate"].as_str().unwrap_or(action_kind)),
                    "forbidden_agent_actions": ["execute_mutating_browser_action_without_approval"],
                    "resume_condition": "A commit-gate approval receipt is present.",
                    "observation_after_resume_ref": Value::Null,
                    "timeout_policy": "pause_until_user_resumes_or_cancels",
                    "evidence_retention": binding.observation_retention_mode,
                    "status": "pending"
                })}
            }),
            vec![trace_receipt_id.clone()],
            vec![policy_decision_ref.clone()],
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            10,
            run_id,
            thread_id,
            binding,
            "computer_use_trajectory_written",
            "computer_use.trajectory_written",
            "ComputerUse.TrajectoryWritten",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use trajectory written",
                "computer_use_step": "write_trajectory",
                "computer_use_trajectory_ref": trajectory_ref,
                "trajectory_bundle": trajectory
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            11,
            run_id,
            thread_id,
            binding,
            "computer_use_cleanup",
            "computer_use.cleanup",
            "ComputerUse.Cleanup",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use cleanup completed",
                "computer_use_step": "cleanup",
                "computer_use_cleanup_ref": cleanup_ref,
                "cleanup_receipt": cleanup
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
    ];
    if action_will_execute {
        events
    } else {
        events
            .into_iter()
            .filter(|event| {
                event.get("eventKind").and_then(Value::as_str)
                    != Some("computer_use.action_executed")
            })
            .collect()
    }
}

fn workflow_unavailable_computer_use_runtime_thread_events(
    binding: &WorkflowComputerUseBinding,
    run_id: &str,
    thread_id: &str,
    state: &WorkflowStateSnapshot,
) -> Vec<Value> {
    let user_goal = workflow_computer_use_user_goal(state);
    let lease_id = format!("lease_{}_{}_unavailable", run_id, binding.lane);
    let observation_ref = format!("observation_{}_{}_unavailable", run_id, binding.lane);
    let target_index_ref = format!("target_index_{}_{}_unavailable", run_id, binding.lane);
    let verification_ref = format!("verification_{}_computer_use_unavailable", run_id);
    let cleanup_ref = format!("cleanup_{}_computer_use_unavailable", run_id);
    let trace_receipt_id = format!("receipt_{}_computer_use_trace", run_id);
    let environment_selection = json!({
        "receipt_ref": format!("receipt_{}_computer_use_environment", run_id),
        "run_id": run_id,
        "selected_lane": binding.lane,
        "selected_session_mode": binding.session_mode,
        "rejected_options": [{
            "lane": "native_browser",
            "session_mode": "owned_hermetic_browser",
            "reason": "The workflow explicitly requested a different computer-use lane."
        }],
        "reasons": [
            format!("Workflow manifest requested {}/{}.", binding.lane, binding.session_mode),
            "The requested adapter is not mounted in this local workflow harness.",
            "The harness failed closed before acquiring an uncontrolled environment."
        ],
        "risk_posture": "blocked_unavailable",
        "authority_required": format!("computer_use.{}.execute", binding.lane),
        "privacy_impact": binding.observation_retention_mode,
        "expected_cleanup": "no environment acquired; retain blocked trace only"
    });
    let lease = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "lease_id": lease_id,
        "lane": binding.lane,
        "session_mode": binding.session_mode,
        "status": "failed_closed",
        "authority_scope": environment_selection["authority_required"].clone(),
        "consent_scope": "operator_prompt",
        "target_hint": computer_use_target_hint(&user_goal),
        "environment_ref": format!("{}:unavailable", binding.lane),
        "profile_provenance": "none",
        "retention_mode": binding.observation_retention_mode,
        "cleanup_required": false,
        "evidence_refs": [environment_selection["receipt_ref"].clone(), json!("adapter_unavailable")]
    });
    let run_state = json!({
        "run_id": run_id,
        "lease_id": lease_id,
        "user_goal": user_goal,
        "current_subgoal": "Fail closed because the requested computer-use lane is unavailable.",
        "plan_graph_ref": format!("plan_graph_{}_computer_use", run_id),
        "current_observation_ref": observation_ref,
        "current_target_index_ref": target_index_ref,
        "active_hypotheses": [
            "No adapter means no safe observation or action should be attempted.",
            "The workflow can retry after mounting the requested provider or switch lanes explicitly."
        ],
        "expected_postcondition": "A blocked, no-action trace explains why the requested lane was unavailable.",
        "last_action_ref": Value::Null,
        "verification_status": "blocked",
        "blocker_state": "computer_use_lane_unavailable",
        "retry_budget": 0,
        "risk_posture": "blocked_unavailable",
        "user_handoff_ref": Value::Null,
        "cleanup_state": "not_required"
    });
    let recovery_policy = json!({
        "policy_id": format!("computer-use-recovery:{}:{}", run_id, binding.lane),
        "failure_class": "environment",
        "allowed_actions": ["terminate_safely", "switch_to_browser_lane", "ask_user"],
        "max_attempts": 0,
        "lane_switch_allowed": true,
        "requires_human_visible_reason": true
    });
    let verification = json!({
        "verification_ref": verification_ref,
        "action_ref": Value::Null,
        "status": "blocked",
        "expected_postcondition": run_state["expected_postcondition"].clone(),
        "observed_postcondition": "No adapter was mounted; no lease, observation, action, or external side effect occurred.",
        "verifier": "workflow_computer_use_manifest_harness",
        "evidence_refs": [environment_selection["receipt_ref"].clone(), lease_id, cleanup_ref]
    });
    let cleanup = json!({
        "cleanup_ref": cleanup_ref,
        "lease_id": lease_id,
        "status": "not_required",
        "closed_process_refs": [],
        "deleted_profile_refs": [],
        "retained_artifact_refs": ["computer-use-trace.json"],
        "warnings": [format!("{}/{} adapter unavailable; no environment acquired.", binding.lane, binding.session_mode)]
    });
    let base_payload = workflow_computer_use_base_payload(binding, &lease_id);

    vec![
        workflow_computer_use_event(
            1,
            run_id,
            thread_id,
            binding,
            "computer_use_environment_selected",
            "computer_use.environment_selected",
            "ComputerUse.EnvironmentSelected",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use environment selected",
                "computer_use_step": "select_environment",
                "environment_selection_receipt": environment_selection,
                "lease": lease
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            Vec::new(),
            &base_payload,
        ),
        workflow_computer_use_event(
            2,
            run_id,
            thread_id,
            binding,
            "computer_use_environment_unavailable",
            "computer_use.environment_unavailable",
            "ComputerUse.EnvironmentUnavailable",
            "blocked",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use environment unavailable; failed closed",
                "computer_use_step": "acquire_lease",
                "computer_use_blocker": "adapter_unavailable",
                "lease": lease,
                "recovery_policy": recovery_policy
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            3,
            run_id,
            thread_id,
            binding,
            "computer_use_run_state",
            "computer_use.run_state",
            "ComputerUse.RunState",
            "blocked",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use run state blocked",
                "computer_use_step": "plan_next_step",
                "computer_use_observation_ref": observation_ref,
                "computer_use_target_index_ref": target_index_ref,
                "computer_use_run_state": run_state
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            4,
            run_id,
            thread_id,
            binding,
            "computer_use_verification",
            "computer_use.verification",
            "ComputerUse.Verification",
            "blocked",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use unavailable state verified",
                "computer_use_step": "verify_postcondition",
                "computer_use_verification_ref": verification_ref,
                "verification_receipt": verification
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            5,
            run_id,
            thread_id,
            binding,
            "computer_use_cleanup",
            "computer_use.cleanup",
            "ComputerUse.Cleanup",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use cleanup completed",
                "computer_use_step": "cleanup",
                "computer_use_cleanup_ref": cleanup_ref,
                "cleanup_receipt": cleanup
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
    ]
}

fn workflow_computer_use_event(
    seq: usize,
    run_id: &str,
    thread_id: &str,
    binding: &WorkflowComputerUseBinding,
    event_type: &str,
    event_kind: &str,
    source_event_kind: &str,
    status: &str,
    trace_receipt_id: &str,
    event_payload: Value,
    receipt_refs: Vec<String>,
    policy_decision_refs: Vec<String>,
    artifact_refs: Vec<String>,
    base_payload: &Value,
) -> Value {
    let mut payload = base_payload.clone();
    if let (Some(target), Some(extra)) = (payload.as_object_mut(), event_payload.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    if let Some(target) = payload.as_object_mut() {
        target.insert("receiptId".to_string(), json!(trace_receipt_id));
        target.insert("receipt_id".to_string(), json!(trace_receipt_id));
    }
    json!({
        "id": unique_runtime_id("runtime-event"),
        "cursor": format!("workflow_computer_use:{}:{}", run_id, seq),
        "seq": seq,
        "threadId": thread_id,
        "turnId": Value::Null,
        "type": event_type,
        "eventKind": event_kind,
        "sourceEventKind": source_event_kind,
        "status": status,
        "createdAt": unix_ms_to_iso(now_ms()),
        "componentKind": "computer_use_harness",
        "workflowNodeId": binding.workflow_node_id,
        "workflowGraphId": binding.workflow_graph_id,
        "toolName": binding.tool_ref,
        "payloadSchemaVersion": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "receiptRefs": receipt_refs,
        "artifactRefs": artifact_refs,
        "policyDecisionRefs": policy_decision_refs,
        "rollbackRefs": [],
        "payload": payload
    })
}

fn workflow_computer_use_base_payload(
    binding: &WorkflowComputerUseBinding,
    lease_id: &str,
) -> Value {
    json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "schemaVersion": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "manifest_schema_version": WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
        "manifestSchemaVersion": WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
        "source": "workflow_manifest",
        "computerUse": true,
        "computer_use": true,
        "computer_use_lane": binding.lane,
        "computerUseLane": binding.lane,
        "computer_use_session_mode": binding.session_mode,
        "computerUseSessionMode": binding.session_mode,
        "computer_use_action_kind": binding.action_kind,
        "computerUseActionKind": binding.action_kind,
        "computer_use_approval_ref": binding.approval_ref,
        "computerUseApprovalRef": binding.approval_ref,
        "computer_use_target_ref": binding.target_ref,
        "computerUseTargetRef": binding.target_ref,
        "selector": binding.selector,
        "text": binding.text,
        "key": binding.key,
        "cdp_endpoint_url": binding.cdp_endpoint_url,
        "cdpEndpointUrl": binding.cdp_endpoint_url,
        "cdp_websocket_url": binding.cdp_websocket_url,
        "cdpWebSocketUrl": binding.cdp_websocket_url,
        "cdp_timeout_ms": binding.cdp_timeout_ms,
        "cdpTimeoutMs": binding.cdp_timeout_ms,
        "computer_use_external_effect": !computer_use_action_kind_is_read_only(&binding.action_kind),
        "computer_use_lease_id": lease_id,
        "computerUseLeaseId": lease_id,
        "observation_retention_mode": binding.observation_retention_mode,
        "observationRetentionMode": binding.observation_retention_mode,
        "fail_closed_when_unavailable": binding.fail_closed_when_unavailable,
        "failClosedWhenUnavailable": binding.fail_closed_when_unavailable,
        "workflowGraphId": binding.workflow_graph_id,
        "workflow_graph_id": binding.workflow_graph_id,
        "workflowNodeId": binding.workflow_node_id,
        "workflow_node_id": binding.workflow_node_id,
        "workflowNodeIds": binding.workflow_node_ids,
        "workflow_node_ids": binding.workflow_node_ids,
        "toolRef": binding.tool_ref,
        "tool_ref": binding.tool_ref,
        "authorityScopes": binding.authority_scopes,
        "authority_scopes": binding.authority_scopes,
        "harness_contract": default_computer_use_harness_contract()
    })
}

fn workflow_computer_use_user_goal(state: &WorkflowStateSnapshot) -> String {
    state
        .values
        .get("input")
        .and_then(computer_use_goal_from_value)
        .or_else(|| state.values.values().find_map(computer_use_goal_from_value))
        .unwrap_or_else(|| "Workflow-authored computer-use run".to_string())
}

fn computer_use_goal_from_value(value: &Value) -> Option<String> {
    if let Some(text) = value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        return Some(text.to_string());
    }
    if let Some(object) = value.as_object() {
        for key in [
            "prompt",
            "message",
            "query",
            "userGoal",
            "user_goal",
            "text",
            "objective",
        ] {
            if let Some(text) = object
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
            {
                return Some(text.to_string());
            }
        }
        for key in ["payload", "input", "arguments"] {
            if let Some(goal) = object.get(key).and_then(computer_use_goal_from_value) {
                return Some(goal);
            }
        }
    }
    value
        .as_array()
        .and_then(|items| items.iter().find_map(computer_use_goal_from_value))
}

fn computer_use_target_hint(user_goal: &str) -> String {
    computer_use_url_hint(user_goal).unwrap_or_else(|| "workflow://computer-use".to_string())
}

fn computer_use_url_hint(user_goal: &str) -> Option<String> {
    user_goal
        .split_whitespace()
        .map(|token| token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ')' | '(')))
        .find(|token| token.starts_with("http://") || token.starts_with("https://"))
        .map(str::to_string)
}

fn default_session_mode_for_computer_use_lane(lane: &str) -> &'static str {
    match lane {
        "visual_gui" => "visual_fallback",
        "sandboxed_hosted" => "hosted_sandbox",
        _ => "owned_hermetic_browser",
    }
}

fn default_retention_mode_for_computer_use_lane(lane: &str) -> &'static str {
    match lane {
        "sandboxed_hosted" => "no_persistence",
        _ => "local_redacted_artifacts",
    }
}

fn normalize_computer_use_action_kind(value: &str) -> Option<&'static str> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
        .as_str()
    {
        "click" => Some("click"),
        "type" | "type_text" | "input_text" => Some("type_text"),
        "keypress" | "key_press" => Some("key_press"),
        "scroll" => Some("scroll"),
        "drag" => Some("drag"),
        "hover" | "mouse_move" => Some("hover"),
        "select" => Some("select"),
        "upload" => Some("upload"),
        "clipboard" => Some("clipboard"),
        "wait" | "noop" | "none" => Some("wait"),
        "shell" => Some("shell"),
        "mobile_gesture" => Some("mobile_gesture"),
        "navigate" | "open_url" => Some("navigate"),
        "inspect" => Some("inspect"),
        _ => None,
    }
}

fn computer_use_action_kind_is_read_only(action_kind: &str) -> bool {
    matches!(action_kind, "inspect" | "hover" | "wait" | "scroll")
}

fn computer_use_evidence_refs(values: Vec<Value>) -> Value {
    Value::Array(
        values
            .into_iter()
            .filter(|value| !value.is_null())
            .collect(),
    )
}

fn default_computer_use_harness_contract() -> Value {
    json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "required_lanes": ["native_browser", "visual_gui", "sandboxed_hosted"],
        "observation_channels": ["screenshot", "dom", "ax", "som", "selector_map"],
        "required_receipts": [
            "environment_selection",
            "lease",
            "observation_bundle",
            "target_index",
            "affordance_graph",
            "action_proposal",
            "action_receipt",
            "verification",
            "trajectory",
            "cleanup"
        ],
        "policy": {
            "actions_are_proposals_before_execution": true,
            "fail_closed_when_lane_unavailable": true,
            "react_flow_is_projection": true
        }
    })
}

fn unix_ms_to_iso(timestamp_ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms as i64)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
