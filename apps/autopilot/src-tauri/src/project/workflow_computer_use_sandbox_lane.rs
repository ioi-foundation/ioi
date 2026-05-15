// apps/autopilot/src-tauri/src/project/workflow_computer_use_sandbox_lane.rs

use super::workflow_computer_use_lane::{
    computer_use_action_kind_is_read_only, computer_use_evidence_refs, computer_use_target_hint,
    workflow_computer_use_base_payload, workflow_computer_use_event,
    workflow_computer_use_user_goal, WorkflowComputerUseBinding,
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
};
use super::*;
use serde_json::{json, Value};

pub(super) fn workflow_local_sandbox_runtime_thread_events(
    binding: &WorkflowComputerUseBinding,
    run_id: &str,
    thread_id: &str,
    state: &WorkflowStateSnapshot,
) -> Vec<Value> {
    let user_goal = workflow_computer_use_user_goal(state);
    let lease_id = format!("lease_{}_sandbox", run_id);
    let observation_ref = format!("observation_{}_sandbox_initial", run_id);
    let target_index_ref = format!("target_index_{}_sandbox_initial", run_id);
    let affordance_graph_ref = format!("affordance_{}_sandbox_initial", run_id);
    let action_kind = binding.action_kind.as_str();
    let action_is_read_only = computer_use_action_kind_is_read_only(action_kind);
    let action_approval_ref = binding.approval_ref.as_deref();
    let action_has_approval = !action_is_read_only && action_approval_ref.is_some();
    let action_will_execute = action_is_read_only || action_has_approval;
    let action_authority = if action_is_read_only {
        "computer_use.sandboxed_hosted.read"
    } else {
        "computer_use.sandboxed_hosted.act"
    };
    let action_risk = if action_is_read_only {
        "read_only"
    } else {
        "possible_external_effect"
    };
    let proposal_ref = format!("proposal_{}_sandbox_{}", run_id, action_kind);
    let action_ref = format!("action_{}_sandbox_{}", run_id, action_kind);
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
    let trace_receipt_id = format!("receipt_{}_computer_use_trace", run_id);
    let trajectory_ref = format!("trajectory_{}_computer_use", run_id);
    let cleanup_ref = format!("cleanup_{}_sandbox_fixture", run_id);
    let target_ref = binding
        .target_ref
        .clone()
        .unwrap_or_else(|| format!("target_{}_sandbox_workspace", run_id));
    let image_ref = binding
        .sandbox_image_ref
        .clone()
        .unwrap_or_else(|| "ioi/sandbox-fixture:local".to_string());
    let task_ref = binding
        .sandbox_task_ref
        .clone()
        .unwrap_or_else(|| format!("sandbox_task_{}", run_id));
    let provider_receipt = json!({
        "object": "ioi.runtime_sandboxed_computer_provider",
        "provider_id": "ioi.sandboxed_hosted.local_fixture",
        "provider_kind": "local_fixture",
        "lane": "sandboxed_hosted",
        "session_mode": binding.session_mode,
        "image_ref": image_ref,
        "task_ref": task_ref,
        "authority_scope": "computer_use.sandboxed_hosted.read",
        "external_credentials_required": false,
        "network_policy": "disabled",
        "persistence_policy": "ephemeral_fixture",
        "fail_closed_when_unavailable": true
    });
    let environment_selection = json!({
        "receipt_ref": format!("receipt_{}_computer_use_environment", run_id),
        "run_id": run_id,
        "selected_lane": "sandboxed_hosted",
        "selected_session_mode": binding.session_mode,
        "rejected_options": [
            {
                "lane": "native_browser",
                "session_mode": "owned_hermetic_browser",
                "reason": "The workflow selected a provider-neutral local sandbox fixture for deterministic execution."
            },
            {
                "lane": "visual_gui",
                "session_mode": "visual_fallback",
                "reason": "The sandbox fixture supplies canonical observation, target, affordance, adapter, and cleanup contracts without coordinate fallback."
            }
        ],
        "reasons": [
            "Workflow manifest contains a Sandboxed Computer primitive.",
            "Local fixture provider makes the sandbox lane executable without external hosted credentials.",
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
        "expected_cleanup": "cleanup_ephemeral_sandbox_fixture_and_retain_trace",
        "provider_receipt": provider_receipt
    });
    let lease = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "lease_id": lease_id,
        "lane": "sandboxed_hosted",
        "session_mode": binding.session_mode,
        "status": "active",
        "authority_scope": action_authority,
        "consent_scope": "operator_prompt",
        "target_hint": computer_use_target_hint(&user_goal),
        "environment_ref": format!("local_sandbox_fixture:{}", run_id),
        "profile_provenance": "ephemeral_local_sandbox_fixture",
        "retention_mode": binding.observation_retention_mode,
        "cleanup_required": true,
        "evidence_refs": [environment_selection["receipt_ref"].clone(), json!("ioi.sandboxed_hosted.local_fixture")]
    });
    let observation = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "observation_ref": observation_ref,
        "lease_id": lease_id,
        "lane": "sandboxed_hosted",
        "session_mode": binding.session_mode,
        "url": Value::Null,
        "title": "IOI deterministic sandbox fixture",
        "app_name": "IOI Local Sandbox Fixture",
        "window_title": "Deterministic sandbox computer session",
        "screenshot_ref": format!("artifact:{}:sandbox_fixture_screen_redacted", run_id),
        "som_ref": format!("artifact:{}:sandbox_fixture_som", run_id),
        "dom_ref": Value::Null,
        "ax_ref": format!("artifact:{}:sandbox_fixture_ax_tree", run_id),
        "selector_map_ref": Value::Null,
        "target_index_ref": target_index_ref,
        "redaction_report_ref": format!("artifact:{}:sandbox_fixture_redaction_report", run_id),
        "freshness_ms": 0,
        "retention_mode": binding.observation_retention_mode,
        "detected_patterns": ["sandbox", "terminal", "file_browser", "task_panel"]
    });
    let target_index = json!({
        "target_index_ref": target_index_ref,
        "observation_ref": observation_ref,
        "coordinate_space_id": format!("sandbox_{}_viewport", run_id),
        "drift_state": "fresh",
        "targets": [{
            "target_ref": target_ref,
            "label": "Sandbox workspace",
            "role": "application",
            "semantic_ids": ["sandbox", "workspace", "terminal", "task-panel"],
            "selectors": [],
            "som_id": 1,
            "ax_ref": format!("artifact:{}:sandbox_fixture_ax_tree#workspace", run_id),
            "bounds": {
                "x": 0,
                "y": 0,
                "width": 1280,
                "height": 720,
                "coordinate_space_id": format!("sandbox_{}_viewport", run_id)
            },
            "confidence": 94,
            "available_actions": ["inspect", "wait", "shell", action_kind]
        }]
    });
    let normalized_action_candidate = if action_kind == "inspect" {
        "inspect sandbox workspace and summarize actionable targets".to_string()
    } else {
        format!("{} {}", action_kind, target_ref)
    };
    let predicted_postcondition = if action_is_read_only {
        "The sandbox fixture has a grounded observation summary and next-action candidates."
            .to_string()
    } else if action_has_approval {
        format!(
            "The sandbox fixture has a grounded {} action approved for execution and verifies the postcondition.",
            action_kind
        )
    } else {
        format!(
            "The sandbox fixture has a grounded {} proposal and pauses before execution for confirmation.",
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
            "action_preconditions": ["fixture_lease_active", "fresh_observation", "target_index_present"],
            "confidence": if action_is_read_only { 95 } else if action_has_approval { 90 } else { 86 },
            "expected_state_transition": if action_is_read_only {
                "The sandbox fixture yields deterministic observation and target evidence without external side effects.".to_string()
            } else if let Some(approval_ref) = action_approval_ref {
                format!("A {} action can proceed because approval {} is present.", action_kind, approval_ref)
            } else {
                format!("A {} action could change sandbox state and must be confirmed before execution.", action_kind)
            },
            "risk_class": action_risk,
            "required_authority": action_authority,
            "confirmation_required": !action_is_read_only,
            "fallback_action_paths": ["reobserve", "terminate_safely", "switch_to_native_browser"],
            "invalidation_conditions": ["fixture_reset", "sandbox_unavailable", "policy_block"]
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
            "The sandbox fixture workspace is present and read-only inspection is the lowest-risk next step.".to_string()
        } else if let Some(approval_ref) = action_approval_ref {
            format!("The requested {} action is grounded to the sandbox target index and approval {} is present.", action_kind, approval_ref)
        } else {
            format!("The requested {} action is grounded to the sandbox target index and requires confirmation before execution.", action_kind)
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
            "coordinate_space_id": format!("sandbox_{}_viewport", run_id),
            "payload_summary": if action_kind == "inspect" {
                "Read-only inspect of the sandbox workspace and target index.".to_string()
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
            "adapter_id": "ioi.sandboxed_hosted.local_fixture",
            "status": "completed",
            "grounding_ref": target_index_ref,
            "postcondition_summary": if action_is_read_only {
                "Read-only sandbox action was grounded in the observation and produced no external side effect."
            } else {
                "Approved mutating sandbox action was grounded in the observation and executed after confirmation."
            },
            "verification_ref": verification_ref,
            "evidence_refs": [observation_ref, target_index_ref, proposal_ref]
        })
    } else {
        Value::Null
    };
    let policy_decision = json!({
        "policy_decision_ref": policy_decision_ref,
        "proposal_ref": proposal_ref,
        "action_kind": action_kind,
        "outcome": if action_is_read_only {
            "approved_for_read_only_probe"
        } else if action_has_approval {
            "approved_after_confirmation"
        } else {
            "requires_confirmation_before_execution"
        },
        "authority_scope": action_authority,
        "approval_ref": action_approval_ref,
        "external_effect": !action_is_read_only,
        "fail_closed": !action_is_read_only && !action_has_approval,
        "reasons": [if action_is_read_only {
            "Read-only sandbox action can execute without external effects."
        } else {
            "Mutating sandbox action requires approval before execution."
        }],
        "evidence_refs": computer_use_evidence_refs(vec![
            json!(observation_ref),
            json!(target_index_ref),
            json!(proposal_ref),
            action_approval_ref.map(|value| json!(value)).unwrap_or(Value::Null)
        ])
    });
    let verification = json!({
        "verification_ref": verification_ref,
        "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
        "status": if action_will_execute { "passed" } else { "requires_human" },
        "expected_postcondition": action_proposal["predicted_postcondition"].clone(),
        "observed_postcondition": if action_is_read_only {
            "Sandbox environment, lease, observation, target index, affordance graph, action proposal, action receipt, verification, outcome, commit gate, trajectory, and cleanup are trace-visible."
        } else if action_has_approval {
            "Approval was present, so the grounded mutating sandbox action executed and produced a verification receipt."
        } else {
            "No mutating sandbox action was executed; the proposal is waiting on the commit gate confirmation."
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
            "Produce a grounded sandbox observation summary without external side effects.".to_string()
        } else if action_has_approval {
            format!("Execute the approved grounded {} sandbox action and verify the postcondition.", action_kind)
        } else {
            format!("Prepare a grounded {} sandbox action and pause before external effects.", action_kind)
        },
        "success_criteria": [verification["expected_postcondition"].clone()],
        "acceptable_side_effects": ["Retain a redacted computer-use trace artifact."],
        "prohibited_side_effects": ["Network access, host filesystem writes, credentials, payments, messages, purchases, or permission changes."],
        "evidence_required": ["verification_receipt", "computer_use_trace"],
        "rollback_or_cleanup_required": true,
        "external_effect_policy": "confirmation_required"
    });
    let commit_gate = if action_will_execute {
        json!({
            "commit_gate_ref": format!("commit_gate_{}_{}", run_id, action_ref),
            "final_action_ref": action_ref,
            "outcome_ref": outcome_contract["outcome_ref"].clone(),
            "external_effect": !action_is_read_only,
            "user_confirmation_required": !action_is_read_only,
            "authority_required": action_authority,
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
    let run_state = json!({
        "run_id": run_id,
        "lease_id": lease_id,
        "user_goal": user_goal,
        "current_subgoal": "Observe the sandbox fixture, index targets, and propose a grounded next action.",
        "plan_graph_ref": format!("plan_graph_{}_computer_use", run_id),
        "current_observation_ref": observation_ref,
        "current_target_index_ref": target_index_ref,
        "active_hypotheses": [
            "The local fixture sandbox should produce deterministic, replayable observation and cleanup evidence.",
            "No external side effect should occur before a policy-gated action proposal."
        ],
        "expected_postcondition": action_proposal["predicted_postcondition"].clone(),
        "last_action_ref": Value::Null,
        "verification_status": if action_will_execute { "unknown" } else { "requires_human" },
        "blocker_state": if action_will_execute { Value::Null } else { json!("commit_gate_requires_confirmation") },
        "retry_budget": 2,
        "risk_posture": environment_selection["risk_posture"].clone(),
        "user_handoff_ref": Value::Null,
        "cleanup_state": "cleanup_required"
    });
    let trajectory = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "trajectory_ref": trajectory_ref,
        "run_id": run_id,
        "lease_id": lease_id,
        "retention_mode": binding.observation_retention_mode,
        "entries": [
            {
                "sequence": 1,
                "event_kind": "select_environment",
                "receipt_ref": environment_selection["receipt_ref"].clone(),
                "summary": format!("Selected sandboxed_hosted/{} lane with native and visual lanes retained as fallbacks.", binding.session_mode)
            },
            {
                "sequence": 2,
                "event_kind": "observe",
                "observation_ref": observation_ref,
                "receipt_ref": observation_ref,
                "summary": "Captured deterministic sandbox fixture observation and target index."
            },
            {
                "sequence": 3,
                "event_kind": "propose_action",
                "observation_ref": observation_ref,
                "proposal_ref": proposal_ref,
                "summary": if action_is_read_only {
                    "Normalized a read-only sandbox proposal and policy-gated it before execution."
                } else {
                    "Normalized a mutating sandbox proposal and stopped at the confirmation gate."
                }
            },
            {
                "sequence": 4,
                "event_kind": "verify_postcondition",
                "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
                "verification_ref": verification_ref,
                "summary": if action_is_read_only {
                    "Verified the read-only sandbox postcondition and retained the trace."
                } else {
                    "Verified that no mutating sandbox action executed before confirmation."
                }
            },
            {
                "sequence": 5,
                "event_kind": "commit_or_handoff",
                "action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
                "receipt_ref": commit_gate["commit_gate_ref"].clone(),
                "summary": if action_is_read_only {
                    "Evaluated the outcome contract and confirmed no external-effect commit was required."
                } else {
                    "Paused at the commit gate until explicit approval is available."
                }
            }
        ]
    });
    let cleanup = json!({
        "cleanup_ref": cleanup_ref,
        "lease_id": lease_id,
        "status": "completed",
        "closed_process_refs": [format!("sandbox_fixture:{}", run_id)],
        "deleted_profile_refs": [format!("sandbox_fixture_workspace:{}", run_id)],
        "retained_artifact_refs": ["computer-use-trace.json", observation["screenshot_ref"].clone()],
        "warnings": []
    });
    let adapter_contract = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "adapter_id": "ioi.sandboxed_hosted.local_fixture",
        "lane": "sandboxed_hosted",
        "supported_session_modes": ["local_sandbox", "hosted_sandbox"],
        "capabilities": ["lease.local_fixture", "observe.screenshot", "observe.ax", "observe.som", "act.inspect", "act.wait", "act.shell", "verify.postcondition", "cleanup.ephemeral_workspace"],
        "emits_observation_bundle": true,
        "emits_action_receipts": true,
        "emits_cleanup_receipts": true,
        "fail_closed_when_unavailable": true,
        "provider_receipt": provider_receipt
    });
    let base_payload = workflow_computer_use_base_payload(binding, &lease_id);
    let mut events = vec![
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "environment_selection_receipt": environment_selection,
                "lease": lease
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "lease": lease,
                "adapter_contract": adapter_contract
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
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use run state projected",
                "computer_use_step": "plan_next_step",
                "computer_use_contract_ingest": "local_sandbox_fixture",
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
            "computer_use_observation",
            "computer_use.observation",
            "ComputerUse.Observation",
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use observation indexed",
                "computer_use_step": "observe",
                "computer_use_contract_ingest": "local_sandbox_fixture",
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
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
            "completed",
            &trace_receipt_id,
            json!({
                "summary": "Computer-use action proposal policy-gated",
                "computer_use_step": "propose_action",
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "computer_use_proposal_ref": proposal_ref,
                "computer_use_target_ref": target_ref,
                "computer_use_policy_decision_ref": policy_decision_ref,
                "action_proposal": action_proposal,
                "policy_gate": {
                    "policy_decision_ref": policy_decision_ref,
                    "outcome": policy_decision["outcome"].clone(),
                    "authority_scope": action_authority,
                    "approval_ref": action_approval_ref
                },
                "policy_decision_receipt": policy_decision
            }),
            vec![trace_receipt_id.clone()],
            vec![policy_decision_ref.clone()],
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
    ];
    if action_will_execute {
        events.push(workflow_computer_use_event(
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
                    "Computer-use read-only sandbox action executed"
                } else {
                    "Computer-use approved mutating sandbox action executed"
                },
                "computer_use_step": "execute_action",
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "computer_use_action_ref": action_ref,
                "computer_use_proposal_ref": proposal_ref,
                "computer_action": action,
                "action_receipt": action_receipt
            }),
            vec![trace_receipt_id.clone(), action_receipt_ref],
            vec![policy_decision_ref.clone()],
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ));
    }
    let verification_seq = if action_will_execute { 8 } else { 7 };
    events.extend(vec![
        workflow_computer_use_event(
            verification_seq,
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
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
            verification_seq + 1,
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "computer_use_commit_gate_ref": commit_gate["commit_gate_ref"].clone(),
                "computer_use_action_ref": if action_will_execute { json!(action_ref) } else { Value::Null },
                "outcome_contract": outcome_contract,
                "commit_gate": commit_gate,
                "human_handoff_state": if action_will_execute { Value::Null } else { json!({
                    "handoff_ref": format!("handoff_{}_{}", run_id, action_kind),
                    "reason": "mutating_sandbox_action_requires_confirmation",
                    "requested_user_action": format!("Approve or reject {}.", action_proposal["normalized_action_candidate"].as_str().unwrap_or(action_kind)),
                    "forbidden_agent_actions": ["execute_mutating_sandbox_action_without_approval"],
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
            verification_seq + 2,
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "computer_use_trajectory_ref": trajectory_ref,
                "trajectory_bundle": trajectory
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
        workflow_computer_use_event(
            verification_seq + 3,
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
                "computer_use_contract_ingest": "local_sandbox_fixture",
                "computer_use_cleanup_ref": cleanup_ref,
                "cleanup_receipt": cleanup
            }),
            vec![trace_receipt_id.clone()],
            Vec::new(),
            vec!["computer-use-trace.json".to_string()],
            &base_payload,
        ),
    ]);
    events
}
