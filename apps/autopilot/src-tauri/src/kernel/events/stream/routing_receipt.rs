use crate::kernel::artifacts as artifact_store;
use crate::kernel::events::clarification::build_clarification_request_with_inference;
use crate::kernel::events::emission::{emit_receipt_digest, register_artifact, register_event};
use crate::kernel::events::support::{
    bind_task_session, clarification_preset_for_tool, is_hard_terminal_task,
    is_identity_resolution_kind, is_install_package_tool,
    is_waiting_for_identity_clarification_step, thread_id_from_session, ClarificationPreset,
    CLARIFICATION_WAIT_STEP,
};
use crate::kernel::notifications;
use crate::kernel::state::update_task_state;
use crate::models::AppState;
use crate::models::{AgentPhase, ArtifactRef, ArtifactType, ChatMessage, GateInfo};
use ioi_ipc::public::RoutingReceipt;
use serde_json::json;
use std::sync::Mutex;
use tauri::Manager;

pub(super) async fn handle_routing_receipt(app: &tauri::AppHandle, receipt: RoutingReceipt) {
    let thread_id = thread_id_from_session(&app, &receipt.session_id);
    let receipt_is_install_tool = is_install_package_tool(&receipt.tool_name);
    let receipt_is_identity_lookup_tool =
        clarification_preset_for_tool(&receipt.tool_name).is_some();
    let receipt_waiting_for_sudo = receipt
        .post_state
        .as_ref()
        .map(|s| {
            s.agent_status
                .to_ascii_lowercase()
                .contains("waiting for sudo password")
                || s.verification_checks
                    .iter()
                    .any(|check: &String| check.eq_ignore_ascii_case("awaiting_sudo_password=true"))
        })
        .unwrap_or(false)
        || (receipt_is_install_tool
            && (receipt
                .resolution_action
                .eq_ignore_ascii_case("wait_for_sudo_password")
                || receipt
                    .escalation_path
                    .eq_ignore_ascii_case("wait_for_sudo_password")));
    let receipt_waiting_for_clarification = receipt
        .post_state
        .as_ref()
        .map(|s| {
            s.verification_checks
                .iter()
                .any(|check: &String| check.eq_ignore_ascii_case("awaiting_clarification=true"))
        })
        .unwrap_or(false)
        || (receipt_is_identity_lookup_tool
            && (receipt
                .resolution_action
                .eq_ignore_ascii_case("wait_for_clarification")
                || receipt
                    .escalation_path
                    .eq_ignore_ascii_case("wait_for_clarification")));

    let receipt_dedup_key = format!(
        "receipt:{}:{}:{}:{}:{}:{}",
        receipt.step_index,
        receipt.tool_name,
        receipt.policy_decision,
        receipt.incident_stage,
        receipt.gate_state,
        receipt.resolution_action
    );

    let already_processed_receipt = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(|task| task.processed_steps.contains(&receipt_dedup_key))
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if already_processed_receipt {
        return;
    }

    let suppress_terminal_receipt = {
        let state_handle = app.state::<Mutex<AppState>>();
        let out = match state_handle.lock() {
            Ok(guard) => guard
                .current_task
                .as_ref()
                .map(is_hard_terminal_task)
                .unwrap_or(false),
            Err(_) => false,
        };
        out
    };
    if suppress_terminal_receipt {
        return;
    }

    let receipt_clarification_request = if receipt_waiting_for_clarification {
        let preset = clarification_preset_for_tool(&receipt.tool_name)
            .unwrap_or(ClarificationPreset::IdentityLookup);
        let clarification_kind = match preset {
            ClarificationPreset::IdentityLookup => "identity_lookup",
            ClarificationPreset::InstallLookup => "install_lookup",
            ClarificationPreset::LaunchLookup => "launch_lookup",
            ClarificationPreset::IntentClarification => "intent_clarification",
        };
        notifications::record_clarification_intervention(
            app,
            &thread_id,
            &receipt.session_id,
            clarification_kind,
            "Clarification is required before the workflow can continue.",
        );
        Some(build_clarification_request_with_inference(&app, preset, &receipt.tool_name, "").await)
    } else {
        None
    };
    if receipt_waiting_for_sudo {
        notifications::record_credential_intervention(
            app,
            &thread_id,
            &receipt.session_id,
            "sudo_password",
            "A one-time sudo password is required to continue the install.",
        );
    }

    let failure_class = if receipt.failure_class_name.is_empty() {
        None
    } else {
        Some(receipt.failure_class_name.as_str())
    };
    let verification = receipt
        .post_state
        .as_ref()
        .map(|s| {
            if s.verification_checks.is_empty() {
                "none".to_string()
            } else {
                s.verification_checks.join(", ")
            }
        })
        .unwrap_or_else(|| "none".to_string());

    let mut summary = format!(
        "RoutingReceipt(step={}, tier={}, tool={}, decision={}, stop={}, policy_hash={})",
        receipt.step_index,
        receipt
            .pre_state
            .as_ref()
            .map(|s| s.tier.as_str())
            .unwrap_or("unknown"),
        receipt.tool_name,
        receipt.policy_decision,
        receipt.stop_condition_hit,
        receipt.policy_binding_hash
    );

    if let Some(class) = failure_class {
        summary.push_str(&format!(", failure_class={}", class));
    }
    if !receipt.intent_class.is_empty() {
        summary.push_str(&format!(", intent_class={}", receipt.intent_class));
    }
    if !receipt.incident_id.is_empty() {
        summary.push_str(&format!(", incident_id={}", receipt.incident_id));
    }
    if !receipt.incident_stage.is_empty() {
        summary.push_str(&format!(", incident_stage={}", receipt.incident_stage));
    }
    if !receipt.strategy_name.is_empty() {
        summary.push_str(&format!(", strategy_name={}", receipt.strategy_name));
    }
    if !receipt.strategy_node.is_empty() {
        summary.push_str(&format!(", strategy_node={}", receipt.strategy_node));
    }
    if !receipt.gate_state.is_empty() {
        summary.push_str(&format!(", gate_state={}", receipt.gate_state));
    }
    if !receipt.resolution_action.is_empty() {
        summary.push_str(&format!(
            ", resolution_action={}",
            receipt.resolution_action
        ));
    }
    if !receipt.escalation_path.is_empty() {
        summary.push_str(&format!(", escalation={}", receipt.escalation_path));
    }
    if !receipt.lineage_ptr.is_empty() {
        summary.push_str(&format!(", lineage={}", receipt.lineage_ptr));
    }
    if !receipt.mutation_receipt_ptr.is_empty() {
        summary.push_str(&format!(
            ", mutation_receipt={}",
            receipt.mutation_receipt_ptr
        ));
    }
    summary.push_str(&format!(", verify=[{}]", verification));

    let mut accepted_for_processing = false;
    update_task_state(app, |t| {
        if t.processed_steps.contains(&receipt_dedup_key) {
            return;
        }
        t.processed_steps.insert(receipt_dedup_key.clone());
        accepted_for_processing = true;

        bind_task_session(t, &receipt.session_id);

        let waiting_for_sudo = t
            .credential_request
            .as_ref()
            .map(|req| req.kind == "sudo_password")
            .unwrap_or(false)
            || t.current_step
                .eq_ignore_ascii_case("Waiting for sudo password");
        let waiting_for_clarification = t
            .clarification_request
            .as_ref()
            .map(|req| is_identity_resolution_kind(&req.kind))
            .unwrap_or(false)
            || is_waiting_for_identity_clarification_step(&t.current_step);
        // Keep interactive wait-state transitions monotonic: routing receipts are audit summaries
        // and must not reopen waiting UI while execution is actively running.
        let receipt_can_assert_sudo_wait =
            receipt_waiting_for_sudo && (waiting_for_sudo || t.phase != AgentPhase::Running);
        let receipt_can_assert_clarification_wait = receipt_waiting_for_clarification
            && (waiting_for_clarification || t.phase != AgentPhase::Running);

        let mut effective_waiting_for_sudo = waiting_for_sudo;
        let mut effective_waiting_for_clarification = waiting_for_clarification;

        // Routing receipts are audit summaries. Once the UI is in an interactive wait state,
        // keep that state sticky until a later execution result or explicit user response clears it.
        if waiting_for_sudo && !receipt_waiting_for_sudo {
            effective_waiting_for_sudo = true;
        }
        if waiting_for_clarification && !receipt_waiting_for_clarification {
            effective_waiting_for_clarification = true;
        }

        if receipt_can_assert_sudo_wait {
            t.phase = AgentPhase::Complete;
            t.current_step = "Waiting for sudo password".to_string();
            t.gate_info = None;
            t.pending_request_hash = None;
            t.clarification_request = None;
            t.credential_request = Some(crate::models::CredentialRequest {
                kind: "sudo_password".to_string(),
                prompt: "A one-time sudo password is required to continue the install.".to_string(),
                one_time: true,
            });
            effective_waiting_for_sudo = true;
        }

        if receipt_can_assert_clarification_wait {
            t.phase = AgentPhase::Complete;
            t.current_step = CLARIFICATION_WAIT_STEP.to_string();
            t.gate_info = None;
            t.pending_request_hash = None;
            t.credential_request = None;
            t.clarification_request = receipt_clarification_request.clone();
            effective_waiting_for_clarification = true;
        }

        if receipt
            .policy_decision
            .eq_ignore_ascii_case("require_approval")
            && !effective_waiting_for_sudo
            && !receipt_can_assert_sudo_wait
            && !effective_waiting_for_clarification
            && !receipt_can_assert_clarification_wait
        {
            t.phase = AgentPhase::Gate;
            t.current_step = "Waiting for approval".to_string();
            if t.gate_info.is_none() {
                t.gate_info = Some(GateInfo {
                    title: "Restricted Action Intercepted".to_string(),
                    description: format!(
                        "The agent is attempting to execute: {}",
                        receipt.tool_name
                    ),
                    risk: "high".to_string(),
                    approve_label: Some("Approve action".to_string()),
                    deny_label: Some("Deny action".to_string()),
                    deadline_ms: None,
                    surface_label: None,
                    scope_label: None,
                    operation_label: None,
                    target_label: None,
                    operator_note: None,
                    pii: None,
                });
            }
        }

        if !effective_waiting_for_sudo
            && !effective_waiting_for_clarification
            && !receipt
                .policy_decision
                .eq_ignore_ascii_case("require_approval")
        {
            t.gate_info = None;
            t.pending_request_hash = None;
            if t.phase == AgentPhase::Gate {
                t.phase = AgentPhase::Running;
            }
            t.current_step = format!(
                "Routing: {} ({})",
                receipt.tool_name, receipt.policy_decision
            );
        }
        t.history.push(ChatMessage {
            role: "system".to_string(),
            text: summary.clone(),
            timestamp: crate::kernel::state::now(),
        });
    });
    if !accepted_for_processing {
        return;
    }

    let receipt_id = format!("{}:{}:{}", thread_id, receipt.step_index, receipt.tool_name);

    let report_ref = {
        let state = app.state::<Mutex<AppState>>();
        let memory_runtime = state.lock().ok().and_then(|s| s.memory_runtime.clone());
        if let Some(memory_runtime) = memory_runtime {
            let report_payload = json!({
                "receipt_id": receipt_id,
                "session_id": receipt.session_id,
                "step_index": receipt.step_index,
                "tool_name": receipt.tool_name,
                "decision": receipt.policy_decision,
                "intent_class": receipt.intent_class,
                "incident_id": receipt.incident_id,
                "incident_stage": receipt.incident_stage,
                "strategy_name": receipt.strategy_name,
                "strategy_node": receipt.strategy_node,
                "gate_state": receipt.gate_state,
                "resolution_action": receipt.resolution_action,
                "failure_class_name": receipt.failure_class_name,
                "summary": summary,
                "artifacts": receipt.artifacts,
                "policy_binding_hash": receipt.policy_binding_hash,
                "verification": receipt
                    .post_state
                    .as_ref()
                    .map(|v| v.verification_checks.clone())
                    .unwrap_or_default(),
            });
            let report = artifact_store::create_report_artifact(
                &memory_runtime,
                &thread_id,
                &format!("Receipt {}", receipt.step_index),
                "Routing policy decision receipt",
                &report_payload,
            );
            let report_ref = ArtifactRef {
                artifact_id: report.artifact_id.clone(),
                artifact_type: ArtifactType::Report,
            };
            register_artifact(&app, report);
            Some(report_ref)
        } else {
            None
        }
    };

    let event = emit_receipt_digest(
        &thread_id,
        receipt.step_index,
        receipt_id,
        &receipt.tool_name,
        receipt
            .pre_state
            .as_ref()
            .map(|s| s.tier.clone())
            .unwrap_or_else(|| "unknown".to_string())
            .as_str(),
        &receipt.policy_decision,
        &receipt.intent_class,
        &receipt.incident_stage,
        &receipt.strategy_node,
        &receipt.gate_state,
        &receipt.resolution_action,
        &summary,
        report_ref,
        Vec::new(),
    );
    register_event(&app, event);
}
