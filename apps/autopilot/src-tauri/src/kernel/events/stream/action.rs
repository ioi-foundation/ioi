use crate::kernel::events::emission::{build_event, register_event};
use crate::kernel::events::stream::fetch_pii::fetch_pii_review_info;
use crate::kernel::events::support::{
    bind_task_session, clarification_preset_for_tool, is_hard_terminal_task,
    is_identity_resolution_kind, is_install_package_tool,
    is_waiting_for_identity_clarification_step, thread_id_from_session,
};
use crate::kernel::state::update_task_state;
use crate::models::{AgentPhase, EventStatus, EventType, GateInfo};
use ioi_ipc::public::ActionIntercepted;
use serde_json::json;
use tauri::Manager;

fn connector_gate_presentation(
    target: &str,
) -> Option<(String, String, String, Option<String>, Option<String>)> {
    let normalized = target.trim().to_ascii_lowercase();
    if !normalized.starts_with("connector__google__") {
        return None;
    }

    let human_label = normalized
        .trim_start_matches("connector__google__")
        .split("__")
        .next()
        .unwrap_or(normalized.as_str())
        .split('_')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let risk = if normalized.contains("expert")
        || normalized.contains("watch")
        || normalized.contains("events_")
        || normalized.contains("bigquery_execute_query")
    {
        "high".to_string()
    } else {
        "medium".to_string()
    };

    Some((
        "Approve Google action".to_string(),
        format!(
            "Shield policy paused the run before {} in your connected Google Workspace. Approve to continue or deny to block the action.",
            human_label
        ),
        risk,
        Some("Approve action".to_string()),
        Some("Deny action".to_string()),
    ))
}

pub(super) async fn handle_action(app: &tauri::AppHandle, action: ActionIntercepted) {
    if action.verdict == "PII_REVIEW_REQUESTED" {
        let pii_info = fetch_pii_review_info(&app, &action.reason).await;
        if let Some(pii) = pii_info {
            update_task_state(&app, |t| {
                t.gate_info = Some(GateInfo {
                    title: "PII Review".to_string(),
                    description:
                        "Sensitive content was detected before egress. Review and choose a deterministic action.".to_string(),
                    risk: "high".to_string(),
                    approve_label: Some("Approve transform".to_string()),
                    deny_label: Some("Deny".to_string()),
                    deadline_ms: Some(pii.deadline_ms),
                    pii: Some(pii.clone()),
                });
                t.pending_request_hash = Some(action.reason.clone());
                bind_task_session(t, &action.session_id);
            });
        }
        return;
    }

    if action.verdict == "REQUIRE_APPROVAL" {
        let pii_info = fetch_pii_review_info(&app, &action.reason).await;
        let (waiting_for_sudo, waiting_for_clarification, hard_terminal_task) = {
            let state_handle = app.state::<std::sync::Mutex<crate::models::AppState>>();
            let out = match state_handle.lock() {
                Ok(guard) => guard
                    .current_task
                    .as_ref()
                    .map(|task| {
                        let waiting_for_sudo = task
                            .credential_request
                            .as_ref()
                            .map(|req| req.kind == "sudo_password")
                            .unwrap_or(false)
                            || task
                                .current_step
                                .eq_ignore_ascii_case("Waiting for sudo password");
                        let waiting_for_clarification = task
                            .clarification_request
                            .as_ref()
                            .map(|req| is_identity_resolution_kind(&req.kind))
                            .unwrap_or(false)
                            || is_waiting_for_identity_clarification_step(&task.current_step);
                        (
                            waiting_for_sudo,
                            waiting_for_clarification,
                            is_hard_terminal_task(task),
                        )
                    })
                    .unwrap_or((false, false, false)),
                Err(_) => (false, false, false),
            };
            out
        };

        let action_is_install = is_install_package_tool(&action.target);
        let action_is_identity_lookup_tool =
            clarification_preset_for_tool(&action.target).is_some();
        let suppress_gate_for_wait = (waiting_for_sudo && action_is_install)
            || (waiting_for_clarification && action_is_identity_lookup_tool);

        let already_gating = {
            let state_handle = app.state::<std::sync::Mutex<crate::models::AppState>>();
            let out = match state_handle.lock() {
                Ok(guard) => guard
                    .current_task
                    .as_ref()
                    .map(|task| {
                        task.phase == AgentPhase::Gate
                            && task.pending_request_hash.as_deref() == Some(action.reason.as_str())
                    })
                    .unwrap_or(false),
                Err(_) => false,
            };
            out
        };

        if !already_gating && !suppress_gate_for_wait && !hard_terminal_task {
            println!("[Autopilot] Policy Gate Triggered for {}", action.target);

            update_task_state(app, |t| {
                t.phase = AgentPhase::Gate;
                let connector_presentation = connector_gate_presentation(&action.target);
                t.current_step = connector_presentation
                    .as_ref()
                    .map(|_| "Waiting for approval".to_string())
                    .unwrap_or_else(|| "Waiting for approval".to_string());
                t.credential_request = None;
                t.clarification_request = None;

                t.gate_info = Some(if let Some(pii) = pii_info.clone() {
                    GateInfo {
                        title: "PII Review".to_string(),
                        description:
                            "Sensitive content was detected before egress. Choose transform, deny, or scoped exception."
                                .to_string(),
                        risk: "high".to_string(),
                        approve_label: Some("Approve transform".to_string()),
                        deny_label: Some("Deny".to_string()),
                        deadline_ms: Some(pii.deadline_ms),
                        pii: Some(pii),
                    }
                } else if let Some((title, description, risk, approve_label, deny_label)) =
                    connector_presentation.clone()
                {
                    GateInfo {
                        title,
                        description,
                        risk,
                        approve_label,
                        deny_label,
                        deadline_ms: None,
                        pii: None,
                    }
                } else {
                    GateInfo {
                        title: "Restricted Action Intercepted".to_string(),
                        description: format!(
                            "The agent is attempting to execute: {}",
                            action.target
                        ),
                        risk: "high".to_string(),
                        approve_label: Some("Approve action".to_string()),
                        deny_label: Some("Deny action".to_string()),
                        deadline_ms: None,
                        pii: None,
                    }
                });

                t.pending_request_hash = Some(action.reason.clone());

                bind_task_session(t, &action.session_id);

                t.history.push(crate::models::ChatMessage {
                    role: "system".to_string(),
                    text: connector_presentation
                        .as_ref()
                        .map(|(_, description, _, _, _)| format!("🛑 {}", description))
                        .unwrap_or_else(|| {
                            format!("🛑 Policy Gate triggered for action: {}", action.target)
                        }),
                    timestamp: crate::kernel::state::now(),
                });

                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                    agent.status = "paused".to_string();
                }
            });

            let thread_id = thread_id_from_session(&app, &action.session_id);
            let event = build_event(
                &thread_id,
                0,
                EventType::Warning,
                "Approval required".to_string(),
                json!({
                    "target": action.target,
                    "verdict": action.verdict,
                    "request_hash": action.reason,
                }),
                json!({
                    "message": "Policy gate triggered",
                }),
                EventStatus::Partial,
                Vec::new(),
                None,
                Vec::new(),
                None,
            );
            register_event(&app, event);

            if let Some(w) = app.get_webview_window("studio") {
                if w.is_visible().unwrap_or(false) {
                    let _ = w.set_focus();
                }
            }
        }
    } else if action.verdict == "BLOCK" {
        update_task_state(app, |t| {
            t.current_step = format!("⛔ Action Blocked: {}", action.target);
            t.phase = AgentPhase::Failed;

            if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                agent.status = "failed".to_string();
            }

            t.history.push(crate::models::ChatMessage {
                role: "system".to_string(),
                text: format!("⛔ Blocked action: {}", action.target),
                timestamp: crate::kernel::state::now(),
            });
        });

        let thread_id = thread_id_from_session(&app, &action.session_id);
        let event = build_event(
            &thread_id,
            0,
            EventType::Error,
            "Action blocked".to_string(),
            json!({
                "target": action.target,
                "verdict": action.verdict,
            }),
            json!({}),
            EventStatus::Failure,
            Vec::new(),
            None,
            Vec::new(),
            None,
        );
        register_event(&app, event);
    }
}
