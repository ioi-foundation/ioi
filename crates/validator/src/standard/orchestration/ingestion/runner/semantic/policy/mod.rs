use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent};
use std::sync::Arc;

mod egress;
mod verdict;

fn policy_request_params(method: &str, params: &[u8]) -> Vec<u8> {
    if serde_json::from_slice::<serde_json::Value>(params).is_ok() {
        return params.to_vec();
    }

    serde_json::to_vec(&serde_json::json!({
        "__ioi_policy_non_json_params": {
            "method": method,
            "encoding": "hex",
            "value": hex::encode(params),
        }
    }))
    .unwrap_or_else(|_| b"{\"__ioi_policy_non_json_params\":null}".to_vec())
}

fn is_desktop_agent_lifecycle_control(method: &str) -> bool {
    matches!(
        method,
        "start@v1"
            | "step@v1"
            | "post_message@v1"
            | "resume@v1"
            | "deny@v1"
            | "register_approval_authority@v1"
            | "revoke_approval_authority@v1"
    )
}

pub(crate) async fn evaluate_service_policy_and_egress(
    p_tx: &ProcessedTx,
    service_id: &str,
    method: &str,
    params: &[u8],
    rules: &ActionRules,
    expected_ts: u64,
    safety_model: &Arc<dyn LocalSafetyModel>,
    os_driver: &Arc<dyn OsDriver>,
    status_guard: &mut lru::LruCache<String, TxStatusEntry>,
    event_broadcaster: &tokio::sync::broadcast::Sender<KernelEvent>,
    allow_approval_bypass_for_message: bool,
    resume_session_id: Option<[u8; 32]>,
) -> bool {
    let request = ActionRequest {
        target: ActionTarget::Custom(method.to_owned()),
        params: policy_request_params(method, params),
        context: ActionContext {
            agent_id: "unknown".into(),
            session_id: resume_session_id,
            window_id: None,
        },
        nonce: 0,
    };

    let mut is_safe = verdict::evaluate_policy_verdict(
        p_tx,
        method,
        rules,
        &request,
        safety_model,
        os_driver,
        status_guard,
        event_broadcaster,
        allow_approval_bypass_for_message,
        service_id == "desktop_agent" && is_desktop_agent_lifecycle_control(method),
    )
    .await;

    if !is_safe {
        return false;
    }

    if service_id == "desktop_agent" && is_desktop_agent_lifecycle_control(method) {
        return true;
    }

    let input_str = match std::str::from_utf8(params) {
        Ok(s) => Some(s),
        Err(_) if service_id == "desktop_agent" => None,
        Err(_) => {
            let reason = "PII firewall requires UTF-8 payload for egress evaluation";
            tracing::warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                crate::standard::orchestration::context::TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            return false;
        }
    };

    if let Some(input_str) = input_str {
        is_safe = egress::evaluate_egress_gate(
            p_tx,
            service_id,
            method,
            input_str,
            rules,
            expected_ts,
            safety_model,
            status_guard,
            event_broadcaster,
        )
        .await;
    }

    is_safe
}

#[cfg(test)]
mod tests {
    use super::is_desktop_agent_lifecycle_control;

    #[test]
    fn desktop_agent_lifecycle_controls_are_distinct_from_runtime_tools() {
        for method in [
            "start@v1",
            "step@v1",
            "post_message@v1",
            "resume@v1",
            "deny@v1",
            "register_approval_authority@v1",
            "revoke_approval_authority@v1",
        ] {
            assert!(
                is_desktop_agent_lifecycle_control(method),
                "{method} should be treated as a lifecycle control"
            );
        }

        for method in [
            "software_install__execute_plan",
            "shell__run",
            "browser__click",
        ] {
            assert!(
                !is_desktop_agent_lifecycle_control(method),
                "{method} is a runtime tool and must remain receipt/policy evaluated"
            );
        }
    }
}
