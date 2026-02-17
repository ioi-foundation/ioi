use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ApprovalToken, KernelEvent};
use std::sync::Arc;

mod egress;
mod verdict;

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
    approval_token: Option<&ApprovalToken>,
    resume_session_id: Option<[u8; 32]>,
) -> bool {
    let request = ActionRequest {
        target: ActionTarget::Custom(method.to_owned()),
        params: params.to_owned(),
        context: ActionContext {
            agent_id: "unknown".into(),
            session_id: resume_session_id,
            window_id: None,
        },
        nonce: 0,
    };

    let presented_approval = if service_id == "desktop_agent" && method == "resume@v1" {
        None
    } else {
        approval_token
    };

    let mut is_safe = verdict::evaluate_policy_verdict(
        p_tx,
        method,
        rules,
        &request,
        safety_model,
        os_driver,
        presented_approval,
        status_guard,
        event_broadcaster,
        allow_approval_bypass_for_message,
    )
    .await;

    if !is_safe {
        return false;
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
