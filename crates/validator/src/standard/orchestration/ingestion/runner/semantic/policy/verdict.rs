use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, Verdict};
use ioi_types::app::{ActionRequest, ApprovalToken, KernelEvent};
use lru::LruCache;
use std::sync::Arc;

pub(crate) async fn evaluate_policy_verdict(
    p_tx: &ProcessedTx,
    method: &str,
    rules: &ActionRules,
    request: &ActionRequest,
    safety_model: &Arc<dyn LocalSafetyModel>,
    os_driver: &Arc<dyn OsDriver>,
    presented_approval: Option<&ApprovalToken>,
    status_guard: &mut LruCache<String, TxStatusEntry>,
    event_broadcaster: &tokio::sync::broadcast::Sender<KernelEvent>,
    allow_approval_bypass_for_message: bool,
) -> bool {
    let verdict =
        PolicyEngine::evaluate(rules, request, safety_model, os_driver, presented_approval).await;

    let mut is_safe = true;
    match verdict {
        Verdict::Allow => {}
        Verdict::Block => {
            is_safe = false;
            let reason = "Blocked by active policy rules";
            tracing::warn!(target: "ingestion", "Transaction blocked: {}", reason);
            let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                verdict: "BLOCK".to_string(),
                target: method.to_string(),
                request_hash: p_tx.canonical_hash,
                session_id: None,
            });

            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                crate::standard::orchestration::context::TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Policy: {}", reason)),
                    block_height: None,
                },
            );
        }
        Verdict::RequireApproval => {
            if allow_approval_bypass_for_message {
                tracing::info!(
                    target: "ingestion",
                    "Downgrading REQUIRE_APPROVAL to ALLOW for desktop_agent post_message@v1"
                );
            } else {
                is_safe = true;
                let reason = "Manual approval required";
                tracing::warn!(
                    target: "ingestion",
                    "Transaction halted (Policy Gate): {}. Allowing for state transition.",
                    reason
                );

                let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                    verdict: "REQUIRE_APPROVAL".to_string(),
                    target: method.to_string(),
                    request_hash: p_tx.canonical_hash,
                    session_id: None,
                });
            }
        }
    }

    is_safe
}
