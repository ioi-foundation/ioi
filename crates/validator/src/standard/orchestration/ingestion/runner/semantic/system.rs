use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_api::chain::WorkloadClientApi;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_client::WorkloadClient;
use ioi_pii::validate_resume_review_contract;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::{ChainTransaction, KernelEvent};
use lru::LruCache;
use std::sync::Arc;
use tracing::{info, warn};

use super::policy::evaluate_service_policy_and_egress;
use super::review::{resolve_resume_context, verify_scoped_exception};
use ioi_types::codec;

pub(crate) async fn evaluate_system_transaction(
    p_tx: &ProcessedTx,
    workload_client: &Arc<WorkloadClient>,
    safety_model: &Arc<dyn LocalSafetyModel>,
    os_driver: &Arc<dyn OsDriver>,
    expected_ts: u64,
    status_guard: &mut LruCache<String, TxStatusEntry>,
    event_broadcaster: &tokio::sync::broadcast::Sender<KernelEvent>,
) -> bool {
    let ChainTransaction::System(sys) = &p_tx.tx else {
        return true;
    };

    let ioi_types::app::SystemPayload::CallService {
        service_id,
        method,
        params,
        ..
    } = &sys.payload
    else {
        return true;
    };

    if service_id != "agentic" && service_id != "desktop_agent" && service_id != "compute_market" {
        return true;
    }

    let allow_approval_bypass_for_message =
        service_id == "desktop_agent" && method == "post_message@v1";
    if allow_approval_bypass_for_message {
        info!(
            target: "ingestion",
            "Approval-gate bypass enabled for desktop_agent post_message@v1"
        );
    }

    let mut approval_token = None;
    let mut resume_session_id = None;
    let mut agent_state = None;
    let mut expected_request_hash_opt = None;
    let mut pii_request_opt = None;

    if service_id == "desktop_agent" && method == "resume@v1" {
        let context =
            match resolve_resume_context(p_tx, workload_client, params, status_guard).await {
                Some(v) => v,
                None => return false,
            };

        approval_token = context.approval_token;
        resume_session_id = context.resume_session_id;
        expected_request_hash_opt = context.expected_request_hash;
        pii_request_opt = context.pii_request;
        agent_state = context.agent_state;

        if agent_state.is_none() {
            let reason = "Missing desktop agent state for resume context";
            warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            return false;
        }
    }

    let global_policy_key = [b"agent::policy::".as_slice(), &[0u8; 32]].concat();
    let rules = match workload_client.query_raw_state(&global_policy_key).await {
        Ok(Some(bytes)) => codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default(),
        _ => ActionRules::default(), // DenyAll
    };

    if service_id == "desktop_agent" && method == "resume@v1" {
        if pii_request_opt.is_some() && approval_token.is_none() {
            let reason = "Missing approval token for review request";
            warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            return false;
        } else if let (Some(expected_request_hash), Some(token)) =
            (expected_request_hash_opt, approval_token.as_ref())
        {
            if let Err(e) = validate_resume_review_contract(
                expected_request_hash,
                token,
                pii_request_opt.as_ref(),
                expected_ts.saturating_mul(1000),
            ) {
                warn!(target: "ingestion", "{}", e);
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: ioi_ipc::public::TxStatus::Rejected,
                        error: Some(format!("Firewall: {}", e)),
                        block_height: None,
                    },
                );
                return false;
            }
        }

        if approval_token.as_ref().and_then(|t| t.pii_action.clone())
            == Some(ioi_types::app::action::PiiApprovalAction::GrantScopedException)
        {
            let token = approval_token.as_ref().expect("checked above");
            if let Some(agent_state) = agent_state.as_ref() {
                if let Some(expected_request_hash) = expected_request_hash_opt {
                    if !verify_scoped_exception(
                        p_tx,
                        expected_request_hash,
                        token,
                        agent_state,
                        workload_client,
                        safety_model,
                        &rules,
                        status_guard,
                        expected_ts,
                    )
                    .await
                    {
                        return false;
                    }
                } else {
                    let reason = "Missing expected request hash for scoped exception verification";
                    warn!(target: "ingestion", "{}", reason);
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: ioi_ipc::public::TxStatus::Rejected,
                            error: Some(format!("Firewall: {}", reason)),
                            block_height: None,
                        },
                    );
                    return false;
                }
            }
        }
    }

    evaluate_service_policy_and_egress(
        p_tx,
        service_id,
        method,
        params,
        &rules,
        expected_ts,
        safety_model,
        os_driver,
        status_guard,
        event_broadcaster,
        allow_approval_bypass_for_message,
        approval_token.as_ref(),
        resume_session_id,
    )
    .await
}
