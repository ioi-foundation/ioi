use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::{
    parse_hash_hex, ProcessedTx,
};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::state::service_namespace_prefix;
use ioi_client::WorkloadClient;
use ioi_services::agentic::desktop::keys::{get_incident_key, get_state_key, pii};
use ioi_services::agentic::desktop::service::step::incident::IncidentState;
use ioi_services::agentic::desktop::{AgentState, ResumeAgentParams};
use ioi_types::app::agentic::PiiReviewRequest;
use ioi_types::app::ApprovalToken;
use ioi_types::codec;
use lru::LruCache;
use std::sync::Arc;

pub(crate) struct ResumeContext {
    pub approval_token: Option<ApprovalToken>,
    pub resume_session_id: Option<[u8; 32]>,
    pub agent_state: Option<AgentState>,
    pub expected_request_hash: Option<[u8; 32]>,
    pub pii_request: Option<PiiReviewRequest>,
}

pub(crate) async fn resolve_resume_context(
    p_tx: &ProcessedTx,
    workload_client: &Arc<WorkloadClient>,
    params: &[u8],
    status_guard: &mut LruCache<String, TxStatusEntry>,
) -> Option<ResumeContext> {
    let Ok(resume) = codec::from_bytes_canonical::<ResumeAgentParams>(params) else {
        let reason = "Invalid resume params payload";
        tracing::warn!(target: "ingestion", "{}", reason);
        status_guard.put(
            p_tx.receipt_hash_hex.clone(),
            TxStatusEntry {
                status: ioi_ipc::public::TxStatus::Rejected,
                error: Some(format!("Firewall: {}", reason)),
                block_height: None,
            },
        );
        return None;
    };

    let resume_session_id = resume.session_id;
    let mut approval_token = resume.approval_token.clone();

    let ns_prefix = service_namespace_prefix("desktop_agent");
    let state_key = get_state_key(&resume.session_id);
    let state_full_key = [ns_prefix.as_slice(), state_key.as_slice()].concat();
    let incident_key = get_incident_key(&resume.session_id);
    let incident_full_key = [ns_prefix.as_slice(), incident_key.as_slice()].concat();

    let agent_state = match workload_client.query_raw_state(&state_full_key).await {
        Ok(Some(bytes)) => match codec::from_bytes_canonical::<AgentState>(&bytes) {
            Ok(v) => Some(v),
            Err(_) => {
                let reason = "Invalid desktop agent state bytes";
                tracing::warn!(target: "ingestion", "{}", reason);
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: ioi_ipc::public::TxStatus::Rejected,
                        error: Some(format!("Firewall: {}", reason)),
                        block_height: None,
                    },
                );
                None
            }
        },
        Ok(None) => {
            let reason = "Missing desktop agent state for resume";
            tracing::warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            None
        }
        Err(e) => {
            let reason = format!("Failed to query desktop agent state: {}", e);
            tracing::warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            None
        }
    };

    if agent_state.is_none() {
        return None;
    }

    let agent_state = agent_state.expect("checked above");

    if approval_token.is_none() {
        approval_token = agent_state.pending_approval.clone();
    }

    let pending_tool_hash = match agent_state.pending_tool_hash {
        Some(v) => v,
        None => {
            let reason = "Missing pending tool hash for resume review verification";
            tracing::warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            return None;
        }
    };

    let pending_gate_hash = match workload_client.query_raw_state(&incident_full_key).await {
        Ok(Some(bytes)) => {
            codec::from_bytes_canonical::<IncidentState>(&bytes)
                .ok()
                .and_then(|incident| {
                    incident
                        .pending_gate
                        .as_ref()
                        .and_then(|pending| parse_hash_hex(&pending.request_hash))
                })
        }
        Ok(None) => None,
        Err(_) => None,
    };

    let expected_request_hash = ioi_pii::resolve_expected_request_hash(
        pending_gate_hash,
        pending_tool_hash,
    );

    let request_key_local = pii::review::request(&expected_request_hash);
    let request_key = [ns_prefix.as_slice(), request_key_local.as_slice()].concat();
    let pii_request_opt = match workload_client.query_raw_state(&request_key).await {
        Ok(Some(bytes)) => match codec::from_bytes_canonical::<PiiReviewRequest>(&bytes) {
            Ok(req) => {
                if let Err(e) = ioi_pii::validate_review_request_compat(&req) {
                    let reason = format!("Incompatible PII review request: {}", e);
                    tracing::warn!(target: "ingestion", "{}", reason);
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: ioi_ipc::public::TxStatus::Rejected,
                            error: Some(format!("Firewall: {}", reason)),
                            block_height: None,
                        },
                    );
                    return None;
                }
                Some(req)
            }
            Err(_) => {
                let reason = "Invalid PII review request bytes";
                tracing::warn!(target: "ingestion", "{}", reason);
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: ioi_ipc::public::TxStatus::Rejected,
                        error: Some(format!("Firewall: {}", reason)),
                        block_height: None,
                    },
                );
                return None;
            }
        },
        Ok(None) => None,
        Err(e) => {
            let reason = format!("Failed to query PII review request: {}", e);
            tracing::warn!(target: "ingestion", "{}", reason);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall: {}", reason)),
                    block_height: None,
                },
            );
            return None;
        }
    };

    Some(ResumeContext {
        approval_token,
        resume_session_id: Some(resume_session_id),
        agent_state: Some(agent_state),
        expected_request_hash: Some(expected_request_hash),
        pii_request: pii_request_opt,
    })
}
