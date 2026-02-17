use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::{
    to_shared_risk_surface_from_egress, ProcessedTx,
};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::state::service_namespace_prefix;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_client::WorkloadClient;
use ioi_pii::{
    check_exception_usage_increment_ok, decode_exception_usage_state, inspect_and_route_with_for_target,
    mint_default_scoped_exception, verify_scoped_exception_for_decision, RiskSurface,
    ScopedExceptionVerifyError,
};
use ioi_services::agentic::desktop::AgentState;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::agentic::AgentTool;
use lru::LruCache;
use std::sync::Arc;

pub(crate) async fn verify_scoped_exception(
    p_tx: &ProcessedTx,
    expected_request_hash: [u8; 32],
    token: &ioi_types::app::ApprovalToken,
    agent_state: &AgentState,
    workload_client: &Arc<WorkloadClient>,
    safety_model: &Arc<dyn LocalSafetyModel>,
    rules: &ActionRules,
    status_guard: &mut LruCache<String, TxStatusEntry>,
    block_timestamp_secs: u64,
) -> bool {
    let pending_tool_jcs = match agent_state.pending_tool_jcs.as_ref() {
        Some(v) => v,
        None => {
            let reason = "Missing pending tool for scoped exception verification";
            tracing::warn!(target: "ingestion", "{}", reason);
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
    };

    let mut tool: AgentTool = match serde_json::from_slice(pending_tool_jcs) {
        Ok(v) => v,
        Err(e) => {
            let reason = format!(
                "Failed to decode pending tool for scoped exception verification: {}",
                e
            );
            tracing::warn!(target: "ingestion", "{}", reason);
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
    };

    let mut verified = false;
    for spec in tool.pii_egress_specs() {
        let Some(text) = tool.pii_egress_field_mut(spec.field) else {
            continue;
        };

        let risk_surface = to_shared_risk_surface_from_egress(spec.risk_surface);
        let safety_model = Arc::clone(safety_model);
        let result = inspect_and_route_with_for_target(
            |input, shared_risk_surface| {
                let safety_model = safety_model.clone();
                Box::pin(async move {
                    let api_risk_surface = match shared_risk_surface {
                        RiskSurface::LocalProcessing => PiiRiskSurface::LocalProcessing,
                        RiskSurface::Egress => PiiRiskSurface::Egress,
                    };
                    let inspection = safety_model.inspect_pii(input, api_risk_surface).await?;
                    Ok(inspection.evidence)
                })
            },
            text,
            &spec.target,
            risk_surface,
            &rules.pii_controls,
            spec.supports_transform,
        )
        .await;

        let (evidence, routed) = match result {
            Ok(v) => v,
            Err(e) => {
                let reason = format!("Scoped exception PII verification failed: {}", e);
                tracing::warn!(target: "ingestion", "{}", reason);
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
        };

        if routed.decision_hash != expected_request_hash {
            continue;
        }

        let scoped_exception = if let Some(existing) = token.scoped_exception.as_ref() {
            existing.clone()
        } else {
            match mint_default_scoped_exception(
                &evidence,
                &spec.target,
                risk_surface,
                expected_request_hash,
                block_timestamp_secs,
                "deterministic-default",
            ) {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("Failed to mint deterministic scoped exception: {}", e);
                    tracing::warn!(target: "ingestion", "{}", reason);
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
        };

        let usage_key_local = ioi_services::agentic::desktop::keys::pii::review::exception_usage(
            &scoped_exception.exception_id,
        );
        let usage_key = [service_namespace_prefix("desktop_agent").as_slice(), usage_key_local.as_slice()]
            .concat();
        let raw_usage = match workload_client.query_raw_state(&usage_key).await {
            Ok(v) => v,
            Err(e) => {
                let reason = format!("Failed to query scoped exception usage: {}", e);
                tracing::warn!(target: "ingestion", "{}", reason);
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
        };
        let uses_consumed = match decode_exception_usage_state(raw_usage.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                let reason = e.to_string();
                tracing::warn!(target: "ingestion", "{}", reason);
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
        };

        if let Err(e) = verify_scoped_exception_for_decision(
            &scoped_exception,
            &evidence,
            &spec.target,
            risk_surface,
            expected_request_hash,
            &rules.pii_controls,
            block_timestamp_secs,
            uses_consumed,
        ) {
            let reason = match e {
                ScopedExceptionVerifyError::PolicyDisabled => "Scoped exception policy disabled",
                ScopedExceptionVerifyError::MissingAllowedClasses => {
                    "Scoped exception missing allowed classes"
                }
                ScopedExceptionVerifyError::DestinationMismatch => {
                    "Scoped exception destination mismatch"
                }
                ScopedExceptionVerifyError::ActionMismatch => "Scoped exception action mismatch",
                ScopedExceptionVerifyError::Expired => "Scoped exception expired",
                ScopedExceptionVerifyError::Overused => "Scoped exception overused",
                ScopedExceptionVerifyError::IneligibleEvidence => {
                    "Scoped exception not eligible for this evidence"
                }
                ScopedExceptionVerifyError::ClassMismatch => "Scoped exception class mismatch",
                ScopedExceptionVerifyError::InvalidMaxUses => "Scoped exception max_uses invalid",
            };
            tracing::warn!(target: "ingestion", "{}", reason);
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

        if let Err(e) = check_exception_usage_increment_ok(uses_consumed) {
            let reason = e.to_string();
            tracing::warn!(target: "ingestion", "{}", reason);
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

        verified = true;
        break;
    }

    if !verified {
        let reason = "Scoped exception does not match pending PII decision";
        tracing::warn!(target: "ingestion", "{}", reason);
        status_guard.put(
            p_tx.receipt_hash_hex.clone(),
            TxStatusEntry {
                status: ioi_ipc::public::TxStatus::Rejected,
                error: Some(format!("Firewall: {}", reason)),
                block_height: None,
            },
        );
    }

    verified
}
