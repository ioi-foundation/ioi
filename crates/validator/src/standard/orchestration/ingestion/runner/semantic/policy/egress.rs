use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::{to_shared_risk_surface, ProcessedTx};
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_pii::{build_decision_material, build_review_summary, inspect_and_route_with_for_target};
use ioi_pii::RiskSurface;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::{KernelEvent, agentic::PiiTarget};
use ioi_types::app::PiiDecisionReceiptEvent;
use std::sync::Arc;

pub(crate) async fn evaluate_egress_gate(
    p_tx: &ProcessedTx,
    service_id: &str,
    method: &str,
    input_str: &str,
    rules: &ActionRules,
    expected_ts: u64,
    safety_model: &Arc<dyn LocalSafetyModel>,
    status_guard: &mut lru::LruCache<String, TxStatusEntry>,
    event_broadcaster: &tokio::sync::broadcast::Sender<KernelEvent>,
) -> bool {
    let pii_target = PiiTarget::ServiceCall {
        service_id: service_id.to_owned(),
        method: method.to_owned(),
    };
    let pii_target_label = pii_target.canonical_label();
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
        input_str,
        &pii_target,
        to_shared_risk_surface(PiiRiskSurface::Egress),
        &rules.pii_controls,
        false,
    )
    .await;

    match result {
        Ok((evidence, routed)) => {
            let _ = event_broadcaster.send(KernelEvent::PiiDecisionReceipt(
                PiiDecisionReceiptEvent {
                    session_id: None,
                    target: pii_target_label.clone(),
                    target_id: Some(pii_target.clone()),
                    risk_surface: "egress".to_string(),
                    decision_hash: routed.decision_hash,
                    decision: routed.decision.clone(),
                    transform_plan_id: routed
                        .transform_plan
                        .as_ref()
                        .map(|p| p.plan_id.clone()),
                    span_count: evidence.spans.len() as u32,
                    ambiguous: evidence.ambiguous,
                    stage2_kind: routed.stage2_decision.as_ref().map(|d| match d {
                        ioi_types::app::agentic::Stage2Decision::ApproveTransformPlan { .. } => {
                            "approve_transform_plan"
                        }
                        ioi_types::app::agentic::Stage2Decision::Deny { .. } => "deny",
                        ioi_types::app::agentic::Stage2Decision::RequestMoreInfo { .. } => {
                            "request_more_info"
                        }
                        ioi_types::app::agentic::Stage2Decision::GrantScopedException { .. } => {
                            "grant_scoped_exception"
                        }
                    }
                    .to_string()),
                    assist_invoked: routed.assist.assist_invoked,
                    assist_applied: routed.assist.assist_applied,
                    assist_kind: routed.assist.assist_kind.clone(),
                    assist_version: routed.assist.assist_version.clone(),
                    assist_identity_hash: routed.assist.assist_identity_hash,
                    assist_input_graph_hash: routed.assist.assist_input_graph_hash,
                    assist_output_graph_hash: routed.assist.assist_output_graph_hash,
                },
            ));

            match routed.decision {
                ioi_types::app::agentic::FirewallDecision::Allow
                | ioi_types::app::agentic::FirewallDecision::AllowLocalOnly => true,
                ioi_types::app::agentic::FirewallDecision::RedactThenAllow
                | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow
                | ioi_types::app::agentic::FirewallDecision::Quarantine
                | ioi_types::app::agentic::FirewallDecision::RequireUserReview => {
                    let reason = format!(
                        "PII review required ({:?}, stage2={:?})",
                        routed.decision,
                        routed.stage2_decision
                    );
                    tracing::warn!(
                        target: "ingestion",
                        "Transaction gated by PII firewall: {}",
                        reason
                    );
                    let material = build_decision_material(
                        &evidence,
                        &routed.decision,
                        routed.transform_plan.as_ref(),
                        routed.stage2_decision.as_ref(),
                        to_shared_risk_surface(PiiRiskSurface::Egress),
                        &pii_target,
                        false,
                        &routed.assist,
                    );
                    let summary = build_review_summary(
                        &evidence,
                        &pii_target,
                        routed.stage2_decision.as_ref(),
                    );
                    let created_at_ms = expected_ts.saturating_mul(1000);
                    let deadline_ms = created_at_ms
                        .saturating_add(rules.pii_controls.stage2_timeout_ms as u64);
                    let _ = event_broadcaster.send(KernelEvent::PiiReviewRequested {
                        decision_hash: routed.decision_hash,
                        material,
                        summary,
                        deadline_ms,
                        session_id: None,
                    });
                    let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                        verdict: "REQUIRE_APPROVAL".to_string(),
                        target: pii_target_label.clone(),
                        request_hash: routed.decision_hash,
                        session_id: None,
                    });

                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: ioi_ipc::public::TxStatus::Rejected,
                            error: Some(format!("Firewall: {}", reason)),
                            block_height: None,
                        },
                    );
                    false
                }
                ioi_types::app::agentic::FirewallDecision::Deny => {
                    let reason = format!(
                        "PII firewall denied raw egress ({:?})",
                        routed.stage2_decision
                    );
                    tracing::warn!(target: "ingestion", "{}", reason);
                    let _ = event_broadcaster.send(KernelEvent::FirewallInterception {
                        verdict: "BLOCK".to_string(),
                        target: pii_target_label.clone(),
                        request_hash: p_tx.canonical_hash,
                        session_id: None,
                    });

                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: ioi_ipc::public::TxStatus::Rejected,
                            error: Some(format!("Firewall: {}", reason)),
                            block_height: None,
                        },
                    );
                    false
                }
            }
        }
        Err(e) => {
            tracing::warn!(target: "ingestion", "PII inspection failure: {}", e);
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: ioi_ipc::public::TxStatus::Rejected,
                    error: Some(format!("Firewall Error: {}", e)),
                    block_height: None,
                },
            );
            false
        }
    }
}
