use crate::agentic::pii_scrubber::PiiScrubber;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_pii::RiskSurface;
use ioi_types::app::agentic::{
    FirewallDecision, InferenceOptions, PiiControls, PiiTarget, Stage2Decision,
};
use ioi_types::app::KernelEvent;
use ioi_types::error::TransactionError;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

/// Runs deterministic pre-cloud PII inspection and returns a safe payload.
pub async fn prepare_cloud_inference_input(
    scrubber: &PiiScrubber,
    event_sender: Option<&Sender<KernelEvent>>,
    session_id: Option<[u8; 32]>,
    provider: &str,
    model: &str,
    input: &[u8],
) -> Result<Vec<u8>, TransactionError> {
    let input_str = std::str::from_utf8(input).map_err(|_| {
        TransactionError::Invalid("PII pre-cloud airlock requires UTF-8 input payload.".to_string())
    })?;

    let target = PiiTarget::CloudInference {
        provider: provider.to_string(),
        model: model.to_string(),
    };
    let policy = PiiControls::default();
    let (scrubbed, _map, report, routed, evidence) = scrubber
        .inspect_route_transform(input_str, &target, RiskSurface::Egress, &policy, true)
        .await
        .map_err(|e| {
            TransactionError::Invalid(format!("PII pre-cloud inspection failed: {}", e))
        })?;

    if let Some(tx) = event_sender {
        let _ = tx.send(KernelEvent::PiiDecisionReceipt(
            ioi_types::app::PiiDecisionReceiptEvent {
                session_id,
                target: target.canonical_label(),
                target_id: Some(target.clone()),
                risk_surface: "egress".to_string(),
                decision_hash: routed.decision_hash,
                decision: routed.decision.clone(),
                transform_plan_id: routed.transform_plan.as_ref().map(|p| p.plan_id.clone()),
                span_count: evidence.spans.len() as u32,
                ambiguous: evidence.ambiguous,
                stage2_kind: routed.stage2_decision.as_ref().map(|d| {
                    match d {
                        Stage2Decision::ApproveTransformPlan { .. } => "approve_transform_plan",
                        Stage2Decision::Deny { .. } => "deny",
                        Stage2Decision::RequestMoreInfo { .. } => "request_more_info",
                        Stage2Decision::GrantScopedException { .. } => "grant_scoped_exception",
                    }
                    .to_string()
                }),
                assist_invoked: routed.assist.assist_invoked,
                assist_applied: routed.assist.assist_applied,
                assist_kind: routed.assist.assist_kind.clone(),
                assist_version: routed.assist.assist_version.clone(),
                assist_identity_hash: routed.assist.assist_identity_hash,
                assist_input_graph_hash: routed.assist.assist_input_graph_hash,
                assist_output_graph_hash: routed.assist.assist_output_graph_hash,
            },
        ));
    }

    match routed.decision {
        FirewallDecision::Allow | FirewallDecision::AllowLocalOnly => Ok(input.to_vec()),
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow => {
            if !report.no_raw_substring_leak {
                return Err(TransactionError::Invalid(
                    "PII pre-cloud transform post-check failed".to_string(),
                ));
            }
            Ok(scrubbed.into_bytes())
        }
        FirewallDecision::Quarantine | FirewallDecision::RequireUserReview => {
            if let Some(tx) = event_sender {
                let _ = tx.send(KernelEvent::FirewallInterception {
                    verdict: "REQUIRE_APPROVAL".to_string(),
                    target: target.canonical_label(),
                    request_hash: routed.decision_hash,
                    session_id,
                });
            }
            Err(TransactionError::PendingApproval(hex::encode(
                routed.decision_hash,
            )))
        }
        FirewallDecision::Deny => {
            if let Some(tx) = event_sender {
                let _ = tx.send(KernelEvent::FirewallInterception {
                    verdict: "BLOCK".to_string(),
                    target: target.canonical_label(),
                    request_hash: routed.decision_hash,
                    session_id,
                });
            }
            Err(TransactionError::Invalid(
                "PII pre-cloud airlock denied raw payload.".to_string(),
            ))
        }
    }
}

/// Executes cloud inference only after the pre-cloud airlock has sanitized the input.
pub async fn execute_cloud_inference(
    runtime: &Arc<dyn InferenceRuntime>,
    scrubber: &PiiScrubber,
    event_sender: Option<&Sender<KernelEvent>>,
    session_id: Option<[u8; 32]>,
    provider: &str,
    model: &str,
    model_hash: [u8; 32],
    input: &[u8],
    options: InferenceOptions,
) -> Result<Vec<u8>, TransactionError> {
    let airlocked =
        prepare_cloud_inference_input(scrubber, event_sender, session_id, provider, model, input)
            .await?;
    runtime
        .execute_inference(model_hash, &airlocked, options)
        .await
        .map_err(|e| TransactionError::Invalid(format!("Cloud inference failed: {}", e)))
}
