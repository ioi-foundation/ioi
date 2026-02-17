use super::super::DesktopAgentService;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_pii::{build_decision_material, build_review_summary, RiskSurface, REVIEW_REQUEST_VERSION};
use ioi_types::app::agentic::{PiiEgressRiskSurface, PiiReviewRequest, PiiTarget};
use ioi_types::codec;
use ioi_types::error::TransactionError;

fn to_shared_risk_surface(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

async fn enforce_text_egress_policy(
    service: &DesktopAgentService,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    target: &PiiTarget,
    risk_surface: RiskSurface,
    supports_transform: bool,
    scoped_exception_hash: Option<[u8; 32]>,
    text: &mut String,
) -> Result<(), TransactionError> {
    let target_label = target.canonical_label();
    let (scrubbed, _map, report, routed, evidence) = service
        .scrubber
        .inspect_route_transform(
            text,
            target,
            risk_surface,
            &rules.pii_controls,
            supports_transform,
        )
        .await
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "PII inspection failed for target '{}': {}",
                target_label, e
            ))
        })?;

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::PiiDecisionReceipt(
            ioi_types::app::PiiDecisionReceiptEvent {
                session_id: Some(session_id),
                target: target_label.clone(),
                target_id: Some(target.clone()),
                risk_surface: match risk_surface {
                    RiskSurface::LocalProcessing => "local_processing".to_string(),
                    RiskSurface::Egress => "egress".to_string(),
                },
                decision_hash: routed.decision_hash,
                decision: routed.decision.clone(),
                transform_plan_id: routed.transform_plan.as_ref().map(|p| p.plan_id.clone()),
                span_count: evidence.spans.len() as u32,
                ambiguous: evidence.ambiguous,
                stage2_kind: routed.stage2_decision.as_ref().map(|d| {
                    match d {
                        ioi_types::app::agentic::Stage2Decision::ApproveTransformPlan {
                            ..
                        } => "approve_transform_plan",
                        ioi_types::app::agentic::Stage2Decision::Deny { .. } => "deny",
                        ioi_types::app::agentic::Stage2Decision::RequestMoreInfo { .. } => {
                            "request_more_info"
                        }
                        ioi_types::app::agentic::Stage2Decision::GrantScopedException {
                            ..
                        } => "grant_scoped_exception",
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

    let scoped_exception_applies = scoped_exception_hash == Some(routed.decision_hash);

    match routed.decision {
        ioi_types::app::agentic::FirewallDecision::Allow
        | ioi_types::app::agentic::FirewallDecision::AllowLocalOnly => Ok(()),
        ioi_types::app::agentic::FirewallDecision::RedactThenAllow
        | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow => {
            if !supports_transform {
                if scoped_exception_applies {
                    return Ok(());
                }
                if let Some(tx) = &service.event_sender {
                    let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                        verdict: "REQUIRE_APPROVAL".to_string(),
                        target: target_label.clone(),
                        request_hash: routed.decision_hash,
                        session_id: Some(session_id),
                    });
                }
                return Err(TransactionError::PendingApproval(hex::encode(
                    routed.decision_hash,
                )));
            }
            if !report.no_raw_substring_leak {
                return Err(TransactionError::Invalid(format!(
                    "PII transform post-check failed for target '{}' (unresolved={}, remaining={}).",
                    target_label, report.unresolved_spans, report.remaining_span_count
                )));
            }
            *text = scrubbed;
            Ok(())
        }
        ioi_types::app::agentic::FirewallDecision::Quarantine
        | ioi_types::app::agentic::FirewallDecision::RequireUserReview => {
            if scoped_exception_applies {
                return Ok(());
            }
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                    verdict: "REQUIRE_APPROVAL".to_string(),
                    target: target_label,
                    request_hash: routed.decision_hash,
                    session_id: Some(session_id),
                });
            }
            Err(TransactionError::PendingApproval(hex::encode(
                routed.decision_hash,
            )))
        }
        ioi_types::app::agentic::FirewallDecision::Deny => {
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                    verdict: "BLOCK".to_string(),
                    target: target_label.clone(),
                    request_hash: routed.decision_hash,
                    session_id: Some(session_id),
                });
            }
            Err(TransactionError::Invalid(format!(
                "PII firewall denied raw egress for '{}'.",
                target_label
            )))
        }
    }
}

fn is_pii_review_required(
    decision: &ioi_types::app::agentic::FirewallDecision,
    supports_transform: bool,
) -> bool {
    matches!(
        decision,
        ioi_types::app::agentic::FirewallDecision::Quarantine
            | ioi_types::app::agentic::FirewallDecision::RequireUserReview
    ) || (!supports_transform
        && matches!(
            decision,
            ioi_types::app::agentic::FirewallDecision::RedactThenAllow
                | ioi_types::app::agentic::FirewallDecision::TokenizeThenAllow
        ))
}

pub(crate) async fn build_pii_review_request_for_tool(
    service: &DesktopAgentService,
    rules: &ActionRules,
    session_id: [u8; 32],
    tool: &ioi_types::app::agentic::AgentTool,
    decision_hash: [u8; 32],
    created_at_ms: u64,
) -> Result<Option<PiiReviewRequest>, TransactionError> {
    let mut candidate_tool = tool.clone();
    for spec in candidate_tool.pii_egress_specs() {
        let Some(text) = candidate_tool.pii_egress_field_mut(spec.field) else {
            continue;
        };
        let (_scrubbed, _map, _report, routed, evidence) = service
            .scrubber
            .inspect_route_transform(
                text,
                &spec.target,
                to_shared_risk_surface(spec.risk_surface),
                &rules.pii_controls,
                spec.supports_transform,
            )
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!(
                    "PII inspection failed while building review request: {}",
                    e
                ))
            })?;

        if routed.decision_hash != decision_hash {
            continue;
        }
        if !is_pii_review_required(&routed.decision, spec.supports_transform) {
            continue;
        }

        let material = build_decision_material(
            &evidence,
            &routed.decision,
            routed.transform_plan.as_ref(),
            routed.stage2_decision.as_ref(),
            to_shared_risk_surface(spec.risk_surface),
            &spec.target,
            spec.supports_transform,
            &routed.assist,
        );
        let summary =
            build_review_summary(&evidence, &spec.target, routed.stage2_decision.as_ref());
        let deadline_ms = created_at_ms.saturating_add(rules.pii_controls.stage2_timeout_ms as u64);

        return Ok(Some(PiiReviewRequest {
            request_version: REVIEW_REQUEST_VERSION,
            decision_hash,
            material,
            summary,
            session_id: Some(session_id),
            created_at_ms,
            deadline_ms,
        }));
    }

    Ok(None)
}

pub(crate) fn persist_pii_review_request(
    state: &mut dyn StateAccess,
    request: &PiiReviewRequest,
) -> Result<(), TransactionError> {
    let key = crate::agentic::desktop::keys::pii::review::request(&request.decision_hash);
    let bytes = codec::to_bytes_canonical(request)?;
    state.insert(&key, &bytes)?;
    Ok(())
}

pub(crate) fn emit_pii_review_requested(service: &DesktopAgentService, request: &PiiReviewRequest) {
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::PiiReviewRequested {
            decision_hash: request.decision_hash,
            material: request.material.clone(),
            summary: request.summary.clone(),
            deadline_ms: request.deadline_ms,
            session_id: request.session_id,
        });
    }
}

pub(super) async fn apply_pii_transform_first(
    service: &DesktopAgentService,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    scoped_exception_hash: Option<[u8; 32]>,
    tool: &mut ioi_types::app::agentic::AgentTool,
) -> Result<(), TransactionError> {
    let specs = tool.pii_egress_specs();
    for spec in specs {
        if let Some(text) = tool.pii_egress_field_mut(spec.field) {
            enforce_text_egress_policy(
                service,
                rules,
                session_id,
                &spec.target,
                to_shared_risk_surface(spec.risk_surface),
                spec.supports_transform,
                scoped_exception_hash,
                text,
            )
            .await?;
        }
    }
    Ok(())
}
