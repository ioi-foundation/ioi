use super::super::DesktopAgentService;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_pii::{build_decision_material, build_review_summary, RiskSurface, REVIEW_REQUEST_VERSION};
use ioi_types::app::agentic::{
    AgentTool, PiiEgressField, PiiEgressRiskSurface, PiiEgressSpec, PiiReviewRequest, PiiTarget,
};
use ioi_types::app::ActionTarget;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::net::IpAddr;
use url::Url;

fn to_shared_risk_surface(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn browser_url_uses_local_processing(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }

    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };

    match parsed.scheme() {
        "about" | "data" | "file" => true,
        "http" | "https" => parsed.host_str().is_some_and(browser_host_is_local),
        _ => false,
    }
}

fn browser_host_is_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }

    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn pii_risk_surface_for_spec(
    tool: &AgentTool,
    spec: &PiiEgressSpec,
    active_browser_url: Option<&str>,
) -> RiskSurface {
    if !matches!(
        spec.target,
        PiiTarget::Action(ActionTarget::BrowserInteract)
    ) {
        return to_shared_risk_surface(spec.risk_surface);
    }

    let browser_url = match (tool, spec.field) {
        (AgentTool::BrowserNavigate { url }, PiiEgressField::BrowserNavigateUrl) => {
            Some(url.as_str())
        }
        _ => active_browser_url,
    };

    if browser_url.is_some_and(browser_url_uses_local_processing) {
        RiskSurface::LocalProcessing
    } else {
        to_shared_risk_surface(spec.risk_surface)
    }
}

async fn enforce_text_egress_policy(
    service: &DesktopAgentService,
    rules: &crate::agentic::rules::ActionRules,
    session_id: [u8; 32],
    field: ioi_types::app::agentic::PiiEgressField,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    supports_transform: bool,
    scoped_exception_hash: Option<[u8; 32]>,
    text: &mut String,
) -> Result<(), TransactionError> {
    let target_label = target.canonical_label();
    let (scrubbed, _map, report, routed, evidence) = service
        .scrubber
        .inspect_route_transform_for_egress_field(
            text,
            field,
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
            .inspect_route_transform_for_egress_field(
                text,
                spec.field,
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
    let needs_active_browser_url = specs.iter().any(|spec| {
        matches!(
            spec.target,
            PiiTarget::Action(ActionTarget::BrowserInteract)
        ) && !matches!(spec.field, PiiEgressField::BrowserNavigateUrl)
    });
    let active_browser_url = if needs_active_browser_url {
        service.browser.active_url().await.ok()
    } else {
        None
    };
    for spec in specs {
        let risk_surface = pii_risk_surface_for_spec(tool, &spec, active_browser_url.as_deref());
        if let Some(text) = tool.pii_egress_field_mut(spec.field) {
            enforce_text_egress_policy(
                service,
                rules,
                session_id,
                spec.field,
                &spec.target,
                risk_surface,
                spec.supports_transform,
                scoped_exception_hash,
                text,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        browser_url_uses_local_processing, pii_risk_surface_for_spec, to_shared_risk_surface,
    };
    use ioi_pii::RiskSurface;
    use ioi_types::app::agentic::{
        AgentTool, PiiEgressField, PiiEgressRiskSurface, PiiEgressSpec, PiiTarget,
    };
    use ioi_types::app::ActionTarget;

    fn browser_interact_spec(field: PiiEgressField, supports_transform: bool) -> PiiEgressSpec {
        PiiEgressSpec {
            field,
            target: PiiTarget::Action(ActionTarget::BrowserInteract),
            supports_transform,
            risk_surface: PiiEgressRiskSurface::Egress,
        }
    }

    #[test]
    fn browser_local_processing_detection_covers_loopback_and_local_schemes() {
        assert!(browser_url_uses_local_processing(
            "http://127.0.0.1:8000/login"
        ));
        assert!(browser_url_uses_local_processing(
            "http://localhost:3000/queue"
        ));
        assert!(browser_url_uses_local_processing(
            "https://bench.localhost/workflow"
        ));
        assert!(browser_url_uses_local_processing(
            "file:///tmp/miniwob.html"
        ));
        assert!(browser_url_uses_local_processing("about:blank"));
        assert!(browser_url_uses_local_processing(
            "data:text/html,<p>fixture</p>"
        ));
        assert!(!browser_url_uses_local_processing(
            "https://example.com/login"
        ));
    }

    #[test]
    fn browser_navigate_uses_destination_url_for_local_processing_routing() {
        let tool = AgentTool::BrowserNavigate {
            url: "http://127.0.0.1:4123/workflow/login".to_string(),
        };
        let spec = browser_interact_spec(PiiEgressField::BrowserNavigateUrl, false);

        assert!(matches!(
            pii_risk_surface_for_spec(&tool, &spec, None),
            RiskSurface::LocalProcessing
        ));
    }

    #[test]
    fn browser_type_uses_active_page_context_for_local_processing_routing() {
        let tool = AgentTool::BrowserType {
            text: "secret".to_string(),
            selector: Some("#password".to_string()),
        };
        let spec = browser_interact_spec(PiiEgressField::BrowserTypeText, true);

        assert!(matches!(
            pii_risk_surface_for_spec(&tool, &spec, Some("file:///tmp/workflow.html")),
            RiskSurface::LocalProcessing
        ));
        assert!(matches!(
            pii_risk_surface_for_spec(&tool, &spec, Some("https://example.com/login")),
            RiskSurface::Egress
        ));
        assert_eq!(
            pii_risk_surface_for_spec(&tool, &spec, None),
            to_shared_risk_surface(PiiEgressRiskSurface::Egress)
        );
    }
}
