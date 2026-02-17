use crate::agentic::rules::{ActionRules, DefaultPolicy, Verdict};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_pii::{build_decision_material, inspect_and_route_with_for_target, RiskSurface};
use ioi_types::app::agentic::{PiiDecisionMaterial, PiiTarget};
use ioi_types::app::{ActionRequest, ApprovalToken};
use std::sync::Arc;

use super::pii::{pii_decision_to_verdict, to_shared_risk_surface};
use super::targets::{is_high_risk_target_for_rules, policy_target_aliases};

/// The core engine for evaluating actions against firewall policies.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluates an ActionRequest against the active policy.
    /// This is the core "Compliance Layer" logic.
    pub async fn evaluate(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
        presented_approval: Option<&ApprovalToken>,
    ) -> Verdict {
        let request_hash = request.hash();

        // 1. Authorization Gate: Check for valid ApprovalToken first.
        // If the user has already signed a token for this EXACT request hash, it bypasses policy checks.
        // This is how the "Gate Window" flow resolves.
        if let Some(token) = presented_approval {
            if token.request_hash == request_hash {
                tracing::info!("Policy Gate: Valid Approval Token presented. Allowing action.");
                return Verdict::Allow;
            } else {
                tracing::warn!(
                    "Policy Gate: Token mismatch. Token for {:?}, Request is {:?}",
                    hex::encode(token.request_hash),
                    hex::encode(request_hash)
                );
            }
        }

        let target_aliases = policy_target_aliases(&request.target);

        // 2. Specific Rules: Linear scan (specific overrides general)
        // First matching rule wins.
        let mut base_verdict = None;
        for rule in &rules.rules {
            if rule.target == "*" || target_aliases.iter().any(|target| rule.target == *target) {
                if Self::check_conditions(
                    rule,
                    &request.target,
                    &request.params,
                    safety_model,
                    os_driver,
                )
                .await
                {
                    base_verdict = Some(rule.action);
                    break;
                }
            }
        }

        let base_verdict = match base_verdict {
            Some(v) => v,
            None => match rules.defaults {
                DefaultPolicy::AllowAll => Verdict::Allow,
                DefaultPolicy::DenyAll => Verdict::Block,
                DefaultPolicy::RequireApproval => Verdict::RequireApproval,
            },
        };

        // 3. Stage B/C PII router overlay.
        let pii_verdict = Self::evaluate_pii_overlay(rules, request, safety_model).await;

        // Preserve explicit policy blocks regardless of PII route.
        if matches!(base_verdict, Verdict::Block) {
            return Verdict::Block;
        }

        match pii_verdict {
            Some(Verdict::Block) => Verdict::Block,
            Some(Verdict::RequireApproval) => Verdict::RequireApproval,
            _ => base_verdict,
        }
    }

    async fn evaluate_pii_overlay(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
    ) -> Option<Verdict> {
        Self::evaluate_pii_overlay_details(rules, request, safety_model)
            .await
            .map(|(verdict, _material)| verdict)
    }

    pub(super) async fn evaluate_pii_overlay_details(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
    ) -> Option<(Verdict, Option<PiiDecisionMaterial>)> {
        let high_risk = is_high_risk_target_for_rules(rules, &request.target);
        let risk_surface = if high_risk {
            PiiRiskSurface::Egress
        } else {
            PiiRiskSurface::LocalProcessing
        };

        let input = match std::str::from_utf8(&request.params) {
            Ok(s) => s,
            Err(_) => {
                if high_risk && !request.params.is_empty() {
                    tracing::warn!(
                        "PII policy: non-UTF8 payload on high-risk target {:?}; blocking (fail-closed).",
                        request.target
                    );
                    return Some((Verdict::Block, None));
                }
                return None;
            }
        };

        let target = PiiTarget::Action(request.target.clone());
        let safety_model = Arc::clone(safety_model);
        let (evidence, routed) = match inspect_and_route_with_for_target(
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
            input,
            &target,
            to_shared_risk_surface(risk_surface),
            &rules.pii_controls,
            false, // Policy engine cannot mutate payloads directly.
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "PII policy inspection failed for {:?} (risk={:?}): {}",
                    request.target,
                    risk_surface,
                    e
                );
                return Some((
                    if high_risk {
                        Verdict::Block
                    } else {
                        Verdict::Allow
                    },
                    None,
                ));
            }
        };

        if !evidence.spans.is_empty() {
            tracing::info!(
                "PII route target={} risk={:?} spans={} ambiguous={} decision={:?} hash={}",
                target.canonical_label(),
                risk_surface,
                evidence.spans.len(),
                evidence.ambiguous,
                routed.decision,
                hex::encode(routed.decision_hash)
            );
        }

        let material = build_decision_material(
            &evidence,
            &routed.decision,
            routed.transform_plan.as_ref(),
            routed.stage2_decision.as_ref(),
            to_shared_risk_surface(risk_surface),
            &target,
            false,
            &routed.assist,
        );

        Some((pii_decision_to_verdict(&routed.decision), Some(material)))
    }
}
