use crate::agentic::rules::{ActionRules, DefaultPolicy, Verdict};
use crate::agentic::runtime::kernel::policy::PolicyEvaluationRecord;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_crypto::algorithms::hash::sha256;
use ioi_pii::{
    build_decision_material, compute_decision_hash, inspect_and_route_with_for_target, RiskSurface,
};
use ioi_types::app::agentic::{PiiDecisionMaterial, PiiTarget};
use ioi_types::app::ActionRequest;
use std::sync::Arc;

use super::pii::{pii_decision_to_verdict, to_shared_risk_surface};
use super::targets::{is_high_risk_target_for_rules, policy_target_aliases};

/// The core engine for evaluating actions against firewall policies.
pub struct PolicyEngine;

impl PolicyEngine {
    async fn evaluate_record_inner(
        rules: &ActionRules,
        request: &ActionRequest,
        working_directory: Option<&str>,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
        include_pii_overlay: bool,
    ) -> PolicyEvaluationRecord {
        let policy_hash = compute_policy_hash(rules);
        if let Err(err) = request.try_hash() {
            tracing::warn!(
                "Policy Gate: request canonicalization/hash failed; blocking (fail-closed): {}",
                err
            );
            return PolicyEvaluationRecord {
                verdict: Verdict::Block,
                matched_rule_ids: vec!["determinism:invalid_request_hash".to_string()],
                default_policy_used: None,
                pii_decision_hash: None,
                policy_hash,
                rule_eval_trace_hash: None,
                lease_eval_hash: None,
            };
        }

        let target_aliases = policy_target_aliases(&request.target);

        // 2. Specific Rules: Linear scan (specific overrides general)
        // First matching rule wins.
        let mut base_verdict = None;
        let mut matched_rule_ids = Vec::new();
        for (index, rule) in rules.rules.iter().enumerate() {
            if rule.target == "*" || target_aliases.iter().any(|target| rule.target == *target) {
                if Self::check_conditions(
                    rule,
                    &request.target,
                    &request.params,
                    working_directory,
                    safety_model,
                    os_driver,
                )
                .await
                {
                    base_verdict = Some(rule.action);
                    matched_rule_ids.push(rule_id_for_record(index, rule));
                    break;
                }
            }
        }

        let default_policy_used = if base_verdict.is_none() {
            Some(default_policy_label(rules.defaults).to_string())
        } else {
            None
        };
        let base_verdict = match base_verdict {
            Some(v) => v,
            None => match rules.defaults {
                DefaultPolicy::AllowAll => Verdict::Allow,
                DefaultPolicy::DenyAll => Verdict::Block,
                DefaultPolicy::RequireApproval => Verdict::RequireApproval,
            },
        };

        // 3. Stage B/C PII router overlay.
        let pii_overlay = if include_pii_overlay {
            Self::evaluate_pii_overlay_details(rules, request, safety_model).await
        } else {
            None
        };
        let pii_decision_hash = pii_overlay
            .as_ref()
            .and_then(|(_verdict, material)| material.as_ref())
            .map(compute_decision_hash);
        let pii_verdict = pii_overlay.map(|(verdict, _material)| verdict);

        // Preserve explicit policy blocks regardless of PII route.
        let verdict = if matches!(base_verdict, Verdict::Block) {
            Verdict::Block
        } else {
            match pii_verdict {
                Some(Verdict::Block) => Verdict::Block,
                Some(Verdict::RequireApproval) => Verdict::RequireApproval,
                _ => base_verdict,
            }
        };

        PolicyEvaluationRecord {
            verdict,
            matched_rule_ids,
            default_policy_used,
            pii_decision_hash,
            policy_hash,
            rule_eval_trace_hash: None,
            lease_eval_hash: None,
        }
    }

    pub async fn evaluate_with_working_directory(
        rules: &ActionRules,
        request: &ActionRequest,
        working_directory: Option<&str>,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
    ) -> Verdict {
        Self::evaluate_record_with_working_directory(
            rules,
            request,
            working_directory,
            safety_model,
            os_driver,
        )
        .await
        .verdict
    }

    pub async fn evaluate_record_with_working_directory(
        rules: &ActionRules,
        request: &ActionRequest,
        working_directory: Option<&str>,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
    ) -> PolicyEvaluationRecord {
        Self::evaluate_record_inner(
            rules,
            request,
            working_directory,
            safety_model,
            os_driver,
            true,
        )
        .await
    }

    pub async fn evaluate_record_without_pii_overlay(
        rules: &ActionRules,
        request: &ActionRequest,
        working_directory: Option<&str>,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
    ) -> PolicyEvaluationRecord {
        Self::evaluate_record_inner(
            rules,
            request,
            working_directory,
            safety_model,
            os_driver,
            false,
        )
        .await
    }

    /// Evaluates an ActionRequest against the active policy.
    /// This is the core "Compliance Layer" logic.
    pub async fn evaluate(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
    ) -> Verdict {
        Self::evaluate_with_working_directory(rules, request, None, safety_model, os_driver).await
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

fn default_policy_label(defaults: DefaultPolicy) -> &'static str {
    match defaults {
        DefaultPolicy::AllowAll => "allow_all",
        DefaultPolicy::DenyAll => "deny_all",
        DefaultPolicy::RequireApproval => "require_approval",
    }
}

fn rule_id_for_record(index: usize, rule: &crate::agentic::rules::Rule) -> String {
    rule.rule_id
        .clone()
        .unwrap_or_else(|| format!("rule:{}:{}", index, rule.target))
}

fn compute_policy_hash(rules: &ActionRules) -> Option<[u8; 32]> {
    let canonical = serde_jcs::to_vec(rules).ok()?;
    let digest = sha256(&canonical).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Some(out)
}
