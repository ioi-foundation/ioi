// Submodule: routing (policy-only routing + assist integration)

use anyhow::Result;
use ioi_types::app::agentic::{
    EvidenceGraph, FirewallDecision, PiiControls, PiiDecisionMaterial, PiiReviewRequest,
    PiiScopedException, PiiTarget, RawOverrideMode, Stage2Decision, TransformAction, TransformPlan,
};
use ioi_types::app::ActionTarget;

use crate::assist::{
    build_assist_receipt, CimAssistContext, CimAssistProvider, CimAssistReceipt, CimAssistResult,
    InspectFuture, NoopCimAssistProvider, RiskSurface,
};
use crate::cim_v0::CimAssistV0Provider;
use crate::decision::{
    build_decision_material, build_transform_plan, compute_decision_hash, has_high_severity,
    has_only_low_severity, is_secret_heavy, with_hash,
};
use crate::review_summary::build_review_summary;
use crate::scoped_exception::{
    mint_default_scoped_exception, verify_scoped_exception_for_decision,
};
use crate::targets::is_high_risk_target;
use crate::targets::legacy_target_from_str;

pub struct PiiRoutingOutcome {
    pub decision: FirewallDecision,
    pub transform_plan: Option<TransformPlan>,
    pub stage2_decision: Option<Stage2Decision>,
    pub assist: CimAssistReceipt,
    pub decision_hash: [u8; 32],
}

pub fn route_pii_decision_with_assist_for_target(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    if graph.spans.is_empty() {
        return with_hash(
            graph,
            FirewallDecision::Allow,
            None,
            None,
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if matches!(risk_surface, RiskSurface::LocalProcessing) {
        return with_hash(
            graph,
            FirewallDecision::AllowLocalOnly,
            None,
            None,
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    let high_risk_target = is_high_risk_target(policy, target);
    let has_high = has_high_severity(graph);
    let low_only = has_only_low_severity(graph);
    let can_transform = policy.safe_transform_enabled && supports_transform;
    let has_secret = is_secret_heavy(graph);

    // Strict egress secret rule: never allow raw secret payloads.
    if has_secret && matches!(risk_surface, RiskSurface::Egress) {
        if !can_transform {
            return with_hash(
                graph,
                FirewallDecision::Deny,
                None,
                Some(Stage2Decision::Deny {
                    reason: "Raw secret egress is not permitted without deterministic transform."
                        .to_string(),
                }),
                risk_surface,
                target,
                supports_transform,
                assist,
            );
        }

        let plan = build_transform_plan(target, graph);
        return with_hash(
            graph,
            match plan.action {
                TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                _ => FirewallDecision::RedactThenAllow,
            },
            Some(plan),
            Some(Stage2Decision::ApproveTransformPlan {
                plan_id: format!("transform::{}", target.canonical_label()),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if has_high && !can_transform {
        return with_hash(
            graph,
            FirewallDecision::Deny,
            None,
            Some(Stage2Decision::Deny {
                reason: "High-severity PII cannot egress as raw content in MVP.".to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if graph.ambiguous {
        if can_transform {
            let plan = build_transform_plan(target, graph);
            return with_hash(
                graph,
                match plan.action {
                    TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                    _ => FirewallDecision::RedactThenAllow,
                },
                Some(plan),
                Some(Stage2Decision::ApproveTransformPlan {
                    plan_id: format!("transform::{}", target.canonical_label()),
                }),
                risk_surface,
                target,
                supports_transform,
                assist,
            );
        }

        return with_hash(
            graph,
            if high_risk_target {
                FirewallDecision::Quarantine
            } else {
                FirewallDecision::RequireUserReview
            },
            None,
            Some(Stage2Decision::RequestMoreInfo {
                question_template:
                    "PII ambiguity detected. Approve deterministic transform or deny raw egress."
                        .to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if low_only
        && matches!(
            policy.raw_override_mode,
            RawOverrideMode::ScopedLowSeverityOnly
        )
        && policy.raw_override_default_enabled
    {
        return with_hash(
            graph,
            FirewallDecision::RequireUserReview,
            None,
            Some(Stage2Decision::RequestMoreInfo {
                question_template:
                    "Low-severity raw override eligible. Review may grant one scoped exception."
                        .to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if can_transform {
        let plan = build_transform_plan(target, graph);
        return with_hash(
            graph,
            match plan.action {
                TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                _ => FirewallDecision::RedactThenAllow,
            },
            Some(plan),
            Some(Stage2Decision::ApproveTransformPlan {
                plan_id: format!("transform::{}", target.canonical_label()),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    with_hash(
        graph,
        if high_risk_target {
            FirewallDecision::Quarantine
        } else {
            FirewallDecision::RequireUserReview
        },
        None,
        Some(Stage2Decision::RequestMoreInfo {
            question_template:
                "PII detected. Approve deterministic transform, grant scoped override, or deny."
                    .to_string(),
        }),
        risk_surface,
        target,
        supports_transform,
        assist,
    )
}

/// Deterministic routing API without an explicit assist provider.
pub fn route_pii_decision_for_target(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
) -> PiiRoutingOutcome {
    let provider = CimAssistV0Provider::default();
    let assist_result = provider
        .assist(
            graph,
            &CimAssistContext {
                target,
                risk_surface,
                policy,
                supports_transform,
            },
        )
        .unwrap_or_else(|_| CimAssistResult {
            output_graph: graph.clone(),
            assist_applied: false,
        });
    let assist = build_assist_receipt(
        &provider,
        graph,
        &assist_result.output_graph,
        assist_result.assist_applied,
    );
    route_pii_decision_with_assist_for_target(
        &assist_result.output_graph,
        policy,
        risk_surface,
        target,
        supports_transform,
        &assist,
    )
}

/// Compatibility routing API without an explicit assist provider.
#[deprecated(note = "Use route_pii_decision_for_target with PiiTarget")]
pub fn route_pii_decision(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &str,
    supports_transform: bool,
) -> PiiRoutingOutcome {
    let mapped = legacy_target_from_str(target);
    route_pii_decision_for_target(graph, policy, risk_surface, &mapped, supports_transform)
}

/// Compatibility routing API with explicit assist provider.
#[deprecated(note = "Use route_pii_decision_with_assist_for_target with PiiTarget")]
pub fn route_pii_decision_with_assist(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &str,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    let mapped = legacy_target_from_str(target);
    route_pii_decision_with_assist_for_target(
        graph,
        policy,
        risk_surface,
        &mapped,
        supports_transform,
        assist,
    )
}

/// Shared pipeline entrypoint for deterministic inspect + assist + route.
///
/// The inspector closure provides deterministic evidence extraction from the caller's
/// local safety model adapter without coupling this crate to `ioi-api`.
pub async fn inspect_and_route_with_provider_for_target<F, P>(
    inspect: F,
    assist_provider: &P,
    input: &str,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
    P: CimAssistProvider + ?Sized,
{
    let input_graph = inspect(input, risk_surface).await?;
    let assist_ctx = CimAssistContext {
        target,
        risk_surface,
        policy,
        supports_transform,
    };
    let assist_result = assist_provider.assist(&input_graph, &assist_ctx)?;
    let assist_receipt = build_assist_receipt(
        assist_provider,
        &input_graph,
        &assist_result.output_graph,
        assist_result.assist_applied,
    );
    let routed = route_pii_decision_with_assist_for_target(
        &assist_result.output_graph,
        policy,
        risk_surface,
        target,
        supports_transform,
        &assist_receipt,
    );
    Ok((assist_result.output_graph, routed))
}

/// Default pipeline entrypoint that always invokes deterministic CIM assist v0.
pub async fn inspect_and_route_with_for_target<F>(
    inspect: F,
    input: &str,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
{
    let provider = CimAssistV0Provider::default();
    inspect_and_route_with_provider_for_target(
        inspect,
        &provider,
        input,
        target,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}

/// Compatibility pipeline entrypoint that accepts legacy string targets.
#[deprecated(note = "Use inspect_and_route_with_for_target with PiiTarget")]
pub async fn inspect_and_route_with<F>(
    inspect: F,
    input: &str,
    target: &str,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
{
    let mapped = legacy_target_from_str(target);
    inspect_and_route_with_for_target(
        inspect,
        input,
        &mapped,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}

/// Compatibility inspect+route entrypoint with explicit assist provider and string target.
#[deprecated(note = "Use inspect_and_route_with_provider_for_target with PiiTarget")]
pub async fn inspect_and_route_with_provider<F, P>(
    inspect: F,
    assist_provider: &P,
    input: &str,
    target: &str,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
    P: CimAssistProvider + ?Sized,
{
    let mapped = legacy_target_from_str(target);
    inspect_and_route_with_provider_for_target(
        inspect,
        assist_provider,
        input,
        &mapped,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}
