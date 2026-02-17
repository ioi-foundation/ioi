// Submodule: decision (hash material + deterministic hashing)

use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, FirewallDecision, PiiClass, PiiControls, PiiDecisionMaterial,
    PiiSeverity, PiiTarget, RawOverrideMode, Stage2Decision, TransformAction, TransformPlan,
};
use parity_scale_codec::Encode;

use crate::assist::{risk_surface_label, stage2_kind, CimAssistReceipt, RiskSurface};
use crate::hashing::sha256_array;
use crate::routing::PiiRoutingOutcome;

pub(crate) fn has_high_severity(graph: &EvidenceGraph) -> bool {
    graph
        .spans
        .iter()
        .any(|s| matches!(s.severity, PiiSeverity::High | PiiSeverity::Critical))
}

pub(crate) fn has_only_low_severity(graph: &EvidenceGraph) -> bool {
    !graph.spans.is_empty()
        && graph
            .spans
            .iter()
            .all(|s| matches!(s.severity, PiiSeverity::Low))
}

pub(crate) fn is_secret_heavy(graph: &EvidenceGraph) -> bool {
    graph
        .spans
        .iter()
        .any(|s| matches!(s.pii_class, PiiClass::ApiKey | PiiClass::SecretToken))
}

pub(crate) fn build_transform_plan(target: &PiiTarget, graph: &EvidenceGraph) -> TransformPlan {
    let target_label = target.canonical_label();
    let span_indices = (0..graph.spans.len() as u32).collect::<Vec<_>>();

    if is_secret_heavy(graph) {
        TransformPlan {
            plan_id: format!("tokenize::{target_label}"),
            action: TransformAction::Tokenize,
            span_indices,
            redaction_label: None,
            token_ref: Some(format!("tokref::{}", hex::encode(graph.source_hash))),
        }
    } else {
        TransformPlan {
            plan_id: format!("redact::{target_label}"),
            action: TransformAction::Redact,
            span_indices,
            redaction_label: Some("REDACTED".to_string()),
            token_ref: None,
        }
    }
}

/// Builds canonical deterministic decision material from a routed outcome.
pub fn build_decision_material(
    graph: &EvidenceGraph,
    decision: &FirewallDecision,
    transform_plan: Option<&TransformPlan>,
    stage2_decision: Option<&Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiDecisionMaterial {
    PiiDecisionMaterial {
        version: 3,
        target: target.clone(),
        risk_surface: risk_surface_label(risk_surface).to_string(),
        supports_transform,
        source_hash: graph.source_hash,
        span_count: graph.spans.len() as u32,
        ambiguous: graph.ambiguous,
        decision: decision.clone(),
        transform_plan_id: transform_plan.map(|p| p.plan_id.clone()),
        stage2_kind: stage2_kind(stage2_decision),
        assist_invoked: assist.assist_invoked,
        assist_applied: assist.assist_applied,
        assist_kind: assist.assist_kind.clone(),
        assist_version: assist.assist_version.clone(),
        assist_identity_hash: assist.assist_identity_hash,
        assist_input_graph_hash: assist.assist_input_graph_hash,
        assist_output_graph_hash: assist.assist_output_graph_hash,
    }
}

/// Computes the canonical decision hash for a fully-populated decision material payload.
pub fn compute_decision_hash(material: &PiiDecisionMaterial) -> [u8; 32] {
    sha256_array(&material.encode()).unwrap_or([0u8; 32])
}

fn decision_hash(
    graph: &EvidenceGraph,
    decision: &FirewallDecision,
    transform_plan: Option<&TransformPlan>,
    stage2_decision: Option<&Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> [u8; 32] {
    let material = build_decision_material(
        graph,
        decision,
        transform_plan,
        stage2_decision,
        risk_surface,
        target,
        supports_transform,
        assist,
    );

    compute_decision_hash(&material)
}

pub(crate) fn with_hash(
    graph: &EvidenceGraph,
    decision: FirewallDecision,
    transform_plan: Option<TransformPlan>,
    stage2_decision: Option<Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    let hash = decision_hash(
        graph,
        &decision,
        transform_plan.as_ref(),
        stage2_decision.as_ref(),
        risk_surface,
        target,
        supports_transform,
        assist,
    );

    PiiRoutingOutcome {
        decision,
        transform_plan,
        stage2_decision,
        assist: assist.clone(),
        decision_hash: hash,
    }
}

// (removed stray doc comment that was left without an item; see `targets.rs` for high-risk helpers)
