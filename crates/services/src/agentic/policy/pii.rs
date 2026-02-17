use crate::agentic::rules::Verdict;
use ioi_api::vm::inference::PiiRiskSurface;
use ioi_pii::RiskSurface;
use ioi_types::app::agentic::FirewallDecision;

pub(super) fn pii_decision_to_verdict(decision: &FirewallDecision) -> Verdict {
    match decision {
        FirewallDecision::Allow | FirewallDecision::AllowLocalOnly => Verdict::Allow,
        FirewallDecision::RedactThenAllow
        | FirewallDecision::TokenizeThenAllow
        | FirewallDecision::Quarantine
        | FirewallDecision::RequireUserReview => Verdict::RequireApproval,
        FirewallDecision::Deny => Verdict::Block,
    }
}

pub(super) fn to_shared_risk_surface(risk_surface: PiiRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiRiskSurface::LocalProcessing => RiskSurface::LocalProcessing,
        PiiRiskSurface::Egress => RiskSurface::Egress,
    }
}
