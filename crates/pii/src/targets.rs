// Submodule: typed PII target policy helpers.

use ioi_types::app::agentic::{PiiControls, PiiTarget};

pub fn is_high_risk_target(policy: &PiiControls, target: &PiiTarget) -> bool {
    let label = target.canonical_label();
    policy
        .high_risk_targets
        .iter()
        .any(|configured| configured == &label)
}
