use crate::agentic::rules::ActionRules;
use ioi_types::app::ActionTarget;

use super::filesystem::filesystem_scope_policy_target;

fn model_control_policy_target(target: &ActionTarget) -> Option<&'static str> {
    match target {
        ActionTarget::Custom(name)
            if name.starts_with("model_registry__")
                || name.starts_with("backend__")
                || name.starts_with("gallery__") =>
        {
            Some("model::control")
        }
        _ => None,
    }
}

pub(crate) fn policy_target_aliases(target: &ActionTarget) -> Vec<String> {
    let mut aliases = vec![target.canonical_label()];
    if let Some(scope_target) = filesystem_scope_policy_target(target) {
        if !aliases.iter().any(|alias| alias == scope_target) {
            aliases.push(scope_target.to_string());
        }
    }
    if let Some(model_control_target) = model_control_policy_target(target) {
        if !aliases.iter().any(|alias| alias == model_control_target) {
            aliases.push(model_control_target.to_string());
        }
    }
    aliases
}

pub(super) fn is_high_risk_target_for_rules(rules: &ActionRules, target: &ActionTarget) -> bool {
    let aliases = policy_target_aliases(target);
    aliases.iter().any(|alias| {
        rules
            .pii_controls
            .high_risk_targets
            .iter()
            .any(|configured| configured == alias)
    })
}
