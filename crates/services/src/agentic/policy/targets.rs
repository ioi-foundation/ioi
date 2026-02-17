use crate::agentic::rules::ActionRules;
use ioi_types::app::ActionTarget;

use super::filesystem::filesystem_scope_policy_target;

pub(super) fn policy_target_aliases(target: &ActionTarget) -> Vec<String> {
    let mut aliases = vec![target.canonical_label()];
    if let ActionTarget::Custom(name) = target {
        let compatibility_aliases: &[&str] = match name.as_str() {
            "browser::click_element" => &["browser::click", "browser__click_element"],
            _ => &[],
        };
        for alias in compatibility_aliases {
            if !aliases.iter().any(|candidate| candidate == alias) {
                aliases.push((*alias).to_string());
            }
        }
    }
    if let Some(scope_target) = filesystem_scope_policy_target(target) {
        if !aliases.iter().any(|alias| alias == scope_target) {
            aliases.push(scope_target.to_string());
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
