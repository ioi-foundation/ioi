use crate::agentic::rules::{ActionRules, DefaultPolicy, Verdict};
use ioi_types::app::agentic::FirewallPolicy;

use super::PolicyEngine;

impl PolicyEngine {
    /// Validates that a proposed policy mutation is monotonic (i.e., strictly safer or equal).
    /// Used by the Optimizer Service during Recursive Self-Improvement cycles.
    pub fn validate_safety_ratchet(
        old_policy: &ActionRules,
        new_policy: &ActionRules,
    ) -> Result<(), String> {
        let old_caps = Self::extract_caps(old_policy);
        let new_caps = Self::extract_caps(new_policy);

        if new_caps.budget_cap > old_caps.budget_cap {
            return Err(format!(
                "Mutation rejected: Attempted to increase budget cap from {} to {}.",
                old_caps.budget_cap, new_caps.budget_cap
            ));
        }

        for domain in &new_caps.network_allowlist {
            if !old_caps.network_allowlist.contains(domain) {
                return Err(format!(
                    "Mutation rejected: Attempted to add new network domain '{}'.",
                    domain
                ));
            }
        }

        if old_caps.require_human_gate && !new_caps.require_human_gate {
            return Err("Mutation rejected: Attempted to remove Human Gate requirement.".into());
        }

        Ok(())
    }

    /// Helper to flatten ActionRules into a comparable FirewallPolicy struct.
    fn extract_caps(rules: &ActionRules) -> FirewallPolicy {
        let mut budget = 0.0;
        let mut network = Vec::new();
        let mut gate = false;

        for rule in &rules.rules {
            if let Some(spend) = rule.conditions.max_spend {
                let amount = spend as f64 / 1000.0;
                if amount > budget {
                    budget = amount;
                }
            }

            if let Some(domains) = &rule.conditions.allow_domains {
                for d in domains {
                    if !network.contains(d) {
                        network.push(d.clone());
                    }
                }
            }

            if rule.action == Verdict::RequireApproval {
                gate = true;
            }
        }

        if rules.defaults == DefaultPolicy::RequireApproval {
            gate = true;
        }

        FirewallPolicy {
            budget_cap: budget,
            network_allowlist: network,
            require_human_gate: gate,
            privacy_level: None,
        }
    }
}
