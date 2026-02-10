// Path: crates/validator/src/firewall/synthesizer.rs

// [FIX] Update import path
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_types::app::agentic::StepTrace;
use serde_json::Value;
use std::collections::HashMap;

/// Synthesizes a security policy from a recorded execution trace.
pub struct PolicySynthesizer;

impl PolicySynthesizer {
    /// Generates an ActionRules policy that whitelists the actions observed in the trace.
    pub fn synthesize(policy_id: &str, traces: &[StepTrace]) -> ActionRules {
        let mut rules_map: HashMap<String, RuleConditions> = HashMap::new();

        for trace in traces {
            // Only learn from successful steps
            if !trace.success {
                continue;
            }

            // Parse the raw output to find the tool call
            if let Ok(tool_call) = serde_json::from_str::<Value>(&trace.raw_output) {
                if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                    let conditions = rules_map.entry(name.to_string()).or_default();

                    // Extract parameters to refine conditions
                    // For MVP, we extract domains from URLs and App names if available.
                    // This logic mirrors the Python SDK's GhostRecorder heuristics.

                    if name == "net__fetch" || name == "browser__navigate" {
                        if let Some(url) = tool_call["arguments"]["url"].as_str() {
                            if let Some(domain) = extract_domain(url) {
                                let domains = conditions.allow_domains.get_or_insert_with(Vec::new);
                                if !domains.contains(&domain) {
                                    domains.push(domain);
                                }
                            }
                        }
                    } else if name == "gui__click" || name == "gui__type" {
                        // [NEW] Suggest blocking high-risk intents for GUI actions if observed in unsafe contexts (heuristic)
                        // For now, we just ensure the rule exists.
                        // Future: integrate SafetyModel hints if trace contains them.
                    }
                }
            }
        }

        // Convert map to Vec<Rule>
        let rules = rules_map
            .into_iter()
            .map(|(target, conditions)| Rule {
                rule_id: Some(format!("auto-{}", target)),
                target,
                conditions,
                action: Verdict::Allow,
            })
            .collect();

        ActionRules {
            policy_id: policy_id.to_string(),
            defaults: DefaultPolicy::DenyAll, // Safe by default
            rules,
        }
    }
}

fn extract_domain(url: &str) -> Option<String> {
    // Simple heuristic: split by / and take the 3rd part (protocol://domain/...)
    let parts: Vec<&str> = url.split('/').collect();
    if parts.len() >= 3 {
        Some(parts[2].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_network_policy() {
        let trace1 = StepTrace {
            session_id: [0; 32],
            step_index: 0,
            visual_hash: [0; 32],
            full_prompt: "".into(),
            raw_output: r#"{"name": "browser__navigate", "arguments": {"url": "https://google.com/search"}}"#.into(),
            success: true,
            error: None,
            cost_incurred: 0,
            fitness_score: None,
            skill_hash: None,
            timestamp: 0,
        };
        let trace2 = StepTrace {
            session_id: [0; 32],
            step_index: 1,
            visual_hash: [0; 32],
            full_prompt: "".into(),
            raw_output: r#"{"name": "gui__click", "arguments": {"x": 100, "y": 100}}"#.into(),
            success: true,
            error: None,
            cost_incurred: 0,
            fitness_score: None,
            skill_hash: None,
            timestamp: 0,
        };

        let policy = PolicySynthesizer::synthesize("test-policy", &[trace1, trace2]);

        assert_eq!(policy.defaults, DefaultPolicy::DenyAll);
        assert_eq!(policy.rules.len(), 2);

        let nav_rule = policy
            .rules
            .iter()
            .find(|r| r.target == "browser__navigate")
            .unwrap();
        assert_eq!(
            nav_rule.conditions.allow_domains,
            Some(vec!["google.com".to_string()])
        );

        let click_rule = policy
            .rules
            .iter()
            .find(|r| r.target == "gui__click")
            .unwrap();
        assert!(click_rule.conditions.allow_domains.is_none());
    }
}
