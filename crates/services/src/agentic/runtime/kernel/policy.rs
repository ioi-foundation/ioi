use crate::agentic::rules::Verdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRecord {
    pub verdict: Verdict,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_decision_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_eval_trace_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_eval_hash: Option<[u8; 32]>,
}

impl PolicyEvaluationRecord {
    pub fn matched_rules_for_decision(&self) -> Vec<String> {
        let mut rules = self.matched_rule_ids.clone();
        if rules.is_empty() {
            if let Some(default_policy) = &self.default_policy_used {
                rules.push(format!("default:{}", default_policy));
            }
        }
        if let Some(hash) = self.pii_decision_hash {
            rules.push(format!("pii:{}", hex::encode(hash)));
        }
        rules
    }
}
