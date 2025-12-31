// Path: crates/validator/src/firewall/rules.rs

use serde::{Deserialize, Serialize};

/// The verdict of the firewall for a specific action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Allow the action to proceed.
    Allow,
    /// Block the action immediately.
    Block,
    /// Pause execution and request user approval.
    RequireApproval,
}

/// A collection of rules defining the security boundary for an agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionRules {
    /// Unique identifier for this policy set.
    pub policy_id: String,
    /// The default behavior if no specific rule matches.
    #[serde(default)]
    pub defaults: DefaultPolicy,
    /// The list of specific rules to evaluate.
    pub rules: Vec<Rule>,
}

/// The default policy behavior (Allow/Deny).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicy {
    /// Allow actions by default unless explicitly blocked.
    AllowAll,
    /// Block actions by default unless explicitly allowed.
    DenyAll,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::DenyAll
    }
}

/// A specific firewall rule matching a target action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Optional unique identifier for the rule.
    pub rule_id: Option<String>,
    /// Target action type (e.g., "net::fetch") or "*" for all.
    pub target: String,
    /// Conditions that must match for this rule to apply.
    pub conditions: RuleConditions,
    /// The verdict if the target and conditions match.
    pub action: Verdict,
}

/// Conditions that refine when a rule applies.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConditions {
    /// List of allowed domains for network requests.
    pub allow_domains: Option<Vec<String>>,
    /// List of allowed file paths for filesystem access.
    pub allow_paths: Option<Vec<String>>,
    /// Maximum spend amount allowed per action/session.
    pub max_spend: Option<u64>,
    /// Rate limit specification (e.g., "10/minute").
    pub rate_limit: Option<String>,
}
