// Path: crates/services/src/agentic/rules.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The verdict of the firewall for a specific action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, Encode, Decode)]
pub struct ActionRules {
    /// Unique identifier for this policy set.
    pub policy_id: String,
    /// The default behavior if no specific rule matches.
    #[serde(default)]
    pub defaults: DefaultPolicy,
    /// The list of specific rules to evaluate.
    pub rules: Vec<Rule>,
}

/// The default policy behavior when no specific rule matches an action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicy {
    /// Allow actions by default unless explicitly blocked.
    AllowAll,
    /// Block actions by default unless explicitly allowed.
    DenyAll,
    /// Pause execution and ask the user for approval by default.
    /// This enables "Interactive Mode", allowing agents to attempt novel actions
    /// without requiring a pre-defined whitelist in genesis.
    RequireApproval,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        // Default to Interactive Mode.
        // This ensures a better developer experience (DX) in local mode,
        // as the user is prompted to sign off on new tool usage rather than
        // the agent failing silently with "Blocked by Policy".
        Self::RequireApproval
    }
}

/// A specific firewall rule matching a target action.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Rule {
    /// Optional unique identifier for the rule.
    pub rule_id: Option<String>,
    /// Target action type (e.g., "net::fetch", "fs::write") or "*" for all.
    pub target: String,
    /// Conditions that must match for this rule to apply.
    pub conditions: RuleConditions,
    /// The verdict if the target and conditions match.
    pub action: Verdict,
}

/// Conditions that refine when a rule applies.
#[derive(Debug, Clone, Serialize, Deserialize, Default, Encode, Decode)]
pub struct RuleConditions {
    /// List of allowed domains for network requests.
    pub allow_domains: Option<Vec<String>>,

    /// List of allowed file paths for filesystem access.
    pub allow_paths: Option<Vec<String>>,

    /// Maximum spend amount allowed per action/session.
    pub max_spend: Option<u64>,

    /// Rate limit specification (e.g., "10/minute").
    pub rate_limit: Option<String>,

    /// List of allowed application names/window titles for GUI interaction.
    /// Used to prevent "click-jacking" into sensitive apps like password managers.
    pub allow_apps: Option<Vec<String>>,

    /// Regex pattern for sensitive content detection in keystrokes.
    /// If the text matches this pattern, the action is BLOCKED.
    pub block_text_pattern: Option<String>,

    /// Whitepaper 9.4: Semantic Integrity.
    /// List of semantic intent tags that are explicitly BLOCKED based on
    /// classification by the LocalSafetyModel.
    /// e.g. ["exfiltration", "system_destruction"]
    pub block_intents: Option<Vec<String>>,
}
