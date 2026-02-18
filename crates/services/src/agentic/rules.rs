// Path: crates/services/src/agentic/rules.rs

use ioi_types::app::agentic::{IntentRoutingPolicy, PiiControls};
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

/// Approval orchestration mode for ontology incident flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Keep one gate prompt active per incident/action fingerprint.
    SinglePending,
    /// Re-prompt up to a bounded count.
    BoundedReprompt,
    /// Prompt on every intercepted attempt.
    AlwaysPrompt,
}

impl Default for ApprovalMode {
    fn default() -> Self {
        Self::SinglePending
    }
}

/// Per-intent/failure policy override for ontology strategy selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default, Encode, Decode)]
pub struct IntentFailureOverride {
    pub intent_class: String,
    pub failure_class: String,
    pub strategy_name: Option<String>,
    pub max_transitions: Option<u32>,
}

/// Optional operator preferences for ontology strategy planning.
#[derive(Debug, Clone, Serialize, Deserialize, Default, Encode, Decode)]
pub struct ToolPreferences {
    /// Preferred install manager order (for example: ["apt-get", "dnf", "yum"]).
    pub install_manager_priority: Vec<String>,
    /// Forbidden recovery tools at policy level.
    pub forbidden_remediation_tools: Vec<String>,
    /// Prompt cap used when `approval_mode=bounded_reprompt`.
    pub bounded_reprompt_limit: u32,
}

/// Ontology incident policy settings.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct OntologyPolicy {
    /// Gate handling mode for repeated approval interceptions.
    pub approval_mode: ApprovalMode,
    /// Maximum transitions allowed inside a single incident state machine.
    pub max_incident_transitions: u32,
    /// Intent/failure-specific override table.
    pub intent_failure_overrides: Vec<IntentFailureOverride>,
    /// Planner preferences and constraints.
    pub tool_preferences: ToolPreferences,
    /// Global intent-routing policy for step/action ontology resolution.
    #[serde(default)]
    pub intent_routing: IntentRoutingPolicy,
}

impl Default for OntologyPolicy {
    fn default() -> Self {
        Self {
            approval_mode: ApprovalMode::SinglePending,
            max_incident_transitions: 32,
            intent_failure_overrides: Vec::new(),
            tool_preferences: ToolPreferences {
                install_manager_priority: Vec::new(),
                forbidden_remediation_tools: Vec::new(),
                bounded_reprompt_limit: 2,
            },
            intent_routing: IntentRoutingPolicy::default(),
        }
    }
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
    /// Ontology/incident orchestration policy.
    #[serde(default)]
    pub ontology_policy: OntologyPolicy,
    /// Local-only PII firewall policy.
    #[serde(default, alias = "pii_policy")]
    pub pii_controls: PiiControls,
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

    /// Additional allowlisted command binaries for `sys::exec` tools.
    /// Extends the built-in system allowlist enforced by the PolicyEngine.
    ///
    /// Note: the policy engine will still hard-deny known shell/interpreter binaries (for example:
    /// `sh`, `bash`, `zsh`, `fish`, `pwsh`, `powershell`, `cmd`) even if they appear here, to
    /// reduce the risk of accidental policy misconfiguration expanding execution surface.
    pub allow_commands: Option<Vec<String>>,

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
