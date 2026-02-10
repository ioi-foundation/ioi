// Path: crates/types/src/app/agentic/security.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Configuration for the "Law" (Firewall) of an agent.
/// Defines the hard constraints and liabilities.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, Default)]
pub struct FirewallPolicy {
    /// Maximum USD spend per execution (converted to tokens).
    pub budget_cap: f64,
    /// List of allowed DNS domains (e.g. "*.stripe.com").
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    /// If true, execution halts for "Hold to Sign".
    pub require_human_gate: bool,
    /// Data egress policy ("none", "masked", "zero-knowledge").
    pub privacy_level: Option<String>,
}