// Path: crates/validator/src/firewall/policy.rs

use crate::firewall::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_api::state::StateAccess;
use ioi_types::app::ActionTarget;
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ioi_types::{codec, error::TransactionError, keys::active_service_key};
use serde_json::Value;

/// Helper to simulate OS context retrieval.
/// In the full implementation, this calls into `ioi-drivers`.
mod os_context {
    pub fn get_active_window_title() -> String {
        // TODO: Wire this to `ioi_drivers::gui::os::get_active_window()`
        // For now, return a placeholder for policy testing.
        "Chrome".to_string()
    }
}

/// The core engine for evaluating actions against firewall policies.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluates an ActionRequest against the active policy.
    /// This is the core "Compliance Layer" logic.
    pub fn evaluate(rules: &ActionRules, target: &ActionTarget, params: &[u8]) -> Verdict {
        let target_str = match target {
            ActionTarget::NetFetch => "net::fetch",
            ActionTarget::FsWrite => "fs::write",
            ActionTarget::FsRead => "fs::read",
            ActionTarget::UiClick => "ui::click",
            ActionTarget::UiType => "ui::type",
            ActionTarget::SysExec => "sys::exec",
            ActionTarget::WalletSign => "wallet::sign",
            ActionTarget::WalletSend => "wallet::send",

            // Phase 1/3 Additions
            ActionTarget::GuiMouseMove => "gui::mouse_move",
            ActionTarget::GuiClick => "gui::click",
            ActionTarget::GuiType => "gui::type",
            ActionTarget::GuiScreenshot => "gui::screenshot",
            ActionTarget::GuiScroll => "gui::scroll",
            ActionTarget::BrowserNavigate => "browser::navigate",
            ActionTarget::BrowserExtract => "browser::extract",

            // [NEW] UCP Support
            ActionTarget::CommerceDiscovery => "ucp::discovery",
            ActionTarget::CommerceCheckout => "ucp::checkout",

            ActionTarget::Custom(s) => s.as_str(),
        };

        // Linear scan of rules (specific overrides general)
        for rule in &rules.rules {
            if rule.target == target_str || rule.target == "*" {
                // If conditions match, return the verdict.
                // If conditions fail, continue to next rule (or default).
                if Self::check_conditions(rule, target, params) {
                    return rule.action;
                }
            }
        }

        match rules.defaults {
            DefaultPolicy::AllowAll => Verdict::Allow,
            DefaultPolicy::DenyAll => Verdict::Block,
        }
    }

    /// Evaluates specific conditions for a rule.
    fn check_conditions(rule: &Rule, target: &ActionTarget, params: &[u8]) -> bool {
        let conditions = &rule.conditions;

        // 1. Context Check: Allowed Apps (GUI Isolation)
        if let Some(allowed_apps) = &conditions.allow_apps {
            match target {
                ActionTarget::GuiClick | ActionTarget::GuiType | ActionTarget::GuiScroll => {
                    let active_app = os_context::get_active_window_title();
                    // Simple substring match for MVP (e.g. "Chrome" matches "Google Chrome")
                    let is_allowed = allowed_apps.iter().any(|app| active_app.contains(app));
                    if !is_allowed {
                        // Policy Violation: Attempting to interact with a protected/unlisted window.
                        return false;
                    }
                }
                _ => {} // Not a GUI action, skip app check
            }
        }

        // 2. Semantic Check: Block Text Pattern (DLP for Keystrokes)
        if let Some(pattern) = &conditions.block_text_pattern {
            if let ActionTarget::GuiType = target {
                // Parse params to extract typed text
                // Params structure: { text: "..." }
                if let Ok(json) = serde_json::from_slice::<Value>(params) {
                    if let Some(text) = json.get("text").and_then(|t| t.as_str()) {
                        // If text contains the blocked pattern (e.g. "sk_live_"), rule matches
                        // But wait: we return TRUE if the rule matches.
                        // Usually "block_text_pattern" implies a BLOCK rule.
                        // So if text contains pattern, condition is TRUE (rule applies).
                        if text.contains(pattern) {
                            return true;
                        } else {
                            // If this was a blocking rule based on content, and content didn't match,
                            // then this rule DOES NOT apply.
                            return false;
                        }
                    }
                }
            }
        }

        // 3. Network Domain Check
        if let Some(allowed_domains) = &conditions.allow_domains {
            if let ActionTarget::NetFetch
            | ActionTarget::BrowserNavigate
            | ActionTarget::CommerceDiscovery
            | ActionTarget::CommerceCheckout = target
            {
                if let Ok(json) = serde_json::from_slice::<Value>(params) {
                    // For UCP, check merchant_url or url
                    let url_field = if matches!(
                        target,
                        ActionTarget::CommerceDiscovery | ActionTarget::CommerceCheckout
                    ) {
                        "merchant_url"
                    } else {
                        "url"
                    };

                    if let Some(url) = json.get(url_field).and_then(|s| s.as_str()) {
                        let domain_match = allowed_domains.iter().any(|d| url.contains(d));
                        if !domain_match {
                            return false;
                        }
                    }
                }
            }
        }

        // 4. [NEW] Spend Limit Check for Commerce
        if let Some(max_spend) = conditions.max_spend {
            if let ActionTarget::CommerceCheckout = target {
                if let Ok(json) = serde_json::from_slice::<Value>(params) {
                    if let Some(amount_val) = json.get("total_amount") {
                        // Handle both number and string representations for amount
                        let amount = if let Some(n) = amount_val.as_f64() {
                            n
                        } else if let Some(s) = amount_val.as_str() {
                            s.parse::<f64>().unwrap_or(0.0)
                        } else {
                            0.0
                        };

                        // Assuming max_spend is in the same unit/currency for MVP
                        // In production, would need currency normalization.
                        if amount > max_spend as f64 {
                            // Rule matches?
                            // If this is an ALLOW rule with a condition "max_spend=50",
                            // and amount is 100, then the condition FAILS.
                            // The rule does NOT apply. Fallback to DenyAll.
                            return false;
                        }
                    }
                }
            }
        }

        // Default: If no specific conditions failed, the rule applies.
        true
    }

    /// Checks permission for a `CallService` transaction.
    /// This replaces the old `precheck_call_service` in `ante`.
    pub fn check_service_call(
        state: &dyn StateAccess,
        service_id: &str,
        method: &str,
        is_internal: bool,
    ) -> Result<(), TransactionError> {
        let meta_key = active_service_key(service_id);
        let maybe_meta_bytes = state.get(&meta_key)?;

        let meta: ActiveServiceMeta = if let Some(bytes) = maybe_meta_bytes {
            codec::from_bytes_canonical(&bytes)?
        } else {
            return Err(TransactionError::Unsupported(format!(
                "Service '{}' is not active",
                service_id
            )));
        };

        // Check Administrative Disable
        let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
        if state.get(&disabled_key)?.is_some() {
            return Err(TransactionError::Unsupported(format!(
                "Service '{}' is administratively disabled",
                service_id
            )));
        }

        // Check Method Permission
        let perm = meta.methods.get(method).ok_or_else(|| {
            TransactionError::Unsupported(format!(
                "Method '{}' not found in service '{}' ABI",
                method, service_id
            ))
        })?;

        if let MethodPermission::Internal = perm {
            if !is_internal {
                return Err(TransactionError::Invalid(
                    "Internal method cannot be called via transaction".into(),
                ));
            }
        }

        Ok(())
    }
}
