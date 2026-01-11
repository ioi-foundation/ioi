// Path: crates/validator/src/firewall/policy.rs

use crate::firewall::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use ioi_types::app::{ActionTarget, ActionRequest, ApprovalToken};
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ioi_types::{codec, error::TransactionError, keys::active_service_key};
use serde_json::Value;
use std::sync::Arc;

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
    ///
    /// # Arguments
    /// * `rules` - The active ActionRules policy set.
    /// * `request` - The canonicalized action request.
    /// * `safety_model` - The local AI model for semantic classification.
    /// * `presented_approval` - An optional signed token from the user authorizing this specific action.
    pub async fn evaluate(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
        presented_approval: Option<&ApprovalToken>,
    ) -> Verdict {
        let request_hash = request.hash();

        // 1. Authorization Gate: Check for valid ApprovalToken first.
        // If the user has explicitly signed off on this EXACT request hash, it bypasses
        // standard policy checks (assuming the token signature is valid).
        // Note: Token signature verification happens in the Orchestrator before calling this,
        // or we assume it's valid if present in this context.
        if let Some(token) = presented_approval {
            if token.request_hash == request_hash {
                // Return Allow immediately, overriding any Block rules.
                // This implements the "User Consent" override.
                return Verdict::Allow; 
            }
        }

        let target_str = match &request.target {
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
                if Self::check_conditions(rule, &request.target, &request.params, safety_model).await {
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
    async fn check_conditions(
        rule: &Rule,
        target: &ActionTarget,
        params: &[u8],
        safety_model: &Arc<dyn LocalSafetyModel>,
    ) -> bool {
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
                        // Condition Fails -> Rule Does Not Apply (if it was an Allow rule)
                        // Wait, logic inversion:
                        // If this is an ALLOW rule, and we are in a disallowed app, the condition fails (returns false).
                        // If this is a BLOCK rule, and we are in a disallowed app?
                        // Usually "allow_apps" implies a whitelist.
                        // "Only match this rule if app is in list".
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
                        if text.contains(pattern) {
                            return true; // Match!
                        } else {
                            // If condition specified a pattern and we didn't match it,
                            // this rule shouldn't trigger.
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
                            return false; // URL not in allowlist
                        }
                    }
                }
            }
        }

        // 4. Spend Limit Check for Commerce
        if let Some(max_spend) = conditions.max_spend {
            if let ActionTarget::CommerceCheckout = target {
                if let Ok(json) = serde_json::from_slice::<Value>(params) {
                    if let Some(amount_val) = json.get("total_amount") {
                        let amount = if let Some(n) = amount_val.as_f64() {
                            n
                        } else if let Some(s) = amount_val.as_str() {
                            s.parse::<f64>().unwrap_or(0.0)
                        } else {
                            0.0
                        };

                        if amount > max_spend as f64 {
                            // Condition failed (amount too high)
                            return false;
                        }
                    }
                }
            }
        }

        // 5. [NEW] Semantic Intent Check (The "Brain" of the Firewall)
        if let Some(blocked_intents) = &conditions.block_intents {
            // Attempt to parse params as a string for classification.
            // For many actions, params is JSON. We classify the entire JSON structure.
            if let Ok(input_str) = std::str::from_utf8(params) {
                // Call the Local Safety Model (BitNet)
                let classification = safety_model.classify_intent(input_str).await.unwrap_or(SafetyVerdict::Safe);

                if let SafetyVerdict::Unsafe(reason) = classification {
                    // If the model identifies an unsafe intent that matches one of our blocked categories
                    // e.g. Reason: "financial_theft detected", Blocked: ["financial_theft"]
                    // We do a simple keyword match for now.
                    if blocked_intents.iter().any(|i| reason.contains(i)) {
                         return true; // Condition matched (Intent is bad)
                    } else {
                        // It was unsafe, but not for the reason specified in this rule?
                        // Or maybe we treat "Unsafe" as a global block.
                        // For flexibility, we only match if the specific intent tag matches.
                        return false; 
                    }
                }
                // If Safe or PII (handled elsewhere), this specific "Block Intent" condition didn't trigger.
                return false;
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