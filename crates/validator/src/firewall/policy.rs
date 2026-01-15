// Path: crates/validator/src/firewall/policy.rs

use crate::firewall::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::{ActionTarget, ActionRequest, ApprovalToken};
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ioi_types::{codec, error::TransactionError, keys::active_service_key};
use serde_json::Value;
use std::sync::Arc;

/// Helper to simulate OS context retrieval.
/// In the full implementation, this calls into `ioi-drivers`.
mod os_context {
    // This module is deprecated in favor of OsDriver trait but kept for reference if needed
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
    /// * `os_driver` - The driver to query live OS context (active window).
    /// * `presented_approval` - An optional signed token from the user authorizing this specific action.
    pub async fn evaluate(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
        presented_approval: Option<&ApprovalToken>,
    ) -> Verdict {
        let request_hash = request.hash();

        // 1. Authorization Gate: Check for valid ApprovalToken first.
        if let Some(token) = presented_approval {
            if token.request_hash == request_hash {
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
                if Self::check_conditions(rule, &request.target, &request.params, safety_model, os_driver).await {
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
        os_driver: &Arc<dyn OsDriver>,
    ) -> bool {
        let conditions = &rule.conditions;

        // 1. Context Check: Allowed Apps (GUI Isolation)
        if let Some(allowed_apps) = &conditions.allow_apps {
            match target {
                ActionTarget::GuiClick | ActionTarget::GuiType | ActionTarget::GuiScroll => {
                    // Use the injected OS driver instead of mock
                    let active_app_opt = os_driver.get_active_window_title().await.unwrap_or(None);
                    
                    if let Some(active_app) = active_app_opt {
                        let is_allowed = allowed_apps.iter().any(|app| active_app.contains(app));
                        if !is_allowed {
                            tracing::warn!("Policy Violation: Blocked interaction with window '{}'", active_app);
                            // If condition fails (app not allowed), the rule (e.g., Allow) should NOT apply.
                            // So we return false.
                            return false;
                        }
                    } else {
                        // If we can't determine the window, fail closed for safety
                        tracing::warn!("Policy Violation: Could not determine active window context");
                        return false;
                    }
                }
                _ => {} // Not a GUI action, skip app check
            }
        }

        // 2. Semantic Check: Block Text Pattern (DLP for Keystrokes)
        if let Some(pattern) = &conditions.block_text_pattern {
            if let ActionTarget::GuiType = target {
                if let Ok(json) = serde_json::from_slice::<Value>(params) {
                    if let Some(text) = json.get("text").and_then(|t| t.as_str()) {
                        if text.contains(pattern) {
                            return true; // Match! (Block this rule)
                        } else {
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
                            return false;
                        }
                    }
                }
            }
        }

        // 5. Semantic Intent Check
        if let Some(blocked_intents) = &conditions.block_intents {
            if let Ok(input_str) = std::str::from_utf8(params) {
                let classification = safety_model.classify_intent(input_str).await.unwrap_or(SafetyVerdict::Safe);

                if let SafetyVerdict::Unsafe(reason) = classification {
                    if blocked_intents.iter().any(|i| reason.contains(i)) {
                         return true; 
                    } else {
                        return false; 
                    }
                }
                return false;
            }
        }

        // Default: If no specific conditions failed, the rule applies.
        true
    }

    /// Checks permission for a `CallService` transaction.
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

        let disabled_key = [meta_key.as_slice(), b"::disabled"].concat();
        if state.get(&disabled_key)?.is_some() {
            return Err(TransactionError::Unsupported(format!(
                "Service '{}' is administratively disabled",
                service_id
            )));
        }

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