use crate::agentic::rules::Rule;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use ioi_types::app::ActionTarget;
use serde_json::Value;
use std::sync::Arc;

use super::filesystem::validate_allow_paths_condition;
use super::PolicyEngine;

fn is_safe_package_identifier(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 128
        && package.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@' | '/' | ':')
        })
}

impl PolicyEngine {
    /// Evaluates specific conditions for a rule.
    /// Returns true if ALL conditions in the rule are met (or if there are no conditions).
    pub(super) async fn check_conditions(
        rule: &Rule,
        target: &ActionTarget,
        params: &[u8],
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
    ) -> bool {
        let conditions = &rule.conditions;

        // [NEW] System Command Allowlist
        if let ActionTarget::SysExec = target {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(params) {
                let cmd = json["command"].as_str().unwrap_or("");

                // STRICT Allowlist for System Commands
                let allowed_commands = vec![
                    "netstat",
                    "ping",
                    "whoami",
                    "ls",
                    "echo",
                    // [FIX] Whitelisted Calculator Apps and Editors
                    "gnome-calculator",
                    "kcalc",
                    "calculator",
                    "calc",
                    "code",
                    "gedit",
                    "nano",
                ];

                if !allowed_commands.contains(&cmd) {
                    tracing::warn!(
                        "Policy Violation: Command '{}' is not in the system allowlist.",
                        cmd
                    );
                    return false;
                }

                // Optional: Check arguments for dangerous characters
                // (e.g. prevent chaining like `ls; rm -rf /`)
                if let Some(args) = json["args"].as_array() {
                    for arg in args {
                        let s = arg.as_str().unwrap_or("");
                        if s.contains(';') || s.contains('|') || s.contains('>') {
                            tracing::warn!(
                                "Policy Violation: Dangerous argument characters detected."
                            );
                            return false;
                        }
                    }
                }
            } else {
                return false; // Failed to parse params
            }
        }

        if let ActionTarget::SysInstallPackage = target {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(params) {
                let package = json["package"].as_str().unwrap_or("").trim();
                if !is_safe_package_identifier(package) {
                    tracing::warn!(
                        "Policy Violation: install package '{}' is not a safe identifier.",
                        package
                    );
                    return false;
                }

                let manager = json["manager"]
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if !manager.is_empty()
                    && !matches!(
                        manager.as_str(),
                        "apt-get"
                            | "apt"
                            | "brew"
                            | "pip"
                            | "pip3"
                            | "npm"
                            | "pnpm"
                            | "cargo"
                            | "winget"
                            | "choco"
                            | "chocolatey"
                            | "yum"
                            | "dnf"
                    )
                {
                    tracing::warn!(
                        "Policy Violation: install manager '{}' is unsupported.",
                        manager
                    );
                    return false;
                }
            } else {
                return false;
            }
        }

        // Filesystem Path Check
        if let Some(allowed_paths) = &conditions.allow_paths {
            if !validate_allow_paths_condition(allowed_paths, target, params) {
                return false;
            }
        }

        // 1. Context Check: Allowed Apps (GUI Isolation & Spatial Bounds)
        if let Some(allowed_apps) = &conditions.allow_apps {
            match target {
                ActionTarget::GuiClick
                | ActionTarget::GuiType
                | ActionTarget::GuiScroll
                | ActionTarget::GuiSequence => {
                    // Use the injected OS driver instead of mock
                    let active_app_opt = os_driver.get_active_window_info().await.unwrap_or(None);

                    if let Some(win) = active_app_opt {
                        // A. App Name Check
                        let title_lc = win.title.to_ascii_lowercase();
                        let app_lc = win.app_name.to_ascii_lowercase();
                        let is_allowed_app = allowed_apps.iter().any(|allowed| {
                            let allowed_lc = allowed.to_ascii_lowercase();
                            title_lc.contains(&allowed_lc) || app_lc.contains(&allowed_lc)
                        });
                        if !is_allowed_app {
                            tracing::warn!(
                                "Policy Violation: Blocked interaction with window '{}'",
                                win.title
                            );
                            // If condition fails (app not allowed), the rule (e.g., Allow) should NOT apply.
                            return false;
                        }

                        // B. Spatial Bounds Check (Click-Jacking Prevention)
                        // If we are clicking, verify the coordinates are INSIDE the active window.
                        if let ActionTarget::GuiClick = target {
                            if let Ok(json) = serde_json::from_slice::<Value>(params) {
                                // Coords might be x/y directly or inside 'coordinate' array for computer usage tool
                                let (x, y) = if let (Some(x_val), Some(y_val)) =
                                    (json.get("x"), json.get("y"))
                                {
                                    (x_val.as_u64(), y_val.as_u64())
                                } else if let Some(coord) =
                                    json.get("coordinate").and_then(|c| c.as_array())
                                {
                                    if coord.len() == 2 {
                                        (coord[0].as_u64(), coord[1].as_u64())
                                    } else {
                                        (None, None)
                                    }
                                } else {
                                    (None, None)
                                };

                                if let (Some(cx), Some(cy)) = (x, y) {
                                    let win_x = win.x as i64;
                                    let win_y = win.y as i64;
                                    let win_w = win.width as i64;
                                    let win_h = win.height as i64;
                                    let click_x = cx as i64;
                                    let click_y = cy as i64;

                                    if click_x < win_x
                                        || click_x > win_x + win_w
                                        || click_y < win_y
                                        || click_y > win_y + win_h
                                    {
                                        tracing::warn!("Policy Violation: Click at ({}, {}) is OUTSIDE active window '{}' bounds ({}, {}, {}, {})", 
                                             click_x, click_y, win.title, win_x, win_y, win_w, win_h);
                                        return false;
                                    }
                                }
                            }
                        }
                    } else {
                        // If we can't determine the window, fail closed for safety
                        tracing::warn!(
                            "Policy Violation: Could not determine active window context"
                        );
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
                            // If block pattern matches, does the rule apply?
                            // This logic depends on the rule action.
                            // If the rule is "Block if pattern matches", returning true applies the block.
                            // If the rule is "Allow", this logic is inverted (we return false if pattern matches).
                            // Assuming `block_text_pattern` implies a negative constraint on an Allow rule:
                            return false;
                        }
                    }
                }
            }
        }

        // 3. Network Domain Check
        if let Some(allowed_domains) = &conditions.allow_domains {
            // [MODIFIED] Check new targets
            if let ActionTarget::NetFetch
            | ActionTarget::WebRetrieve
            | ActionTarget::BrowserInteract
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
                let classification = safety_model
                    .classify_intent(input_str)
                    .await
                    .unwrap_or(SafetyVerdict::Safe);

                if let SafetyVerdict::Unsafe(reason) = classification {
                    if blocked_intents.iter().any(|i| reason.contains(i)) {
                        // If intent is blocked, the rule (assuming Allow) should NOT apply.
                        return false;
                    }
                }
            }
        }

        // Default: If no specific conditions failed (or if there were no conditions set in the rule),
        // then the rule matches. This enables "Catch-All" rules where conditions are None/Default.
        true
    }
}
