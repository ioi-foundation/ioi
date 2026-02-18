use crate::agentic::rules::Rule;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use ioi_types::app::ActionTarget;
use serde_json::Value;
use std::sync::Arc;
use url::Url;

use super::filesystem::validate_allow_paths_condition;
use super::PolicyEngine;

fn host_for_allow_domains(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{}", trimmed)))
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

fn normalize_allowed_domain_entry(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    host_for_allow_domains(trimmed).or_else(|| {
        let candidate = trimmed.trim_matches('.').trim();
        if candidate.is_empty() {
            None
        } else {
            Some(candidate.to_ascii_lowercase())
        }
    })
}

fn allow_domains_match_url(allowed_domains: &[String], url: &str) -> bool {
    let Some(host) = host_for_allow_domains(url) else {
        return false;
    };

    allowed_domains
        .iter()
        .filter_map(|d| normalize_allowed_domain_entry(d))
        .any(|allowed| host == allowed || host.ends_with(&format!(".{}", allowed)))
}

fn is_safe_package_identifier(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 128
        && package.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@' | '/' | ':')
        })
}

fn normalize_sys_exec_command_for_policy(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // If the command is a path, compare against the basename so `/bin/bash` is treated as `bash`.
    let basename = trimmed
        .rsplit_once('/')
        .map(|(_, tail)| tail)
        .unwrap_or(trimmed)
        .rsplit_once('\\')
        .map(|(_, tail)| tail)
        .unwrap_or(trimmed);

    let basename = basename
        .trim_matches(|c: char| c == '"' || c == '\'')
        .trim();
    if basename.is_empty() {
        return None;
    }
    Some(basename.to_ascii_lowercase())
}

fn is_denied_sys_exec_command(command_lc: &str) -> bool {
    // Guardrail: never allow command interpreters/shells via policy configuration.
    // If these slip into allowlists, metachar args become meaningful again and the
    // effective execution surface expands sharply.
    matches!(
        command_lc,
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "ksh"
            | "csh"
            | "tcsh"
            | "pwsh"
            | "powershell"
            | "cmd"
            | "cmd.exe"
    )
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
                // Only enforce command allowlists for sys__exec-style payloads that carry a
                // concrete `command` field. Other sys::exec-targeted tools (for example:
                // sys__change_directory, sys__exec_session_reset, os__launch_app) omit it.
                let cmd = json
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty());

                if let Some(cmd) = cmd {
                    // STRICT built-in allowlist for system commands.
                    const DEFAULT_ALLOWED_COMMANDS: &[&str] = &[
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

                    let Some(cmd_lc) = normalize_sys_exec_command_for_policy(cmd) else {
                        return false;
                    };
                    if is_denied_sys_exec_command(cmd_lc.as_str()) {
                        tracing::warn!(
                            "Policy Violation: Command '{}' is a denied interpreter/shell binary.",
                            cmd
                        );
                        return false;
                    }

                    let mut is_allowed = DEFAULT_ALLOWED_COMMANDS
                        .iter()
                        .any(|allowed| allowed == &cmd_lc);

                    // Policy-configured extensions (exact match, case-insensitive).
                    if !is_allowed {
                        if let Some(extra) = conditions.allow_commands.as_ref() {
                            is_allowed = extra
                                .iter()
                                .map(|v| v.trim())
                                .filter(|v| !v.is_empty())
                                .filter_map(normalize_sys_exec_command_for_policy)
                                .any(|allowed| allowed == cmd_lc);
                        }
                    }

                    if !is_allowed {
                        tracing::warn!(
                            "Policy Violation: Command '{}' is not in the system allowlist.",
                            cmd
                        );
                        return false;
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
            if let ActionTarget::NetFetch
            | ActionTarget::WebRetrieve
            | ActionTarget::BrowserInteract
            | ActionTarget::CommerceDiscovery
            | ActionTarget::CommerceCheckout = target
            {
                // Only fail-closed when the action is expected to carry an explicit URL in params.
                // BrowserInteract tools often omit `url` (click/type/scroll), so we do not
                // hard-block them here without additional runtime evidence wiring.
                let require_url = matches!(
                    target,
                    ActionTarget::NetFetch
                        | ActionTarget::WebRetrieve
                        | ActionTarget::CommerceDiscovery
                        | ActionTarget::CommerceCheckout
                );

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
                        if !allow_domains_match_url(allowed_domains, url) {
                            return false;
                        }
                    } else if require_url {
                        return false;
                    }
                } else if require_url {
                    return false;
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
