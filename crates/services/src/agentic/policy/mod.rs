// Path: crates/services/src/agentic/policy/mod.rs

use crate::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface, SafetyVerdict};
use ioi_pii::{build_decision_material, inspect_and_route_with_for_target, RiskSurface};
use ioi_types::app::agentic::{FirewallDecision, PiiDecisionMaterial, PiiTarget};
use ioi_types::app::{ActionRequest, ActionTarget, ApprovalToken};
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ioi_types::{codec, error::TransactionError, keys::active_service_key};
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

// [FIX] Renamed NodeLaw to FirewallPolicy
use ioi_types::app::agentic::FirewallPolicy;

/// The core engine for evaluating actions against firewall policies.
pub struct PolicyEngine;

fn is_safe_package_identifier(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 128
        && package.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@' | '/' | ':')
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemScope {
    Read,
    Write,
}

impl FilesystemScope {
    fn policy_target(self) -> &'static str {
        match self {
            Self::Read => "fs::read",
            Self::Write => "fs::write",
        }
    }
}

fn filesystem_scope_for_target(target: &ActionTarget) -> Option<FilesystemScope> {
    match target {
        ActionTarget::FsRead => Some(FilesystemScope::Read),
        ActionTarget::FsWrite => Some(FilesystemScope::Write),
        ActionTarget::Custom(name) => match name.as_str() {
            "fs::read"
            | "filesystem__read_file"
            | "filesystem__list_directory"
            | "filesystem__search" => Some(FilesystemScope::Read),
            "fs::write"
            | "filesystem__write_file"
            | "filesystem__patch"
            | "filesystem__delete_path"
            | "filesystem__create_directory"
            | "filesystem__move_path"
            | "filesystem__copy_path" => Some(FilesystemScope::Write),
            _ => None,
        },
        _ => None,
    }
}

fn policy_target_aliases(target: &ActionTarget) -> Vec<String> {
    let mut aliases = vec![target.canonical_label()];
    if let ActionTarget::Custom(name) = target {
        let compatibility_aliases: &[&str] = match name.as_str() {
            "browser::click_element" => &["browser::click", "browser__click_element"],
            _ => &[],
        };
        for alias in compatibility_aliases {
            if !aliases.iter().any(|candidate| candidate == alias) {
                aliases.push((*alias).to_string());
            }
        }
    }
    if let Some(scope) = filesystem_scope_for_target(target) {
        let scope_target = scope.policy_target();
        if !aliases.iter().any(|alias| alias == scope_target) {
            aliases.push(scope_target.to_string());
        }
    }
    aliases
}

fn is_high_risk_target_for_rules(rules: &ActionRules, target: &ActionTarget) -> bool {
    let aliases = policy_target_aliases(target);
    aliases.iter().any(|alias| {
        rules
            .pii_controls
            .high_risk_targets
            .iter()
            .any(|configured| configured == alias)
    })
}

fn pii_decision_to_verdict(decision: &FirewallDecision) -> Verdict {
    match decision {
        FirewallDecision::Allow | FirewallDecision::AllowLocalOnly => Verdict::Allow,
        FirewallDecision::RedactThenAllow
        | FirewallDecision::TokenizeThenAllow
        | FirewallDecision::Quarantine
        | FirewallDecision::RequireUserReview => Verdict::RequireApproval,
        FirewallDecision::Deny => Verdict::Block,
    }
}

fn to_shared_risk_surface(risk_surface: PiiRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiRiskSurface::LocalProcessing => RiskSurface::LocalProcessing,
        PiiRiskSurface::Egress => RiskSurface::Egress,
    }
}

fn required_filesystem_path_keys(target: &ActionTarget) -> Option<&'static [&'static str]> {
    match target {
        ActionTarget::FsRead | ActionTarget::FsWrite => Some(&["path"]),
        ActionTarget::Custom(name) => match name.as_str() {
            "fs::read"
            | "filesystem__read_file"
            | "filesystem__list_directory"
            | "filesystem__search"
            | "fs::write"
            | "filesystem__write_file"
            | "filesystem__patch"
            | "filesystem__delete_path"
            | "filesystem__create_directory" => Some(&["path"]),
            "filesystem__move_path" | "filesystem__copy_path" => {
                Some(&["source_path", "destination_path"])
            }
            _ => None,
        },
        _ => None,
    }
}

fn extract_required_paths(params: &Value, keys: &[&str]) -> Option<Vec<String>> {
    let mut paths = Vec::with_capacity(keys.len());
    for key in keys {
        let path = params.get(*key)?.as_str()?.trim();
        if path.is_empty() {
            return None;
        }
        paths.push(path.to_string());
    }
    Some(paths)
}

fn normalize_policy_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut segments: Vec<OsString> = Vec::new();

    for component in Path::new(trimmed).components() {
        match component {
            Component::Prefix(value) => {
                if prefix.replace(value.as_os_str().to_os_string()).is_some() {
                    return None;
                }
            }
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::Normal(segment) => segments.push(segment.to_os_string()),
            Component::ParentDir => {
                if segments.pop().is_none() {
                    return None;
                }
            }
        }
    }

    let mut normalized = PathBuf::new();
    if let Some(value) = prefix {
        normalized.push(value);
    }
    if has_root {
        normalized.push(std::path::MAIN_SEPARATOR.to_string());
    }
    for segment in segments {
        normalized.push(segment);
    }

    if normalized.as_os_str().is_empty() {
        if has_root {
            normalized.push(std::path::MAIN_SEPARATOR.to_string());
        } else {
            normalized.push(".");
        }
    }

    Some(normalized)
}

fn validate_allow_paths_condition(
    allowed_paths: &[String],
    target: &ActionTarget,
    params: &[u8],
) -> bool {
    let Some(required_keys) = required_filesystem_path_keys(target) else {
        return true;
    };

    let parsed = match serde_json::from_slice::<Value>(params) {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!(
                "Policy Blocking FS Access: Failed to decode params for {:?}: {}",
                target,
                e
            );
            return false;
        }
    };

    let requested_paths = match extract_required_paths(&parsed, required_keys) {
        Some(paths) => paths,
        None => {
            tracing::warn!(
                "Policy Blocking FS Access: Missing required path fields {:?} for {:?}.",
                required_keys,
                target
            );
            return false;
        }
    };

    let normalized_allowed_paths = match allowed_paths
        .iter()
        .map(|allowed| normalize_policy_path(allowed))
        .collect::<Option<Vec<_>>>()
    {
        Some(paths) => paths,
        None => {
            tracing::warn!(
                "Policy Blocking FS Access: allow_paths contains invalid root(s): {:?}",
                allowed_paths
            );
            return false;
        }
    };

    let denied_paths: Vec<String> = requested_paths
        .into_iter()
        .filter_map(|path| {
            let normalized_path = match normalize_policy_path(&path) {
                Some(value) => value,
                None => return Some(format!("{path} (invalid path traversal)")),
            };

            let allowed = normalized_allowed_paths
                .iter()
                .any(|allowed| normalized_path.starts_with(allowed));

            if allowed {
                None
            } else {
                Some(format!(
                    "{} (normalized: {})",
                    path,
                    normalized_path.display()
                ))
            }
        })
        .collect();

    if !denied_paths.is_empty() {
        tracing::warn!(
            "Policy Blocking FS Access: Requested path(s) {:?} outside allowed roots {:?}",
            denied_paths,
            normalized_allowed_paths
        );
        return false;
    }

    true
}

impl PolicyEngine {
    /// Evaluates an ActionRequest against the active policy.
    /// This is the core "Compliance Layer" logic.
    pub async fn evaluate(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
        os_driver: &Arc<dyn OsDriver>,
        presented_approval: Option<&ApprovalToken>,
    ) -> Verdict {
        let request_hash = request.hash();

        // 1. Authorization Gate: Check for valid ApprovalToken first.
        // If the user has already signed a token for this EXACT request hash, it bypasses policy checks.
        // This is how the "Gate Window" flow resolves.
        if let Some(token) = presented_approval {
            if token.request_hash == request_hash {
                tracing::info!("Policy Gate: Valid Approval Token presented. Allowing action.");
                return Verdict::Allow;
            } else {
                tracing::warn!(
                    "Policy Gate: Token mismatch. Token for {:?}, Request is {:?}",
                    hex::encode(token.request_hash),
                    hex::encode(request_hash)
                );
            }
        }

        let target_aliases = policy_target_aliases(&request.target);

        // 2. Specific Rules: Linear scan (specific overrides general)
        // First matching rule wins.
        let mut base_verdict = None;
        for rule in &rules.rules {
            if rule.target == "*" || target_aliases.iter().any(|target| rule.target == *target) {
                if Self::check_conditions(
                    rule,
                    &request.target,
                    &request.params,
                    safety_model,
                    os_driver,
                )
                .await
                {
                    base_verdict = Some(rule.action);
                    break;
                }
            }
        }

        let base_verdict = match base_verdict {
            Some(v) => v,
            None => match rules.defaults {
                DefaultPolicy::AllowAll => Verdict::Allow,
                DefaultPolicy::DenyAll => Verdict::Block,
                DefaultPolicy::RequireApproval => Verdict::RequireApproval,
            },
        };

        // 3. Stage B/C PII router overlay.
        let pii_verdict = Self::evaluate_pii_overlay(rules, request, safety_model).await;

        // Preserve explicit policy blocks regardless of PII route.
        if matches!(base_verdict, Verdict::Block) {
            return Verdict::Block;
        }

        match pii_verdict {
            Some(Verdict::Block) => Verdict::Block,
            Some(Verdict::RequireApproval) => Verdict::RequireApproval,
            _ => base_verdict,
        }
    }

    async fn evaluate_pii_overlay(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
    ) -> Option<Verdict> {
        Self::evaluate_pii_overlay_details(rules, request, safety_model)
            .await
            .map(|(verdict, _material)| verdict)
    }

    async fn evaluate_pii_overlay_details(
        rules: &ActionRules,
        request: &ActionRequest,
        safety_model: &Arc<dyn LocalSafetyModel>,
    ) -> Option<(Verdict, Option<PiiDecisionMaterial>)> {
        let high_risk = is_high_risk_target_for_rules(rules, &request.target);
        let risk_surface = if high_risk {
            PiiRiskSurface::Egress
        } else {
            PiiRiskSurface::LocalProcessing
        };

        let input = match std::str::from_utf8(&request.params) {
            Ok(s) => s,
            Err(_) => {
                if high_risk && !request.params.is_empty() {
                    tracing::warn!(
                        "PII policy: non-UTF8 payload on high-risk target {:?}; blocking (fail-closed).",
                        request.target
                    );
                    return Some((Verdict::Block, None));
                }
                return None;
            }
        };

        let target = PiiTarget::Action(request.target.clone());
        let safety_model = Arc::clone(safety_model);
        let (evidence, routed) = match inspect_and_route_with_for_target(
            |input, shared_risk_surface| {
                let safety_model = safety_model.clone();
                Box::pin(async move {
                    let api_risk_surface = match shared_risk_surface {
                        RiskSurface::LocalProcessing => PiiRiskSurface::LocalProcessing,
                        RiskSurface::Egress => PiiRiskSurface::Egress,
                    };
                    let inspection = safety_model.inspect_pii(input, api_risk_surface).await?;
                    Ok(inspection.evidence)
                })
            },
            input,
            &target,
            to_shared_risk_surface(risk_surface),
            &rules.pii_controls,
            false, // Policy engine cannot mutate payloads directly.
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "PII policy inspection failed for {:?} (risk={:?}): {}",
                    request.target,
                    risk_surface,
                    e
                );
                return Some((
                    if high_risk {
                        Verdict::Block
                    } else {
                        Verdict::Allow
                    },
                    None,
                ));
            }
        };

        if !evidence.spans.is_empty() {
            tracing::info!(
                "PII route target={} risk={:?} spans={} ambiguous={} decision={:?} hash={}",
                target.canonical_label(),
                risk_surface,
                evidence.spans.len(),
                evidence.ambiguous,
                routed.decision,
                hex::encode(routed.decision_hash)
            );
        }

        let material = build_decision_material(
            &evidence,
            &routed.decision,
            routed.transform_plan.as_ref(),
            routed.stage2_decision.as_ref(),
            to_shared_risk_surface(risk_surface),
            &target,
            false,
            &routed.assist,
        );

        Some((pii_decision_to_verdict(&routed.decision), Some(material)))
    }

    /// Evaluates specific conditions for a rule.
    /// Returns true if ALL conditions in the rule are met (or if there are no conditions).
    async fn check_conditions(
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

    /// Checks permission for a `CallService` transaction based on the service's ABI metadata.
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

    /// Validates that a proposed policy mutation is monotonic (i.e., strictly safer or equal).
    /// Used by the Optimizer Service during Recursive Self-Improvement cycles.
    pub fn validate_safety_ratchet(
        old_policy: &ActionRules,
        new_policy: &ActionRules,
    ) -> Result<(), String> {
        let old_caps = Self::extract_caps(old_policy);
        let new_caps = Self::extract_caps(new_policy);

        if new_caps.budget_cap > old_caps.budget_cap {
            return Err(format!(
                "Mutation rejected: Attempted to increase budget cap from {} to {}.",
                old_caps.budget_cap, new_caps.budget_cap
            ));
        }

        for domain in &new_caps.network_allowlist {
            if !old_caps.network_allowlist.contains(domain) {
                return Err(format!(
                    "Mutation rejected: Attempted to add new network domain '{}'.",
                    domain
                ));
            }
        }

        if old_caps.require_human_gate && !new_caps.require_human_gate {
            return Err("Mutation rejected: Attempted to remove Human Gate requirement.".into());
        }

        Ok(())
    }

    /// Helper to flatten ActionRules into a comparable FirewallPolicy struct.
    fn extract_caps(rules: &ActionRules) -> FirewallPolicy {
        let mut budget = 0.0;
        let mut network = Vec::new();
        let mut gate = false;

        for rule in &rules.rules {
            if let Some(spend) = rule.conditions.max_spend {
                let amount = spend as f64 / 1000.0;
                if amount > budget {
                    budget = amount;
                }
            }

            if let Some(domains) = &rule.conditions.allow_domains {
                for d in domains {
                    if !network.contains(d) {
                        network.push(d.clone());
                    }
                }
            }

            if rule.action == Verdict::RequireApproval {
                gate = true;
            }
        }

        if rules.defaults == DefaultPolicy::RequireApproval {
            gate = true;
        }

        FirewallPolicy {
            budget_cap: budget,
            network_allowlist: network,
            require_human_gate: gate,
            privacy_level: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        policy_target_aliases, required_filesystem_path_keys, validate_allow_paths_condition,
        PolicyEngine,
    };
    use crate::agentic::rules::{ActionRules, DefaultPolicy};
    use anyhow::Result;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
    use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
    use ioi_pii::{compute_decision_hash, route_pii_decision_for_target, RiskSurface};
    use ioi_types::app::agentic::{
        EvidenceGraph, EvidenceSpan, PiiClass, PiiConfidenceBucket, PiiControls, PiiSeverity,
        PiiTarget,
    };
    use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
    use ioi_types::error::VmError;
    use std::sync::Arc;

    struct DummySafety {
        graph: EvidenceGraph,
    }

    #[async_trait]
    impl LocalSafetyModel for DummySafety {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            Ok(vec![])
        }

        async fn inspect_pii(
            &self,
            _input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: self.graph.clone(),
                ambiguous: self.graph.ambiguous,
                stage2_status: None,
            })
        }
    }

    struct DummyOs;

    #[async_trait]
    impl OsDriver for DummyOs {
        async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
            Ok(None)
        }

        async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
            Ok(None)
        }

        async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
            Ok(false)
        }

        async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_clipboard(&self) -> Result<String, VmError> {
            Ok(String::new())
        }
    }

    #[test]
    fn custom_copy_target_keeps_exact_name_and_fs_write_alias() {
        let aliases = policy_target_aliases(&ActionTarget::Custom("filesystem__copy_path".into()));
        assert_eq!(aliases[0], "filesystem__copy_path");
        assert!(aliases.iter().any(|alias| alias == "fs::write"));
    }

    #[test]
    fn browser_click_element_target_keeps_compatibility_aliases() {
        let aliases = policy_target_aliases(&ActionTarget::Custom("browser::click_element".into()));
        assert_eq!(aliases[0], "browser::click_element");
        assert!(aliases.iter().any(|alias| alias == "browser::click"));
        assert!(aliases
            .iter()
            .any(|alias| alias == "browser__click_element"));
    }

    #[test]
    fn copy_and_move_require_source_and_destination_paths() {
        let keys = required_filesystem_path_keys(&ActionTarget::Custom(
            "filesystem__move_path".to_string(),
        ))
        .expect("move path should require deterministic path keys");
        assert_eq!(keys, ["source_path", "destination_path"]);
    }

    #[test]
    fn allow_paths_blocks_copy_when_destination_outside_allowed_roots() {
        let allowed = vec!["/workspace".to_string()];
        let params = serde_json::json!({
            "source_path": "/workspace/src.txt",
            "destination_path": "/tmp/out.txt"
        });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let allowed_by_policy = validate_allow_paths_condition(
            &allowed,
            &ActionTarget::Custom("filesystem__copy_path".into()),
            &params,
        );
        assert!(!allowed_by_policy);
    }

    #[test]
    fn allow_paths_accepts_copy_when_all_paths_are_within_allowed_roots() {
        let allowed = vec!["/workspace".to_string()];
        let params = serde_json::json!({
            "source_path": "/workspace/src.txt",
            "destination_path": "/workspace/out/dst.txt"
        });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let allowed_by_policy = validate_allow_paths_condition(
            &allowed,
            &ActionTarget::Custom("filesystem__copy_path".into()),
            &params,
        );
        assert!(allowed_by_policy);
    }

    #[test]
    fn allow_paths_blocks_prefix_collision_path() {
        let allowed = vec!["/workspace".to_string()];
        let params = serde_json::json!({
            "path": "/workspace2/private.txt"
        });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let allowed_by_policy =
            validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
        assert!(!allowed_by_policy);
    }

    #[test]
    fn allow_paths_blocks_parent_traversal_segments() {
        let allowed = vec!["/workspace".to_string()];
        let params = serde_json::json!({
            "path": "/workspace/../../etc/passwd"
        });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let allowed_by_policy =
            validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
        assert!(!allowed_by_policy);
    }

    #[test]
    fn allow_paths_accepts_normalized_path_within_allowed_root() {
        let allowed = vec!["/workspace".to_string()];
        let params = serde_json::json!({
            "path": "/workspace/subdir/../notes.txt"
        });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let allowed_by_policy =
            validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
        assert!(allowed_by_policy);
    }

    #[test]
    fn pii_overlay_material_hash_matches_direct_router_hash() {
        let graph = EvidenceGraph {
            version: 1,
            source_hash: [7u8; 32],
            ambiguous: false,
            spans: vec![EvidenceSpan {
                start_index: 5,
                end_index: 27,
                pii_class: PiiClass::ApiKey,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/api_key".to_string(),
                validator_passed: true,
                context_keywords: vec!["api key".to_string()],
                evidence_source: "test".to_string(),
            }],
        };
        let rules = ActionRules {
            policy_id: "policy".to_string(),
            defaults: DefaultPolicy::AllowAll,
            ontology_policy: Default::default(),
            pii_controls: PiiControls::default(),
            rules: vec![],
        };
        let request = ActionRequest {
            target: ActionTarget::ClipboardWrite,
            params: b"copy sk_live_abcd1234abcd1234".to_vec(),
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };

        let safety = Arc::new(DummySafety {
            graph: graph.clone(),
        }) as Arc<dyn LocalSafetyModel>;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let (_verdict, material_opt) = rt
            .block_on(PolicyEngine::evaluate_pii_overlay_details(
                &rules, &request, &safety,
            ))
            .expect("pii overlay details");
        let material = material_opt.expect("expected material from successful route");
        let overlay_hash = compute_decision_hash(&material);

        let direct = route_pii_decision_for_target(
            &graph,
            &rules.pii_controls,
            RiskSurface::Egress,
            &PiiTarget::Action(ActionTarget::ClipboardWrite),
            false,
        );
        assert_eq!(overlay_hash, direct.decision_hash);
    }
}
