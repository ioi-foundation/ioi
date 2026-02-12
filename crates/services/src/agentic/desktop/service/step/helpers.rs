// Path: crates/services/src/agentic/desktop/service/step/helpers.rs

use crate::agentic::rules::{ActionRules, Rule, RuleConditions, Verdict};

fn browser_allow_apps() -> Vec<String> {
    vec![
        "Chrome".to_string(),
        "Chromium".to_string(),
        "Brave".to_string(),
        "Firefox".to_string(),
        "Edge".to_string(),
        "Safari".to_string(),
        "Arc".to_string(),
    ]
}

pub fn default_safe_policy() -> ActionRules {
    ActionRules {
        policy_id: "default-safe".to_string(),
        defaults: crate::agentic::rules::DefaultPolicy::RequireApproval,
        rules: vec![
            // Lifecycle / Meta-Tools
            Rule {
                rule_id: Some("allow-complete".into()),
                target: "agent__complete".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-pause".into()),
                target: "agent__pause".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-await".into()),
                target: "agent__await_result".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // Read-Only Capability Defaults
            Rule {
                rule_id: Some("allow-ui-read".into()),
                target: "gui::screenshot".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-browser-read".into()),
                target: "browser::extract".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-browser-scroll".into()),
                target: "browser::scroll".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // Low-risk browser interaction defaults.
            Rule {
                rule_id: Some("allow-browser-gui-click".into()),
                target: "gui::click".into(),
                conditions: RuleConditions {
                    allow_apps: Some(browser_allow_apps()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-browser-gui-type".into()),
                target: "gui::type".into(),
                conditions: RuleConditions {
                    allow_apps: Some(browser_allow_apps()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-browser-gui-scroll".into()),
                target: "gui::scroll".into(),
                conditions: RuleConditions {
                    allow_apps: Some(browser_allow_apps()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
            // Allow Chat Reply
            Rule {
                rule_id: Some("allow-chat-reply".into()),
                target: "chat__reply".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // [NEW] Allow Echo for testing/feedback
            // The PolicyEngine's internal allowlist ensures this is safe (only allows safe commands)
            Rule {
                rule_id: Some("allow-sys-exec-echo".into()),
                target: "sys::exec".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // [NEW] Allow Hermetic Navigation
            Rule {
                rule_id: Some("allow-hermetic-nav".into()),
                target: "browser::navigate::hermetic".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // [NEW] Gate Local Navigation
            Rule {
                rule_id: Some("gate-local-nav".into()),
                target: "browser::navigate::local".into(),
                conditions: Default::default(),
                action: Verdict::RequireApproval,
            },
        ],
    }
}

pub fn sanitize_llm_json(input: &str) -> String {
    let trimmed = input.trim();
    // Check for markdown code blocks
    if trimmed.starts_with("```") {
        let lines: Vec<&str> = trimmed.lines().collect();
        // Remove first line (```json or ```) and last line (```) if valid
        if lines.len() >= 2 && lines.last().unwrap().trim().starts_with("```") {
            return lines[1..lines.len() - 1].join("\n");
        }
    }
    // Also handle raw strings that might just have the json prefix without backticks
    if let Some(json_start) = trimmed.strip_prefix("json") {
        return json_start.to_string();
    }

    input.to_string()
}

/// Extracts top-level window names for a lightweight "Glance" at the desktop state.
pub fn extract_window_titles(xml: &str) -> String {
    let mut titles = Vec::new();
    for line in xml.lines() {
        // Simple string matching to avoid XML parsing overhead in the hot loop
        if line.contains("role=\"window\"") {
            if let Some(start) = line.find("name=\"") {
                let rest = &line[start + 6..];
                if let Some(end) = rest.find('"') {
                    if !rest[..end].trim().is_empty() {
                        titles.push(rest[..end].to_string());
                    }
                }
            }
        }
    }
    if titles.is_empty() {
        "Desktop / Unknown".to_string()
    } else {
        titles.join(", ")
    }
}
