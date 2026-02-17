// Path: crates/services/src/agentic/desktop/service/step/helpers.rs

use crate::agentic::rules::{ActionRules, OntologyPolicy, Rule, RuleConditions, Verdict};

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
        ontology_policy: OntologyPolicy::default(),
        pii_controls: Default::default(),
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
                rule_id: Some("allow-browser-inspect".into()),
                target: "browser::inspect".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-web-retrieve".into()),
                target: "web::retrieve".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // Memory (SCS-backed, read-only) defaults.
            Rule {
                rule_id: Some("allow-memory-search".into()),
                target: "memory::search".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-memory-inspect".into()),
                target: "memory::inspect".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("gate-memory-inspect-observation".into()),
                target: "memory::inspect_observation".into(),
                conditions: Default::default(),
                action: Verdict::RequireApproval,
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

pub fn should_log_raw_prompt_content() -> bool {
    std::env::var("IOI_LOG_RAW_PROMPTS")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

pub fn should_auto_complete_open_app_goal(
    goal: &str,
    app_name: &str,
    target_hint: Option<&str>,
) -> bool {
    let goal_lc = goal.to_ascii_lowercase();
    if goal_lc.trim().is_empty() {
        return false;
    }

    let has_launch_verb = ["open ", "launch ", "start ", "run "]
        .iter()
        .any(|verb| goal_lc.contains(verb));
    if !has_launch_verb {
        return false;
    }

    let app_lc = app_name.trim().to_ascii_lowercase();
    let hint_lc = target_hint.unwrap_or("").trim().to_ascii_lowercase();
    if app_lc.is_empty() && hint_lc.is_empty() {
        return false;
    }
    let mentions_target = (!app_lc.is_empty() && goal_lc.contains(&app_lc))
        || (!hint_lc.is_empty() && goal_lc.contains(&hint_lc));
    if !mentions_target {
        return false;
    }

    // If the goal clearly includes follow-up interaction, launching is not terminal.
    let follow_up_actions = [
        " click ",
        " type ",
        " enter ",
        " compute ",
        " calculate ",
        " solve ",
        " search ",
        " browse ",
        " navigate ",
        " extract ",
        " summarize ",
        " read ",
        " write ",
        " edit ",
        " create ",
        " delete ",
        " screenshot ",
        " test ",
        " run tests",
    ];
    !follow_up_actions
        .iter()
        .any(|marker| goal_lc.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::should_auto_complete_open_app_goal;

    #[test]
    fn auto_complete_open_app_goal_for_simple_launch() {
        assert!(should_auto_complete_open_app_goal(
            "Open calculator",
            "calculator",
            Some("calculator")
        ));
    }

    #[test]
    fn does_not_auto_complete_when_follow_up_actions_exist() {
        assert!(!should_auto_complete_open_app_goal(
            "Open calculator and compute 2+2",
            "calculator",
            Some("calculator")
        ));
    }

    #[test]
    fn requires_goal_to_mention_target_app() {
        assert!(!should_auto_complete_open_app_goal(
            "Open the app",
            "calculator",
            Some("calculator")
        ));
    }
}
