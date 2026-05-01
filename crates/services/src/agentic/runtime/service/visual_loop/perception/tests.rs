use super::{normalize_browser_chrome_top, should_omit_passive_workspace_context};
use crate::agentic::runtime::types::ExecutionTier;
use ioi_types::app::agentic::{IntentScopeProfile, LlmToolDefinition};

fn tool(name: &str) -> LlmToolDefinition {
    LlmToolDefinition {
        name: name.to_string(),
        description: String::new(),
        parameters: "{}".to_string(),
    }
}

#[test]
fn normalize_browser_chrome_top_clamps_reasonable_values() {
    assert_eq!(normalize_browser_chrome_top(115.0), Some(115));
    assert_eq!(normalize_browser_chrome_top(115.4), Some(115));
    assert_eq!(normalize_browser_chrome_top(115.6), Some(116));
    assert_eq!(normalize_browser_chrome_top(0.0), None);
    assert_eq!(normalize_browser_chrome_top(12.0), None);
    assert_eq!(normalize_browser_chrome_top(999.0), None);
    assert_eq!(normalize_browser_chrome_top(f64::NAN), None);
    assert_eq!(normalize_browser_chrome_top(f64::INFINITY), None);
}

#[test]
fn omits_passive_workspace_context_for_dom_headless_browser_ui_steps() {
    assert!(should_omit_passive_workspace_context(
        ExecutionTier::DomHeadless,
        "Chromium (chromium)",
        Some(IntentScopeProfile::UiInteraction),
        &[tool("browser__inspect"), tool("browser__click")]
    ));
}

#[test]
fn retains_passive_workspace_context_for_command_steps() {
    assert!(!should_omit_passive_workspace_context(
        ExecutionTier::DomHeadless,
        "Chromium (chromium)",
        Some(IntentScopeProfile::CommandExecution),
        &[tool("browser__inspect"), tool("browser__click")]
    ));
}
