use crate::agentic::runtime::service::decision_loop::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::types::ExecutionTier;
use crate::agentic::runtime::worker_templates::delegation_template_hint;
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};
use serde_json::json;

pub(crate) fn should_expose_headless_browser_followups(
    tier: ExecutionTier,
    browser_tools_allowed: bool,
    is_browser_active: bool,
) -> bool {
    browser_tools_allowed && (tier == ExecutionTier::DomHeadless || is_browser_active)
}

pub(super) fn push_builtin_tools(
    tools: &mut Vec<LlmToolDefinition>,
    tier: ExecutionTier,
    is_browser_active: bool,
    allow_browser_navigation: bool,
    allow_web_search: bool,
    allow_web_read: bool,
    resolved_intent: Option<&ResolvedIntentState>,
) {
    include!("builtins/native.rs");
    include!("builtins/web_retrieval.rs");
    include!("builtins/http_fetch.rs");
    include!("builtins/app_launching.rs");
    include!("builtins/semantic_click.rs");
    include!("builtins/ui_inspection.rs");
    include!("builtins/typing.rs");
    include!("builtins/scrolling.rs");
    include!("builtins/browser.rs");
    include!("builtins/memory.rs");
    include!("builtins/model_memory.rs");
    include!("builtins/media.rs");
    include!("builtins/model_registry.rs");
    include!("builtins/screen.rs");
    include!("builtins/system.rs");
    include!("builtins/system_tier13.rs");
    include!("builtins/shell_continuity.rs");
    include!("builtins/os_control.rs");
    include!("builtins/clipboard.rs");
    include!("builtins/filesystem_chat.rs");
    include!("builtins/workflow_monitor.rs");
    include!("builtins/meta_failure.rs");
}

#[cfg(test)]
#[path = "builtins/tests.rs"]
mod tests;
