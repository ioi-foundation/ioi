use crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution;
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
    include!("builtins/native_capabilities.rs");
    include!("builtins/typed_web_retrieval_intent_gated.rs");
    include!(
        "builtins/tier_1_deterministic_http_fetch_apis_docs_governed_by_actiontarget_netfetch.rs"
    );
    include!("builtins/app_launching_global_capability.rs");
    include!("builtins/semantic_click_global_capability_tier_independent.rs");
    include!("builtins/tier_2_ui_inspection_primitive_semantic_accessibility_dom.rs");
    include!("builtins/global_typing_capability.rs");
    include!("builtins/global_scroll_capability.rs");
    include!("builtins/browser_interaction_conditional.rs");
    include!("builtins/memory_tools.rs");
    include!("builtins/native_model_memory_capabilities.rs");
    include!("builtins/native_media_capabilities.rs");
    include!("builtins/native_model_registry_control.rs");
    include!("builtins/only_expose_screen_tools_in_visualforeground_tier_3.rs");
    include!("builtins/deterministic_system_tools_are_available_across_all_tiers.rs");
    include!("builtins/deterministic_system_tools_are_available_across_all_tiers_13.rs");
    include!("builtins/openinterpreter_style_shell_continuity_persistent_session.rs");
    include!("builtins/os_control_tools.rs");
    include!("builtins/clipboard_tier_1_deterministic_primitive.rs");
    include!("builtins/common_tools_chat_fs.rs");
    include!("builtins/automation_monitor_local_workflow_runtime.rs");
    include!("builtins/meta_tool_explicit_failure_trigger_escalation.rs");
}

#[cfg(test)]
#[path = "builtins/tests.rs"]
mod tests;
