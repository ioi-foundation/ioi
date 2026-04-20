use crate::agentic::runtime::adapters;
use crate::agentic::runtime::service::step::intent_resolver::{
    is_tool_allowed_for_resolution, is_tool_allowed_for_selected_provider,
};
use crate::agentic::runtime::service::step::signals::is_browser_surface;
use crate::agentic::runtime::types::ExecutionTier;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::mcp::McpManager;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};
use std::collections::HashSet;
use std::sync::Arc;

use super::{builtins, skills};

fn split_active_window_label(active_window_title: &str) -> (String, String) {
    let label = active_window_title.trim();
    if label.is_empty() {
        return (String::new(), String::new());
    }

    if label.ends_with(')') {
        if let Some(open_paren) = label.rfind('(') {
            let title = label[..open_paren].trim();
            let app = label[open_paren + 1..label.len() - 1].trim();
            if !app.is_empty() {
                return (title.to_string(), app.to_string());
            }
        }
    }

    // Fallback when no explicit "(App)" suffix is present.
    (label.to_string(), label.to_string())
}

/// Discovers tools available to the agent.
pub async fn discover_tools(
    state: &dyn StateAccess,
    memory_runtime: Option<&MemoryRuntime>,
    mcp: Option<&McpManager>,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tier: ExecutionTier,
    active_window_title: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Vec<LlmToolDefinition> {
    let mut tools = Vec::new();
    let mut mcp_tool_names: HashSet<String> = HashSet::new();

    // Browser detection (shared signal contract used across perception/cognition/execution).
    let (window_title, window_app) = split_active_window_label(active_window_title);
    let is_browser_active = is_browser_surface(&window_app, &window_title);

    let allow_browser_navigation =
        is_tool_allowed_for_resolution(resolved_intent, "browser__navigate");
    let allow_web_search = is_tool_allowed_for_resolution(resolved_intent, "web__search");
    let allow_web_read = is_tool_allowed_for_resolution(resolved_intent, "web__read");

    let (mut adapter_tools, adapter_tool_names) =
        adapters::discover_adapter_tools(state, mcp, active_window_title, resolved_intent).await;
    mcp_tool_names.extend(adapter_tool_names);
    tools.append(&mut adapter_tools);

    // Built-in deterministic tools + tier-gated UI controls
    builtins::push_builtin_tools(
        &mut tools,
        tier,
        is_browser_active,
        allow_browser_navigation,
        allow_web_search,
        allow_web_read,
        resolved_intent,
    );

    // Skill discovery via semantic search + reputation ranking
    if let Some(memory_runtime) = memory_runtime {
        skills::inject_skill_tools(state, memory_runtime, query, runtime, &mut tools).await;
    }

    // Final filter:
    // - With a resolved intent, expose only tools whose capabilities satisfy the intent scope.
    // - Without a resolved intent, keep the discovered set for pre-resolution operation.
    tools.retain(|tool| {
        if resolved_intent.is_none() {
            return true;
        }
        let allowed = is_tool_allowed_for_resolution(resolved_intent, &tool.name);
        let provider_allowed = is_tool_allowed_for_selected_provider(resolved_intent, &tool.name);
        if !allowed && mcp_tool_names.contains(&tool.name) {
            tracing::debug!(
                "Hiding MCP tool '{}' because it is outside resolved intent capability scope",
                tool.name
            );
        }
        allowed && provider_allowed
    });

    tools
}

#[cfg(test)]
#[path = "discovery/tests.rs"]
mod tests;
