use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::mcp::McpManager;
use ioi_scs::SovereignContextStore;
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};
use std::collections::HashSet;
use std::sync::Arc;

use super::{builtins, mcp, services, skills};

/// Discovers tools available to the agent.
pub async fn discover_tools(
    state: &dyn StateAccess,
    scs: Option<&std::sync::Mutex<SovereignContextStore>>,
    mcp: Option<&McpManager>,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tier: ExecutionTier,
    active_window_title: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Vec<LlmToolDefinition> {
    let mut tools = Vec::new();
    let mut mcp_tool_names: HashSet<String> = HashSet::new();

    // Browser detection
    let t = active_window_title.to_lowercase();
    let is_browser_active = t.contains("chrome")
        || t.contains("firefox")
        || t.contains("brave")
        || t.contains("edge")
        || t.contains("safari");

    let allow_browser_navigation =
        is_tool_allowed_for_resolution(resolved_intent, "browser__navigate");
    let allow_web_search = is_tool_allowed_for_resolution(resolved_intent, "web__search");
    let allow_web_read = is_tool_allowed_for_resolution(resolved_intent, "web__read");

    // Dynamic service tools (on-chain services)
    services::push_service_tools(state, active_window_title, &mut tools);

    // MCP tool discovery
    if let Some(mcp) = mcp {
        mcp::push_mcp_tools(mcp, &mut tools, &mut mcp_tool_names).await;
    }

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
    if let Some(scs) = scs {
        skills::inject_skill_tools(state, scs, query, runtime, &mut tools).await;
    }

    // Final filter:
    // - Always respect resolved-intent allowlist.
    // - Keep MCP tools when the intent scope allows external tools even if not explicitly listed.
    let allow_mcp_tools = resolved_intent
        .map(|resolved| {
            !matches!(
                resolved.scope,
                ioi_types::app::agentic::IntentScopeProfile::Conversation
                    | ioi_types::app::agentic::IntentScopeProfile::Unknown
            )
        })
        .unwrap_or(true);

    tools.retain(|tool| {
        if is_tool_allowed_for_resolution(resolved_intent, &tool.name) {
            return true;
        }
        allow_mcp_tools && mcp_tool_names.contains(&tool.name)
    });

    tools
}

#[cfg(test)]
mod tests {
    use super::discover_tools;
    use crate::agentic::desktop::tools::should_expose_headless_browser_followups;
    use crate::agentic::desktop::types::ExecutionTier;
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
    use std::sync::Arc;

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: format!("{scope:?}"),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "intent-matrix-v2".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            constrained: false,
        }
    }

    #[test]
    fn headless_tier_hides_browser_followups_when_not_allowed() {
        assert!(!should_expose_headless_browser_followups(
            ExecutionTier::DomHeadless,
            false,
            true
        ));
    }

    #[test]
    fn headless_tier_exposes_browser_followups_when_allowed() {
        assert!(should_expose_headless_browser_followups(
            ExecutionTier::DomHeadless,
            true,
            false
        ));
    }

    #[test]
    fn non_headless_hides_followups() {
        assert!(!should_expose_headless_browser_followups(
            ExecutionTier::VisualForeground,
            true,
            false
        ));
    }

    #[test]
    fn non_headless_exposes_followups_when_browser_active() {
        assert!(should_expose_headless_browser_followups(
            ExecutionTier::VisualForeground,
            true,
            true
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conversation_scope_hides_browser_tools_in_discovery() {
        let intent = resolved(IntentScopeProfile::Conversation);
        let state = IAVLTree::new(HashCommitmentScheme::new());
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let tools = discover_tools(
            &state,
            None,
            None,
            "summarize this note",
            runtime,
            ExecutionTier::DomHeadless,
            "terminal",
            Some(&intent),
        )
        .await;
        assert!(tools.iter().any(|t| t.name == "chat__reply"));
        assert!(!tools.iter().any(|t| t.name == "browser__navigate"));
        assert!(!tools.iter().any(|t| t.name == "web__search"));
        assert!(!tools.iter().any(|t| t.name == "web__read"));
        assert!(!tools.iter().any(|t| t.name == "os__copy"));
        assert!(!tools.iter().any(|t| t.name == "os__paste"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workspace_ops_scope_exposes_clipboard_tools_in_headless_discovery() {
        let intent = resolved(IntentScopeProfile::WorkspaceOps);
        let state = IAVLTree::new(HashCommitmentScheme::new());
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let tools = discover_tools(
            &state,
            None,
            None,
            "copy this text into clipboard",
            runtime,
            ExecutionTier::DomHeadless,
            "terminal",
            Some(&intent),
        )
        .await;
        assert!(tools.iter().any(|t| t.name == "os__copy"));
        assert!(tools.iter().any(|t| t.name == "os__paste"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn web_research_scope_keeps_browser_tools_in_discovery() {
        let intent = resolved(IntentScopeProfile::WebResearch);
        let state = IAVLTree::new(HashCommitmentScheme::new());
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let tools = discover_tools(
            &state,
            None,
            None,
            "crawl this url and summarize key details",
            runtime,
            ExecutionTier::DomHeadless,
            "terminal",
            Some(&intent),
        )
        .await;
        assert!(tools.iter().any(|t| t.name == "browser__navigate"));
        assert!(tools.iter().any(|t| t.name == "web__search"));
        assert!(tools.iter().any(|t| t.name == "web__read"));
        assert!(tools.iter().any(|t| t.name == "chat__reply"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn visual_foreground_browser_window_exposes_browser_followups() {
        let intent = resolved(IntentScopeProfile::WebResearch);
        let state = IAVLTree::new(HashCommitmentScheme::new());
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let tools = discover_tools(
            &state,
            None,
            None,
            "open search and click a result",
            runtime,
            ExecutionTier::VisualForeground,
            "Google Chrome (chrome)",
            Some(&intent),
        )
        .await;

        assert!(tools.iter().any(|t| t.name == "browser__snapshot"));
        assert!(tools.iter().any(|t| t.name == "browser__click_element"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn visual_foreground_non_browser_window_hides_browser_followups() {
        let intent = resolved(IntentScopeProfile::WebResearch);
        let state = IAVLTree::new(HashCommitmentScheme::new());
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let tools = discover_tools(
            &state,
            None,
            None,
            "open search and click a result",
            runtime,
            ExecutionTier::VisualForeground,
            "Calculator",
            Some(&intent),
        )
        .await;

        assert!(!tools.iter().any(|t| t.name == "browser__snapshot"));
        assert!(!tools.iter().any(|t| t.name == "browser__click_element"));
    }
}
