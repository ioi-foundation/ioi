use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::types::ExecutionTier;
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
    include!("builtins/only_expose_computer_tools_in_visualforeground_tier_3.rs");
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
mod tests {
    use super::*;
    use ioi_types::app::agentic::{
        CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };

    fn resolved_ui_intent() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "ui.interaction".to_string(),
            scope: IntentScopeProfile::UiInteraction,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("ui.interact"),
                CapabilityId::from("ui.inspect"),
                CapabilityId::from("conversation.reply"),
            ],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "intent-matrix-v2".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    #[test]
    fn browser_text_and_clipboard_tools_surface_selector_targeting() {
        let resolved = resolved_ui_intent();
        let mut tools = Vec::new();
        push_builtin_tools(
            &mut tools,
            ExecutionTier::DomHeadless,
            true,
            true,
            false,
            false,
            Some(&resolved),
        );

        let select_text = tools
            .iter()
            .find(|tool| tool.name == "browser__select_text")
            .expect("browser__select_text should be available");
        assert!(
            select_text.description.contains("by `selector`"),
            "{}",
            select_text.description
        );

        let paste_clipboard = tools
            .iter()
            .find(|tool| tool.name == "browser__paste_clipboard")
            .expect("browser__paste_clipboard should be available");
        assert!(
            paste_clipboard.description.contains("Pass `selector`"),
            "{}",
            paste_clipboard.description
        );
    }

    #[test]
    fn browser_synthetic_click_surfaces_in_dom_headless_tier() {
        let resolved = resolved_ui_intent();
        let mut tools = Vec::new();
        push_builtin_tools(
            &mut tools,
            ExecutionTier::DomHeadless,
            true,
            true,
            false,
            false,
            Some(&resolved),
        );

        let synthetic_click = tools
            .iter()
            .find(|tool| tool.name == "browser__synthetic_click")
            .expect("browser__synthetic_click should be available");
        assert!(
            synthetic_click
                .description
                .contains("not normalized 0-1 fractions"),
            "{}",
            synthetic_click.description
        );
        assert!(
            synthetic_click
                .parameters
                .contains(r#""id":{"description":"Optional semantic ID from browser__snapshot"#),
            "{}",
            synthetic_click.parameters
        );
        assert!(
            synthetic_click.parameters.contains(r#""type":"number""#),
            "{}",
            synthetic_click.parameters
        );
        assert!(
            synthetic_click
                .parameters
                .contains("Prefer this instead of guessing raw coordinates"),
            "{}",
            synthetic_click.parameters
        );
        assert!(
            synthetic_click
                .parameters
                .contains("absolute viewport x coordinate in CSS pixels"),
            "{}",
            synthetic_click.parameters
        );

        let move_mouse = tools
            .iter()
            .find(|tool| tool.name == "browser__move_mouse")
            .expect("browser__move_mouse should be available");
        assert!(
            move_mouse
                .description
                .contains("does NOT activate page content"),
            "{}",
            move_mouse.description
        );
        assert!(
            move_mouse.parameters.contains(r#""type":"number""#),
            "{}",
            move_mouse.parameters
        );
        assert!(
            move_mouse.description.contains("normalized 0-1 fractions"),
            "{}",
            move_mouse.description
        );
    }
}
