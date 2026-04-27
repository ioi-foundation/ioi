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
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-v2".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [1u8; 32],
        evidence_requirements_hash: [2u8; 32],
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
        .find(|tool| tool.name == "browser__select")
        .expect("browser__select should be available");
    assert!(
        select_text.description.contains("by `selector`"),
        "{}",
        select_text.description
    );

    let paste_clipboard = tools
        .iter()
        .find(|tool| tool.name == "browser__paste")
        .expect("browser__paste should be available");
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
        .find(|tool| tool.name == "browser__click_at")
        .expect("browser__click_at should be available");
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
            .contains(r#""id":{"description":"Optional semantic ID from browser__inspect"#),
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
        .find(|tool| tool.name == "browser__move_pointer")
        .expect("browser__move_pointer should be available");
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

#[test]
fn delegate_tool_surfaces_builtin_worker_templates() {
    let resolved = resolved_ui_intent();
    let mut tools = Vec::new();
    push_builtin_tools(
        &mut tools,
        ExecutionTier::DomHeadless,
        false,
        false,
        true,
        true,
        Some(&resolved),
    );

    let delegate = tools
        .iter()
        .find(|tool| tool.name == "agent__delegate")
        .expect("agent__delegate should be available");
    assert!(
        delegate.description.contains("researcher"),
        "{}",
        delegate.description
    );
    assert!(
        delegate.description.contains("verifier"),
        "{}",
        delegate.description
    );
    assert!(
        delegate.description.contains("coder"),
        "{}",
        delegate.description
    );
    assert!(delegation_template_hint().contains("researcher"));
    assert!(delegation_template_hint().contains("live_research_brief"));
}
