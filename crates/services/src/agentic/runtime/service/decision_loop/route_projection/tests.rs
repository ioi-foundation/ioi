use super::{
    build_effective_tool_surface, currentness_override_for_resolved_intent, direct_answer_blockers,
    file_output_intent, output_intent, resolved_intent_requires_local_install,
    route_family_for_resolved_intent, skill_prep_required,
};
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition,
    ProviderRouteCandidate, ProviderSelectionMode, ProviderSelectionState, ResolvedIntentState,
};

fn tool(name: &str) -> LlmToolDefinition {
    LlmToolDefinition {
        name: name.to_string(),
        description: format!("{name} description"),
        parameters: "{}".to_string(),
    }
}

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test.intent".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn route_family_uses_resolved_scope_defaults() {
    assert_eq!(
        route_family_for_resolved_intent(Some(&resolved(IntentScopeProfile::WebResearch))),
        "research"
    );
    assert_eq!(
        route_family_for_resolved_intent(Some(&resolved(IntentScopeProfile::WorkspaceOps))),
        "coding"
    );
    assert_eq!(
        route_family_for_resolved_intent(Some(&resolved(IntentScopeProfile::UiInteraction))),
        "computer_use"
    );
}

#[test]
fn currentness_override_tracks_research_scope_and_temporal_intents() {
    let mut clock_resolved = resolved(IntentScopeProfile::Conversation);
    clock_resolved.intent_id = "system.clock.read".to_string();
    clock_resolved.required_capabilities = vec![CapabilityId::from("sys.time.read")];
    assert!(currentness_override_for_resolved_intent(Some(
        &clock_resolved
    )));
    assert!(currentness_override_for_resolved_intent(Some(&resolved(
        IntentScopeProfile::WebResearch
    ))));
}

#[test]
fn effective_tool_surface_prefers_selected_provider_and_keeps_fallbacks() {
    let mut resolved = resolved(IntentScopeProfile::Conversation);
    resolved.required_capabilities = vec![CapabilityId::from("mail.reply")];
    resolved.provider_selection = Some(ProviderSelectionState {
        mode: ProviderSelectionMode::DynamicSynthesis,
        selected_provider_family: Some("mail.google.gmail".to_string()),
        selected_route_label: Some("google_gmail".to_string()),
        selected_provider_id: Some("mail.google.gmail::primary".to_string()),
        selected_connector_id: Some("google.workspace".to_string()),
        selection_basis: Some("semantic_match".to_string()),
        candidates: vec![ProviderRouteCandidate {
            provider_family: "mail.google.gmail".to_string(),
            route_label: "google_gmail".to_string(),
            connector_id: "google.workspace".to_string(),
            provider_id: Some("mail.google.gmail::primary".to_string()),
            account_label: Some("connected@example.com".to_string()),
            capabilities: vec![CapabilityId::from("mail.reply")],
            summary: "Connected Gmail".to_string(),
        }],
    });

    let surface = build_effective_tool_surface(
        &[
            tool("google_gmail__draft_email"),
            tool("chat__reply"),
            tool("memory__search"),
        ],
        Some(&resolved),
        "google_gmail__draft_email",
    );

    assert_eq!(surface.primary_tools, vec!["google_gmail__draft_email"]);
    assert_eq!(
        surface.broad_fallback_tools,
        vec!["chat__reply", "memory__search"]
    );
    assert_eq!(
        surface.projected_tools,
        vec![
            "google_gmail__draft_email".to_string(),
            "chat__reply".to_string(),
            "memory__search".to_string()
        ]
    );
}

#[test]
fn coding_read_tools_do_not_force_file_output_or_skill_prep() {
    assert!(!file_output_intent("coding", "file__list"));
    assert!(!file_output_intent("coding", "file__read"));
    assert!(!file_output_intent("coding", "file__search"));
    assert!(!skill_prep_required("coding", "file__list"));
    assert!(!skill_prep_required("coding", "file__read"));
    assert!(!skill_prep_required("coding", "file__search"));
}

#[test]
fn file_mutation_tools_still_require_file_output_and_prep() {
    assert!(file_output_intent("coding", "file__write"));
    assert!(file_output_intent("coding", "file__edit"));
    assert!(skill_prep_required("coding", "file__write"));
    assert!(skill_prep_required("coding", "file__edit"));
}

#[test]
fn tool_steps_without_delivery_intent_stay_in_tool_execution_mode() {
    assert_eq!(
        output_intent("file__list", true, false, false, false),
        "tool_execution"
    );
    assert_eq!(
        output_intent("chat__reply", true, false, false, false),
        "direct_inline"
    );
}

#[test]
fn resolved_install_intent_blocks_direct_inline_output() {
    let mut install_intent = resolved(IntentScopeProfile::CommandExecution);
    install_intent.intent_id = "software.install.desktop_app".to_string();
    install_intent.required_capabilities = vec![CapabilityId::from("software.install.execute")];
    assert!(resolved_intent_requires_local_install(Some(
        &install_intent
    )));
    assert!(!resolved_intent_requires_local_install(Some(&resolved(
        IntentScopeProfile::Conversation
    ))));

    let blockers = direct_answer_blockers(false, true, false, false, false, false, false);
    assert!(blockers.contains(&"host_mutation_requested".to_string()));
    assert_eq!(
        output_intent("chat__reply", false, false, false, false),
        "tool_execution"
    );
}
