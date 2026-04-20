use super::*;
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, InstructionBindingKind, InstructionContract,
    InstructionSideEffectMode, InstructionSlotBinding, IntentConfidenceBand, ProtectedSlotKind,
};

fn resolved_intent_with_contract(
    scope: IntentScopeProfile,
    operation: &str,
    slot_bindings: Vec<InstructionSlotBinding>,
) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "delegation.task".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("memory.access")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: Some(InstructionContract {
            operation: operation.to_string(),
            side_effect_mode: InstructionSideEffectMode::ReadOnly,
            slot_bindings,
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }
}

fn literal_slot(slot: &str, value: &str) -> InstructionSlotBinding {
    InstructionSlotBinding {
        slot: slot.to_string(),
        binding_kind: InstructionBindingKind::UserLiteral,
        value: Some(value.to_string()),
        origin: ArgumentOrigin::ModelInferred,
        protected_slot_kind: ProtectedSlotKind::Unknown,
    }
}

#[test]
fn normalized_web_search_query_preserves_entity_bound_local_business_expansion_queries() {
    let goal = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let retrieval_query = "\"Brothers Italian Cuisine\" italian \"Anderson, SC\"";

    let normalized = normalized_web_search_query(goal, retrieval_query).expect("normalized query");
    let lower = normalized.to_ascii_lowercase();

    assert!(
        lower.contains("\"brothers italian cuisine\""),
        "expected entity-bound query to survive normalization: {}",
        normalized
    );
    assert!(
        lower.contains("\"anderson, sc\""),
        "expected locality scope to survive normalization: {}",
        normalized
    );
    assert!(
        !lower.eq("italian in anderson, sc"),
        "entity-bound expansion query collapsed to generic discovery query: {}",
        normalized
    );
}

#[test]
fn normalized_web_search_query_keeps_generic_local_business_discovery_queries_generic() {
    let goal = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let retrieval_query = "italian restaurants in Anderson, SC";

    let normalized = normalized_web_search_query(goal, retrieval_query).expect("normalized query");

    assert_eq!(normalized, "italian restaurants in Anderson, SC");
}

#[test]
fn normalize_web_research_tool_call_preserves_memory_search_for_citation_audit_verifier() {
    let resolved = resolved_intent_with_contract(
        IntentScopeProfile::Conversation,
        "verify",
        vec![
            literal_slot("template_id", "verifier"),
            literal_slot("workflow_id", "citation_audit"),
        ],
    );
    let mut tool = AgentTool::MemorySearch {
        query: "the latest NIST post-quantum cryptography standards".to_string(),
    };

    normalize_web_research_tool_call(
        &mut tool,
        Some(&resolved),
        "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources, then return a citation verifier scorecard with blockers and next checks.",
    );

    assert!(matches!(tool, AgentTool::MemorySearch { .. }));
}

#[test]
fn normalize_web_research_tool_call_still_promotes_live_research_memory_search() {
    let resolved =
        resolved_intent_with_contract(IntentScopeProfile::WebResearch, "web.research", vec![]);
    let mut tool = AgentTool::MemorySearch {
        query: "the latest NIST post-quantum cryptography standards".to_string(),
    };

    normalize_web_research_tool_call(
        &mut tool,
        Some(&resolved),
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
    );

    let AgentTool::WebSearch { query, .. } = tool else {
        panic!("expected live research memory search to become web search");
    };
    assert!(query.to_ascii_lowercase().contains("nist"), "query={query}");
}
