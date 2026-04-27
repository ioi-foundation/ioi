use super::{
    inject_google_connector_tools_if_needed, inject_mail_connector_fallback_tools_if_needed,
    push_service_tools,
};
use ioi_api::state::namespaced::ReadOnlyNamespacedStateAccess;
use ioi_api::state::service_namespace_prefix;
use ioi_api::state::StateAccess;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition, ResolvedIntentState,
};
use ioi_types::codec;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use std::collections::BTreeMap;

fn active_wallet_network_meta() -> ActiveServiceMeta {
    let mut methods = BTreeMap::new();
    methods.insert("mail_reply@v1".to_string(), MethodPermission::User);
    methods.insert("mail_read_latest@v1".to_string(), MethodPermission::User);
    ActiveServiceMeta {
        id: "wallet_network".to_string(),
        abi_version: 1,
        state_schema: "wallet_network.v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    }
}

fn desktop_agent_meta(allowed_system_prefixes: Vec<String>) -> ActiveServiceMeta {
    let mut methods = BTreeMap::new();
    methods.insert("step@v1".to_string(), MethodPermission::User);
    ActiveServiceMeta {
        id: "desktop_agent".to_string(),
        abi_version: 1,
        state_schema: "desktop_agent.v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes,
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    }
}

#[test]
fn namespaced_discovery_without_upgrade_prefix_still_exposes_service_tools() {
    let mut root_state = IAVLTree::new(HashCommitmentScheme::new());
    root_state
        .insert(
            &active_service_key("wallet_network"),
            &codec::to_bytes_canonical(&active_wallet_network_meta()).expect("encode meta"),
        )
        .expect("insert active service meta");

    let desktop_meta = desktop_agent_meta(vec![]);
    let prefix = service_namespace_prefix("desktop_agent");
    let namespaced = ReadOnlyNamespacedStateAccess::new(&root_state, prefix, &desktop_meta);

    let mut tools = Vec::new();
    push_service_tools(&namespaced, "Autopilot Chat", &mut tools);

    assert!(
        tools.iter().any(|tool| tool.name == "wallet_network__mail_reply"),
        "wallet mail tool should remain discoverable from globally readable upgrade::active:: registry"
    );
}

#[test]
fn namespaced_discovery_with_upgrade_prefix_exposes_service_tools() {
    let mut root_state = IAVLTree::new(HashCommitmentScheme::new());
    root_state
        .insert(
            &active_service_key("wallet_network"),
            &codec::to_bytes_canonical(&active_wallet_network_meta()).expect("encode meta"),
        )
        .expect("insert active service meta");

    let desktop_meta = desktop_agent_meta(vec!["upgrade::active::".to_string()]);
    let prefix = service_namespace_prefix("desktop_agent");
    let namespaced = ReadOnlyNamespacedStateAccess::new(&root_state, prefix, &desktop_meta);

    let mut tools = Vec::new();
    push_service_tools(&namespaced, "Autopilot Chat", &mut tools);

    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "wallet_network__mail_reply"),
        "wallet mail tool should be visible when upgrade::active:: is allowlisted"
    );
}

fn resolved_intent(
    intent_id: &str,
    required_capabilities: Vec<CapabilityId>,
) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities,
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
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
fn injects_mail_connector_fallback_tools_for_mail_intent_when_missing() {
    let mut tools = vec![];
    let resolved = resolved_intent(
        "mail.reply",
        vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
        ],
    );

    inject_mail_connector_fallback_tools_if_needed(Some(&resolved), &mut tools);

    assert!(
        tools.iter().any(|tool| tool.name == "wallet_network__mail_reply"),
        "mail.reply intent should receive canonical wallet mail fallback tool when discovery returned none"
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "wallet_network__mail_read_latest"),
        "mail fallback should include read/list/delete primitives for deterministic mailbox workflows"
    );
}

#[test]
fn does_not_inject_mail_connector_fallback_tools_for_non_mail_intent() {
    let mut tools = vec![];
    let resolved = resolved_intent(
        "conversation.reply",
        vec![CapabilityId::from("conversation.reply")],
    );

    inject_mail_connector_fallback_tools_if_needed(Some(&resolved), &mut tools);

    assert!(
        tools.is_empty(),
        "non-mail intents must not receive mail connector fallback tools"
    );
}

#[test]
fn does_not_duplicate_mail_connector_tools_when_registry_discovered() {
    let mut tools = vec![LlmToolDefinition {
        name: "wallet_network__mail_reply".to_string(),
        description: "existing tool".to_string(),
        parameters: "{}".to_string(),
    }];
    let resolved = resolved_intent(
        "mail.reply",
        vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
        ],
    );

    inject_mail_connector_fallback_tools_if_needed(Some(&resolved), &mut tools);

    let reply_count = tools
        .iter()
        .filter(|tool| tool.name == "wallet_network__mail_reply")
        .count();
    assert_eq!(
        reply_count, 1,
        "fallback must not duplicate discovered mail tools"
    );
}

#[test]
fn injects_google_connector_tools_once() {
    let mut tools = vec![];

    inject_google_connector_tools_if_needed(&mut tools);
    inject_google_connector_tools_if_needed(&mut tools);

    let gmail_send_count = tools
        .iter()
        .filter(|tool| tool.name == "connector__google__gmail_send_email")
        .count();
    assert_eq!(gmail_send_count, 1);
    assert!(tools
        .iter()
        .any(|tool| tool.name == "connector__google__workflow_file_announce"));
}
