use crate::agentic::runtime::connectors::google_workspace;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};
use ioi_types::codec;
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use regex::Regex;
use serde_json::json;

pub(crate) fn should_expose_service_method_tool(service_id: &str, simple_name: &str) -> bool {
    if service_id.eq_ignore_ascii_case("wallet_network")
        && simple_name.starts_with("mail_connector_")
    {
        return false;
    }
    true
}

pub(crate) fn is_mail_connector_tool_name(name: &str) -> bool {
    matches!(
        name,
        "wallet_network__mail_read_latest"
            | "wallet_mail_read_latest"
            | "mail__read_latest"
            | "wallet_network__mail_list_recent"
            | "wallet_mail_list_recent"
            | "mail__list_recent"
            | "wallet_network__mail_delete_spam"
            | "wallet_mail_delete_spam"
            | "mail__delete_spam"
            | "wallet_network__mail_reply"
            | "wallet_mail_reply"
            | "mail__reply"
    )
}

pub(crate) fn resolved_intent_requires_mail_connector(
    resolved_intent: Option<&ResolvedIntentState>,
) -> bool {
    let Some(resolved) = resolved_intent else {
        return false;
    };
    if resolved
        .intent_id
        .trim()
        .to_ascii_lowercase()
        .starts_with("mail.")
    {
        return true;
    }
    resolved
        .required_capabilities
        .iter()
        .any(|cap| cap.as_str().starts_with("mail."))
}

pub(crate) fn has_discovered_mail_connector_tools(tools: &[LlmToolDefinition]) -> bool {
    tools
        .iter()
        .any(|tool| is_mail_connector_tool_name(tool.name.as_str()))
}

pub(crate) fn has_discovered_google_connector_tools(tools: &[LlmToolDefinition]) -> bool {
    tools
        .iter()
        .any(|tool| google_workspace::is_google_connector_tool_name(tool.name.as_str()))
}

pub(crate) fn push_mail_connector_fallback_tools(tools: &mut Vec<LlmToolDefinition>) {
    let read_latest_params = json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "description": "Mailbox alias (default: primary)." },
            "channel_id": { "type": "string", "description": "Optional hex channel id override." },
            "lease_id": { "type": "string", "description": "Optional hex lease id override." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "wallet_network__mail_read_latest".to_string(),
        description: "Read the latest message from a connected mailbox through wallet network."
            .to_string(),
        parameters: read_latest_params.to_string(),
    });

    let list_recent_params = json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "description": "Mailbox alias (default: primary)." },
            "limit": { "type": "integer", "description": "Maximum number of messages to list." },
            "channel_id": { "type": "string", "description": "Optional hex channel id override." },
            "lease_id": { "type": "string", "description": "Optional hex lease id override." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "wallet_network__mail_list_recent".to_string(),
        description: "List recent messages from a connected mailbox through wallet network."
            .to_string(),
        parameters: list_recent_params.to_string(),
    });

    let delete_spam_params = json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "description": "Mailbox alias (default: primary)." },
            "max_count": { "type": "integer", "description": "Maximum spam messages to delete." },
            "dry_run": { "type": "boolean", "description": "When true, preview deletions without mutation." },
            "channel_id": { "type": "string", "description": "Optional hex channel id override." },
            "lease_id": { "type": "string", "description": "Optional hex lease id override." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "wallet_network__mail_delete_spam".to_string(),
        description: "Delete spam/junk messages from a connected mailbox through wallet network."
            .to_string(),
        parameters: delete_spam_params.to_string(),
    });

    let reply_params = json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "description": "Mailbox alias (default: primary)." },
            "reply_to_message_id": { "type": "string", "description": "Optional message id to thread the outbound email against." },
            "channel_id": { "type": "string", "description": "Optional hex channel id override." },
            "lease_id": { "type": "string", "description": "Optional hex lease id override." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "wallet_network__mail_reply".to_string(),
        description:
            "Draft and send an outbound email through a connected mailbox via wallet network using the latest user request as the authoritative draft source. Optional explicit canonical fields `to`, `subject`, and `body` are accepted only when they are complete and final; otherwise the runtime synthesizes the final draft before execution."
                .to_string(),
        parameters: reply_params.to_string(),
    });
}

pub(crate) fn push_google_connector_tools(tools: &mut Vec<LlmToolDefinition>) {
    let mut discovered = google_workspace::google_connector_tool_definitions();
    tools.append(&mut discovered);
}

pub(crate) fn inject_mail_connector_fallback_tools_if_needed(
    resolved_intent: Option<&ResolvedIntentState>,
    tools: &mut Vec<LlmToolDefinition>,
) {
    if !resolved_intent_requires_mail_connector(resolved_intent) {
        return;
    }
    if has_discovered_mail_connector_tools(tools) {
        return;
    }
    log::warn!(
        "No mail connector tools discovered from active service metadata; injecting canonical wallet mail tool fallback for mail intent."
    );
    push_mail_connector_fallback_tools(tools);
}

pub(crate) fn inject_google_connector_tools_if_needed(tools: &mut Vec<LlmToolDefinition>) {
    if has_discovered_google_connector_tools(tools) {
        return;
    }
    push_google_connector_tools(tools);
}

pub(crate) fn push_service_tools(
    state: &dyn StateAccess,
    active_window_title: &str,
    tools: &mut Vec<LlmToolDefinition>,
) {
    // Dynamic Service Tools (On-Chain Services)
    if let Ok(iter) = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX) {
        for item in iter {
            if let Ok((_, val_bytes)) = item {
                if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&val_bytes) {
                    // Apply Context Filter
                    if let Some(pattern) = &meta.context_filter {
                        if let Ok(re) = Regex::new(pattern) {
                            if !re.is_match(active_window_title) {
                                log::debug!(
                                    "Filtering service {} (Context: '{}' != '{}')",
                                    meta.id,
                                    pattern,
                                    active_window_title
                                );
                                continue;
                            }
                        } else {
                            log::warn!(
                                "Invalid regex in service {} context_filter: {}",
                                meta.id,
                                pattern
                            );
                            continue;
                        }
                    }

                    for (method, perm) in &meta.methods {
                        if *perm == ioi_types::service_configs::MethodPermission::User {
                            let simple_name = method.split('@').next().unwrap_or(method);
                            if !should_expose_service_method_tool(&meta.id, simple_name) {
                                continue;
                            }
                            let tool_name = format!("{}__{}", meta.id, simple_name);

                            let params_json = json!({
                                "type": "object",
                                "additionalProperties": true,
                                "description": "JSON object parameters for the service method"
                            });

                            tools.push(LlmToolDefinition {
                                name: tool_name,
                                description: format!(
                                    "Call method {} on service {}",
                                    simple_name, meta.id
                                ),
                                parameters: params_json.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        CapabilityId, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition,
        ResolvedIntentState,
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
        push_service_tools(&namespaced, "Autopilot Studio", &mut tools);

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
        push_service_tools(&namespaced, "Autopilot Studio", &mut tools);

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
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "medium".to_string(),
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
}
