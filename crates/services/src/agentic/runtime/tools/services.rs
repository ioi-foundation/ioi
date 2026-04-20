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
#[path = "services/tests.rs"]
mod tests;
