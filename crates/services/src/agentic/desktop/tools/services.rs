use ioi_api::state::StateAccess;
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::codec;
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use regex::Regex;
use serde_json::json;

fn should_expose_service_method_tool(service_id: &str, simple_name: &str) -> bool {
    if service_id.eq_ignore_ascii_case("wallet_network")
        && simple_name.starts_with("mail_connector_")
    {
        return false;
    }
    true
}

pub(super) fn push_service_tools(
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
                                "properties": {
                                    "params": { "type": "string", "description": "JSON encoded parameters" }
                                }
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
