use ioi_api::state::StateAccess;
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::codec;
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use serde_json::json;

pub fn discover_tools(state: &dyn StateAccess) -> Vec<LlmToolDefinition> {
    let mut tools = Vec::new();
    
    // 1. Dynamic Service Tools
    if let Ok(iter) = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX) {
        for item in iter {
            if let Ok((_, val_bytes)) = item {
                if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&val_bytes) {
                    for (method, perm) in &meta.methods {
                        if *perm == ioi_types::service_configs::MethodPermission::User {
                            let simple_name = method.split('@').next().unwrap_or(method);
                            let tool_name = format!("{}__{}", meta.id, simple_name);
                            let params_json = json!({
                                "type": "object",
                                "properties": {
                                    "params": { "type": "string", "description": "JSON encoded parameters" }
                                }
                            });
                            tools.push(LlmToolDefinition {
                                name: tool_name,
                                description: format!("Call method {} on service {}", simple_name, meta.id),
                                parameters: params_json.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // 2. Native Capabilities
    let nav_params = json!({
        "type": "object",
        "properties": {
            "url": { "type": "string", "description": "The URL to navigate to (must start with http/https)" }
        },
        "required": ["url"]
    });
    tools.push(LlmToolDefinition {
        name: "browser__navigate".to_string(),
        description: "Navigate the internal browser to a URL and return page content.".to_string(),
        parameters: nav_params.to_string(),
    });

    let extract_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "browser__extract".to_string(),
        description: "Extract the HTML content from the current browser page.".to_string(),
        parameters: extract_params.to_string(),
    });

    let click_selector_params = json!({
        "type": "object",
        "properties": {
            "selector": { "type": "string", "description": "CSS selector to click (e.g. '#login-button')" }
        },
        "required": ["selector"]
    });
    tools.push(LlmToolDefinition {
        name: "browser__click".to_string(),
        description: "Click an element on the current page using a CSS selector.".to_string(),
        parameters: click_selector_params.to_string(),
    });

    let gui_params = json!({
        "type": "object",
        "properties": {
            "x": { "type": "integer" },
            "y": { "type": "integer" },
            "button": { "type": "string", "enum": ["left", "right"] }
        },
        "required": ["x", "y"]
    });
    tools.push(LlmToolDefinition {
        name: "gui__click".to_string(),
        description: "Click on UI element at coordinates".to_string(),
        parameters: gui_params.to_string(),
    });

    let delegate_params = json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string" },
            "budget": { "type": "integer" }
        },
        "required": ["goal", "budget"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__delegate".to_string(),
        description: "Spawn a sub-agent to handle a specific subtask.".to_string(),
        parameters: delegate_params.to_string(),
    });

    let await_params = json!({
        "type": "object",
        "properties": {
            "child_session_id_hex": { "type": "string" }
        },
        "required": ["child_session_id_hex"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__await_result".to_string(),
        description: "Check if a child agent has completed its task. Returns 'Running' if not finished.".to_string(),
        parameters: await_params.to_string(),
    });

    let pause_params = json!({
        "type": "object",
        "properties": {
            "reason": { "type": "string" }
        },
        "required": ["reason"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__pause".to_string(),
        description: "Pause execution to wait for user input or long-running tasks.".to_string(),
        parameters: pause_params.to_string(),
    });

    let complete_params = json!({
        "type": "object",
        "properties": {
            "result": { "type": "string", "description": "The final result or summary of the completed task." }
        },
        "required": ["result"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__complete".to_string(),
        description: "Call this when you have successfully achieved the goal to finish the session.".to_string(),
        parameters: complete_params.to_string(),
    });

    let checkout_params = json!({
        "type": "object",
        "properties": {
            "merchant_url": { "type": "string" },
            "items": { 
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "quantity": { "type": "integer" }
                    }
                }
            },
            "total_amount": { "type": "number", "description": "Total amount to authorize" },
            "currency": { "type": "string" },
            "buyer_email": { "type": "string" }
        },
        "required": ["merchant_url", "items", "total_amount", "currency"]
    });
    tools.push(LlmToolDefinition {
        name: "commerce__checkout".to_string(),
        description: "Purchase items from a UCP-compatible merchant using secure payment injection.".to_string(),
        parameters: checkout_params.to_string(),
    });

    let sys_params = json!({
        "type": "object",
        "properties": {
            "command": { 
                "type": "string", 
                "description": "The binary to execute (e.g., 'ls', 'netstat', 'ping')" 
            },
            "args": { 
                "type": "array", 
                "items": { "type": "string" },
                "description": "Arguments for the command" 
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__exec".to_string(),
        description: "Execute a terminal command on the local system and return the output.".to_string(),
        parameters: sys_params.to_string(),
    });

    // [NEW] Filesystem Write
    let fs_write_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to write the file to" },
            "content": { "type": "string", "description": "Text content to write" }
        },
        "required": ["path", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__write_file".to_string(),
        description: "Write text content to a file on the local filesystem. Use this to save data.".to_string(),
        parameters: fs_write_params.to_string(),
    });

    tools
}