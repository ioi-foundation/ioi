// Path: crates/services/src/agentic/desktop/tools.rs

use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{LlmToolDefinition}; 
use ioi_types::codec;
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use serde_json::json;
use ioi_scs::{SovereignContextStore, FrameType}; 
use ioi_types::app::agentic::AgentMacro; 
use std::sync::Arc;
use ioi_api::vm::inference::InferenceRuntime; 

/// Discovers tools available to the agent.
///
/// Uses semantic search for skills instead of full scan.
pub async fn discover_tools(
    state: &dyn StateAccess,
    scs: Option<&std::sync::Mutex<SovereignContextStore>>,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
) -> Vec<LlmToolDefinition> {
    let mut tools = Vec::new();
    
    // 1. Dynamic Service Tools (On-Chain Services)
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

    // 2. Native Capabilities (Hardcoded for stability)

    let computer_params = json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "type", "key", "hotkey", 
                    "mouse_move", "left_click", "left_click_id", 
                    "left_click_drag", "drag_drop", 
                    "screenshot", "cursor_position"
                ],
                "description": "The specific action to perform."
            },
            "coordinate": {
                "type": "array",
                "items": { "type": "integer" },
                "minItems": 2,
                "maxItems": 2,
                "description": "(x, y) coordinates."
            },
            "from": {
                 "type": "array",
                 "items": { "type": "integer" },
                 "minItems": 2,
                 "maxItems": 2,
                 "description": "Start coordinates for drag_drop."
            },
            "to": {
                 "type": "array",
                 "items": { "type": "integer" },
                 "minItems": 2,
                 "maxItems": 2,
                 "description": "End coordinates for drag_drop."
            },
            "text": {
                "type": "string",
                "description": "Text to type or key name."
            },
            "keys": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Array of keys for hotkey chord (e.g. ['Control', 'c'])."
            },
            "id": {
                "type": "integer",
                "description": "The Set-of-Marks ID tag to click. Required for left_click_id."
            }
        },
        "required": ["action"]
    });

    tools.push(LlmToolDefinition {
        name: "computer".to_string(),
        description: "Control the computer (mouse/keyboard/hotkeys).".to_string(),
        parameters: computer_params.to_string(),
    });

    let chat_params = json!({
        "type": "object",
        "properties": {
            "message": { "type": "string", "description": "The response text to show to the user." }
        },
        "required": ["message"]
    });
    tools.push(LlmToolDefinition {
        name: "chat__reply".to_string(),
        description: "Send a text message or answer to the user. Use this for all conversation/replies.".to_string(),
        parameters: chat_params.to_string(),
    });

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
        description: "Click on UI element at coordinates (Legacy)".to_string(),
        parameters: gui_params.to_string(),
    });

    let gui_type_params = json!({
        "type": "object",
        "properties": {
            "text": { "type": "string" }
        },
        "required": ["text"]
    });
    tools.push(LlmToolDefinition {
        name: "gui__type".to_string(),
        description: "Type text (Legacy)".to_string(),
        parameters: gui_type_params.to_string(),
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
                "description": "The binary to execute (e.g., 'ls', 'netstat', 'ping', 'gnome-calculator', 'firefox')" 
            },
            "args": { 
                "type": "array", 
                "items": { "type": "string" },
                "description": "Arguments for the command" 
            },
            "detach": {
                "type": "boolean",
                "description": "Set to true if launching a GUI application or long-running process that should stay open. Default is false (waits 5s)."
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__exec".to_string(),
        description: "Execute a terminal command or launch an application on the local system. Use 'detach: true' for GUI apps (calculators, browsers) so they stay open.".to_string(),
        parameters: sys_params.to_string(),
    });

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

    let fs_read_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to read" }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__read_file".to_string(),
        description: "Read text content from a file.".to_string(),
        parameters: fs_read_params.to_string(),
    });

    let fs_ls_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Directory path to list" }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__list_directory".to_string(),
        description: "List files and directories at a given path.".to_string(),
        parameters: fs_ls_params.to_string(),
    });

    // 3. Skill Discovery via Semantic Search (O(log N))
    if let Some(store_mutex) = scs {
        // Generate embedding for the query (Goal + Context)
        if let Ok(query_vec) = runtime.embed_text(query).await {
            // Access Index
            let search_results = {
                if let Ok(store) = store_mutex.lock() {
                    if let Ok(index_arc) = store.get_vector_index() {
                        if let Ok(index) = index_arc.lock() {
                             if let Some(idx) = index.as_ref() {
                                 // Search top 5 relevant skills
                                 idx.search_hybrid(&query_vec, 5).unwrap_or_default()
                             } else { vec![] }
                        } else { vec![] }
                    } else { vec![] }
                } else { vec![] }
            };

            // Retrieve and Deserialize
            if !search_results.is_empty() {
                if let Ok(store) = store_mutex.lock() {
                     for (frame_id, distance, f_type, _) in search_results {
                         // Relevance threshold: 0.4 distance in cosine similarity (0.0 is exact match)
                         if f_type == FrameType::Skill && distance < 0.4 { 
                             if let Ok(payload) = store.read_frame_payload(frame_id) {
                                 if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(payload) {
                                     log::debug!("Injected relevant skill: {} (Dist: {:.2})", skill.definition.name, distance);
                                     tools.push(skill.definition);
                                 }
                             }
                         }
                     }
                }
            }
        } else {
             log::warn!("Failed to embed query for skill discovery. Skipping dynamic skills.");
        }
    }

    tools
}