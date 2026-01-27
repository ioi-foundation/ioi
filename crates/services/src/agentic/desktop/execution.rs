// Path: crates/services/src/agentic/desktop/execution.rs

use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, MouseButton as ApiButton};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::KernelEvent;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentMacro; // [NEW] Import Macro Type
use ioi_types::app::ActionRequest;
use ioi_types::app::ActionTarget;

pub struct ToolExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub history_entry: Option<String>,
}

pub struct ToolExecutor {
    gui: Arc<dyn GuiDriver>,
    terminal: Arc<TerminalDriver>,
    browser: Arc<BrowserDriver>,
    mcp: Arc<McpManager>, 
    event_sender: Option<Sender<KernelEvent>>,
    // [NEW] Cache of learned macros, populated by discover_tools/service
    macros: std::collections::HashMap<String, AgentMacro>, 
}

impl ToolExecutor {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        mcp: Arc<McpManager>,
        event_sender: Option<Sender<KernelEvent>>,
    ) -> Self {
        Self {
            gui,
            terminal,
            browser,
            mcp,
            event_sender,
            macros: std::collections::HashMap::new(),
        }
    }
    
    // [NEW] Method to hydrate known macros
    pub fn with_macros(mut self, macros: std::collections::HashMap<String, AgentMacro>) -> Self {
        self.macros = macros;
        self
    }

    /// Helper to safely extract arguments regardless of whether they are under "arguments" or "parameters"
    fn get_args<'a>(&self, tool_call: &'a Value) -> &'a Value {
        if tool_call.get("arguments").is_some() {
            &tool_call["arguments"]
        } else if tool_call.get("parameters").is_some() {
            &tool_call["parameters"]
        } else {
            // Fallback: assume the tool_call itself might be the args if flattened (unlikely but safe default)
            tool_call
        }
    }
    
    /// Helper: Interpolate macro templates like "{{username}}" with actual values
    fn interpolate_params(&self, template_bytes: &[u8], args: &Value) -> Vec<u8> {
        // Simple string replacement for MVP. Production needs robust JSON template engine.
        if let Ok(template_str) = String::from_utf8(template_bytes.to_vec()) {
            let mut result = template_str;
            if let Some(arg_map) = args.as_object() {
                for (k, v) in arg_map {
                    let placeholder = format!("{{{{{}}}}}", k); // {{key}}
                    let replacement = if let Some(s) = v.as_str() { s.to_string() } else { v.to_string() };
                    result = result.replace(&placeholder, &replacement);
                }
            }
            return result.into_bytes();
        }
        template_bytes.to_vec()
    }

    pub async fn execute(
        &self,
        name: &str,
        tool_call: &Value,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
    ) -> ToolExecutionResult {
        let mut success = false;
        let mut error = None;
        let mut history_entry = None;

        let args = self.get_args(tool_call);
        
        // [NEW] Check for Macro Execution (Learned Skill)
        if let Some(skill_macro) = self.macros.get(name) {
            log::info!("Executing Learned Skill: {}", name);
            
            // Execute the macro steps sequentially
            // For MVP, we treat this as an atomic block. 
            // In full implementation, we might want to yield or check visual state between steps.
            for (i, step) in skill_macro.steps.iter().enumerate() {
                // Interpolate params with current args
                let final_params = self.interpolate_params(&step.params, args);
                
                // Recursively execute the atomic action
                // Note: We map the ActionTarget back to our tool names or driver calls.
                // Since this executor handles tool names, we need to map internal targets to logic.
                
                let step_res = match &step.target {
                    ActionTarget::GuiClick => {
                        // Deserialize params to get x,y
                        if let Ok(p) = serde_json::from_slice::<Value>(&final_params) {
                             let x = p["x"].as_u64().unwrap_or(0) as u32;
                             let y = p["y"].as_u64().unwrap_or(0) as u32;
                             self.gui.inject_input(InputEvent::Click {
                                button: ApiButton::Left,
                                x, y,
                                expected_visual_hash: None // Macros trust their sequence usually, or we could pass visual_phash if relevant
                             }).await.map_err(|e| e.to_string())
                        } else {
                            Err("Invalid macro params".to_string())
                        }
                    },
                    ActionTarget::GuiType => {
                         if let Ok(p) = serde_json::from_slice::<Value>(&final_params) {
                             let text = p["text"].as_str().unwrap_or("").to_string();
                             self.gui.inject_input(InputEvent::Type { text }).await.map_err(|e| e.to_string())
                         } else {
                            Err("Invalid macro params".to_string())
                         }
                    },
                    ActionTarget::BrowserNavigate => {
                         if let Ok(p) = serde_json::from_slice::<Value>(&final_params) {
                             let url = p["url"].as_str().unwrap_or("").to_string();
                             self.browser.navigate(&url).await.map(|_| ()).map_err(|e| e.to_string())
                         } else {
                            Err("Invalid macro params".to_string())
                         }
                    },
                    _ => Err(format!("Unsupported macro action target: {:?}", step.target))
                };

                if let Err(e) = step_res {
                    return ToolExecutionResult {
                        success: false,
                        error: Some(format!("Macro step {} failed: {}", i, e)),
                        history_entry: Some(format!("Macro '{}' failed at step {}", name, i))
                    };
                }
            }
            
            return ToolExecutionResult {
                success: true,
                error: None,
                history_entry: Some(format!("Executed learned skill: {}", name))
            };
        }

        match name {
            // [NEW] "Computer Use" Tool Handler (Claude 3.5 Sonnet Compatible)
            "computer" => {
                let action = args["action"].as_str().unwrap_or("");
                let text = args["text"].as_str();
                
                // Extract coordinates if present
                let (x, y) = if let Some(coords) = args["coordinate"].as_array() {
                    if coords.len() >= 2 {
                        (coords[0].as_u64().unwrap_or(0) as u32, coords[1].as_u64().unwrap_or(0) as u32)
                    } else { (0, 0) }
                } else { (0, 0) };

                match action {
                    "mouse_move" => {
                        match self.gui.inject_input(InputEvent::MouseMove { x, y }).await {
                            Ok(_) => { success = true; history_entry = Some(format!("Moved mouse to ({}, {})", x, y)); }
                            Err(e) => error = Some(e.to_string())
                        }
                    }
                    "left_click" => {
                        // Move then click (robustness)
                        let move_res = self.gui.inject_input(InputEvent::MouseMove { x, y }).await;
                        let click_res = self.gui.inject_input(InputEvent::Click {
                            button: ApiButton::Left,
                            x, y,
                            expected_visual_hash: Some(visual_phash)
                        }).await;
                        
                        if move_res.is_ok() && click_res.is_ok() {
                             success = true;
                             history_entry = Some(format!("Left Click at ({}, {})", x, y));
                        } else {
                             error = Some("Failed to move or click".to_string());
                        }
                    }
                    "left_click_drag" => {
                        // Implementing drag via MouseDown/MouseUp events
                        match self.gui.inject_input(InputEvent::MouseDown { button: ApiButton::Left, x, y }).await {
                             Ok(_) => {
                                  // For MVP safety, we immediately release to prevent stuck drags if next command fails.
                                  // Real implementation would wait for next move command.
                                  let _ = self.gui.inject_input(InputEvent::MouseUp { button: ApiButton::Left, x, y }).await;
                                  success = true;
                                  history_entry = Some(format!("Drag (Simulated Click) at {}, {}", x, y));
                             },
                             Err(e) => error = Some(e.to_string())
                        }
                    }
                    "type" => {
                        if let Some(t) = text {
                            match self.gui.inject_input(InputEvent::Type { text: t.to_string() }).await {
                                Ok(_) => { success = true; history_entry = Some(format!("Typed: {}", t)); }
                                Err(e) => error = Some(e.to_string())
                            }
                        } else {
                            error = Some("Missing 'text' argument for type action".to_string());
                        }
                    }
                    "key" => {
                         if let Some(k) = text {
                             match self.gui.inject_input(InputEvent::KeyPress { key: k.to_string() }).await {
                                 Ok(_) => { success = true; history_entry = Some(format!("Pressed Key: {}", k)); }
                                 Err(e) => error = Some(e.to_string())
                             }
                         } else {
                             error = Some("Missing 'text' (key) argument".to_string());
                         }
                    }
                    "screenshot" => {
                        success = true;
                        history_entry = Some("Took screenshot (implicit)".to_string());
                    }
                    "cursor_position" => {
                        success = true;
                        history_entry = Some("Cursor position: (960, 540) [Mock]".to_string());
                    }
                    _ => error = Some(format!("Unknown computer action: {}", action))
                }
            }
            "gui__click" => {
                let x = args["x"].as_u64().unwrap_or(0) as u32;
                let y = args["y"].as_u64().unwrap_or(0) as u32;
                match self.gui.inject_input(InputEvent::Click {
                    button: ApiButton::Left,
                    x,
                    y,
                    expected_visual_hash: Some(visual_phash),
                }).await {
                    Ok(_) => success = true,
                    Err(e) => error = Some(e.to_string()),
                }
            }
            "sys__exec" => {
                let cmd = args["command"].as_str().unwrap_or("");
                let cmd_args: Vec<String> = args["args"]
                    .as_array()
                    .map(|arr| arr.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
                    .unwrap_or_default();

                let detach = args["detach"].as_bool().unwrap_or(false);

                if cmd.is_empty() {
                    error = Some("Command is empty. Check if LLM output 'arguments' or 'parameters' key.".to_string());
                } else {
                    match self.terminal.execute(cmd, &cmd_args, detach).await {
                        Ok(output) => {
                            success = true;
                            let safe_output: String = if output.len() > 1000 {
                                format!("{}... (truncated)", &output[..1000])
                            } else {
                                output
                            };
                            history_entry = Some(format!("System Output: {}", safe_output));

                            if let Some(tx) = &self.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id,
                                    step_index,
                                    tool_name: "sys__exec".to_string(),
                                    output: safe_output,
                                });
                            }
                        }
                        Err(e) => {
                            error = Some(e.to_string());
                        }
                    }
                }
            }
            "browser__navigate" => {
                let url = args["url"].as_str().unwrap_or("");
                if url.is_empty() {
                    error = Some("URL argument is missing".to_string());
                } else {
                    match self.browser.navigate(url).await {
                        Ok(content) => {
                            success = true;
                            let content_len = content.len();
                            let preview = if content_len > 300 { 
                                format!("{}...", &content[..300]) 
                            } else { 
                                content.clone() 
                            };
                            history_entry = Some(format!("Browser: Navigated to {} ({} chars). Preview: {}", url, content_len, preview));
                            
                            if let Some(tx) = &self.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id,
                                    step_index,
                                    tool_name: "browser__navigate".to_string(),
                                    output: format!("Navigated to {}. Content len: {}", url, content_len),
                                });
                            }
                        }
                        Err(e) => error = Some(format!("Browser navigation failed: {}", e)),
                    }
                }
            }
            "browser__extract" => {
                match self.browser.extract_dom().await {
                    Ok(content) => {
                        success = true;
                        let content_len = content.len();
                        let preview = if content_len > 300 { 
                            format!("{}...", &content[..300]) 
                        } else { 
                            content.clone() 
                        };
                        history_entry = Some(format!("Browser: Extracted DOM. Preview: {}", preview));

                        if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "browser__extract".to_string(),
                                output: format!("Extracted DOM ({} chars)", content_len),
                            });
                        }
                    }
                    Err(e) => error = Some(format!("Browser extraction failed: {}", e)),
                }
            }
            "browser__click" => {
                let selector = args["selector"].as_str().unwrap_or("");
                if selector.is_empty() {
                    error = Some("Selector argument is missing".to_string());
                } else {
                    match self.browser.click_selector(selector).await {
                        Ok(_) => {
                            success = true;
                            history_entry = Some(format!("Clicked element: {}", selector));

                            if let Some(tx) = &self.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id,
                                    step_index,
                                    tool_name: "browser__click".to_string(),
                                    output: format!("Clicked: {}", selector),
                                });
                            }
                        }
                        Err(e) => error = Some(format!("Click failed: {}", e)),
                    }
                }
            }
            "chat__reply" => {
                let msg = args["message"].as_str().unwrap_or("...");
                success = true;
                history_entry = Some(format!("Replied: {}", msg));
                
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index,
                        tool_name: "chat::reply".to_string(), 
                        output: msg.to_string(),
                    });
                }
            }
            _ => {
                // MCP Fallback for unknown tools
                if name.contains("__") {
                    let mcp_args = args.clone();
                    match self.mcp.execute_tool(name, mcp_args).await {
                        Ok(output) => {
                            success = true;
                            let preview = if output.len() > 300 {
                                format!("{}...", &output[..300])
                            } else {
                                output.clone()
                            };
                            
                            history_entry = Some(format!("Tool '{}' executed via MCP. Output: {}", name, preview));
                            
                            if let Some(tx) = &self.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id,
                                    step_index,
                                    tool_name: name.to_string(),
                                    output,
                                });
                            }
                        },
                        Err(e) => {
                            error = Some(format!("MCP Execution Failed: {}", e));
                        }
                    }
                } else {
                    success = true; 
                }
            }
        }

        ToolExecutionResult { success, error, history_entry }
    }
}