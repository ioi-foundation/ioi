// Path: crates/services/src/agentic/desktop/execution.rs

// [FIX] Removed unused import
// use anyhow::anyhow;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, MouseButton as ApiButton};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::KernelEvent;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

use ioi_drivers::mcp::McpManager; // NEW IMPORT

pub struct ToolExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub history_entry: Option<String>,
}

pub struct ToolExecutor {
    gui: Arc<dyn GuiDriver>,
    terminal: Arc<TerminalDriver>,
    browser: Arc<BrowserDriver>,
    mcp: Arc<McpManager>, // NEW FIELD
    event_sender: Option<Sender<KernelEvent>>,
}

impl ToolExecutor {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        mcp: Arc<McpManager>, // NEW PARAMETER
        event_sender: Option<Sender<KernelEvent>>,
    ) -> Self {
        Self {
            gui,
            terminal,
            browser,
            mcp,
            event_sender,
        }
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

        match name {
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

                // [FIX] Parse detach flag (default false)
                let detach = args["detach"].as_bool().unwrap_or(false);

                if cmd.is_empty() {
                    error = Some("Command is empty. Check if LLM output 'arguments' or 'parameters' key.".to_string());
                } else {
                    // [FIX] Pass detach argument
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
            // --- NEW: Chat Tool Handler ---
            "chat__reply" => {
                let msg = args["message"].as_str().unwrap_or("...");
                success = true;
                history_entry = Some(format!("Replied: {}", msg));
                
                // Emit the specific event that the UI listens for to render chat bubbles
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index,
                        tool_name: "chat::reply".to_string(), // Canonical UI event name
                        output: msg.to_string(),
                    });
                }
            }
            // ------------------------------
            _ => {
                // MCP Fallback for unknown tools
                if name.contains("__") {
                    let mcp_args = args.clone();
                    match self.mcp.execute_tool(name, mcp_args).await {
                        Ok(output) => {
                            success = true;
                            // [FIX] Include output content in history log
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
                    // Fallback for non-driver tools (handled in main loop or unrecognized)
                    success = true; // Assume success if just logging thought
                }
            }
        }

        ToolExecutionResult { success, error, history_entry }
    }
}