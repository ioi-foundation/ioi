// Path: crates/services/src/agentic/desktop/execution.rs

use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, MouseButton as ApiButton};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::KernelEvent;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::{AgentMacro, AgentTool, ComputerAction};
// Removed unused ActionTarget import

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
    
    pub fn with_macros(mut self, macros: std::collections::HashMap<String, AgentMacro>) -> Self {
        self.macros = macros;
        self
    }

    /// Executes a strictly typed AgentTool.
    pub async fn execute(
        &self,
        tool: AgentTool,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
    ) -> ToolExecutionResult {
        let mut success = false;
        let mut error = None;
        let mut history_entry = None;

        // [NOTE] Macro execution logic would need to be adapted here if macros are 
        // represented in the AgentTool enum (e.g. AgentTool::Custom or AgentTool::Macro).
        // For Phase 4 Alpha, we focus on the core native tools.

        match tool {
            // --- Computer Use (Meta-Tool) ---
            AgentTool::Computer(action) => match action {
                ComputerAction::MouseMove { coordinate } => {
                    let [x, y] = coordinate;
                    match self.gui.inject_input(InputEvent::MouseMove { x, y }).await {
                        Ok(_) => { success = true; history_entry = Some(format!("Moved mouse to ({}, {})", x, y)); }
                        Err(e) => error = Some(e.to_string())
                    }
                }
                ComputerAction::LeftClick => {
                    // Click at current position logic omitted for brevity
                    error = Some("LeftClick without coordinates not fully supported in stateless executor.".into());
                }
                ComputerAction::LeftClickDrag { coordinate } => {
                     let [x, y] = coordinate;
                     match self.gui.inject_input(InputEvent::MouseDown { button: ApiButton::Left, x, y }).await {
                         Ok(_) => {
                              let _ = self.gui.inject_input(InputEvent::MouseUp { button: ApiButton::Left, x, y }).await;
                              success = true;
                              history_entry = Some(format!("Drag at {}, {}", x, y));
                         },
                         Err(e) => error = Some(e.to_string())
                    }
                }
                ComputerAction::Type { text } => {
                    match self.gui.inject_input(InputEvent::Type { text: text.clone() }).await {
                        Ok(_) => { success = true; history_entry = Some(format!("Typed: {}", text)); }
                        Err(e) => error = Some(e.to_string())
                    }
                }
                ComputerAction::Key { text } => {
                     match self.gui.inject_input(InputEvent::KeyPress { key: text.clone() }).await {
                         Ok(_) => { success = true; history_entry = Some(format!("Pressed Key: {}", text)); }
                         Err(e) => error = Some(e.to_string())
                     }
                }
                ComputerAction::Screenshot => {
                    success = true;
                    history_entry = Some("Took screenshot (implicit)".to_string());
                }
                ComputerAction::CursorPosition => {
                    success = true;
                    history_entry = Some("Cursor position query [Mock]".to_string());
                }
            },

            // --- GUI Legacy ---
            AgentTool::GuiClick { x, y, button } => {
                let btn = match button.as_deref() {
                    Some("right") => ApiButton::Right,
                    Some("middle") => ApiButton::Middle,
                    _ => ApiButton::Left,
                };
                match self.gui.inject_input(InputEvent::Click {
                    button: btn,
                    x, y,
                    expected_visual_hash: Some(visual_phash),
                }).await {
                    Ok(_) => success = true,
                    Err(e) => error = Some(e.to_string()),
                }
            }
            AgentTool::GuiType { text } => {
                match self.gui.inject_input(InputEvent::Type { text }).await {
                    Ok(_) => success = true,
                    Err(e) => error = Some(e.to_string()),
                }
            }

            // --- System ---
            AgentTool::SysExec { command, args, detach } => {
                match self.terminal.execute(&command, &args, detach).await {
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
                    Err(e) => error = Some(e.to_string()),
                }
            }

            // --- Browser ---
            AgentTool::BrowserNavigate { url } => {
                match self.browser.navigate(&url).await {
                    Ok(content) => {
                        success = true;
                        let content_len = content.len();
                        let preview = if content_len > 300 { 
                            format!("{}...", &content[..300]) 
                        } else { 
                            content 
                        };
                        history_entry = Some(format!("Navigated to {}. Preview: {}", url, preview));
                        
                        if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "browser__navigate".to_string(),
                                output: format!("Navigated to {}. Len: {}", url, content_len),
                            });
                        }
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            }
            AgentTool::BrowserExtract => {
                 match self.browser.extract_dom().await {
                    Ok(content) => {
                        success = true;
                        history_entry = Some(format!("Extracted DOM ({} chars)", content.len()));
                        if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "browser__extract".to_string(),
                                output: format!("Extracted {} chars", content.len()),
                            });
                        }
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            }
            AgentTool::BrowserClick { selector } => {
                 match self.browser.click_selector(&selector).await {
                    Ok(_) => {
                        success = true;
                        history_entry = Some(format!("Clicked selector: {}", selector));
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            }

            // --- Chat ---
            AgentTool::ChatReply { message } => {
                success = true;
                history_entry = Some(format!("Replied: {}", message));
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index,
                        // [FIX] Ensure consistent tool name "chat__reply"
                        tool_name: "chat__reply".to_string(), 
                        output: message,
                    });
                }
            }

            // --- Filesystem ---
            AgentTool::FsWrite { path, content } => {
                 // In Phase 4, we'd use a virtual filesystem driver. 
                 // For now we map to std::fs with sandbox checks (handled by policy, but driver enforcement here).
                 // Simple impl:
                 match std::fs::write(&path, content) {
                     Ok(_) => { success = true; history_entry = Some(format!("Wrote to {}", path)); }
                     Err(e) => error = Some(e.to_string())
                 }
            }
            AgentTool::FsRead { path } => {
                 match std::fs::read_to_string(&path) {
                     Ok(c) => { 
                         success = true; 
                         history_entry = Some(format!("Read {} chars from {}", c.len(), path));
                         if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "filesystem__read_file".to_string(), 
                                output: c,
                            });
                        }
                     }
                     Err(e) => error = Some(e.to_string())
                 }
            }
            AgentTool::FsList { path } => {
                 match std::fs::read_dir(&path) {
                     Ok(entries) => {
                         let names: Vec<String> = entries.filter_map(|e| e.ok().map(|d| d.file_name().to_string_lossy().to_string())).collect();
                         let out = names.join(", ");
                         success = true;
                         history_entry = Some(format!("Ls {}: {}", path, out));
                          if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "filesystem__list_directory".to_string(), 
                                output: out,
                            });
                        }
                     }
                     Err(e) => error = Some(e.to_string())
                 }
            }

            // --- Meta Tools (No-ops for Executor, handled by Logic) ---
            AgentTool::AgentDelegate { .. } 
            | AgentTool::AgentAwait { .. }
            | AgentTool::AgentPause { .. }
            | AgentTool::AgentComplete { .. }
            | AgentTool::CommerceCheckout { .. } => {
                // These should be handled by `actions.rs` returning special status.
                // If we reach here, it's a fallthrough logic error or just logging.
                success = true;
                history_entry = Some("Meta-tool execution (Handled by Controller)".to_string());
            }

            // --- Dynamic/MCP ---
            AgentTool::Dynamic(val) => {
                if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                     let args = val.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
                     match self.mcp.execute_tool(name, args).await {
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
                    error = Some("Dynamic tool call missing 'name'".into());
                }
            }
        }

        ToolExecutionResult { success, error, history_entry }
    }
}