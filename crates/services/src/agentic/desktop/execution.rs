// Path: crates/services/src/agentic/desktop/execution.rs

use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, AtomicInput, MouseButton as ApiButton};
use ioi_drivers::browser::{BrowserDriver, BrowserError}; 
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::KernelEvent;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;
use std::time::Duration;
use std::thread;

use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::{AgentMacro, AgentTool, ComputerAction};

/// Helper to safely truncate strings by character count (not bytes) to avoid UTF-8 panics.
fn safe_truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        result.push_str("...");
    }
    result
}

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

        match tool {
            // --- Computer Use (Meta-Tool) ---
            AgentTool::Computer(action) => match action {
                ComputerAction::LeftClickId { id } => {
                    match self.gui.get_element_center(id).await {
                        Ok(Some((x, y))) => {
                            match self.gui.inject_input(InputEvent::MouseMove { x, y }).await {
                                Ok(_) => {
                                    match self.gui.inject_input(InputEvent::Click { 
                                        button: ApiButton::Left, x, y, expected_visual_hash: Some(visual_phash) 
                                    }).await {
                                        Ok(_) => {
                                            success = true;
                                            history_entry = Some(format!("Clicked Element ID #{} at ({}, {})", id, x, y));
                                        },
                                        Err(e) => error = Some(format!("Click failed: {}", e))
                                    }
                                },
                                Err(e) => error = Some(format!("Approach move failed: {}", e))
                            }
                        },
                        Ok(None) => error = Some(format!("Element ID {} not found in current visual state (Cache miss). Screen may have changed.", id)),
                        Err(e) => error = Some(format!("Failed to resolve element ID: {}", e))
                    }
                },
                ComputerAction::MouseMove { coordinate } => {
                    let [x, y] = coordinate;
                    match self.gui.inject_input(InputEvent::MouseMove { x, y }).await {
                        Ok(_) => { success = true; history_entry = Some(format!("Moved mouse to ({}, {})", x, y)); }
                        Err(e) => error = Some(e.to_string())
                    }
                },
                
                ComputerAction::LeftClick { coordinate } => {
                    if let Some([x, y]) = coordinate {
                        match self.gui.inject_input(InputEvent::MouseMove { x, y }).await {
                            Ok(_) => {
                                match self.gui.inject_input(InputEvent::Click { 
                                    button: ApiButton::Left, x, y, expected_visual_hash: Some(visual_phash) 
                                }).await {
                                    Ok(_) => { success = true; history_entry = Some(format!("Clicked at ({}, {})", x, y)); }
                                    Err(e) => error = Some(e.to_string())
                                }
                            },
                            Err(e) => error = Some(format!("Failed to move to coords: {}", e))
                        }
                    } else {
                        error = Some("Stateless execution requires explicit coordinates for 'left_click'.".into());
                    }
                },
                
                ComputerAction::LeftClickDrag { coordinate } => {
                     let [x, y] = coordinate;
                     
                     let sequence = vec![
                         AtomicInput::MouseDown { button: ApiButton::Left },
                         AtomicInput::Wait { millis: 50 }, 
                         AtomicInput::MouseMove { x, y },
                         AtomicInput::Wait { millis: 50 }, 
                         AtomicInput::MouseUp { button: ApiButton::Left },
                     ];

                     match self.gui.inject_input(InputEvent::AtomicSequence(sequence)).await {
                         Ok(_) => {
                              success = true;
                              history_entry = Some(format!("Dragged to ({}, {})", x, y));
                         },
                         Err(e) => error = Some(e.to_string())
                    }
                },

                ComputerAction::Hotkey { keys } => {
                    if keys.is_empty() {
                         error = Some("Hotkey requires at least one key".into());
                    } else {
                        let mut sequence = Vec::new();
                        let (action_key, modifiers) = keys.split_last().unwrap();
                        
                        for k in modifiers {
                            sequence.push(AtomicInput::KeyDown { key: k.clone() });
                        }
                        
                        sequence.push(AtomicInput::KeyPress { key: action_key.clone() });
                        
                        for k in modifiers.iter().rev() {
                            sequence.push(AtomicInput::KeyUp { key: k.clone() });
                        }

                        match self.gui.inject_input(InputEvent::AtomicSequence(sequence)).await {
                            Ok(_) => { 
                                success = true; 
                                history_entry = Some(format!("Executed Hotkey: {}", keys.join("+"))); 
                            },
                            Err(e) => error = Some(e.to_string())
                        }
                    }
                },

                ComputerAction::DragDrop { from, to } => {
                     let [x1, y1] = from;
                     let [x2, y2] = to;
                     
                     let sequence = vec![
                         AtomicInput::MouseMove { x: x1, y: y1 },
                         AtomicInput::Wait { millis: 50 },
                         AtomicInput::MouseDown { button: ApiButton::Left },
                         AtomicInput::Wait { millis: 100 }, 
                         AtomicInput::MouseMove { x: x2, y: y2 },
                         AtomicInput::Wait { millis: 100 }, 
                         AtomicInput::MouseUp { button: ApiButton::Left },
                     ];

                     match self.gui.inject_input(InputEvent::AtomicSequence(sequence)).await {
                         Ok(_) => {
                              success = true;
                              history_entry = Some(format!("DragDrop from ({},{}) to ({},{})", x1, y1, x2, y2));
                         },
                         Err(e) => error = Some(e.to_string())
                    }
                },
                
                ComputerAction::Type { text } => {
                    match self.gui.inject_input(InputEvent::Type { text: text.clone() }).await {
                        Ok(_) => { success = true; history_entry = Some(format!("Typed: {}", text)); }
                        Err(e) => error = Some(e.to_string())
                    }
                },
                ComputerAction::Key { text } => {
                     match self.gui.inject_input(InputEvent::KeyPress { key: text.clone() }).await {
                         Ok(_) => { success = true; history_entry = Some(format!("Pressed Key: {}", text)); }
                         Err(e) => error = Some(e.to_string())
                     }
                },
                ComputerAction::Screenshot => {
                    success = true;
                    history_entry = Some("Took screenshot (implicit)".to_string());
                },
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
            },
            AgentTool::GuiType { text } => {
                match self.gui.inject_input(InputEvent::Type { text }).await {
                    Ok(_) => success = true,
                    Err(e) => error = Some(e.to_string()),
                }
            },

            // --- System ---
            AgentTool::SysExec { command, args, detach } => {
                // [FIX] Robust Action-Layer Guard for Browser Launch
                // Check command base name AND arguments for browser tokens
                let cmd_lower = std::path::Path::new(&command)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&command)
                    .to_lowercase();
                
                let mut tokens = vec![cmd_lower];
                tokens.extend(args.iter().take(3).map(|a| a.to_lowercase()));
                
                let is_browser = tokens.iter().any(|t| matches!(t.as_str(),
                    "firefox" | "firefox-bin" | "chrome" | "google-chrome" |
                    "chromium" | "chromium-browser" | "brave" | "msedge"
                ));

                if is_browser {
                     let msg = format!("Policy Violation: Do not launch '{}' manually. Use 'browser__navigate' instead.", command);
                     error = Some(msg.clone());
                     history_entry = Some(msg.clone());
                     
                     // [FIX] Emit event so UI shows the rejection
                     if let Some(tx) = &self.event_sender {
                        let _ = tx.send(KernelEvent::AgentActionResult {
                            session_id,
                            step_index,
                            tool_name: "sys__exec".to_string(),
                            output: msg,
                        });
                    }
                } else {
                    match self.terminal.execute(&command, &args, detach).await {
                        Ok(output) => {
                            success = true;
                            let safe_output = safe_truncate(&output, 1000);
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
            },

            // --- Browser ---
            AgentTool::BrowserNavigate { url } => {
                match self.browser.navigate(&url).await {
                    Ok(content) => {
                        success = true;
                        let preview = safe_truncate(&content, 300);
                        history_entry = Some(format!("Navigated to {}. Preview: {}", url, preview));
                        
                        if let Some(tx) = &self.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index,
                                tool_name: "browser__navigate".to_string(),
                                output: format!("Navigated to {}. Len: {}", url, content.len()),
                            });
                        }
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            },
            
            AgentTool::BrowserExtract {} => {
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
                    Err(BrowserError::NoActivePage) => {
                        match self.browser.navigate("about:blank").await {
                            Ok(_) => match self.browser.extract_dom().await {
                                Ok(content) => {
                                    success = true;
                                    history_entry = Some(format!(
                                        "Auto-repaired (opened about:blank), then extracted DOM ({} chars)",
                                        content.len()
                                    ));
                                    
                                    if let Some(tx) = &self.event_sender {
                                        let _ = tx.send(KernelEvent::AgentActionResult {
                                            session_id,
                                            step_index,
                                            tool_name: "browser__extract".to_string(),
                                            output: format!("Auto-repaired (opened about:blank). Extracted {} chars", content.len()),
                                        });
                                    }
                                }
                                Err(e2) => {
                                    error = Some(format!("BrowserExtract failed after auto-repair: {}", e2));
                                }
                            },
                            Err(e_nav) => {
                                error = Some(format!("Auto-repair failed to open about:blank: {}", e_nav));
                            }
                        }
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            },
            
            AgentTool::BrowserClick { selector } => {
                 match self.browser.click_selector(&selector).await {
                    Ok(_) => {
                        success = true;
                        history_entry = Some(format!("Clicked selector: {}", selector));
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            },

            // [FIX] Synthetic Click (Level 2) logic
            AgentTool::Dynamic(val) if val.get("name").and_then(|n| n.as_str()) == Some("browser__synthetic_click") => {
                if let Some(args) = val.get("arguments") {
                    let x = args.get("x").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    let y = args.get("y").and_then(|n| n.as_f64()).unwrap_or(0.0);
                    
                    match self.browser.synthetic_click(x, y).await {
                        Ok(_) => {
                            success = true;
                            history_entry = Some(format!("Background clicked at ({}, {})", x, y));
                        },
                        Err(e) => error = Some(format!("Synthetic click failed: {}", e))
                    }
                } else {
                    error = Some("Missing arguments for browser__synthetic_click".into());
                }
            },

            AgentTool::ChatReply { message } => {
                success = true;
                history_entry = Some(format!("Replied: {}", message));
                if let Some(tx) = &self.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index,
                        tool_name: "chat__reply".to_string(), 
                        output: message,
                    });
                }
            },

            AgentTool::FsWrite { path, content } => {
                 match std::fs::write(&path, content) {
                     Ok(_) => { success = true; history_entry = Some(format!("Wrote to {}", path)); }
                     Err(e) => error = Some(e.to_string())
                 }
            },

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
            },

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
            },
            
            // --- Dynamic/MCP ---
            AgentTool::Dynamic(val) => {
                if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                     let args = val.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
                     match self.mcp.execute_tool(name, args).await {
                        Ok(output) => {
                            success = true;
                            let preview = safe_truncate(&output, 300);
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
            },
            
            _ => { 
                // Meta tools handled by controller
                success = true;
                history_entry = Some("Meta-tool execution (Handled by Controller)".to_string());
            }
        }

        ToolExecutionResult { success, error, history_entry }
    }
}