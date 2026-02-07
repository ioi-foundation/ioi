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
            AgentTool::Computer(action) => match action {
                ComputerAction::LeftClickId { id } => {
                    match self.gui.get_element_center(id).await {
                        Ok(Some((x, y))) => {
                            // Atomic approach: Move then Click
                            let seq = vec![
                                AtomicInput::MouseMove { x, y },
                                AtomicInput::Wait { millis: 50 },
                                AtomicInput::MouseDown { button: ApiButton::Left },
                                AtomicInput::MouseUp { button: ApiButton::Left }
                            ];
                            match self.gui.inject_input(InputEvent::AtomicSequence(seq)).await {
                                Ok(_) => {
                                    success = true;
                                    history_entry = Some(format!("Clicked Element ID #{} at ({}, {})", id, x, y));
                                },
                                Err(e) => error = Some(format!("Click failed: {}", e))
                            }
                        },
                        Ok(None) => error = Some(format!("Element ID {} not found in visual cache.", id)),
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
                         let seq = vec![
                            AtomicInput::MouseMove { x, y },
                            AtomicInput::Wait { millis: 50 },
                            AtomicInput::MouseDown { button: ApiButton::Left },
                            AtomicInput::MouseUp { button: ApiButton::Left }
                        ];
                        match self.gui.inject_input(InputEvent::AtomicSequence(seq)).await {
                            Ok(_) => { success = true; history_entry = Some(format!("Clicked at ({}, {})", x, y)); }
                            Err(e) => error = Some(e.to_string())
                        }
                    } else {
                        error = Some("Stateless execution requires explicit coordinates.".into());
                    }
                },
                
                // [NEW] Drag & Drop using Atomic Sequence
                ComputerAction::LeftClickDrag { coordinate } => {
                     let [x, y] = coordinate;
                     let sequence = vec![
                         AtomicInput::MouseDown { button: ApiButton::Left },
                         AtomicInput::Wait { millis: 100 }, 
                         AtomicInput::MouseMove { x, y },
                         AtomicInput::Wait { millis: 100 }, 
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

                ComputerAction::DragDrop { from, to } => {
                     let [x1, y1] = from;
                     let [x2, y2] = to;
                     let sequence = vec![
                         AtomicInput::MouseMove { x: x1, y: y1 },
                         AtomicInput::Wait { millis: 100 },
                         AtomicInput::MouseDown { button: ApiButton::Left },
                         AtomicInput::Wait { millis: 200 }, // Hold to grab
                         AtomicInput::MouseMove { x: x2, y: y2 },
                         AtomicInput::Wait { millis: 200 }, // Hold to settle
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

                // [NEW] Hotkeys using Atomic Sequence (KeyDown -> KeyPress -> KeyUp)
                ComputerAction::Hotkey { keys } => {
                    if keys.is_empty() {
                         error = Some("Hotkey requires at least one key".into());
                    } else {
                        let mut sequence = Vec::new();
                        let (action_key, modifiers) = keys.split_last().unwrap();
                        
                        // Press modifiers
                        for k in modifiers {
                            sequence.push(AtomicInput::KeyDown { key: k.clone() });
                        }
                        
                        // Click action key
                        sequence.push(AtomicInput::KeyPress { key: action_key.clone() });
                        
                        // Release modifiers in reverse
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
                    history_entry = Some("Took screenshot".to_string());
                },
                ComputerAction::CursorPosition => {
                    success = true;
                    history_entry = Some("Cursor position query [Mock]".to_string());
                }
            },
            
            // Legacy tools...
            AgentTool::GuiClick { x, y, button } => {
                let btn = match button.as_deref() {
                    Some("right") => ApiButton::Right,
                    Some("middle") => ApiButton::Middle,
                    _ => ApiButton::Left,
                };
                match self.gui.inject_input(InputEvent::Click {
                    button: btn, x, y, expected_visual_hash: Some(visual_phash),
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
            AgentTool::SysExec { command, args, detach } => {
                match self.terminal.execute(&command, &args, detach).await {
                    Ok(output) => {
                        success = true;
                        history_entry = Some(format!("System Output: {}", safe_truncate(&output, 1000)));
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            },
            AgentTool::BrowserNavigate { url } => {
                match self.browser.navigate(&url).await {
                    Ok(content) => {
                        success = true;
                        history_entry = Some(format!("Navigated to {}. Preview: {}", url, safe_truncate(&content, 300)));
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            },
            AgentTool::BrowserExtract {} => {
                 match self.browser.extract_dom().await {
                    Ok(content) => {
                        success = true;
                        history_entry = Some(format!("Extracted DOM ({} chars)", content.len()));
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
            AgentTool::BrowserSyntheticClick { x, y } => {
                match self.browser.synthetic_click(x as f64, y as f64).await {
                    Ok(_) => {
                        success = true;
                        history_entry = Some(format!("Synthetic Click at ({}, {})", x, y));
                    },
                    Err(e) => error = Some(e.to_string())
                }
            },
            AgentTool::ChatReply { message } => {
                success = true;
                history_entry = Some(format!("Replied: {}", message));
                // Event emitted by caller (action.rs)
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
                     }
                     Err(e) => error = Some(e.to_string())
                 }
            },
            AgentTool::FsList { path } => {
                 match std::fs::read_dir(&path) {
                     Ok(entries) => {
                         let names: Vec<String> = entries.filter_map(|e| e.ok().map(|d| d.file_name().to_string_lossy().to_string())).collect();
                         success = true;
                         history_entry = Some(format!("Ls {}: {}", path, names.join(", ")));
                     }
                     Err(e) => error = Some(e.to_string())
                 }
            },
            
            // [MODIFIED] Dynamic tool execution with OS tool interception
            AgentTool::Dynamic(val) => {
                if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                     let args = val.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
                     
                     match name {
                         // Intercept OS tools here to report error for misconfigured service
                         "os__focus_window" | "os__copy" | "os__paste" => {
                             error = Some(format!("Tool '{}' requires OsDriver but none was available in context (check actions.rs)", name));
                         },
                         _ => {
                             match self.mcp.execute_tool(name, args).await {
                                Ok(output) => {
                                    success = true;
                                    history_entry = Some(format!("Tool '{}' executed via MCP. Output: {}", name, safe_truncate(&output, 300)));
                                },
                                Err(e) => error = Some(format!("MCP Execution Failed: {}", e))
                            }
                         }
                     }
                } else {
                    error = Some("Dynamic tool call missing 'name'".into());
                }
            },
            _ => { 
                success = true;
                history_entry = Some("Meta-tool execution".to_string());
            }
        }

        ToolExecutionResult { success, error, history_entry }
    }
}