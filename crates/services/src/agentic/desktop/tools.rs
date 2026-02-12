// Path: crates/services/src/agentic/desktop/tools.rs

use crate::agentic::desktop::keys::get_skill_stats_key;
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_scs::{FrameType, SovereignContextStore};
use ioi_types::app::agentic::AgentMacro;
use ioi_types::app::agentic::{LlmToolDefinition, SkillStats};
use ioi_types::codec;
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use regex::Regex;
use serde_json::json;
use std::sync::Arc;

/// Discovers tools available to the agent.
pub async fn discover_tools(
    state: &dyn StateAccess,
    scs: Option<&std::sync::Mutex<SovereignContextStore>>,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tier: ExecutionTier,
    active_window_title: &str,
) -> Vec<LlmToolDefinition> {
    let mut tools = Vec::new();

    // 1. Browser Detection
    let t = active_window_title.to_lowercase();
    let is_browser_active = t.contains("chrome")
        || t.contains("firefox")
        || t.contains("brave")
        || t.contains("edge")
        || t.contains("safari");

    // 2. Dynamic Service Tools (On-Chain Services)
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

    // 3. Native Capabilities

    // Browser Navigation (ALWAYS AVAILABLE)
    // This allows the agent to open a browser from the Desktop/Terminal context.
    let nav_params = json!({
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to navigate to (must start with http/https)."
            }
        },
        "required": ["url"]
    });
    tools.push(LlmToolDefinition {
        name: "browser__navigate".to_string(),
        description: "Navigates the agent's dedicated secure browser to a URL. To interact with your running applications, use os__focus_window and visual tools.".to_string(),
        parameters: nav_params.to_string(),
    });

    // [MOVED] App Launching (Global Capability)
    // We expose this in all tiers to allow the agent to open applications (like Calculator) immediately.
    let launch_params = json!({
        "type": "object",
        "properties": {
            "app_name": {
                "type": "string",
                "description": "Common name of the application (e.g. 'calculator', 'code', 'browser')"
            }
        },
        "required": ["app_name"]
    });
    tools.push(LlmToolDefinition {
        name: "os__launch_app".to_string(),
        description: "Intelligently find and launch a local application. Prefer this over 'sys__exec' for GUI apps.".to_string(),
        parameters: launch_params.to_string(),
    });

    // [NEW] Semantic Click (Global Capability - Tier Independent)
    // We expose this in ALL tiers so the agent doesn't need to escalate to "Computer" (Tier 3)
    // just to click a button it can already "see" in the XML.
    let click_sem_params = json!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "The stable ID of the element (e.g. 'btn_submit')."
            }
        },
        "required": ["id"]
    });
    tools.push(LlmToolDefinition {
        name: "gui__click_element".to_string(),
        description:
            "Click a UI element by its ID. Preferred over coordinate clicking. Works in background."
                .to_string(),
        parameters: click_sem_params.to_string(),
    });

    // [NEW] Global typing capability.
    // `gui__type` is implemented by the executor but was not exposed here, causing
    // avoidable "missing_capability: computer" failures for simple type intents.
    let gui_type_params = json!({
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Text to type into the currently focused input."
            }
        },
        "required": ["text"]
    });
    tools.push(LlmToolDefinition {
        name: "gui__type".to_string(),
        description: "Type text into the focused UI control.".to_string(),
        parameters: gui_type_params.to_string(),
    });

    // Global scroll capability.
    let scroll_params = json!({
        "type": "object",
        "properties": {
            "delta_y": { "type": "integer", "description": "Vertical scroll amount. Positive = Down." },
            "delta_x": { "type": "integer", "description": "Horizontal scroll amount. Positive = Right." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "gui__scroll".to_string(),
        description:
            "Scroll the mouse wheel. Ensure the mouse is hovering over the target area first."
                .to_string(),
        parameters: scroll_params.to_string(),
    });

    // Browser Interaction (CONDITIONAL)
    // Only expose these if we are actually looking at a browser.
    // This prevents the agent from trying to "browse" local apps like Calculator.
    if is_browser_active {
        // Synthetic Click ONLY in VisualBackground
        if tier == ExecutionTier::VisualBackground {
            let synthetic_click_params = json!({
                "type": "object",
                "properties": {
                    "x": { "type": "integer" },
                    "y": { "type": "integer" }
                },
                "required": ["x", "y"]
            });

            tools.push(LlmToolDefinition {
                name: "browser__synthetic_click".to_string(),
                description: "Click a coordinate (x,y) inside the web page directly. Does NOT move the user's mouse cursor.".to_string(),
                parameters: synthetic_click_params.to_string(),
            });
        }

        let browser_scroll_params = json!({
            "type": "object",
            "properties": {
                "delta_y": { "type": "integer", "description": "Vertical scroll amount. Positive = Down." },
                "delta_x": { "type": "integer", "description": "Horizontal scroll amount. Positive = Right." }
            }
        });
        tools.push(LlmToolDefinition {
            name: "browser__scroll".to_string(),
            description: "Scroll the browser page via CDP. Works in headless mode.".to_string(),
            parameters: browser_scroll_params.to_string(),
        });

        let browser_type_params = json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "description": "Text to type." },
                "selector": { "type": "string", "description": "Optional CSS selector to focus before typing." }
            },
            "required": ["text"]
        });
        tools.push(LlmToolDefinition {
            name: "browser__type".to_string(),
            description: "Type text into the browser via CDP. Works in headless mode.".to_string(),
            parameters: browser_type_params.to_string(),
        });

        let browser_key_params = json!({
            "type": "object",
            "properties": {
                "key": { "type": "string", "description": "Key to press (for example: 'Enter', 'Tab', 'Backspace', 'ArrowDown')." }
            },
            "required": ["key"]
        });
        tools.push(LlmToolDefinition {
            name: "browser__key".to_string(),
            description: "Press a keyboard key in the browser via CDP. Works in headless mode."
                .to_string(),
            parameters: browser_key_params.to_string(),
        });

        let extract_params = json!({
            "type": "object",
            "properties": {},
            "required": []
        });
        tools.push(LlmToolDefinition {
            name: "browser__extract".to_string(),
            description: "Extract the current browser accessibility tree as semantic XML with stable element IDs.".to_string(),
            parameters: extract_params.to_string(),
        });

        let click_id_params = json!({
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Semantic element ID from browser__extract output (e.g. 'btn_sign_in')."
                }
            },
            "required": ["id"]
        });
        tools.push(LlmToolDefinition {
            name: "browser__click_element".to_string(),
            description: "Click a page element by semantic ID from browser__extract. Preferred over CSS selectors in headless mode.".to_string(),
            parameters: click_id_params.to_string(),
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
            description: "Click/focus a page element via CSS selector with built-in precondition checks and keyboard fallback for search inputs.".to_string(),
            parameters: click_selector_params.to_string(),
        });
    }

    // [NEW] Memory Tools
    let mem_search_params = json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Semantic search query (e.g. 'error message from last run', 'login button location')" }
        },
        "required": ["query"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__search".to_string(),
        description:
            "Search the agent's long-term memory (SCS) for past observations, thoughts, or actions."
                .to_string(),
        parameters: mem_search_params.to_string(),
    });

    let mem_inspect_params = json!({
        "type": "object",
        "properties": {
            "frame_id": { "type": "integer", "description": "The ID of the memory frame to inspect (obtained from memory__search)" }
        },
        "required": ["frame_id"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__inspect".to_string(),
        description: "Retrieve detailed content of a specific memory frame. If it's an image, returns a detailed description.".to_string(),
        parameters: mem_inspect_params.to_string(),
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
        description: "Spawn a sub-agent to handle a complex, multi-step subtask (e.g. 'Research this topic'). Do NOT use for simple atomic actions like clicking or opening apps.".to_string(),
        parameters: delegate_params.to_string(),
    });

    // Only expose Computer tools in VisualForeground (Tier 3)
    if tier == ExecutionTier::VisualForeground {
        // [UPDATED] UI-TARS Style: Visual Semantic Search
        // We update the description to encourage using this for icons.
        let find_params = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "UI target description (text, icon, color, or shape), e.g. 'gear icon', 'red button', 'Submit Button'" }
            },
            "required": ["query"]
        });
        tools.push(LlmToolDefinition {
            name: "ui__find".to_string(),
            description: "Find an on-screen element by semantic or visual description, including unlabeled icons. Returns coordinates. Use this to find Desktop icons or dock items if 'os__launch_app' fails.".to_string(),
            parameters: find_params.to_string(),
        });

        let computer_params = json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "type", "key", "hotkey",
                        "mouse_move", "left_click", "right_click",
                        "left_click_id", "left_click_element", "right_click_id", "right_click_element",
                        "left_click_drag", "drag_drop", "drag_drop_id", "drag_drop_element",
                        "screenshot", "cursor_position", "scroll"
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
                "from_id": {
                    "type": ["integer", "string"],
                    "description": "Source ID for drag actions (SoM integer or semantic string)."
                },
                "to_id": {
                    "type": ["integer", "string"],
                    "description": "Destination ID for drag actions (SoM integer or semantic string)."
                },
                "delta": {
                     "type": "array",
                     "items": { "type": "integer" },
                     "minItems": 2,
                     "maxItems": 2,
                     "description": "Scroll delta [dx, dy] for scroll action."
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
                    "type": ["integer", "string"],
                    "description": "The ID to click. Use Integer for SoM tags, String for Semantic IDs."
                }
            },
            "required": ["action"]
        });

        tools.push(LlmToolDefinition {
            name: "computer".to_string(),
            description: "Control the computer (mouse/keyboard/hotkeys).".to_string(),
            parameters: computer_params.to_string(),
        });
    }

    // Deterministic System tools are available across all tiers.
    // They are Tier-1 primitives and should remain available in ToolFirst/AxFirst modes.
    let sys_params = json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The binary to execute (e.g., 'ls', 'gnome-calculator', 'code', 'ping')."
            },
            "args": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Arguments for the command"
            },
            "detach": {
                "type": "boolean",
                "description": "Set to true if launching a GUI application."
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__exec".to_string(),
        description: "Execute a terminal command or launch a local GUI application. Use 'detach: true' for persistent apps.".to_string(),
        parameters: sys_params.to_string(),
    });

    let sys_change_dir_params = json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Target directory path (absolute or relative to the current working directory)."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__change_directory".to_string(),
        description: "Change the persistent working directory for subsequent `sys__exec` commands."
            .to_string(),
        parameters: sys_change_dir_params.to_string(),
    });

    // 4. OS Control Tools
    if tier == ExecutionTier::VisualForeground {
        let focus_params = json!({
            "type": "object",
            "properties": {
                "title": { "type": "string", "description": "Exact or partial title of the window or app to focus (e.g. 'Calculator')." }
            },
            "required": ["title"]
        });
        tools.push(LlmToolDefinition {
            name: "os__focus_window".to_string(),
            description: "Bring a specific application window to the foreground. REQUIRED before clicking buttons in that app.".to_string(),
            parameters: focus_params.to_string(),
        });

        let copy_params = json!({
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "Text to place in the clipboard" }
            },
            "required": ["content"]
        });
        tools.push(LlmToolDefinition {
            name: "os__copy".to_string(),
            description: "Write text to the system clipboard (Copy).".to_string(),
            parameters: copy_params.to_string(),
        });

        let paste_params = json!({
            "type": "object",
            "properties": {},
            "required": []
        });
        tools.push(LlmToolDefinition {
            name: "os__paste".to_string(),
            description: "Read text from the system clipboard (Paste).".to_string(),
            parameters: paste_params.to_string(),
        });
    }

    // Common Tools (Chat, FS) - Available in all tiers

    let chat_params = json!({
        "type": "object",
        "properties": {
            "message": { "type": "string", "description": "The response text to show to the user." }
        },
        "required": ["message"]
    });
    tools.push(LlmToolDefinition {
        name: "chat__reply".to_string(),
        description: "Send a text message or answer to the user. WARNING: This PAUSES execution to wait for user input. Do not use for intermediate status updates.".to_string(),
        parameters: chat_params.to_string(),
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
        description:
            "Check if a child agent has completed its task. Returns 'Running' if not finished."
                .to_string(),
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
        description:
            "Call this when you have successfully achieved the goal to finish the session."
                .to_string(),
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
        description:
            "Purchase items from a UCP-compatible merchant using secure payment injection."
                .to_string(),
        parameters: checkout_params.to_string(),
    });

    let fs_write_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to write the file to" },
            "content": { "type": "string", "description": "Text content to write, or replacement content for a specific line when line_number is set" },
            "line_number": {
                "type": "integer",
                "minimum": 1,
                "description": "Optional 1-based line index to edit atomically. When omitted, writes the full file content."
            }
        },
        "required": ["path", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__write_file".to_string(),
        description: "Write text content to a file, or edit a single line deterministically by setting line_number."
            .to_string(),
        parameters: fs_write_params.to_string(),
    });

    let fs_edit_line_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to the file to edit" },
            "line_number": {
                "type": "integer",
                "minimum": 1,
                "description": "1-based line index to replace."
            },
            "content": { "type": "string", "description": "Replacement content for the target line." }
        },
        "required": ["path", "line_number", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__edit_line".to_string(),
        description: "Deterministically replace exactly one line in a file (alias of filesystem__write_file with line_number).".to_string(),
        parameters: fs_edit_line_params.to_string(),
    });

    let fs_patch_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Absolute path to the file to patch" },
            "search": {
                "type": "string",
                "description": "Exact string block to replace. Must match exactly one occurrence."
            },
            "replace": { "type": "string", "description": "Replacement content for the matched block" }
        },
        "required": ["path", "search", "replace"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__patch".to_string(),
        description:
            "Replace a unique text block in a file. Fails if search is missing or ambiguous."
                .to_string(),
        parameters: fs_patch_params.to_string(),
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

    let fs_search_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Root directory to search in" },
            "regex": { "type": "string", "description": "Rust regex pattern to find in file content" },
            "file_pattern": { "type": "string", "description": "Optional glob pattern to filter file names (e.g. '*.rs')" }
        },
        "required": ["path", "regex"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__search".to_string(),
        description: "Recursively search for a regex pattern in files under a directory and return matching lines."
            .to_string(),
        parameters: fs_search_params.to_string(),
    });

    let install_pkg_params = json!({
        "type": "object",
        "properties": {
            "package": {
                "type": "string",
                "description": "Package name or identifier to install (e.g. 'pydantic', '@scope/pkg', 'ripgrep')."
            },
            "manager": {
                "type": "string",
                "enum": ["apt-get", "brew", "pip", "npm", "pnpm", "cargo", "winget", "choco", "yum", "dnf"],
                "description": "Optional package manager. If omitted, platform default is used (Linux: apt-get, macOS: brew, Windows: winget)."
            }
        },
        "required": ["package"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__install_package".to_string(),
        description: "Install a dependency via a deterministic manager mapping. Prefer this over raw sys__exec for package installs."
            .to_string(),
        parameters: install_pkg_params.to_string(),
    });

    // Meta Tool: Explicit Failure (Trigger Escalation)
    let fail_params = json!({
        "type": "object",
        "properties": {
            "reason": { "type": "string", "description": "Why you cannot proceed (e.g. 'Missing sys__exec tool')" },
            "missing_capability": { "type": "string", "description": "The specific tool or permission you need" }
        },
        "required": ["reason"]
    });
    tools.push(LlmToolDefinition {
        name: "system__fail".to_string(),
        description: "Call this if you cannot proceed with the available tools. This signals the system to escalate your permissions or switch execution tiers.".to_string(),
        parameters: fail_params.to_string(),
    });

    // 3. Skill Discovery via Semantic Search + Reputation Ranking (The Change)
    if let Some(store_mutex) = scs {
        if let Ok(query_vec) = runtime.embed_text(query).await {
            // A. Get Candidates from Vector Index
            let candidates = {
                if let Ok(store) = store_mutex.lock() {
                    if let Ok(index_arc) = store.get_vector_index() {
                        if let Ok(index) = index_arc.lock() {
                            if let Some(idx) = index.as_ref() {
                                idx.search_hybrid(&query_vec, 10).unwrap_or_default()
                            } else {
                                vec![]
                            }
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            };

            // B. Re-Rank based on Reputation (RSI)
            // We fetch stats for each candidate from the State.
            let mut ranked_skills = Vec::new();

            for (frame_id, distance, f_type, visual_hash) in candidates {
                if f_type != FrameType::Skill {
                    continue;
                }

                // Fetch stats
                let stats_key = get_skill_stats_key(&visual_hash);
                let reliability = if let Ok(Some(bytes)) = state.get(&stats_key) {
                    if let Ok(s) = codec::from_bytes_canonical::<SkillStats>(&bytes) {
                        s.reliability()
                    } else {
                        0.5 // Default (Laplace smoothing baseline)
                    }
                } else {
                    0.5
                };

                // Adjusted Score: Lower distance is better.
                // We subtract reliability from distance (bonus).
                let adjusted_score = distance - (reliability * 0.2);

                // Retrieve definition
                if let Ok(store) = store_mutex.lock() {
                    if let Ok(payload) = store.read_frame_payload(frame_id) {
                        if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&payload) {
                            ranked_skills.push((adjusted_score, skill.definition, reliability));
                        }
                    }
                }
            }

            // Sort by adjusted score (ascending)
            ranked_skills
                .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

            // Take top 5
            for (_, def, rel) in ranked_skills.into_iter().take(5) {
                let mut def_with_stats = def;
                // Append reliability to description so the LLM knows it's a good tool
                def_with_stats.description = format!(
                    "{} (Reliability: {:.0}%)",
                    def_with_stats.description,
                    rel * 100.0
                );
                log::debug!(
                    "Injecting Skill: {} (Reliability: {:.2})",
                    def_with_stats.name,
                    rel
                );
                tools.push(def_with_stats);
            }
        }
    }

    tools
}
