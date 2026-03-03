use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::types::ExecutionTier;
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};
use serde_json::json;

pub(crate) fn should_expose_headless_browser_followups(
    tier: ExecutionTier,
    browser_tools_allowed: bool,
    is_browser_active: bool,
) -> bool {
    browser_tools_allowed && (tier == ExecutionTier::DomHeadless || is_browser_active)
}

pub(super) fn push_builtin_tools(
    tools: &mut Vec<LlmToolDefinition>,
    tier: ExecutionTier,
    is_browser_active: bool,
    allow_browser_navigation: bool,
    allow_web_search: bool,
    allow_web_read: bool,
    resolved_intent: Option<&ResolvedIntentState>,
) {
    // Native capabilities

    // Browser Navigation (intent-gated)
    // Avoid exposing browser actions for pure text tasks (e.g. summarize/draft/reply).
    if allow_browser_navigation {
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
    }

    // Typed Web Retrieval (intent-gated)
    // Prefer these for web research so the model gets a provenance-tracked evidence bundle.
    if allow_web_search {
        let params = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Search query." },
                "limit": { "type": "integer", "description": "Optional max results (default small)." }
            },
            "required": ["query"]
        });
        tools.push(LlmToolDefinition {
            name: "web__search".to_string(),
            description:
                "Search the web using an edge/local SERP and return typed sources with provenance (no UI automation).".to_string(),
            parameters: params.to_string(),
        });
    }

    if allow_web_read {
        let params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to read (http/https)." },
                "max_chars": { "type": "integer", "description": "Optional max extracted characters." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "web__read".to_string(),
            description:
                "Read a URL and return extracted text with deterministic quote spans for citations."
                    .to_string(),
            parameters: params.to_string(),
        });
    }

    // Tier-1 deterministic HTTP fetch (APIs/docs) governed by ActionTarget::NetFetch.
    if is_tool_allowed_for_resolution(resolved_intent, "net__fetch") {
        let params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to fetch (http/https)." },
                "max_chars": { "type": "integer", "description": "Optional max response body characters to return (truncated deterministically)." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "net__fetch".to_string(),
            description: "Fetch a URL over HTTP(S) and return raw response text + status for API calls (no browser UI automation).".to_string(),
            parameters: params.to_string(),
        });
    }

    // App Launching (Global Capability)
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
        description:
            "Intelligently find and launch a local application. Prefer this over 'sys__exec' for GUI apps."
                .to_string(),
        parameters: launch_params.to_string(),
    });

    // Semantic Click (Global Capability - Tier Independent)
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

    // Tier-2 UI inspection primitive (semantic accessibility DOM).
    let snapshot_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "gui__snapshot".to_string(),
        description: "Snapshot the current desktop UI accessibility tree as semantic XML with stable element IDs (use before gui__click_element).".to_string(),
        parameters: snapshot_params.to_string(),
    });

    // Global typing capability.
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
    // Follow-up browser tools are exposed in DOM headless flows and when a browser
    // window is active (including visual tiers) to prevent navigate-only loops.
    if is_browser_active
        && tier == ExecutionTier::VisualBackground
        && is_tool_allowed_for_resolution(resolved_intent, "browser__synthetic_click")
    {
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

    if should_expose_headless_browser_followups(tier, allow_browser_navigation, is_browser_active) {
        if is_tool_allowed_for_resolution(resolved_intent, "browser__scroll") {
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
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__type") {
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
                description: "Type text into the browser via CDP. Works in headless mode."
                    .to_string(),
                parameters: browser_type_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__key") {
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
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__find_text") {
            let browser_find_text_params = json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Literal text to find." },
                    "scope": {
                        "type": "string",
                        "description": "Search scope: 'visible' (default) or 'document'.",
                        "enum": ["visible", "document"]
                    },
                    "scroll": { "type": "boolean", "description": "Scroll first match into view." }
                },
                "required": ["query"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__find_text".to_string(),
                description: "Find literal text on the page and optionally scroll to first match."
                    .to_string(),
                parameters: browser_find_text_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__screenshot") {
            let browser_screenshot_params = json!({
                "type": "object",
                "properties": {
                    "full_page": { "type": "boolean", "description": "Capture beyond viewport for full page screenshot." }
                },
                "required": ["full_page"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__screenshot".to_string(),
                description: "Capture a browser screenshot as visual observation evidence."
                    .to_string(),
                parameters: browser_screenshot_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__wait") {
            let browser_wait_params = json!({
                "type": "object",
                "properties": {
                    "ms": { "type": "integer", "description": "Milliseconds to wait (1-30000). Use for fixed-duration waits. Mutually exclusive with condition waits." },
                    "condition": {
                        "type": "string",
                        "description": "Condition to wait for. Use together with timeout_ms when not providing ms.",
                        "enum": ["selector_visible", "text_present", "dom_stable"]
                    },
                    "selector": { "type": "string", "description": "Selector used by condition='selector_visible'." },
                    "query": { "type": "string", "description": "Literal text used by condition='text_present'." },
                    "scope": {
                        "type": "string",
                        "description": "Text search scope for condition='text_present'.",
                        "enum": ["visible", "document"]
                    },
                    "timeout_ms": { "type": "integer", "description": "Timeout for condition waits in milliseconds (1-30000). Required when condition is provided." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__wait".to_string(),
                description: "Wait in browser workflows by fixed duration or condition. Valid forms are either {ms} or {condition, timeout_ms}; the executor enforces this contract."
                    .to_string(),
                parameters: browser_wait_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__upload_file") {
            let browser_upload_file_params = json!({
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "One or more workspace-scoped file paths to attach."
                    },
                    "selector": {
                        "type": "string",
                        "description": "Optional CSS selector for file input (defaults to input[type='file'])."
                    },
                    "som_id": { "type": "integer", "description": "Optional SoM ID for target file input." }
                },
                "required": ["paths"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__upload_file".to_string(),
                description: "Attach local files to a browser file input by selector or SoM ID."
                    .to_string(),
                parameters: browser_upload_file_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__dropdown_options") {
            let browser_dropdown_options_params = json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string", "description": "CSS selector for a native <select> element. Provide this or som_id." },
                    "som_id": { "type": "integer", "description": "SoM ID for a native <select> element. Provide this or selector." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__dropdown_options".to_string(),
                description: "List options for a native <select> dropdown. Provide exactly one locator: selector or som_id; executor validates this contract."
                    .to_string(),
                parameters: browser_dropdown_options_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__select_dropdown") {
            let browser_select_dropdown_params = json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string", "description": "CSS selector for a native <select> element. Provide this or som_id." },
                    "som_id": { "type": "integer", "description": "SoM ID for a native <select> element. Provide this or selector." },
                    "value": { "type": "string", "description": "Option value to select (exact match). Provide this or label." },
                    "label": { "type": "string", "description": "Visible option label to select (exact match). Provide this or value." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__select_dropdown".to_string(),
                description: "Select an option in a native <select> dropdown. Provide exactly one locator (selector or som_id) and one selector target (value or label); executor validates this contract."
                    .to_string(),
                parameters: browser_select_dropdown_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__go_back") {
            let browser_back_params = json!({
                "type": "object",
                "properties": {
                    "steps": { "type": "integer", "description": "Optional number of history entries to go back (default 1)." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__go_back".to_string(),
                description: "Navigate back in browser history.".to_string(),
                parameters: browser_back_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__tab_list") {
            let browser_tab_list_params = json!({
                "type": "object",
                "properties": {},
                "required": []
            });
            tools.push(LlmToolDefinition {
                name: "browser__tab_list".to_string(),
                description: "List open browser tabs with stable tab IDs.".to_string(),
                parameters: browser_tab_list_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__tab_switch") {
            let browser_tab_switch_params = json!({
                "type": "object",
                "properties": {
                    "tab_id": { "type": "string", "description": "Tab ID returned by browser__tab_list." }
                },
                "required": ["tab_id"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__tab_switch".to_string(),
                description: "Switch the active browser tab.".to_string(),
                parameters: browser_tab_switch_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__tab_close") {
            let browser_tab_close_params = json!({
                "type": "object",
                "properties": {
                    "tab_id": { "type": "string", "description": "Tab ID returned by browser__tab_list." }
                },
                "required": ["tab_id"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__tab_close".to_string(),
                description: "Close a browser tab by ID.".to_string(),
                parameters: browser_tab_close_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__snapshot") {
            let snapshot_params = json!({
                "type": "object",
                "properties": {},
                "required": []
            });
            tools.push(LlmToolDefinition {
                name: "browser__snapshot".to_string(),
                description:
                    "Snapshot the current browser page as semantic XML with stable element IDs."
                        .to_string(),
                parameters: snapshot_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__click_element") {
            let click_id_params = json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Semantic element ID from browser__snapshot output (e.g. 'btn_sign_in')."
                    }
                },
                "required": ["id"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__click_element".to_string(),
                description: "Click a page element by semantic ID from browser__snapshot. Preferred over CSS selectors in headless mode.".to_string(),
                parameters: click_id_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__click") {
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
    }

    // Memory Tools
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
    let math_eval_params = json!({
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "Arithmetic expression to evaluate locally (for example: '247 * 38' or '(12 + 8) / 5')."
            }
        },
        "required": ["expression"]
    });
    tools.push(LlmToolDefinition {
        name: "math__eval".to_string(),
        description:
            "Evaluate a pure arithmetic expression locally without invoking shell commands."
                .to_string(),
        parameters: math_eval_params.to_string(),
    });

    // Deterministic System tools are available across all tiers.
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
            "stdin": {
                "type": "string",
                "description": "Optional stdin payload sent to the process before waiting for output."
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

    // OpenInterpreter-style shell continuity (persistent session).
    let sys_session_params = json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The command to execute inside the persistent shell session (e.g. 'export', 'source', 'python', 'echo')."
            },
            "args": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Arguments for the command"
            },
            "stdin": {
                "type": "string",
                "description": "Optional stdin payload sent to the process before waiting for output."
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "sys__exec_session".to_string(),
        description: "Execute a command inside a persistent shell session scoped to this agent session. Use this when you need shell continuity across calls (exports, sourcing env, shell vars).".to_string(),
        parameters: sys_session_params.to_string(),
    });

    let sys_session_reset_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "sys__exec_session_reset".to_string(),
        description: "Reset the persistent shell session used by `sys__exec_session` (kills the session and starts fresh on next call).".to_string(),
        parameters: sys_session_reset_params.to_string(),
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

    // OS Control Tools
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
    }

    // Clipboard (Tier-1 deterministic primitive)
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

    // Common Tools (Chat, FS)
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

    let fs_stat_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to inspect for deterministic metadata." }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__stat".to_string(),
        description:
            "Return deterministic metadata for a file or directory, including modified timestamp."
                .to_string(),
        parameters: fs_stat_params.to_string(),
    });

    let fs_move_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source path to move or rename." },
            "destination_path": { "type": "string", "description": "Destination path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination path."
            }
        },
        "required": ["source_path", "destination_path"]
    });
    let fs_copy_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source path to copy." },
            "destination_path": { "type": "string", "description": "Destination path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination path."
            }
        },
        "required": ["source_path", "destination_path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__copy_path".to_string(),
        description: "Copy a file/directory deterministically without invoking shell commands."
            .to_string(),
        parameters: fs_copy_params.to_string(),
    });

    tools.push(LlmToolDefinition {
        name: "filesystem__move_path".to_string(),
        description:
            "Move or rename a file/directory deterministically without invoking shell commands."
                .to_string(),
        parameters: fs_move_params.to_string(),
    });

    let fs_delete_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to delete." },
            "recursive": {
                "type": "boolean",
                "description": "When true, delete directories recursively."
            },
            "ignore_missing": {
                "type": "boolean",
                "description": "When true, treat missing paths as success."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__delete_path".to_string(),
        description:
            "Delete a file/symlink, or a directory when recursive=true, using deterministic filesystem APIs."
                .to_string(),
        parameters: fs_delete_params.to_string(),
    });

    let fs_create_directory_params = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Directory path to create." },
            "recursive": {
                "type": "boolean",
                "description": "When true, create missing parent directories as needed."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__create_directory".to_string(),
        description: "Create a directory deterministically without invoking shell commands."
            .to_string(),
        parameters: fs_create_directory_params.to_string(),
    });

    let fs_create_zip_params = json!({
        "type": "object",
        "properties": {
            "source_path": { "type": "string", "description": "Source directory path to compress." },
            "destination_zip_path": { "type": "string", "description": "Destination .zip file path." },
            "overwrite": {
                "type": "boolean",
                "description": "When true, replace an existing destination zip file."
            }
        },
        "required": ["source_path", "destination_zip_path"]
    });
    tools.push(LlmToolDefinition {
        name: "filesystem__create_zip".to_string(),
        description:
            "Create a zip archive from a source directory deterministically without invoking shell commands."
                .to_string(),
        parameters: fs_create_zip_params.to_string(),
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
}
