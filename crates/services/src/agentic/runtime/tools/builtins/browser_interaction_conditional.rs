{
    // Browser Interaction (CONDITIONAL)
    // Follow-up browser tools are exposed in DOM headless flows and when a browser
    // window is active (including visual tiers) to prevent navigate-only loops.
    if should_expose_headless_browser_followups(tier, allow_browser_navigation, is_browser_active)
        && is_tool_allowed_for_resolution(resolved_intent, "browser__subagent")
        && is_tool_allowed_for_resolution(resolved_intent, "agent__delegate")
    {
        let browser_subagent_params = json!({
            "type": "object",
            "properties": {
                "task_name": {
                    "type": "string",
                    "description": "Short user-facing label for the delegated browser task."
                },
                "task_summary": {
                    "type": "string",
                    "description": "Concise summary of the browser objective."
                },
                "recording_name": {
                    "type": "string",
                    "description": "Recording or evidence label retained for the browser run."
                },
                "task": {
                    "type": "string",
                    "description": "Full semantic browser task contract. Describe the goal, success condition, and any constraints here."
                },
                "reused_subagent_id": {
                    "type": "string",
                    "description": "Optional prior browser subagent id to resume."
                },
                "media_paths": {
                    "type": "array",
                    "description": "Optional local media paths to keep in scope while the browser worker runs.",
                    "items": { "type": "string" }
                }
            },
            "required": ["task_name", "task_summary", "recording_name", "task"]
        });
        tools.push(LlmToolDefinition {
            name: "browser__subagent".to_string(),
            description:
                "Run a packaged autonomous browser specialist as one blocking tool call. The parent waits for the final semantic report while the runtime streams delegated browser progress to the user."
                    .to_string(),
            parameters: browser_subagent_params.to_string(),
        });
    }

    let (browser_top_edge_jump_json, browser_bottom_edge_jump_json) = if cfg!(target_os = "macos")
    {
        (
            r#"{"key":"ArrowUp","modifiers":["Meta"]}"#,
            r#"{"key":"ArrowDown","modifiers":["Meta"]}"#,
        )
    } else {
        (
            r#"{"key":"Home","modifiers":["Control"]}"#,
            r#"{"key":"End","modifiers":["Control"]}"#,
        )
    };

    if should_expose_headless_browser_followups(tier, allow_browser_navigation, is_browser_active)
        && is_tool_allowed_for_resolution(resolved_intent, "browser__click_at")
    {
        let synthetic_click_params = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "description": "Optional semantic ID from browser__inspect for a grounded coordinate target. This may also be a numeric `som_id` from the tagged screenshot. Prefer this instead of guessing raw coordinates when the target is already named in the observation." },
                "x": { "type": "number", "description": "Optional absolute viewport x coordinate in CSS pixels. Fractional pixel values are allowed. Do not use normalized 0-1 fractions. Provide this together with y when no grounded target id is available." },
                "y": { "type": "number", "description": "Optional absolute viewport y coordinate in CSS pixels. Fractional pixel values are allowed. Do not use normalized 0-1 fractions. Provide this together with x when no grounded target id is available." },
                "continue_with": {
                    "type": "object",
                    "description": "Optional immediate follow-up browser action to execute after the coordinate click succeeds, without another inference turn. Use only when the next browser action is already grounded, timing matters, and the coordinate click has an observable browser reaction. If the coordinate click is exploratory or only changes visual geometry, re-evaluate before any visible-control follow-up. Do not use this for drag setup or pointer button state changes.",
                    "properties": {
                        "name": {
                            "type": "string",
                            "enum": [
                                "browser__click",
                                "browser__press_key",
                                "browser__hover",
                                "browser__click_at",
                                "browser__move_pointer",
                                "browser__scroll",
                                "browser__select",
                                "browser__paste",
                                "browser__find_text",
                                "browser__select_option"
                            ]
                        },
                        "arguments": {
                            "type": "object",
                            "description": "Arguments for the follow-up browser action. Example: {\"id\":\"btn_submit\"}."
                        }
                    },
                    "required": ["name", "arguments"]
                }
            },
        });

        tools.push(LlmToolDefinition {
            name: "browser__click_at".to_string(),
            description: "Activate a page coordinate directly without moving the user's mouse cursor. Prefer `id` when browser__inspect already names the grounded target; otherwise provide raw `x` and `y` viewport CSS pixels. Coordinates are absolute viewport CSS pixels, not normalized 0-1 fractions. Preferred for grounded coordinate-style actions on canvases, SVG surfaces, and blank regions that do not expose a DOM-clickable control. When the next browser action is already grounded, timing matters, and the coordinate click has an observable browser reaction, pair it with `continue_with` for an immediate follow-up. If the coordinate click is exploratory or only changes visual geometry, re-evaluate before any visible-control follow-up. Do not use `continue_with` for drag setup or pointer button state changes.".to_string(),
            parameters: synthetic_click_params.to_string(),
        });
    }

    if should_expose_headless_browser_followups(tier, allow_browser_navigation, is_browser_active) {
        if is_tool_allowed_for_resolution(resolved_intent, "browser__hover") {
            let browser_hover_params = json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string", "description": "CSS selector for the hover target. Provide this or id." },
                    "id": { "type": "string", "description": "Semantic ID from browser__inspect. Provide this or selector." },
                    "duration_ms": {
                        "type": "integer",
                        "description": "Optional bounded tracking window to keep reacquiring the target without another inference turn. Prefer this when the target moves or when hover must be maintained over time."
                    },
                    "resample_interval_ms": {
                        "type": "integer",
                        "description": "Optional refresh cadence used while duration_ms tracking is active. Omit it to use the default high-fidelity cadence, or set a positive value to trade fidelity for lower runtime churn."
                    }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__hover".to_string(),
                description: "Move the browser pointer onto a target without clicking. Useful for hover-driven menus, tooltips, drag setup, and short bounded hover tracking. When a grounded target moves or must stay hovered over time, prefer one `browser__hover` with `duration_ms` instead of spending extra inference turns on repeated hover actions.".to_string(),
                parameters: browser_hover_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__move_pointer") {
            let browser_move_mouse_params = json!({
                "type": "object",
                "properties": {
                    "x": { "type": "number", "description": "Absolute viewport x coordinate in CSS pixels. Fractional pixel values are allowed. Do not use normalized 0-1 fractions." },
                    "y": { "type": "number", "description": "Absolute viewport y coordinate in CSS pixels. Fractional pixel values are allowed. Do not use normalized 0-1 fractions." }
                },
                "required": ["x", "y"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__move_pointer".to_string(),
                description: "Reposition the browser pointer to absolute viewport CSS pixels without clicking. Do not use normalized 0-1 fractions. This alone does NOT activate page content; use `browser__click_at` for coordinate-only activation, or pair it with `browser__pointer_down` and `browser__pointer_up` for drag flows. Works in headless mode.".to_string(),
                parameters: browser_move_mouse_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__pointer_down") {
            let browser_mouse_down_params = json!({
                "type": "object",
                "properties": {
                    "button": {
                        "type": "string",
                        "description": "Mouse button to press. Defaults to left.",
                        "enum": ["left", "right", "middle", "back", "forward"]
                    }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__pointer_down".to_string(),
                description: "Press a browser mouse button at the current pointer position. Compose with browser__hover or browser__move_pointer for drag flows.".to_string(),
                parameters: browser_mouse_down_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__pointer_up") {
            let browser_mouse_up_params = json!({
                "type": "object",
                "properties": {
                    "button": {
                        "type": "string",
                        "description": "Mouse button to release. Defaults to left.",
                        "enum": ["left", "right", "middle", "back", "forward"]
                    }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__pointer_up".to_string(),
                description: "Release a browser mouse button at the current pointer position. Compose with browser__pointer_down for drag flows.".to_string(),
                parameters: browser_mouse_up_params.to_string(),
            });
        }

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
                description:
                    "Type text into the browser via CDP. Works in headless mode. When using numeric `som_id` tags from `browser__inspect`, focus the field first with `browser__click`, optionally via `continue_with`."
                        .to_string(),
                parameters: browser_type_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__select") {
            let browser_select_text_params = json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string", "description": "Optional CSS selector for the selection target. Defaults to the active element." },
                    "start_offset": { "type": "integer", "description": "Optional inclusive selection start offset." },
                    "end_offset": { "type": "integer", "description": "Optional exclusive selection end offset." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__select".to_string(),
                description: "Select text directly inside a browser element by `selector`, or within the active field if no selector is provided. Works in headless mode."
                    .to_string(),
                parameters: browser_select_text_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__press_key") {
            let browser_key_params = json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "Key to press (for example: 'Enter', 'Tab', 'Backspace', 'ArrowDown', 'a')." },
                    "selector": {
                        "type": "string",
                        "description": "Optional CSS selector to focus before pressing the key. Prefer this when the intended scrollable control, textbox, listbox, or combobox is already grounded in the current browser observation."
                    },
                    "modifiers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": format!(
                            "Optional modifier keys to hold while pressing the key (for example: ['Control'], ['Meta', 'Shift']). For edge-jump chords, emit {} or {}.",
                            browser_top_edge_jump_json,
                            browser_bottom_edge_jump_json,
                        )
                    }
                },
                "required": ["key"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__press_key".to_string(),
                description: format!(
                    "Press a keyboard key or modifier-aware key chord in the browser via CDP. Pass `selector` when you need the key to land on a specific grounded browser control without a separate focus click. For chords, include both `key` and `modifiers`, for example {}. Works in headless mode.",
                    browser_top_edge_jump_json,
                ),
                parameters: browser_key_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__copy") {
            tools.push(LlmToolDefinition {
                name: "browser__copy".to_string(),
                description: "Copy the current browser text selection into the system clipboard."
                    .to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                })
                .to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__paste") {
            let browser_paste_clipboard_params = json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string", "description": "Optional CSS selector to focus before inserting clipboard text." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__paste".to_string(),
                description: "Insert the current system clipboard contents into the browser. Pass `selector` to focus a target field first when you want to paste without a separate click."
                    .to_string(),
                parameters: browser_paste_clipboard_params.to_string(),
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
                    "timeout_ms": { "type": "integer", "description": "Timeout for condition waits in milliseconds (1-30000). Required when condition is provided." },
                    "continue_with": {
                        "type": "object",
                        "description": "Optional immediate follow-up browser action to execute as soon as the wait finishes, without another inference turn. Use only when the next browser action is already grounded and timing matters.",
                        "properties": {
                            "name": {
                                "type": "string",
                                "enum": [
                                    "browser__click",
                                    "browser__click",
                                    "browser__type",
                                    "browser__press_key",
                                    "browser__hover",
                                    "browser__click_at",
                                    "browser__move_pointer",
                                    "browser__pointer_down",
                                    "browser__pointer_up",
                                    "browser__scroll",
                                    "browser__select",
                                    "browser__paste",
                                    "browser__find_text",
                                    "browser__select_option"
                                ]
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for the follow-up browser action. Example: {\"id\":\"btn_two\"}."
                            }
                        },
                        "required": ["name", "arguments"]
                    }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__wait".to_string(),
                description: "Wait in browser workflows by fixed duration or condition. Valid forms are {ms}, {condition, timeout_ms}, or either form plus `continue_with` for an immediate grounded follow-up browser action once the wait finishes."
                    .to_string(),
                parameters: browser_wait_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__upload") {
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
                name: "browser__upload".to_string(),
                description: "Attach local files to a browser file input by selector or SoM ID."
                    .to_string(),
                parameters: browser_upload_file_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__list_options") {
            let browser_dropdown_options_params = json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Semantic browser ID from browser__inspect or the recent browser observation. Prefer this in headless browser mode." },
                    "selector": { "type": "string", "description": "CSS selector for a native <select> element. Provide this, id, or som_id." },
                    "som_id": { "type": "integer", "description": "Visual SoM ID for a native <select> element. Use this only when a screenshot/SoM view is present. Provide this, id, or selector." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__list_options".to_string(),
                description: "List options for a native <select> dropdown. Provide exactly one locator: id, selector, or som_id; executor validates this contract."
                    .to_string(),
                parameters: browser_dropdown_options_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__select_option") {
            let browser_select_dropdown_params = json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Semantic browser ID from browser__inspect or the recent browser observation. Prefer this in headless browser mode." },
                    "selector": { "type": "string", "description": "CSS selector for a native <select> element. Provide this, id, or som_id." },
                    "som_id": { "type": "integer", "description": "Visual SoM ID for a native <select> element. Use this only when a screenshot/SoM view is present. Provide this, id, or selector." },
                    "value": { "type": "string", "description": "Option value to select (exact match). Provide this or label." },
                    "label": { "type": "string", "description": "Visible option label to select (exact match). Provide this or value." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__select_option".to_string(),
                description: "Select an option in a native <select> dropdown. Provide exactly one locator (id, selector, or som_id) and one selector target (value or label); executor validates this contract."
                    .to_string(),
                parameters: browser_select_dropdown_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__back") {
            let browser_back_params = json!({
                "type": "object",
                "properties": {
                    "steps": { "type": "integer", "description": "Optional number of history entries to go back (default 1)." }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__back".to_string(),
                description: "Navigate back in browser history.".to_string(),
                parameters: browser_back_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__list_tabs") {
            let browser_tab_list_params = json!({
                "type": "object",
                "properties": {},
                "required": []
            });
            tools.push(LlmToolDefinition {
                name: "browser__list_tabs".to_string(),
                description: "List open browser tabs with stable tab IDs.".to_string(),
                parameters: browser_tab_list_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__switch_tab") {
            let browser_tab_switch_params = json!({
                "type": "object",
                "properties": {
                    "tab_id": { "type": "string", "description": "Tab ID returned by browser__list_tabs." }
                },
                "required": ["tab_id"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__switch_tab".to_string(),
                description: "Switch the active browser tab.".to_string(),
                parameters: browser_tab_switch_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__close_tab") {
            let browser_tab_close_params = json!({
                "type": "object",
                "properties": {
                    "tab_id": { "type": "string", "description": "Tab ID returned by browser__list_tabs." }
                },
                "required": ["tab_id"]
            });
            tools.push(LlmToolDefinition {
                name: "browser__close_tab".to_string(),
                description: "Close a browser tab by ID.".to_string(),
                parameters: browser_tab_close_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__inspect") {
            let snapshot_params = json!({
                "type": "object",
                "properties": {},
                "required": []
            });
            tools.push(LlmToolDefinition {
                name: "browser__inspect".to_string(),
                description:
                    "Snapshot the current browser page as semantic XML from the accessibility tree, with `som_id` numeric element tags that match an attached marked screenshot. The output may also include Browser-use state text, a Browser-use-style selector map, Browser-use tabs/page-info/pending-request metadata, and BrowserGym extra-properties, focused-bid, AXTree, and DOM sections after the root XML."
                        .to_string(),
                parameters: snapshot_params.to_string(),
            });
        }

        if is_tool_allowed_for_resolution(resolved_intent, "browser__click") {
            let click_id_params = json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Element ID from browser__inspect output. This may be a semantic ID (for example 'btn_sign_in') or a numeric `som_id` such as '12' from the tagged screenshot. Provide this or `ids`."
                    },
                    "ids": {
                        "type": "array",
                        "description": "Ordered element IDs from browser__inspect output to click in sequence without interleaving other actions. Each item may be a semantic ID or a numeric `som_id`. Provide this or `id`.",
                        "items": {
                            "type": "string"
                        },
                        "minItems": 1
                    },
                    "delay_ms_between_ids": {
                        "type": "integer",
                        "description": "Optional fixed delay in milliseconds inserted between consecutive `ids` clicks. Use this only with ordered `ids` when timing matters enough that another inference turn would introduce avoidable drift."
                    },
                    "continue_with": {
                        "type": "object",
                        "description": "Optional immediate follow-up browser action to execute after the click succeeds, without another inference turn. Use this when a visible gate or commit click should hand off directly to an already grounded browser action.",
                        "properties": {
                            "name": {
                                "type": "string",
                                "enum": [
                                    "browser__click",
                                    "browser__click",
                                    "browser__press_key",
                                    "browser__hover",
                                    "browser__click_at",
                                    "browser__move_pointer",
                                    "browser__pointer_down",
                                    "browser__pointer_up",
                                    "browser__scroll",
                                    "browser__select",
                                    "browser__paste",
                                    "browser__find_text",
                                    "browser__select_option"
                                ]
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for the follow-up browser action. Example: {\"ids\":[\"btn_one\",\"btn_two\"],\"delay_ms_between_ids\":2000}."
                            }
                        },
                        "required": ["name", "arguments"]
                    }
                }
            });
            tools.push(LlmToolDefinition {
                name: "browser__click".to_string(),
                description: "Click one page element by browser__inspect ID, or click an ordered list of IDs in sequence. Numeric `som_id` values from the tagged screenshot are preferred for generic browser actions; semantic IDs remain supported for compatibility. With ordered `ids`, you may also provide `delay_ms_between_ids` for precise multi-click timing without another inference turn. Use `continue_with` when the click must hand off directly to another already grounded browser action, including focus-then-type on a visible field or a visible gate/commit click followed by another grounded action. Preferred over CSS selectors in headless mode.".to_string(),
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
}
