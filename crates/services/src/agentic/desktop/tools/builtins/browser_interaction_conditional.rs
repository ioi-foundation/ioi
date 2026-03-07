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
