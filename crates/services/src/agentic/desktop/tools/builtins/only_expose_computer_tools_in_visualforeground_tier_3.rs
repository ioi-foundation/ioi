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
