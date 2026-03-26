use crate::computer_use_suite::types::AllowedToolProfile;
use serde_json::{json, Value};

fn function_tool(name: &str, description: &str, parameters: Value) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        }
    })
}

fn supports_select(profile: AllowedToolProfile) -> bool {
    matches!(
        profile,
        AllowedToolProfile::BrowserCoreWithSelect
            | AllowedToolProfile::BrowserCoreWithSelectionClipboard
    )
}

fn supports_selection_clipboard(profile: AllowedToolProfile) -> bool {
    matches!(
        profile,
        AllowedToolProfile::BrowserCoreWithSelectionClipboard
    )
}

pub(super) fn browser_tools(profile: AllowedToolProfile) -> Vec<Value> {
    let mut tools = vec![
        function_tool(
            "browser__click",
            "Click a grounded page element via a literal CSS selector already shown in the observation. Do not use browser snapshot XML ids here.",
            json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string" }
                },
                "required": ["selector"]
            }),
        ),
        function_tool(
            "browser__click_element",
            "Click a grounded page element by its semantic XML id from browser__snapshot. Do not prepend '#'.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "ids": { "type": "array", "items": { "type": "string" } },
                    "delay_ms_between_ids": { "type": "integer" },
                    "continue_with": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "arguments": { "type": "object" }
                        },
                        "required": ["name", "arguments"]
                    }
                }
            }),
        ),
        function_tool(
            "browser__synthetic_click",
            "Click a grounded coordinate target or raw viewport coordinates.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "x": { "type": "number" },
                    "y": { "type": "number" },
                    "continue_with": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "arguments": { "type": "object" }
                        },
                        "required": ["name", "arguments"]
                    }
                }
            }),
        ),
        function_tool(
            "browser__hover",
            "Move the pointer onto a selector or semantic id without clicking.",
            json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string" },
                    "id": { "type": "string" },
                    "duration_ms": { "type": "integer" },
                    "resample_interval_ms": { "type": "integer" }
                }
            }),
        ),
        function_tool(
            "browser__move_mouse",
            "Move the browser pointer to viewport coordinates.",
            json!({
                "type": "object",
                "properties": {
                    "x": { "type": "number" },
                    "y": { "type": "number" }
                },
                "required": ["x", "y"]
            }),
        ),
        function_tool(
            "browser__mouse_down",
            "Press a mouse button at the current pointer position.",
            json!({
                "type": "object",
                "properties": {
                    "button": { "type": "string" }
                }
            }),
        ),
        function_tool(
            "browser__mouse_up",
            "Release a mouse button at the current pointer position.",
            json!({
                "type": "object",
                "properties": {
                    "button": { "type": "string" }
                }
            }),
        ),
        function_tool(
            "browser__scroll",
            "Scroll the browser viewport.",
            json!({
                "type": "object",
                "properties": {
                    "delta_y": { "type": "integer" },
                    "delta_x": { "type": "integer" }
                }
            }),
        ),
        function_tool(
            "browser__type",
            "Type text into a browser field. Prefer providing selector.",
            json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "selector": { "type": "string" }
                },
                "required": ["text"]
            }),
        ),
        function_tool(
            "browser__key",
            "Press a browser key, optionally against a selector and with modifiers.",
            json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "selector": { "type": "string" },
                    "modifiers": { "type": "array", "items": { "type": "string" } },
                    "continue_with": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "arguments": { "type": "object" }
                        },
                        "required": ["name", "arguments"]
                    }
                },
                "required": ["key"]
            }),
        ),
        function_tool(
            "browser__screenshot",
            "Capture a browser screenshot.",
            json!({
                "type": "object",
                "properties": {
                    "full_page": { "type": "boolean" }
                },
                "required": ["full_page"]
            }),
        ),
        function_tool(
            "browser__wait",
            "Wait by duration or condition before continuing.",
            json!({
                "type": "object",
                "properties": {
                    "ms": { "type": "integer" },
                    "condition": { "type": "string" },
                    "selector": { "type": "string" },
                    "query": { "type": "string" },
                    "scope": { "type": "string" },
                    "timeout_ms": { "type": "integer" },
                    "continue_with": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "arguments": { "type": "object" }
                        },
                        "required": ["name", "arguments"]
                    }
                }
            }),
        ),
        function_tool(
            "browser__snapshot",
            "Capture a semantic browser snapshot.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
    ];

    if supports_selection_clipboard(profile) {
        tools.push(function_tool(
            "browser__select_text",
            "Select text inside a browser element or active field.",
            json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string" },
                    "start_offset": { "type": "integer" },
                    "end_offset": { "type": "integer" }
                }
            }),
        ));
        tools.push(function_tool(
            "browser__copy_selection",
            "Copy the current browser selection into the clipboard.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ));
        tools.push(function_tool(
            "browser__paste_clipboard",
            "Paste the clipboard into a browser field.",
            json!({
                "type": "object",
                "properties": {
                    "selector": { "type": "string" }
                }
            }),
        ));
    }

    if supports_select(profile) {
        tools.push(function_tool(
            "browser__dropdown_options",
            "List native dropdown options for a selector or semantic id.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "selector": { "type": "string" },
                    "som_id": { "type": "integer" }
                }
            }),
        ));
        tools.push(function_tool(
            "browser__select_dropdown",
            "Select a native dropdown option by value or visible label.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "selector": { "type": "string" },
                    "som_id": { "type": "integer" },
                    "value": { "type": "string" },
                    "label": { "type": "string" }
                }
            }),
        ));
    }

    tools
}
