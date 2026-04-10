{
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
}
