{
    // Clipboard (Tier-1 deterministic primitive)
    let copy_params = json!({
        "type": "object",
        "properties": {
            "content": { "type": "string", "description": "Text to place in the clipboard" }
        },
        "required": ["content"]
    });
    tools.push(LlmToolDefinition {
        name: "clipboard__copy".to_string(),
        description: "Write text to the system clipboard (Copy).".to_string(),
        parameters: copy_params.to_string(),
    });

    let paste_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "clipboard__paste".to_string(),
        description: "Read text from the system clipboard (Paste).".to_string(),
        parameters: paste_params.to_string(),
    });
}
