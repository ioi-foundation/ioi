{
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
}
