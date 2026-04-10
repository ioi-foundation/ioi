{
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
}
