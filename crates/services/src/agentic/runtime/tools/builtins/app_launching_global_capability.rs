{
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
        name: "app__launch".to_string(),
        description:
            "Intelligently find and launch a local application. Prefer this over 'shell__run' for GUI apps."
                .to_string(),
        parameters: launch_params.to_string(),
    });
}
