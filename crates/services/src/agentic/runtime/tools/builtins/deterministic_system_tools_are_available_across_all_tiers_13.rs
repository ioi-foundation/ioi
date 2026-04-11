{
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
        name: "shell__run".to_string(),
        description: "Execute a terminal command or launch a local GUI application. Use 'detach: true' for persistent apps.".to_string(),
        parameters: sys_params.to_string(),
    });
}
