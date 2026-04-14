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
            "wait_ms_before_async": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional wait threshold before returning a retained command handle. If the command is still running after this many milliseconds, the tool returns a command_id instead of blocking."
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
        description: "Execute a terminal command or launch a local GUI application. Set wait_ms_before_async to get a retained command handle for long-running commands; use detach=true for GUI launches that should not stream logs.".to_string(),
        parameters: sys_params.to_string(),
    });

    let sys_status_params = json!({
        "type": "object",
        "properties": {
            "command_id": {
                "type": "string",
                "description": "Stable retained command identifier returned by shell__run or shell__start when the command outlived the async wait threshold."
            }
        },
        "required": ["command_id"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__status".to_string(),
        description: "Read-only status lookup for a retained running or completed command. Returns running/completed state, timing metadata, exit code when available, and the merged output tail.".to_string(),
        parameters: sys_status_params.to_string(),
    });

    let sys_input_params = json!({
        "type": "object",
        "properties": {
            "command_id": {
                "type": "string",
                "description": "Stable retained command identifier."
            },
            "stdin": {
                "type": "string",
                "description": "Raw stdin payload to send to the running command."
            }
        },
        "required": ["command_id", "stdin"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__input".to_string(),
        description: "Send raw stdin to a retained running command without reissuing the command.".to_string(),
        parameters: sys_input_params.to_string(),
    });

    let sys_terminate_params = json!({
        "type": "object",
        "properties": {
            "command_id": {
                "type": "string",
                "description": "Stable retained command identifier."
            }
        },
        "required": ["command_id"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__terminate".to_string(),
        description: "Terminate a retained running command. Use this instead of launching a second shell command to stop the process.".to_string(),
        parameters: sys_terminate_params.to_string(),
    });
}
