{
    // OpenInterpreter-style shell continuity (persistent session).
    let sys_session_params = json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The command to execute inside the persistent shell session (e.g. 'export', 'source', 'python', 'echo')."
            },
            "args": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Arguments for the command"
            },
            "stdin": {
                "type": "string",
                "description": "Optional stdin payload sent to the process before waiting for output."
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__start".to_string(),
        description: "Execute a command inside a persistent shell session scoped to this agent session. Use this when you need shell continuity across calls (exports, sourcing env, shell vars).".to_string(),
        parameters: sys_session_params.to_string(),
    });

    let sys_session_reset_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "shell__reset".to_string(),
        description: "Reset the persistent shell session used by `shell__start` (kills the session and starts fresh on next call).".to_string(),
        parameters: sys_session_reset_params.to_string(),
    });

    let sys_change_dir_params = json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Target directory path (absolute or relative to the current working directory)."
            }
        },
        "required": ["path"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__cd".to_string(),
        description: "Change the persistent working directory for subsequent `shell__run` commands."
            .to_string(),
        parameters: sys_change_dir_params.to_string(),
    });
}
