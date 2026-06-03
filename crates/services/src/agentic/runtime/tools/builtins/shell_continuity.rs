{
    // OpenInterpreter-style shell continuity (persistent session).
    let sys_session_params = json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The binary or shell builtin to execute inside the persistent shell session. For retained helpers, provide a complete observable program instead of launching a bare interpreter/REPL."
            },
            "args": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Arguments for the command. For example, a Node stdin helper should use ['-e', 'process.stdin.resume(); process.stdin.on(...)'] rather than starting bare 'node'."
            },
            "stdin": {
                "type": "string",
                "description": "Optional stdin payload sent to the process before waiting for output."
            },
            "wait_ms_before_async": {
                "type": "integer",
                "minimum": 0,
                "description": "Optional wait threshold before returning a retained command handle. Commands that keep running past this threshold return a command_id while preserving the owning terminal_id."
            }
        },
        "required": ["command"]
    });
    tools.push(LlmToolDefinition {
        name: "shell__start".to_string(),
        description: "Execute a command inside a persistent shell session scoped to this agent session. Use this when you need shell continuity across calls (exports, sourcing env, shell vars), and set wait_ms_before_async to retain a running command handle without losing the session. For retained/background helpers, start a complete command that will emit observable output for later shell__input/shell__status calls; do not start a bare interpreter unless the user explicitly asks for an interactive REPL.".to_string(),
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
