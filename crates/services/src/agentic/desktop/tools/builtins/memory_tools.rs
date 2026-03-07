{
    // Memory Tools
    let mem_search_params = json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Semantic search query (e.g. 'error message from last run', 'login button location')" }
        },
        "required": ["query"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__search".to_string(),
        description:
            "Search the agent's long-term memory (SCS) for past observations, thoughts, or actions."
                .to_string(),
        parameters: mem_search_params.to_string(),
    });

    let mem_inspect_params = json!({
        "type": "object",
        "properties": {
            "frame_id": { "type": "integer", "description": "The ID of the memory frame to inspect (obtained from memory__search)" }
        },
        "required": ["frame_id"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__inspect".to_string(),
        description: "Retrieve detailed content of a specific memory frame. If it's an image, returns a detailed description.".to_string(),
        parameters: mem_inspect_params.to_string(),
    });

    let delegate_params = json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string" },
            "budget": { "type": "integer" }
        },
        "required": ["goal", "budget"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__delegate".to_string(),
        description: "Spawn a sub-agent to handle a complex, multi-step subtask (e.g. 'Research this topic'). Do NOT use for simple atomic actions like clicking or opening apps.".to_string(),
        parameters: delegate_params.to_string(),
    });
}
