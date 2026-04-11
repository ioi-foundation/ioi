{
    // Tier-1 deterministic HTTP fetch (APIs/docs) governed by ActionTarget::NetFetch.
    if is_tool_allowed_for_resolution(resolved_intent, "http__fetch") {
        let params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to fetch (http/https)." },
                "max_chars": { "type": "integer", "description": "Optional max response body characters to return (truncated deterministically)." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "http__fetch".to_string(),
            description: "Fetch a URL over HTTP(S) and return raw response text + status for API calls (no browser UI automation).".to_string(),
            parameters: params.to_string(),
        });
    }
}
