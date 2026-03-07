    // Typed Web Retrieval (intent-gated)
    // Prefer these for web research so the model gets a provenance-tracked evidence bundle.
    if allow_web_search {
        let params = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Search query." },
                "limit": { "type": "integer", "description": "Optional max results (default small)." }
            },
            "required": ["query"]
        });
        tools.push(LlmToolDefinition {
            name: "web__search".to_string(),
            description:
                "Search the web using an edge/local SERP and return typed sources with provenance (no UI automation).".to_string(),
            parameters: params.to_string(),
        });
    }

    if allow_web_read {
        let params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to read (http/https)." },
                "max_chars": { "type": "integer", "description": "Optional max extracted characters." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "web__read".to_string(),
            description:
                "Read a URL and return extracted text with deterministic quote spans for citations."
                    .to_string(),
            parameters: params.to_string(),
        });
    }
