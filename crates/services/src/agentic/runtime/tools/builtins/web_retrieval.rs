{
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
                "max_chars": { "type": "integer", "description": "Optional max extracted characters." },
                "allow_browser_fallback": {
                    "type": "boolean",
                    "description": "Optional strictness control. Set false to fail instead of escalating to browser-backed retrieval."
                }
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

        let media_params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Exact media/page URL to inspect." },
                "language": { "type": "string", "description": "Requested transcript language (for example: 'en')." },
                "max_chars": { "type": "integer", "description": "Optional max transcript characters to return." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "media__extract_transcript".to_string(),
            description:
                "Extract transcript text from a remote audio/video URL using managed media providers with provenance evidence."
                    .to_string(),
            parameters: media_params.to_string(),
        });

        let multimodal_params = json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Exact media/page URL to inspect." },
                "language": { "type": "string", "description": "Requested transcript language (for example: 'en')." },
                "max_chars": { "type": "integer", "description": "Optional max transcript characters to return." },
                "frame_limit": { "type": "integer", "description": "Optional max sampled frames to analyze." }
            },
            "required": ["url"]
        });
        tools.push(LlmToolDefinition {
            name: "media__extract_evidence".to_string(),
            description:
                "Extract transcript plus visual frame evidence from a remote audio/video URL using managed media tooling with provenance evidence."
                    .to_string(),
            parameters: multimodal_params.to_string(),
        });
    }
}
