{
    // Native model-backed retrieval helpers.
    // Keep these gated to memory-capable intents so we do not expose a second
    // general-purpose response surface inside ordinary conversation flows.
    let allow_native_model_memory_tools =
        is_tool_allowed_for_resolution(resolved_intent, "model__embeddings")
            || is_tool_allowed_for_resolution(resolved_intent, "model__rerank");

    if allow_native_model_memory_tools {
        let embedding_params = json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to embed for semantic comparison. You may also pass the same value as `input`."
                },
                "input": {
                    "type": "string",
                    "description": "Alias of `text` for text embeddings."
                },
                "image_base64": {
                    "type": "string",
                    "description": "Optional base64-encoded image payload for image embeddings."
                },
                "mime_type": {
                    "type": "string",
                    "description": "Optional MIME type when embedding an image payload."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local embedding model."
                }
            }
        });
        tools.push(LlmToolDefinition {
            name: "model__embeddings".to_string(),
            description:
                "Generate a kernel-native embedding for text or image inputs so you can compare memory or evidence semantically. Do not use this as a final user answer."
                    .to_string(),
            parameters: embedding_params.to_string(),
        });

        let rerank_params = json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The semantic query used to score candidate items."
                },
                "candidates": {
                    "type": "array",
                    "description": "Candidate strings to rerank by relevance.",
                    "items": { "type": "string" }
                },
                "top_k": {
                    "type": "integer",
                    "description": "Optional number of top-ranked candidates to return."
                },
                "model_id": {
                    "type": "string",
                    "description": "Optional model identifier to force a specific local reranker."
                }
            },
            "required": ["query", "candidates"]
        });
        tools.push(LlmToolDefinition {
            name: "model__rerank".to_string(),
            description:
                "Rerank candidate memory or evidence snippets using the kernel-native local reranker. Use this to order candidate facts before you inspect or cite them."
                    .to_string(),
            parameters: rerank_params.to_string(),
        });
    }
}
