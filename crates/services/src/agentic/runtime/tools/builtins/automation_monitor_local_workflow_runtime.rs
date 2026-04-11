{
    if resolved_intent.is_some()
        && is_tool_allowed_for_resolution(resolved_intent, "monitor__create")
    {
        let params = json!({
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Optional human-readable workflow title."
                },
                "description": {
                    "type": "string",
                    "description": "Optional human-readable workflow description."
                },
                "keywords": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Keywords that should trigger the monitor."
                },
                "interval_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "description": "Optional polling interval in seconds. Minimum 60."
                },
                "source_prompt": {
                    "type": "string",
                    "description": "Optional original user wording preserved in workflow provenance."
                }
            },
            "required": ["keywords"]
        });
        tools.push(LlmToolDefinition {
            name: "monitor__create".to_string(),
            description:
                "Install a durable local monitor workflow in the automation kernel. Use this for 'monitor/watch/notify me whenever' requests instead of shell timers, cron, or systemd."
                    .to_string(),
            parameters: params.to_string(),
        });
    }
}
