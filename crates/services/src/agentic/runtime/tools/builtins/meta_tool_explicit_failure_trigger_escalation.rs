{
    // Meta Tool: Explicit Failure (Trigger Escalation)
    let fail_params = json!({
        "type": "object",
        "properties": {
            "reason": { "type": "string", "description": "Why you cannot proceed (e.g. 'Missing sys__exec tool')" },
            "missing_capability": { "type": "string", "description": "The specific tool or permission you need" }
        },
        "required": ["reason"]
    });
    tools.push(LlmToolDefinition {
        name: "system__fail".to_string(),
        description: "Call this if you cannot proceed with the available tools. This signals the system to escalate your permissions or switch execution tiers.".to_string(),
        parameters: fail_params.to_string(),
    });
}
