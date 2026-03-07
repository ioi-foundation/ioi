{
    // Deterministic System tools are available across all tiers.
    let math_eval_params = json!({
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "Arithmetic expression to evaluate locally (for example: '247 * 38' or '(12 + 8) / 5')."
            }
        },
        "required": ["expression"]
    });
    tools.push(LlmToolDefinition {
        name: "math__eval".to_string(),
        description:
            "Evaluate a pure arithmetic expression locally without invoking shell commands."
                .to_string(),
        parameters: math_eval_params.to_string(),
    });
}
