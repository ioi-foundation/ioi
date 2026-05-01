{
    // Global scroll capability.
    let scroll_params = json!({
        "type": "object",
        "properties": {
            "delta_y": { "type": "integer", "description": "Vertical scroll amount. Positive = Down." },
            "delta_x": { "type": "integer", "description": "Horizontal scroll amount. Positive = Right." }
        }
    });
    tools.push(LlmToolDefinition {
        name: "screen__scroll".to_string(),
        description:
            "Scroll the mouse wheel. Ensure the mouse is hovering over the target area first."
                .to_string(),
        parameters: scroll_params.to_string(),
    });
}
