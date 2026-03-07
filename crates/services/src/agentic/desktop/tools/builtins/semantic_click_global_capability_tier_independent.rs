{
    // Semantic Click (Global Capability - Tier Independent)
    let click_sem_params = json!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "The stable ID of the element (e.g. 'btn_submit')."
            }
        },
        "required": ["id"]
    });
    tools.push(LlmToolDefinition {
        name: "gui__click_element".to_string(),
        description:
            "Click a UI element by its ID. Preferred over coordinate clicking. Works in background."
                .to_string(),
        parameters: click_sem_params.to_string(),
    });
}
