    // Tier-2 UI inspection primitive (semantic accessibility DOM).
    let snapshot_params = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    tools.push(LlmToolDefinition {
        name: "gui__snapshot".to_string(),
        description: "Snapshot the current desktop UI accessibility tree as semantic XML with stable element IDs (use before gui__click_element).".to_string(),
        parameters: snapshot_params.to_string(),
    });
