use super::*;

#[test]
fn serialize_graph_response_input_wraps_system_prompt_and_prompt_template() {
    let config = json!({
        "systemPrompt": "Operate carefully.",
        "prompt": "Summarize {{topic}}."
    });
    let input = json!({
        "topic": "kernel receipts"
    });

    let serialized =
        serialize_graph_response_input(&config, &input).expect("response input should serialize");
    let messages: Value =
        serde_json::from_slice(&serialized).expect("serialized messages should parse");

    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], "Operate carefully.");
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(messages[1]["content"], "Summarize kernel receipts.");
}

#[test]
fn resolve_rerank_candidates_prefers_upstream_results() {
    let config = json!({});
    let input = json!({
        "results": [
            { "content": "kernel-native responses" },
            { "summary": "typed media receipts" },
            { "output_text": "parent playbook visibility" }
        ]
    });

    let candidates = resolve_rerank_candidates(&config, &input);

    assert_eq!(
        candidates,
        vec![
            "kernel-native responses".to_string(),
            "typed media receipts".to_string(),
            "parent playbook visibility".to_string()
        ]
    );
}

#[test]
fn infer_text_payload_uses_scalar_strings_without_extra_quotes() {
    let input = Value::String("hello world".to_string());

    let payload = infer_text_payload(&input);

    assert_eq!(payload.as_deref(), Some("hello world"));
}

#[test]
fn resolve_optional_binary_input_returns_none_when_absent() {
    let config = json!({});
    let input = json!({});

    let resolved = resolve_optional_binary_input(
        &config,
        &input,
        &["maskImagePath"],
        &["maskImageBase64"],
        &["maskImageBytes"],
        "mask image",
    )
    .expect("optional binary lookup should succeed");

    assert!(resolved.is_none());
}
