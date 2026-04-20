use super::extract_balanced_json_object;

#[test]
fn extracts_json_with_escaped_quotes() {
    let payload = r#"prefix {\"msg\":\"hello \\\"world\\\"\",\"n\":1} suffix"#;
    let start = payload.find('{').expect("json start");
    let extracted = extract_balanced_json_object(payload, start).expect("json payload");
    assert_eq!(extracted, r#"{\"msg\":\"hello \\\"world\\\"\",\"n\":1}"#);
}
