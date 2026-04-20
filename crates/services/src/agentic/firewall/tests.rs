use super::*;

#[test]
fn test_canonicalization_determinism() {
    let json1 = r#"{"b": 1, "a": [2, 1]}"#;
    let json2 = r#"{  "a": [2, 1], "b": 1}"#; // Different whitespace and order

    let c1 = SemanticFirewall::canonicalize(json1).unwrap();
    let c2 = SemanticFirewall::canonicalize(json2).unwrap();

    assert_eq!(
        c1, c2,
        "Canonical output must be identical regardless of input formatting"
    );

    // JCS implies keys are sorted: {"a":[2,1],"b":1}
    let s1 = String::from_utf8(c1).unwrap();
    assert!(s1.starts_with(r#"{"a""#));
}
