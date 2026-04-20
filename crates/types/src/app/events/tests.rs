use super::PiiDecisionReceiptEvent;

#[test]
fn pii_decision_receipt_event_back_compat_defaults() {
    let legacy_json = r#"{
        "session_id": null,
        "target": "clipboard::write",
        "target_id": null,
        "risk_surface": "egress",
        "decision_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "decision": "allow",
        "transform_plan_id": null,
        "span_count": 0,
        "ambiguous": false,
        "stage2_kind": null
    }"#;

    let parsed: PiiDecisionReceiptEvent =
        serde_json::from_str(legacy_json).expect("legacy pii receipt event");
    assert!(!parsed.assist_invoked);
    assert!(!parsed.assist_applied);
    assert_eq!(parsed.assist_kind, "");
    assert_eq!(parsed.assist_version, "");
    assert_eq!(parsed.assist_identity_hash, [0u8; 32]);
    assert_eq!(parsed.assist_input_graph_hash, [0u8; 32]);
    assert_eq!(parsed.assist_output_graph_hash, [0u8; 32]);
    assert!(parsed.target_id.is_none());
}
