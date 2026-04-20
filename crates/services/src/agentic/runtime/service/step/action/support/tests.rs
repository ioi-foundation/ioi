use super::{
    action_fingerprint_execution_label, action_fingerprint_execution_step,
    drop_legacy_action_fingerprint_receipt, mark_action_fingerprint_executed_at_step,
};
use crate::agentic::runtime::types::ToolCallStatus;
use std::collections::BTreeMap;

#[test]
fn action_fingerprint_step_roundtrips_when_recorded_with_step() {
    let mut log = BTreeMap::new();
    mark_action_fingerprint_executed_at_step(&mut log, "abc", 7, "success");
    assert_eq!(action_fingerprint_execution_step(&log, "abc"), Some(7));
}

#[test]
fn action_fingerprint_label_roundtrips_when_recorded_with_step() {
    let mut log = BTreeMap::new();
    mark_action_fingerprint_executed_at_step(&mut log, "abc", 7, "success");
    assert_eq!(
        action_fingerprint_execution_label(&log, "abc").as_deref(),
        Some("success")
    );
}

#[test]
fn legacy_action_fingerprint_marker_is_dropped() {
    let mut log = BTreeMap::new();
    log.insert(
        "action_fingerprint::legacy".to_string(),
        ToolCallStatus::Executed("success".to_string()),
    );
    assert!(drop_legacy_action_fingerprint_receipt(&mut log, "legacy"));
    assert_eq!(action_fingerprint_execution_step(&log, "legacy"), None);
    assert!(log.get("action_fingerprint::legacy").is_none());
}
