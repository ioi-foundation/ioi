use super::patch_apply_failure_message;
use std::path::Path;

#[test]
fn patch_search_miss_maps_to_no_effect_after_action() {
    let message = patch_apply_failure_message(
        Path::new("/tmp/example.py"),
        "search block not found in file",
    );
    assert!(message.starts_with("ERROR_CLASS=NoEffectAfterAction"));
    assert!(message.contains("file__replace_line"));
    assert!(message.contains("file__write"));
}

#[test]
fn malformed_patch_payload_maps_to_unexpected_state() {
    let message = patch_apply_failure_message(
        Path::new("/tmp/example.py"),
        "search block must be non-empty",
    );
    assert!(message.starts_with("ERROR_CLASS=UnexpectedState"));
}
