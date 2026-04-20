use super::{ActionVerifier, StateSnapshot};

#[test]
fn verify_impact_detects_no_change() {
    let before = StateSnapshot {
        tree_hash: 10,
        visual_hash: [0u8; 32],
        timestamp: 100,
    };
    let after = StateSnapshot {
        tree_hash: 10,
        visual_hash: [0u8; 32],
        timestamp: 200,
    };
    let result = ActionVerifier::verify_impact(&before, &after);
    assert!(!result.is_significant());
    assert!(!result.tree_changed);
    assert_eq!(result.visual_distance, 0);
}

#[test]
fn verify_impact_detects_change() {
    let before = StateSnapshot {
        tree_hash: 10,
        visual_hash: [0u8; 32],
        timestamp: 100,
    };
    let mut after_hash = [0u8; 32];
    after_hash[0] = 0b1111_1111;
    let after = StateSnapshot {
        tree_hash: 11,
        visual_hash: after_hash,
        timestamp: 200,
    };
    let result = ActionVerifier::verify_impact(&before, &after);
    assert!(result.is_significant());
    assert!(result.tree_changed);
}
