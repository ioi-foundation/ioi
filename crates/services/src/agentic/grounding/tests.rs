use super::*;

#[test]
fn test_normalize_click_normalized_floats() {
    // Test 0.0-1.0 range (e.g. general VLMs)
    let req = normalize_click(0.5, 0.5, 1920, 1080, "test-agent".into(), None, 1, None);

    // 50% of 1920 is 960
    // 50% of 1080 is 540
    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();

    assert_eq!(params["x"], 960);
    assert_eq!(params["y"], 540);
    assert_eq!(req.target, ActionTarget::GuiClick);
}

#[test]
fn test_normalize_click_thousand_scale() {
    // Test 0-1000 range (e.g. UI-TARS)
    let req = normalize_click(500.0, 500.0, 1920, 1080, "test-agent".into(), None, 1, None);

    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();

    // Should produce same result as 0.5
    assert_eq!(params["x"], 960);
    assert_eq!(params["y"], 540);
}

#[test]
fn test_normalize_click_clamping() {
    // Test out of bounds (1500) clamps to 1.0 (max pixel)
    // 1.5 in float space would clamp.
    // 1500 in int space / 1000 = 1.5 -> clamps.
    let req = normalize_click(
        1500.0,
        -50.0,
        1000,
        1000,
        "test-agent".into(),
        None,
        1,
        None,
    );

    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();

    assert_eq!(params["x"], 1000); // Clamped to max width
    assert_eq!(params["y"], 0); // Clamped to min height (0)
}

#[test]
fn test_normalize_click_with_hash() {
    let hash = [0xAA; 32];
    let req = normalize_click(0.5, 0.5, 100, 100, "test".into(), None, 1, Some(hash));
    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();

    assert_eq!(params["expected_visual_hash"], hex::encode(hash));
}
