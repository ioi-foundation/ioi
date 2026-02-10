// Path: crates/services/src/agentic/grounding.rs

use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use serde_json::json;

/// Helper to produce canonical JSON bytes for parameters.
fn to_canonical_params(value: serde_json::Value) -> Vec<u8> {
    // In production, use serde_jcs::to_vec. For this module, we assume standard JSON serialization
    // is sufficient as a placeholder, or we import serde_jcs if available.
    // Using serde_json::to_vec for now to match imports availability.
    serde_json::to_vec(&value).unwrap_or_default()
}

/// Converts VLM output coordinates to OS absolute pixel coordinates.
///
/// Supports both:
/// - Normalized Floats: [0.0, 1.0] (e.g. GPT-4o-V)
/// - Integer Scale: [0, 1000] (e.g. UI-TARS)
///
/// This function acts as the "translation layer" between the fuzzy AI world and the rigid OS world.
pub fn normalize_click(
    vlm_x: f32,
    vlm_y: f32,
    screen_w: u32,
    screen_h: u32,
    agent_id: String,
    session_id: Option<[u8; 32]>,
    nonce: u64,
    visual_hash: Option<[u8; 32]>, // [NEW] Argument for visual integrity check
) -> ActionRequest {
    // Heuristic: If coordinates are > 1.0, assume they are in [0, 1000] space
    // which is common for UI-TARS and other specific GUI agent models.
    let (norm_x, norm_y) = if vlm_x > 1.0 || vlm_y > 1.0 {
        (vlm_x / 1000.0, vlm_y / 1000.0)
    } else {
        (vlm_x, vlm_y)
    };

    // Clamp coordinates to valid range [0.0, 1.0] to prevent out-of-bounds errors
    let clamped_x = norm_x.clamp(0.0, 1.0);
    let clamped_y = norm_y.clamp(0.0, 1.0);

    // Calculate absolute pixels based on the captured screen dimensions.
    // Note: The GUI operator handles DPI scaling (logical vs physical) internally.
    let abs_x = (clamped_x * screen_w as f32) as u32;
    let abs_y = (clamped_y * screen_h as f32) as u32;

    // Construct params with optional visual_hash
    let mut params_json = json!({
        "button": "left",
        "x": abs_x,
        "y": abs_y
    });

    if let Some(hash) = visual_hash {
        params_json["expected_visual_hash"] = json!(hex::encode(hash));
    }

    // Construct the canonical ActionRequest
    ActionRequest {
        target: ActionTarget::GuiClick,
        params: to_canonical_params(params_json),
        context: ActionContext {
            agent_id,
            session_id,
            window_id: None, // Context injection handles window binding later
        },
        nonce,
    }
}

/// Parses a raw VLM output string (e.g. "Action: click(0.5, 0.5)" or "click(500, 500)") into structured data.
/// This replaces the regex parsing in UI-TARS.
pub fn parse_vlm_action(
    raw_output: &str,
    screen_w: u32,
    screen_h: u32,
    agent_id: String,
    session_id: Option<[u8; 32]>,
    nonce: u64,
    current_screen_hash: Option<[u8; 32]>, // [NEW] Inject the hash of the frame the VLM saw
) -> Option<ActionRequest> {
    // Simple heuristic parser for MVP.
    // UI-TARS uses specific tokens like `<click> x y </click>`.

    if raw_output.contains("click") {
        // Mock parsing logic: extract floats from string
        // In a real impl, this would use a robust parser combinator.
        // Assuming format "click x y" where x, y are floats.
        let parts: Vec<&str> = raw_output.split_whitespace().collect();
        if parts.len() >= 3 {
            if let (Ok(x), Ok(y)) = (parts[1].parse::<f32>(), parts[2].parse::<f32>()) {
                return Some(normalize_click(
                    x,
                    y,
                    screen_w,
                    screen_h,
                    agent_id,
                    session_id,
                    nonce,
                    current_screen_hash,
                ));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
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
}
