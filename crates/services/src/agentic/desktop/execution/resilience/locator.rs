use crate::agentic::desktop::types::ExecutionTier;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::gui::accessibility::Rect;
use ioi_drivers::gui::geometry::{CoordinateSpace, Point};
use ioi_types::app::agentic::InferenceOptions;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub struct VisualLocator {
    runtime: Arc<dyn InferenceRuntime>,
}

impl VisualLocator {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn localize(
        &self,
        screenshot: &[u8],
        query: &str,
        window_rect: Rect,
        hint_xml: Option<&str>,
        tier: Option<ExecutionTier>,
    ) -> Result<Point, LocalizationError> {
        if !matches!(tier, Some(ExecutionTier::VisualForeground)) {
            return Err(LocalizationError::TierViolation);
        }

        let b64 = BASE64.encode(screenshot);
        let hint = hint_xml
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                let truncated = s.chars().take(5_000).collect::<String>();
                format!("Accessibility hint (possibly truncated):\n{}", truncated)
            })
            .unwrap_or_default();

        let prompt = format!(
            "Locate the UI target for query: '{}'.\n\
             Return STRICT JSON only: {{\"x\": integer, \"y\": integer, \"confidence\": float, \"reasoning\": string}}.\n\
             Coordinates must be screen-logical and inside active window rect ({}, {}, {}, {}).\n\
             {}",
            query,
            window_rect.x,
            window_rect.y,
            window_rect.width,
            window_rect.height,
            hint
        );

        let messages = json!([
            {"role": "system", "content": "You are a strict visual locator. Output JSON only."},
            {"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": format!("data:image/png;base64,{}", b64)}}
            ]}
        ]);

        let input_bytes = serde_json::to_vec(&messages)
            .map_err(|e| LocalizationError::InvalidOutput(e.to_string()))?;
        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            ..Default::default()
        };

        let output_bytes = self
            .runtime
            .execute_inference([0u8; 32], &input_bytes, options)
            .await
            .map_err(|e| LocalizationError::Runtime(e.to_string()))?;

        let raw = String::from_utf8_lossy(&output_bytes).to_string();
        if raw.to_ascii_lowercase().contains("refusal") {
            return Err(LocalizationError::ModelRefusal);
        }

        let parsed = parse_localization_output(&raw)?;
        if parsed.confidence < 0.60 {
            return Err(LocalizationError::LowConfidence(parsed.confidence));
        }

        if !point_in_rect(parsed.x, parsed.y, window_rect) {
            return Err(LocalizationError::OutOfBounds);
        }

        Ok(Point::new(
            parsed.x as f64,
            parsed.y as f64,
            CoordinateSpace::ScreenLogical,
        ))
    }
}

#[derive(Debug, Clone)]
pub enum LocalizationError {
    LowConfidence(f32),
    OutOfBounds,
    ModelRefusal,
    TierViolation,
    Runtime(String),
    InvalidOutput(String),
}

#[derive(Debug, Deserialize)]
struct LocalizationReply {
    x: i32,
    y: i32,
    confidence: f32,
    #[serde(default, rename = "reasoning")]
    _reasoning: String,
}

fn parse_localization_output(raw: &str) -> Result<LocalizationReply, LocalizationError> {
    if let Ok(reply) = serde_json::from_str::<LocalizationReply>(raw.trim()) {
        return Ok(reply);
    }

    if let (Some(start), Some(end)) = (raw.find('{'), raw.rfind('}')) {
        if end > start {
            let slice = &raw[start..=end];
            if let Ok(reply) = serde_json::from_str::<LocalizationReply>(slice) {
                return Ok(reply);
            }
        }
    }

    Err(LocalizationError::InvalidOutput(format!(
        "Failed to parse localization JSON: {}",
        raw
    )))
}

fn point_in_rect(x: i32, y: i32, rect: Rect) -> bool {
    if rect.width <= 0 || rect.height <= 0 {
        return false;
    }
    let x2 = rect.x + rect.width;
    let y2 = rect.y + rect.height;
    x >= rect.x && x <= x2 && y >= rect.y && y <= y2
}
