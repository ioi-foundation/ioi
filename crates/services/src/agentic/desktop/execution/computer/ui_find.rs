use super::super::resilience;
use super::super::resilience::locator::{LocalizationError, VisualLocator};
use super::super::{ToolExecutionResult, ToolExecutor};
use super::semantics::{find_semantic_ui_match, UiFindSemanticMatch};
use super::tree::fetch_lensed_tree;
use crate::agentic::desktop::types::ExecutionTier;
use image::load_from_memory;
use ioi_drivers::gui::accessibility::Rect;
use serde_json::json;

fn execution_tier_label(tier: Option<ExecutionTier>) -> &'static str {
    match tier {
        Some(ExecutionTier::DomHeadless) => "ToolFirst",
        Some(ExecutionTier::VisualBackground) => "AxFirst",
        Some(ExecutionTier::VisualForeground) => "VisualLast",
        None => "Unknown",
    }
}

fn build_ui_find_success(
    query: &str,
    found: UiFindSemanticMatch,
    active_lens: Option<&str>,
    tier: Option<ExecutionTier>,
) -> ToolExecutionResult {
    let payload = json!({
        "query": query,
        "x": found.x,
        "y": found.y,
        "id": found.id,
        "role": found.role,
        "label": found.label,
        "source": found.source,
        "confidence": found.confidence,
        "tier": execution_tier_label(tier),
        "lens": active_lens.unwrap_or("none"),
    });
    ToolExecutionResult::success(format!("UI find resolved: {}", payload))
}

fn ui_find_window_rect(exec: &ToolExecutor) -> Option<Rect> {
    exec.active_window.as_ref().and_then(|win| {
        if win.width > 0 && win.height > 0 {
            Some(Rect {
                x: win.x,
                y: win.y,
                width: win.width,
                height: win.height,
            })
        } else {
            None
        }
    })
}

fn ui_find_screen_rect_from_image(image_bytes: &[u8]) -> Option<Rect> {
    let image = load_from_memory(image_bytes).ok()?;
    Some(Rect {
        x: 0,
        y: 0,
        width: image.width() as i32,
        height: image.height() as i32,
    })
}

fn ui_find_rect_valid(rect: Rect) -> bool {
    rect.width > 0 && rect.height > 0
}

fn map_ui_find_localization_error(err: LocalizationError, query: &str) -> ToolExecutionResult {
    match err {
        LocalizationError::LowConfidence(conf) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Visual localization confidence too low ({:.2}) for '{}'.",
            conf, query
        )),
        LocalizationError::OutOfBounds => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Visual localization for '{}' was outside active window.",
            query
        )),
        LocalizationError::ModelRefusal => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Vision model refused localization for '{}'.",
            query
        )),
        LocalizationError::TierViolation => ToolExecutionResult::failure(
            "ERROR_CLASS=TierViolation Vision localization is only allowed in VisualForeground tier.",
        ),
        LocalizationError::Runtime(err) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Vision runtime failed while localizing '{}': {}",
            query, err
        )),
        LocalizationError::InvalidOutput(err) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Vision localization output was invalid for '{}': {}",
            query, err
        )),
    }
}

async fn find_ui_with_vision(
    exec: &ToolExecutor,
    query: &str,
    hint_xml: Option<&str>,
    tree_rect: Option<Rect>,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    let screenshot = match exec.gui.capture_raw_screen().await {
        Ok(bytes) => bytes,
        Err(err) => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=MissingDependency Failed to capture screenshot for ui__find: {}",
                err
            ))
        }
    };

    let window_rect = ui_find_window_rect(exec)
        .or(tree_rect.filter(|rect| ui_find_rect_valid(*rect)))
        .or_else(|| ui_find_screen_rect_from_image(&screenshot))
        .unwrap_or(Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        });

    let locator = VisualLocator::new(exec.inference.clone());
    let point = match locator
        .localize(&screenshot, query, window_rect, hint_xml, exec.current_tier)
        .await
    {
        Ok(point) => point,
        Err(err) => return map_ui_find_localization_error(err, query),
    };

    build_ui_find_success(
        query,
        UiFindSemanticMatch {
            id: None,
            role: None,
            label: None,
            x: point.x.round() as i32,
            y: point.y.round() as i32,
            source: "visual_locator",
            confidence: 0.70,
        },
        active_lens,
        exec.current_tier,
    )
}

pub(super) async fn find_element_coordinates(
    exec: &ToolExecutor,
    query: &str,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    let query = query.trim();
    if query.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=TargetNotFound ui__find requires a non-empty query.",
        );
    }

    let mut tree_rect: Option<Rect> = None;
    let mut hint_xml: Option<String> = None;
    let mut tree_fetch_error: Option<String> = None;

    match fetch_lensed_tree(exec, active_lens).await {
        Ok(tree) => {
            if ui_find_rect_valid(tree.rect) {
                tree_rect = Some(tree.rect);
            }
            hint_xml = Some(ioi_drivers::gui::accessibility::serialize_tree_to_xml(
                &tree, 0,
            ));

            if let Some(found) = find_semantic_ui_match(&tree, query) {
                return build_ui_find_success(query, found, active_lens, exec.current_tier);
            }
        }
        Err(err) => {
            tree_fetch_error = Some(err);
        }
    }

    if resilience::allow_vision_fallback_for_tier(exec.current_tier) {
        return find_ui_with_vision(exec, query, hint_xml.as_deref(), tree_rect, active_lens).await;
    }

    if let Some(err) = tree_fetch_error {
        return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=MissingDependency ui__find could not inspect accessibility tree: {}",
            err
        ));
    }

    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=TargetNotFound ui__find could not locate '{}' in current semantic context. Retry in VisualForeground for vision-assisted localization.",
        query
    ))
}
