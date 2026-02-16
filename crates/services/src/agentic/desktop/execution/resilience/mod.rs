use super::computer::{click_element_by_id, exec_click, fetch_lensed_tree};
use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use image::load_from_memory;
use ioi_api::vm::drivers::gui::MouseButton;
use ioi_drivers::gui::accessibility::Rect;
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use tokio::time::{sleep, Duration};

pub mod locator;
pub mod verifier;

use locator::{LocalizationError, VisualLocator};
use verifier::{ActionVerifier, StateSnapshot, VerificationResult};

pub async fn execute_reflexive_click(
    exec: &ToolExecutor,
    target_id: Option<&str>,
    target_query: &str,
    active_lens: Option<&str>,
    allow_vision_fallback: bool,
) -> ToolExecutionResult {
    let query = if !target_query.trim().is_empty() {
        target_query.trim()
    } else {
        target_id.unwrap_or("").trim()
    };

    let pre_state = ActionVerifier::capture_snapshot(exec, active_lens)
        .await
        .ok();

    let mut result = match target_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => click_element_by_id(exec, id, active_lens).await,
        None => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound Target '{}' could not be resolved semantically.",
            query
        )),
    };

    if !result.success
        && allow_vision_fallback
        && is_target_resolution_failure(result.error.as_deref())
    {
        result = attempt_visual_click(exec, query, active_lens).await;
    }

    if !result.success {
        return result;
    }

    let Some(before) = pre_state else {
        return result;
    };

    let verification = match verify_after_click(exec, &before, active_lens).await {
        Ok(v) => v,
        Err(_) => return result,
    };

    if verification.is_significant() {
        return result;
    }

    // One retry: re-resolve semantically first, then vision if allowed.
    let mut retry = match target_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => click_element_by_id(exec, id, active_lens).await,
        None => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=NoEffectAfterAction UI state unchanged after click on '{}'.",
            query
        )),
    };

    if !retry.success
        && allow_vision_fallback
        && is_target_resolution_failure(retry.error.as_deref())
    {
        retry = attempt_visual_click(exec, query, active_lens).await;
    }

    if !retry.success {
        return retry;
    }

    match verify_after_click(exec, &before, active_lens).await {
        Ok(v) if v.is_significant() => retry,
        Ok(v) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=NoEffectAfterAction UI state static after click (tree_changed={}, visual_distance={}).",
            v.tree_changed, v.visual_distance
        )),
        Err(_) => retry,
    }
}

fn is_target_resolution_failure(error: Option<&str>) -> bool {
    let Some(msg) = error else {
        return false;
    };
    let lower = msg.to_ascii_lowercase();
    lower.contains("error_class=targetnotfound")
        || lower.contains("target") && (lower.contains("not found") || lower.contains("unresolved"))
        || lower.contains("element") && lower.contains("not found")
}

async fn verify_after_click(
    exec: &ToolExecutor,
    before: &StateSnapshot,
    active_lens: Option<&str>,
) -> Result<VerificationResult, String> {
    sleep(Duration::from_millis(220)).await;
    let after = ActionVerifier::capture_snapshot(exec, active_lens).await?;
    Ok(ActionVerifier::verify_impact(before, &after))
}

async fn attempt_visual_click(
    exec: &ToolExecutor,
    query: &str,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    let screenshot = match exec.gui.capture_raw_screen().await {
        Ok(bytes) => bytes,
        Err(e) => {
            return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Failed to capture screen for visual localization: {}",
            e
        ))
        }
    };

    let (hint_xml, tree_rect) = match fetch_lensed_tree(exec, active_lens).await {
        Ok(tree) => {
            let rect = if is_valid_rect(tree.rect) {
                Some(tree.rect)
            } else {
                None
            };
            let xml = ioi_drivers::gui::accessibility::serialize_tree_to_xml(&tree, 0);
            (Some(xml), rect)
        }
        Err(_) => (None, None),
    };

    let window_rect = window_rect_from_executor(exec)
        .or(tree_rect)
        .or_else(|| screen_rect_from_image(&screenshot))
        .unwrap_or(Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        });

    let locator = VisualLocator::new(
        exec.inference.clone(),
        exec.pii_scrubber.clone(),
        exec.event_sender.clone(),
    );
    let point = match locator
        .localize(
            &screenshot,
            query,
            window_rect,
            hint_xml.as_deref(),
            exec.current_tier,
        )
        .await
    {
        Ok(point) => point,
        Err(err) => return map_localization_error(err, query),
    };

    let transform = NativeOperator::current_display_transform();
    let target = ClickTarget::Exact(point);
    let resolved = match NativeOperator::resolve_click_target(target, &transform) {
        Ok(point) => point,
        Err(e) => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=VisionTargetNotFound Invalid localized click target for '{}': {}",
                query, e
            ))
        }
    };

    exec_click(exec, MouseButton::Left, target, resolved, transform, None).await
}

fn window_rect_from_executor(exec: &ToolExecutor) -> Option<Rect> {
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

fn screen_rect_from_image(image_bytes: &[u8]) -> Option<Rect> {
    let img = load_from_memory(image_bytes).ok()?;
    Some(Rect {
        x: 0,
        y: 0,
        width: img.width() as i32,
        height: img.height() as i32,
    })
}

fn is_valid_rect(rect: Rect) -> bool {
    rect.width > 0 && rect.height > 0
}

fn map_localization_error(err: LocalizationError, query: &str) -> ToolExecutionResult {
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
        LocalizationError::Runtime(e) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Vision runtime failed while localizing '{}': {}",
            query, e
        )),
        LocalizationError::InvalidOutput(e) => ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VisionTargetNotFound Vision localization output was invalid for '{}': {}",
            query, e
        )),
    }
}

pub fn allow_vision_fallback_for_tier(tier: Option<ExecutionTier>) -> bool {
    matches!(tier, Some(ExecutionTier::VisualForeground))
}
