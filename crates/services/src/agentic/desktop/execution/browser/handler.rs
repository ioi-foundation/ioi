use super::super::{ToolExecutionResult, ToolExecutor};
use super::element_click::{
    find_semantic_target_by_id, handle_browser_click_element, selector_fallback_candidates,
    BrowserSemanticTarget,
};
use super::selector_click::{ensure_browser_focus_guard, handle_browser_click};
use super::tree::{apply_browser_auto_lens, detect_human_challenge, render_browser_tree_xml};
use crate::agentic::desktop::middleware;
use ioi_drivers::gui::accessibility::AccessibilityNode;
use ioi_types::app::agentic::{AgentTool, AgentToolCall};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use tokio::time::{sleep, Duration, Instant};

const RECENT_BROWSER_HOVER_SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(5_000);
const DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS: u64 = 0;
const MIN_BROWSER_HOVER_TRACK_INTERVAL_MS: u64 = 0;
const MAX_BROWSER_HOVER_TRACK_INTERVAL_MS: u64 = 1_000;
const MAX_BROWSER_HOVER_TRACK_DURATION_MS: u64 = 30_000;
#[derive(Debug, Clone)]
struct ResolvedHoverTarget {
    x: f64,
    y: f64,
    target: serde_json::Value,
    tracking_selector: Option<String>,
}

fn semantic_candidates(semantic_blob: &str) -> Vec<String> {
    semantic_blob
        .split(',')
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(str::to_string)
        .collect()
}

async fn capture_browser_tree_xml(exec: &ToolExecutor) -> Option<String> {
    let raw_tree = exec.browser.get_accessibility_tree().await.ok()?;
    let transformed = apply_browser_auto_lens(raw_tree);
    Some(render_browser_tree_xml(&transformed))
}

fn normalize_browser_follow_up(
    call: &AgentToolCall,
    parent_tool_name: &str,
) -> Result<AgentTool, String> {
    let wrapper = json!({
        "name": call.name,
        "arguments": call.arguments,
    });
    let wrapper_json = serde_json::to_string(&wrapper)
        .map_err(|e| format!("{parent_tool_name} follow-up encoding failed: {}", e))?;
    let tool = middleware::normalize_tool_call(&wrapper_json)
        .map_err(|e| format!("{parent_tool_name} follow-up normalization failed: {}", e))?;
    if parent_tool_name == "browser__synthetic_click"
        && matches!(
            tool,
            AgentTool::BrowserMouseDown { .. } | AgentTool::BrowserMouseUp { .. }
        )
    {
        return Err(
            "browser__synthetic_click follow-up does not support pointer button state changes; use grounded drag tools as separate steps."
                .to_string(),
        );
    }
    if matches!(
        tool,
        AgentTool::BrowserClick { .. }
            | AgentTool::BrowserClickElement { .. }
            | AgentTool::BrowserWait { .. }
            | AgentTool::BrowserKey { .. }
            | AgentTool::BrowserHover { .. }
            | AgentTool::BrowserSyntheticClick { .. }
            | AgentTool::BrowserMoveMouse { .. }
            | AgentTool::BrowserMouseDown { .. }
            | AgentTool::BrowserMouseUp { .. }
            | AgentTool::BrowserScroll { .. }
            | AgentTool::BrowserSelectText { .. }
            | AgentTool::BrowserPasteClipboard { .. }
            | AgentTool::BrowserFindText { .. }
            | AgentTool::BrowserSelectDropdown { .. }
    ) {
        Ok(tool)
    } else {
        Err(format!(
            "{parent_tool_name} follow-up only supports immediate browser interaction tools; got '{}'.",
            call.name.trim(),
        ))
    }
}

fn history_entry_json_value(entry: Option<&str>) -> serde_json::Value {
    let Some(entry) = entry.map(str::trim).filter(|value| !value.is_empty()) else {
        return serde_json::Value::Null;
    };
    serde_json::from_str(entry).unwrap_or_else(|_| serde_json::Value::String(entry.to_string()))
}

fn browser_follow_up_activates_visible_control(tool: &AgentTool) -> Result<bool, String> {
    match tool {
        AgentTool::BrowserClick { .. } | AgentTool::BrowserClickElement { .. } => Ok(true),
        AgentTool::BrowserWait { continue_with, .. } => {
            let Some(continue_with) = continue_with.as_ref() else {
                return Ok(false);
            };
            let nested = normalize_browser_follow_up(continue_with, "browser__wait")?;
            browser_follow_up_activates_visible_control(&nested)
        }
        AgentTool::BrowserSyntheticClick { continue_with, .. } => {
            let Some(continue_with) = continue_with.as_ref() else {
                return Ok(false);
            };
            let nested = normalize_browser_follow_up(continue_with, "browser__synthetic_click")?;
            browser_follow_up_activates_visible_control(&nested)
        }
        _ => Ok(false),
    }
}

fn synthetic_click_postcondition_met(postcondition: &serde_json::Value) -> bool {
    postcondition
        .get("met")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn browser_semantic_target_is_actionable(target: &BrowserSemanticTarget) -> bool {
    target.backend_dom_node_id.is_some()
        || target.cdp_node_id.is_some()
        || target.center_point.is_some()
}

#[derive(Debug)]
struct DispatchedBrowserClickElement {
    id: String,
    method: String,
    center_point: Option<(f64, f64)>,
}

async fn dispatch_browser_click_element_without_verification(
    exec: &ToolExecutor,
    id: &str,
) -> Result<DispatchedBrowserClickElement, ToolExecutionResult> {
    if let Some(blocked) = ensure_browser_focus_guard(exec) {
        return Err(blocked);
    }

    let raw_tree = match exec.browser.get_accessibility_tree().await {
        Ok(tree) => tree,
        Err(e) => {
            return Err(ToolExecutionResult::failure(format!(
                "Failed to fetch browser accessibility tree: {}",
                e
            )))
        }
    };
    let transformed = apply_browser_auto_lens(raw_tree);
    let Some(semantic_target) = find_semantic_target_by_id(&transformed, id) else {
        return Err(ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__snapshot` again and retry with a fresh ID.",
            id
        )));
    };
    if !browser_semantic_target_is_actionable(&semantic_target) {
        return Err(ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
            id
        )));
    }

    let mut click_errors = Vec::new();
    if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
        match exec.browser.click_backend_dom_node(backend_id).await {
            Ok(()) => {
                return Ok(DispatchedBrowserClickElement {
                    id: id.to_string(),
                    method: "backend_dom_node_id".to_string(),
                    center_point: None,
                })
            }
            Err(e) => click_errors.push(format!("backend_dom_node_id={}", e)),
        }
    }
    if let Some(cdp_id) = semantic_target.cdp_node_id.as_deref() {
        match exec.browser.click_ax_node(cdp_id).await {
            Ok(()) => {
                return Ok(DispatchedBrowserClickElement {
                    id: id.to_string(),
                    method: "cdp_node_id".to_string(),
                    center_point: None,
                })
            }
            Err(e) => click_errors.push(format!("cdp_node_id={}", e)),
        }
    }
    if let Some((x, y)) = semantic_target.center_point {
        match exec.browser.synthetic_click(x, y).await {
            Ok(()) => {
                return Ok(DispatchedBrowserClickElement {
                    id: id.to_string(),
                    method: "geometry_center".to_string(),
                    center_point: Some((x, y)),
                })
            }
            Err(e) => click_errors.push(format!("geometry_center=({:.2},{:.2})={}", x, y, e)),
        }
    }
    for selector in selector_fallback_candidates(&semantic_target) {
        match exec.browser.click_selector(&selector).await {
            Ok(()) => {
                return Ok(DispatchedBrowserClickElement {
                    id: id.to_string(),
                    method: format!("selector_fallback:{selector}"),
                    center_point: None,
                })
            }
            Err(error) => click_errors.push(format!("selector_fallback({})={}", selector, error)),
        }
    }

    Err(ToolExecutionResult::failure(format!(
        "ERROR_CLASS=NoEffectAfterAction Failed to dispatch timed click element '{}'. click_errors={}",
        id,
        json!(click_errors)
    )))
}

async fn execute_browser_wait_follow_up(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    continue_with: &AgentToolCall,
) -> Result<ToolExecutionResult, String> {
    let tool = normalize_browser_follow_up(continue_with, "browser__wait")?;
    Ok(Box::pin(execute_normalized_browser_follow_up(
        exec,
        semantic_map,
        tool,
    ))
    .await)
}

async fn execute_browser_synthetic_click_follow_up(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    continue_with: &AgentToolCall,
    postcondition_met: bool,
) -> Result<ToolExecutionResult, String> {
    let tool = normalize_browser_follow_up(continue_with, "browser__synthetic_click")?;
    if !postcondition_met && browser_follow_up_activates_visible_control(&tool)? {
        return Err(
            "ERROR_CLASS=PostActionObservationRequired browser__synthetic_click continue_with cannot activate a visible control until the coordinate click is re-observed. Re-evaluate the page or surface before submit/commit clicks."
                .to_string(),
        );
    }
    Ok(Box::pin(execute_normalized_browser_follow_up(
        exec,
        semantic_map,
        tool,
    ))
    .await)
}

async fn execute_browser_click_follow_up(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    continue_with: &AgentToolCall,
) -> Result<ToolExecutionResult, String> {
    let tool = normalize_browser_follow_up(continue_with, "browser__click_element")?;
    Ok(Box::pin(execute_normalized_browser_follow_up(
        exec,
        semantic_map,
        tool,
    ))
    .await)
}

async fn execute_normalized_browser_follow_up(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    tool: AgentTool,
) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserClickElement {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
        } => {
            Box::pin(execute_browser_click_element_tool(
                exec,
                semantic_map,
                id,
                ids,
                delay_ms_between_ids,
                continue_with,
            ))
            .await
        }
        other => Box::pin(handle(exec, other, semantic_map)).await,
    }
}

async fn finalize_browser_click_result(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    click_result: ToolExecutionResult,
    continue_with: Option<AgentToolCall>,
) -> ToolExecutionResult {
    let Some(continue_with) = continue_with else {
        return click_result;
    };
    if !click_result.success {
        return click_result;
    }

    let click_entry = history_entry_json_value(click_result.history_entry.as_deref());
    let click_visual_observation = click_result.visual_observation;
    let follow_up_result =
        match execute_browser_click_follow_up(exec, semantic_map, &continue_with).await {
            Ok(result) => result,
            Err(reason) => {
                return ToolExecutionResult::failure(format!(
                    "Browser click follow-up failed: {}",
                    reason
                ))
            }
        };
    if !follow_up_result.success {
        let payload = json!({
            "click": click_entry,
            "continue_with": {
                "name": continue_with.name,
                "arguments": continue_with.arguments,
                "success": false,
                "error": follow_up_result.error,
            }
        });
        return ToolExecutionResult::failure(format!(
            "Browser click follow-up failed: {}",
            payload
        ));
    }

    let payload = json!({
        "click": click_entry,
        "continue_with": {
            "name": continue_with.name,
            "arguments": continue_with.arguments,
            "success": true,
            "result": history_entry_json_value(follow_up_result.history_entry.as_deref()),
        }
    });
    if let Some(visual_observation) = follow_up_result
        .visual_observation
        .or(click_visual_observation)
    {
        ToolExecutionResult::success_with_visual_observation(
            payload.to_string(),
            visual_observation,
        )
    } else {
        ToolExecutionResult::success(payload.to_string())
    }
}

async fn execute_browser_click_element_tool(
    exec: &ToolExecutor,
    semantic_map: Option<&BTreeMap<u32, String>>,
    id: Option<String>,
    ids: Vec<String>,
    delay_ms_between_ids: Option<u64>,
    continue_with: Option<AgentToolCall>,
) -> ToolExecutionResult {
    let ordered_ids: Vec<String> = if !ids.is_empty() {
        ids
    } else if let Some(single_id) = id {
        vec![single_id]
    } else {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidInput browser__click_element requires `id` or a non-empty `ids` list.",
        );
    };
    let click_result =
        handle_browser_click_elements(exec, &ordered_ids, delay_ms_between_ids).await;
    finalize_browser_click_result(exec, semantic_map, click_result, continue_with).await
}

fn synthetic_click_postcondition_payload(
    pre_tree_xml: Option<&str>,
    pre_url: Option<&str>,
    post_tree_xml: Option<&str>,
    post_url: Option<&str>,
) -> serde_json::Value {
    let tree_changed = pre_tree_xml
        .zip(post_tree_xml)
        .is_some_and(|(pre, post)| pre != post);
    let url_changed = pre_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .zip(post_url.map(str::trim).filter(|value| !value.is_empty()))
        .is_some_and(|(pre, post)| pre != post);

    json!({
        "met": tree_changed || url_changed,
        "tree_changed": tree_changed,
        "url_changed": url_changed,
    })
}

async fn handle_browser_click_elements(
    exec: &ToolExecutor,
    ids: &[String],
    delay_ms_between_ids: Option<u64>,
) -> ToolExecutionResult {
    if ids.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidInput browser__click_element requires `id` or a non-empty `ids` list.",
        );
    }

    if !ids.is_empty() && delay_ms_between_ids.is_some() && ids.len() < 2 {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidInput browser__click_element delay_ms_between_ids requires at least two ordered `ids`.",
        );
    }

    if ids.len() == 1 {
        return handle_browser_click_element(exec, &ids[0]).await;
    }

    if let Some(delay_ms_between_ids) = delay_ms_between_ids {
        if delay_ms_between_ids == 0 || delay_ms_between_ids > 30_000 {
            return ToolExecutionResult::failure(
                "ERROR_CLASS=InvalidInput browser__click_element delay_ms_between_ids must be between 1 and 30000.",
            );
        }
    }

    let mut intermediate_dispatches = Vec::new();
    for id in ids.iter().take(ids.len() - 1) {
        let delay_deadline =
            delay_ms_between_ids.map(|delay_ms| Instant::now() + Duration::from_millis(delay_ms));
        let dispatch = match dispatch_browser_click_element_without_verification(exec, id).await {
            Ok(dispatch) => dispatch,
            Err(error) => return error,
        };
        let mut dispatch_payload = json!({
            "id": dispatch.id,
            "method": dispatch.method,
        });
        if let Some((x, y)) = dispatch.center_point {
            dispatch_payload["center_point"] = json!([x, y]);
        }
        intermediate_dispatches.push(dispatch_payload);

        if let Some(delay_deadline) = delay_deadline {
            let remaining = delay_deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                sleep(remaining).await;
            }
        }
    }

    let final_id = ids
        .last()
        .expect("multi-id click sequence should have final id");
    let final_result = handle_browser_click_element(exec, final_id).await;
    if !final_result.success {
        let payload = json!({
            "ids": ids,
            "delay_ms_between_ids": delay_ms_between_ids,
            "intermediate_dispatches": intermediate_dispatches,
            "final_id": final_id,
            "final_error": final_result.error,
        });
        return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=PartialBatchClickFailed {}",
            payload
        ));
    }

    let payload = json!({
        "ids": ids,
        "delay_ms_between_ids": delay_ms_between_ids,
        "intermediate_dispatches": intermediate_dispatches,
        "final_result": history_entry_json_value(final_result.history_entry.as_deref()),
    });
    if let Some(visual_observation) = final_result.visual_observation {
        return ToolExecutionResult::success_with_visual_observation(
            payload.to_string(),
            visual_observation,
        );
    }
    ToolExecutionResult::success(payload.to_string())
}

fn resolve_home_directory() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(user_profile) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(user_profile));
    }
    if let (Some(home_drive), Some(home_path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        if !home_drive.is_empty() && !home_path.is_empty() {
            let mut combined = PathBuf::from(home_drive);
            combined.push(home_path);
            return Ok(combined);
        }
    }
    Err("Home directory is not configured (HOME/USERPROFILE).".to_string())
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        return resolve_home_directory();
    }
    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Ok(resolve_home_directory()?.join(remainder));
    }
    Ok(PathBuf::from(path))
}

fn resolve_upload_scope_root(cwd: Option<&str>) -> Result<PathBuf, String> {
    let normalized = cwd.unwrap_or(".").trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        expand_tilde_path(normalized)?
    };
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        env::current_dir()
            .map_err(|e| format!("Failed to resolve current directory: {}", e))?
            .join(candidate)
    };
    let canonical = std::fs::canonicalize(&absolute).map_err(|e| {
        format!(
            "Failed to resolve upload scope root '{}': {}",
            absolute.display(),
            e
        )
    })?;
    if !canonical.is_dir() {
        return Err(format!(
            "Upload scope root '{}' is not a directory.",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn resolve_scoped_upload_paths(paths: &[String], cwd: Option<&str>) -> Result<Vec<String>, String> {
    if paths.is_empty() {
        return Err("browser__upload_file requires at least one path".to_string());
    }

    let scope_root = resolve_upload_scope_root(cwd)?;
    let mut resolved = Vec::with_capacity(paths.len());

    for raw in paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("browser__upload_file paths cannot be empty".to_string());
        }

        let requested = expand_tilde_path(trimmed)?;
        let candidate = if requested.is_absolute() {
            requested
        } else {
            scope_root.join(requested)
        };

        let canonical = std::fs::canonicalize(&candidate).map_err(|e| {
            format!(
                "Failed to resolve upload path '{}' within scope '{}': {}",
                trimmed,
                scope_root.display(),
                e
            )
        })?;
        if !canonical.is_file() {
            return Err(format!(
                "Upload path is not a file: '{}'",
                canonical.display()
            ));
        }
        if !canonical.starts_with(&scope_root) {
            return Err(format!(
                "Upload path '{}' is outside allowed scope root '{}'.",
                canonical.display(),
                scope_root.display()
            ));
        }

        resolved.push(canonical.to_string_lossy().to_string());
    }

    Ok(resolved)
}

async fn resolve_semantic_target_from_som(
    exec: &ToolExecutor,
    som_id: u32,
    semantic_map: Option<&BTreeMap<u32, String>>,
) -> Result<super::element_click::BrowserSemanticTarget, String> {
    let semantic_map = semantic_map.ok_or_else(|| {
        "SoM map unavailable. Run a fresh perception step before using som_id.".to_string()
    })?;
    let semantic_blob = semantic_map
        .get(&som_id)
        .ok_or_else(|| format!("SoM id '{}' not found in current semantic map.", som_id))?;
    let candidates = semantic_candidates(semantic_blob);
    if candidates.is_empty() {
        return Err(format!(
            "SoM id '{}' has no semantic candidates in the current map.",
            som_id
        ));
    }

    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("Failed to fetch browser accessibility tree: {}", e))?;
    let transformed = apply_browser_auto_lens(raw_tree);

    for candidate in candidates {
        if let Some(target) = find_semantic_target_by_id(&transformed, &candidate) {
            return Ok(target);
        }
    }

    Err(format!(
        "None of the semantic IDs for SoM id '{}' are present in the current browser snapshot.",
        som_id
    ))
}

async fn resolve_browser_target_from_id(
    exec: &ToolExecutor,
    id: &str,
) -> Result<BrowserSemanticTarget, String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("semantic browser id cannot be empty".to_string());
    }

    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("Failed to fetch browser accessibility tree: {}", e))?;
    let transformed = apply_browser_auto_lens(raw_tree);

    find_semantic_target_by_id(&transformed, id).ok_or_else(|| {
        format!(
            "Semantic browser id '{}' not found in current browser snapshot.",
            id
        )
    })
}

fn browser_type_selector_lookup_token(selector: &str) -> Option<&str> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    let token = selector.strip_prefix('#').unwrap_or(selector);
    if token.is_empty()
        || token
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return None;
    }

    Some(token)
}

fn browser_type_selector_fallbacks_for_target(
    requested_selector: &str,
    target: &BrowserSemanticTarget,
) -> Vec<String> {
    let requested_selector = requested_selector.trim();
    selector_fallback_candidates(target)
        .into_iter()
        .filter(|candidate| candidate.trim() != requested_selector)
        .collect()
}

async fn browser_type_selector_candidates(
    exec: &ToolExecutor,
    selector: Option<&str>,
) -> Vec<Option<String>> {
    let Some(requested_selector) = selector
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
        .map(str::to_string)
    else {
        return vec![None];
    };

    let mut candidates = vec![Some(requested_selector.clone())];
    let Some(token) = browser_type_selector_lookup_token(&requested_selector) else {
        return candidates;
    };

    let Ok(target) = resolve_browser_target_from_id(exec, token).await else {
        return candidates;
    };

    for fallback in browser_type_selector_fallbacks_for_target(&requested_selector, &target) {
        if !candidates
            .iter()
            .flatten()
            .any(|candidate| candidate == &fallback)
        {
            candidates.push(Some(fallback));
        }
    }

    candidates
}

fn browser_type_error_supports_selector_retry(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("failed to focus selector")
        || message.contains("selector focus failed")
        || message.contains("target not found")
}

fn normalized_browser_button(button: Option<&str>) -> &'static str {
    match button
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("right") => "right",
        Some("middle") => "middle",
        Some("back") => "back",
        Some("forward") => "forward",
        _ => "left",
    }
}

async fn resolve_hover_target(
    exec: &ToolExecutor,
    selector: Option<&str>,
    id: Option<&str>,
) -> Result<ResolvedHoverTarget, String> {
    let selector = selector
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let id = id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    if selector.is_some() == id.is_some() {
        return Err("provide exactly one of selector or id".to_string());
    }

    if let Some(selector) = selector {
        let rect = exec
            .browser
            .get_selector_rect_window_logical(&selector)
            .await
            .map_err(|e| format!("resolve hover selector '{}': {}", selector, e))?;
        let center = rect.center();
        let tracking_selector = selector.clone();
        return Ok(ResolvedHoverTarget {
            x: center.x,
            y: center.y,
            target: json!({
                "selector": selector,
                "target_kind": "selector",
            }),
            tracking_selector: Some(tracking_selector),
        });
    }

    let id = id.expect("exactly one hover locator should be present");
    let recent_tree = exec
        .browser
        .recent_accessibility_snapshot(RECENT_BROWSER_HOVER_SNAPSHOT_MAX_AGE)
        .await
        .map(|(_snapshot_url, tree)| apply_browser_auto_lens(tree));
    if let Some(tree) = recent_tree.as_ref() {
        if let Ok(target) = resolve_hover_target_from_transformed_trees(&id, None, Some(tree)) {
            return Ok(target);
        }
    }
    let raw_tree = exec
        .browser
        .get_accessibility_tree()
        .await
        .map_err(|e| format!("resolve hover semantic id '{}': {}", id, e))?;
    let transformed = apply_browser_auto_lens(raw_tree);
    resolve_hover_target_from_transformed_trees(&id, Some(&transformed), recent_tree.as_ref())
}

async fn resolve_tracked_hover_target(
    exec: &ToolExecutor,
    selector: Option<&str>,
    id: Option<&str>,
    tracking_selector: Option<&str>,
) -> Result<ResolvedHoverTarget, String> {
    if let Some(selector) = selector {
        return resolve_hover_target(exec, Some(selector), None).await;
    }

    let id = id.expect("hover tracking requires a semantic id or selector");
    if let Some(tracking_selector) = tracking_selector {
        if let Ok(rect) = exec
            .browser
            .get_selector_rect_window_logical(tracking_selector)
            .await
        {
            let center = rect.center();
            return Ok(ResolvedHoverTarget {
                x: center.x,
                y: center.y,
                target: json!({
                    "id": id,
                    "target_kind": "semantic_id",
                    "resolved_from": "selector_rect_tracking",
                    "tracking_selector": tracking_selector,
                }),
                tracking_selector: Some(tracking_selector.to_string()),
            });
        }
    }

    resolve_hover_target(exec, None, Some(id)).await
}

fn hover_tracking_selector(target: &BrowserSemanticTarget) -> Option<String> {
    selector_fallback_candidates(target).into_iter().next()
}

fn resolve_hover_semantic_target_from_transformed_trees(
    id: &str,
    current_tree: Option<&AccessibilityNode>,
    recent_tree: Option<&AccessibilityNode>,
) -> Result<(BrowserSemanticTarget, &'static str), String> {
    for (tree, resolved_from) in [
        (current_tree, "current_accessibility_tree"),
        (recent_tree, "recent_accessibility_snapshot"),
    ] {
        let Some(tree) = tree else {
            continue;
        };
        let Some(target) = find_semantic_target_by_id(tree, id) else {
            continue;
        };
        return Ok((target, resolved_from));
    }

    Err(format!("semantic browser target '{}' not found", id))
}

fn resolve_hover_target_from_transformed_trees(
    id: &str,
    current_tree: Option<&AccessibilityNode>,
    recent_tree: Option<&AccessibilityNode>,
) -> Result<ResolvedHoverTarget, String> {
    let (target, resolved_from) =
        resolve_hover_semantic_target_from_transformed_trees(id, current_tree, recent_tree)?;
    let center = target
        .center_point
        .ok_or_else(|| format!("semantic browser target '{}' has no geometry center", id))?;
    let tracking_selector = hover_tracking_selector(&target);
    let payload_tracking_selector = tracking_selector.clone();
    let payload_selector = target.selector.clone();
    let payload_dom_id = target.dom_id.clone();
    let payload_backend_dom_node_id = target.backend_dom_node_id.clone();
    let payload_cdp_node_id = target.cdp_node_id.clone();
    Ok(ResolvedHoverTarget {
        x: center.0,
        y: center.1,
        target: json!({
            "id": id,
            "target_kind": "semantic_id",
            "resolved_from": resolved_from,
            "focused": target.focused,
            "editable": target.editable,
            "tag_name": target.tag_name,
            "backend_dom_node_id": payload_backend_dom_node_id,
            "cdp_node_id": payload_cdp_node_id,
            "dom_id": payload_dom_id,
            "selector": payload_selector,
            "tracking_selector": payload_tracking_selector,
        }),
        tracking_selector,
    })
}

fn normalize_hover_tracking_window(
    duration_ms: Option<u64>,
    resample_interval_ms: Option<u64>,
) -> Result<Option<(u64, u64)>, String> {
    let Some(duration_ms) = duration_ms else {
        if resample_interval_ms.is_some() {
            return Err("browser__hover resample_interval_ms requires duration_ms.".to_string());
        }
        return Ok(None);
    };

    if duration_ms == 0 || duration_ms > MAX_BROWSER_HOVER_TRACK_DURATION_MS {
        return Err(format!(
            "browser__hover duration_ms must be between 1 and {}.",
            MAX_BROWSER_HOVER_TRACK_DURATION_MS
        ));
    }

    let resample_interval_ms =
        resample_interval_ms.unwrap_or(DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS);
    if !(MIN_BROWSER_HOVER_TRACK_INTERVAL_MS..=MAX_BROWSER_HOVER_TRACK_INTERVAL_MS)
        .contains(&resample_interval_ms)
    {
        return Err(format!(
            "browser__hover resample_interval_ms must be between {} and {}.",
            MIN_BROWSER_HOVER_TRACK_INTERVAL_MS, MAX_BROWSER_HOVER_TRACK_INTERVAL_MS
        ));
    }

    Ok(Some((duration_ms, resample_interval_ms)))
}

fn should_use_browser_side_hover_tracking(
    tracking_window: Option<(u64, u64)>,
    selector: Option<&str>,
    pointer_buttons: i64,
) -> bool {
    tracking_window.is_some_and(|(_, resample_interval_ms)| resample_interval_ms == 0)
        && selector.is_some()
        && pointer_buttons == 0
}

async fn confirm_selector_hover(exec: &ToolExecutor, selector: &str, x: f64, y: f64) -> bool {
    for attempt in 0..3 {
        if exec
            .browser
            .is_selector_hovered(selector)
            .await
            .unwrap_or(false)
        {
            return true;
        }
        if attempt >= 2 {
            break;
        }
        sleep(Duration::from_millis(35)).await;
        if exec.browser.move_mouse(x, y).await.is_err() {
            break;
        }
    }
    false
}

fn record_hover_resolution_counters(
    target: &ResolvedHoverTarget,
    recent_snapshot_resolutions: &mut u32,
    selector_rect_resolutions: &mut u32,
) {
    match target
        .target
        .get("resolved_from")
        .and_then(serde_json::Value::as_str)
    {
        Some("recent_accessibility_snapshot") => {
            *recent_snapshot_resolutions += 1;
        }
        Some("selector_rect_tracking") => {
            *selector_rect_resolutions += 1;
        }
        _ => {}
    }
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    semantic_map: Option<&BTreeMap<u32, String>>,
) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url } => match exec.browser.navigate(&url).await {
            Ok(content) => {
                if let Some(reason) = detect_human_challenge(&url, &content) {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually in your own browser/app, then resume: {}",
                        reason, url
                    ));
                }

                ToolExecutionResult::success(format!(
                    "Navigated to {}. Content len: {}",
                    url,
                    content.len()
                ))
            }
            Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
        },
        AgentTool::BrowserSnapshot {} => match exec.browser.get_accessibility_tree().await {
            Ok(raw_tree) => {
                let transformed = apply_browser_auto_lens(raw_tree);
                ToolExecutionResult::success(render_browser_tree_xml(&transformed))
            }
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => handle_browser_click(exec, &selector).await,
        AgentTool::BrowserClickElement {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
        } => {
            execute_browser_click_element_tool(
                exec,
                semantic_map,
                id,
                ids,
                delay_ms_between_ids,
                continue_with,
            )
            .await
        }
        AgentTool::BrowserHover {
            selector,
            id,
            duration_ms,
            resample_interval_ms,
        } => {
            let tracking_window =
                match normalize_hover_tracking_window(duration_ms, resample_interval_ms) {
                    Ok(window) => window,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=InvalidInput Browser hover failed: {}",
                            reason
                        ))
                    }
                };
            let selector_ref = selector.as_deref();
            let id_ref = id.as_deref();
            match resolve_hover_target(exec, selector_ref, id_ref).await {
                Ok(initial_target) => {
                    let tracking_selector = initial_target.tracking_selector.clone();
                    let mut target = initial_target;
                    if tracking_window.is_some() {
                        if let Ok(refreshed_target) = resolve_tracked_hover_target(
                            exec,
                            selector_ref,
                            id_ref,
                            tracking_selector.as_deref(),
                        )
                        .await
                        {
                            target = refreshed_target;
                        }
                    }
                    let mut tracking_samples = 0u32;
                    let mut tracking_refresh_failures = 0u32;
                    let mut recent_snapshot_resolutions = 0u32;
                    let mut selector_rect_resolutions = 0u32;
                    let mut synthetic_event_refreshes = 0u32;
                    let mut used_animation_frame_refresh = false;
                    let tracking_deadline =
                        tracking_window.map(|(duration_ms, _)| Instant::now() + Duration::from_millis(duration_ms));
                    let pointer_buttons = exec.browser.pointer_state().await.buttons;
                    if should_use_browser_side_hover_tracking(
                        tracking_window,
                        selector_ref,
                        pointer_buttons,
                    ) {
                        let Some((duration_ms, _)) = tracking_window else {
                            unreachable!("browser-side hover tracking requires a timing window");
                        };
                        let Some(selector_for_tracking) = tracking_selector.as_deref() else {
                            unreachable!("browser-side hover tracking requires a selector");
                        };
                        match exec
                            .browser
                            .track_selector_hover(selector_for_tracking, duration_ms, false)
                            .await
                        {
                            Ok(outcome) if outcome.dispatched => {
                                synthetic_event_refreshes = outcome.samples;
                                tracking_samples = outcome.samples;
                                used_animation_frame_refresh = outcome.used_animation_frame;
                                if let (Some(last_x), Some(last_y)) =
                                    (outcome.last_x, outcome.last_y)
                                {
                                    target.x = last_x;
                                    target.y = last_y;
                                }
                            }
                            Ok(_) | Err(_) => {
                                tracking_refresh_failures += 1;
                            }
                        }
                    } else {
                        loop {
                            match exec.browser.move_mouse(target.x, target.y).await {
                                Ok(()) => {}
                                Err(e) => {
                                    return ToolExecutionResult::failure(format!(
                                        "Browser hover failed: {}",
                                        e
                                    ))
                                }
                            }

                            tracking_samples += 1;
                            record_hover_resolution_counters(
                                &target,
                                &mut recent_snapshot_resolutions,
                                &mut selector_rect_resolutions,
                            );

                            let Some((_, resample_interval_ms)) = tracking_window else {
                                break;
                            };
                            let Some(deadline) = tracking_deadline else {
                                break;
                            };
                            if Instant::now() >= deadline {
                                break;
                            }

                            if resample_interval_ms > 0 {
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                sleep(remaining.min(Duration::from_millis(resample_interval_ms)))
                                    .await;
                            }
                            if Instant::now() >= deadline {
                                break;
                            }

                            match resolve_tracked_hover_target(
                                exec,
                                selector_ref,
                                id_ref,
                                tracking_selector.as_deref(),
                            )
                            .await
                            {
                                Ok(next_target) => {
                                    target = next_target;
                                }
                                Err(_) => {
                                    tracking_refresh_failures += 1;
                                }
                            }
                        }
                    }

                    if tracking_window.is_some() {
                        if let Ok(next_target) = resolve_tracked_hover_target(
                            exec,
                            selector_ref,
                            id_ref,
                            tracking_selector.as_deref(),
                        )
                        .await
                        {
                            target = next_target;
                            if exec.browser.move_mouse(target.x, target.y).await.is_ok() {
                                tracking_samples += 1;
                                match target
                                    .target
                                    .get("resolved_from")
                                    .and_then(serde_json::Value::as_str)
                                {
                                    Some("recent_accessibility_snapshot") => {
                                        recent_snapshot_resolutions += 1;
                                    }
                                    Some("selector_rect_tracking") => {
                                        selector_rect_resolutions += 1;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    let hovered = if let Some(selector) = selector_ref {
                        Some(confirm_selector_hover(exec, selector, target.x, target.y).await)
                    } else {
                        None
                    };
                    let mut payload = json!({
                        "pointer": {
                            "action": "hover",
                            "x": target.x,
                            "y": target.y,
                            "target": target.target,
                            "hovered": hovered,
                        }
                    });
                    if let Some((duration_ms, resample_interval_ms)) = tracking_window {
                        payload["tracking"] = json!({
                            "duration_ms": duration_ms,
                            "resample_interval_ms": resample_interval_ms,
                            "samples": tracking_samples,
                            "refresh_failures": tracking_refresh_failures,
                            "recent_snapshot_resolutions": recent_snapshot_resolutions,
                            "selector_rect_resolutions": selector_rect_resolutions,
                            "synthetic_event_refreshes": synthetic_event_refreshes,
                            "used_animation_frame_refresh": used_animation_frame_refresh,
                        });
                    }
                    if selector_ref.is_some() && hovered != Some(true) {
                        ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=NoEffectAfterAction Browser hover target was not hovered: {}",
                            payload
                        ))
                    } else {
                        ToolExecutionResult::success(payload.to_string())
                    }
                }
                Err(reason) => {
                    ToolExecutionResult::failure(format!("Browser hover failed: {}", reason))
                }
            }
        }
        AgentTool::BrowserMoveMouse { x, y } => match exec.browser.move_mouse(x as f64, y as f64).await {
            Ok(()) => {
                let state = exec.browser.pointer_state().await;
                let payload = json!({
                    "pointer": {
                        "action": "move",
                        "x": state.x,
                        "y": state.y,
                        "buttons": state.buttons,
                    }
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser mouse move failed: {}", e)),
        },
        AgentTool::BrowserMouseDown { button } => {
            let button = normalized_browser_button(button.as_deref());
            let state = exec.browser.pointer_state().await;
            match exec.browser.mouse_down(state.x, state.y, button).await {
                Ok(()) => {
                    let state = exec.browser.pointer_state().await;
                    let payload = json!({
                        "pointer": {
                            "action": "mouse_down",
                            "button": button,
                            "x": state.x,
                            "y": state.y,
                            "buttons": state.buttons,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser mouse down failed: {}", e)),
            }
        }
        AgentTool::BrowserMouseUp { button } => {
            let button = normalized_browser_button(button.as_deref());
            let state = exec.browser.pointer_state().await;
            match exec.browser.mouse_up(state.x, state.y, button).await {
                Ok(()) => {
                    let state = exec.browser.pointer_state().await;
                    let payload = json!({
                        "pointer": {
                            "action": "mouse_up",
                            "button": button,
                            "x": state.x,
                            "y": state.y,
                            "buttons": state.buttons,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser mouse up failed: {}", e)),
            }
        }
        AgentTool::BrowserSyntheticClick {
            x,
            y,
            continue_with,
        } => {
            let pre_tree_xml = capture_browser_tree_xml(exec).await;
            let pre_url = exec.browser.active_url().await.ok();
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => {
                    let post_tree_xml = capture_browser_tree_xml(exec).await;
                    let post_url = exec.browser.active_url().await.ok();
                    let click_payload = json!({
                        "synthetic_click": {
                            "x": x,
                            "y": y,
                        },
                        "postcondition": synthetic_click_postcondition_payload(
                            pre_tree_xml.as_deref(),
                            pre_url.as_deref(),
                            post_tree_xml.as_deref(),
                            post_url.as_deref(),
                        ),
                    });

                    if let Some(continue_with) = continue_with {
                        let follow_up_result =
                            match execute_browser_synthetic_click_follow_up(
                                exec,
                                semantic_map,
                                &continue_with,
                                synthetic_click_postcondition_met(&click_payload["postcondition"]),
                            )
                            .await
                            {
                                Ok(result) => result,
                                Err(reason) => {
                                    return ToolExecutionResult::failure(format!(
                                        "Browser synthetic click follow-up failed: {}",
                                        reason
                                    ))
                                }
                            };
                        if !follow_up_result.success {
                            let payload = json!({
                                "synthetic_click": click_payload["synthetic_click"].clone(),
                                "postcondition": click_payload["postcondition"].clone(),
                                "continue_with": {
                                    "name": continue_with.name,
                                    "arguments": continue_with.arguments,
                                    "success": false,
                                    "error": follow_up_result.error,
                                }
                            });
                            return ToolExecutionResult::failure(format!(
                                "Browser synthetic click follow-up failed: {}",
                                payload
                            ));
                        }

                        let payload = json!({
                            "synthetic_click": click_payload["synthetic_click"].clone(),
                            "postcondition": click_payload["postcondition"].clone(),
                            "continue_with": {
                                "name": continue_with.name,
                                "arguments": continue_with.arguments,
                                "success": true,
                                "result": history_entry_json_value(
                                    follow_up_result.history_entry.as_deref()
                                ),
                            }
                        });
                        if let Some(visual_observation) = follow_up_result.visual_observation {
                            ToolExecutionResult::success_with_visual_observation(
                                payload.to_string(),
                                visual_observation,
                            )
                        } else {
                            ToolExecutionResult::success(payload.to_string())
                        }
                    } else {
                        ToolExecutionResult::success(click_payload.to_string())
                    }
                }
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            match exec.browser.scroll(delta_x, delta_y).await {
                Ok(outcome) => {
                    let payload = json!({ "scroll": outcome });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser scroll failed: {}", e)),
            }
        }
        AgentTool::BrowserType { text, selector } => {
            let selector_candidates = browser_type_selector_candidates(exec, selector.as_deref()).await;
            let mut last_error = None;

            for (index, candidate) in selector_candidates.iter().enumerate() {
                match exec.browser.type_text(&text, candidate.as_deref()).await {
                    Ok(outcome) => {
                    let payload = json!({
                        "typed": {
                            "requested_selector": selector,
                            "resolved_selector": candidate,
                            "selector": outcome.selector,
                            "dom_id": outcome.dom_id,
                            "tag_name": outcome.tag_name,
                            "text": text,
                            "value": outcome.value,
                            "focused": outcome.focused,
                            "scroll_top": outcome.scroll_top,
                            "scroll_height": outcome.scroll_height,
                            "client_height": outcome.client_height,
                            "can_scroll_up": outcome.can_scroll_up,
                            "can_scroll_down": outcome.can_scroll_down,
                            "already_satisfied": outcome.already_satisfied,
                            "autocomplete": outcome.autocomplete,
                        }
                    });
                        return ToolExecutionResult::success(payload.to_string());
                    }
                    Err(e) => {
                        let message = e.to_string();
                        last_error = Some(message.clone());
                        let has_more_candidates = index + 1 < selector_candidates.len();
                        if !(has_more_candidates && browser_type_error_supports_selector_retry(&message)) {
                            break;
                        }
                    }
                }
            }

            ToolExecutionResult::failure(format!(
                "Browser type failed: {}",
                last_error.unwrap_or_else(|| "unknown type error".to_string())
            ))
        }
        AgentTool::BrowserSelectText {
            selector,
            start_offset,
            end_offset,
        } => match exec
            .browser
            .select_text(selector.as_deref(), start_offset, end_offset)
            .await
        {
            Ok(result) if result.found && !result.selected_text.is_empty() => {
                let payload = json!({
                    "selection": {
                        "selector": selector,
                        "target_kind": result.target_kind,
                        "selected_text": result.selected_text,
                        "start_offset": result.start_offset,
                        "end_offset": result.end_offset,
                        "text_length": result.text_length,
                        "focused": result.focused,
                        "collapsed": result.collapsed,
                    }
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Ok(result) if !result.found => {
                ToolExecutionResult::failure("Browser select text failed: target not found")
            }
            Ok(result) => ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Browser select text produced an empty selection: {}",
                json!({ "selection": result })
            )),
            Err(e) => ToolExecutionResult::failure(format!("Browser select text failed: {}", e)),
        },
        AgentTool::BrowserKey { key, modifiers } => {
            let modifiers = modifiers.unwrap_or_default();
            match exec.browser.press_key(&key, &modifiers).await {
                Ok(outcome) => {
                    let payload = json!({
                        "key": {
                            "key": key,
                            "modifiers": modifiers,
                            "is_chord": !modifiers.is_empty(),
                            "selector": outcome.selector,
                            "dom_id": outcome.dom_id,
                            "tag_name": outcome.tag_name,
                            "value": outcome.value,
                            "focused": outcome.focused,
                            "scroll_top": outcome.scroll_top,
                            "scroll_height": outcome.scroll_height,
                            "client_height": outcome.client_height,
                            "can_scroll_up": outcome.can_scroll_up,
                            "can_scroll_down": outcome.can_scroll_down,
                            "autocomplete": outcome.autocomplete,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Err(e) => ToolExecutionResult::failure(format!("Browser key press failed: {}", e)),
            }
        }
        AgentTool::BrowserCopySelection {} => match exec.browser.read_selection().await {
            Ok(selection) if selection.found && !selection.selected_text.is_empty() => {
                match exec.os.set_clipboard(&selection.selected_text).await {
                    Ok(()) => {
                        let payload = json!({
                            "clipboard": {
                                "action": "copy_selection",
                                "target_kind": selection.target_kind,
                                "text": selection.selected_text,
                                "text_length": selection.selected_text.chars().count(),
                                "selection_start": selection.start_offset,
                                "selection_end": selection.end_offset,
                            }
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(err) => ToolExecutionResult::failure(format!(
                        "Browser copy selection failed: {}",
                        err
                    )),
                }
            }
            Ok(selection) => ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Browser copy selection has no selected text: {}",
                json!({ "selection": selection })
            )),
            Err(e) => ToolExecutionResult::failure(format!("Browser copy selection failed: {}", e)),
        },
        AgentTool::BrowserPasteClipboard { selector } => match exec.os.get_clipboard().await {
            Ok(clipboard_text) if !clipboard_text.is_empty() => {
                match exec
                    .browser
                    .type_text(&clipboard_text, selector.as_deref())
                    .await
                {
                    Ok(outcome) => {
                        let payload = json!({
                            "clipboard": {
                                "action": "paste_clipboard",
                                "selector": outcome.selector,
                                "text": clipboard_text,
                                "text_length": clipboard_text.chars().count(),
                                "value": outcome.value,
                                "focused": outcome.focused,
                                "autocomplete": outcome.autocomplete,
                            }
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser paste clipboard failed: {}",
                        e
                    )),
                }
            }
            Ok(_) => ToolExecutionResult::failure(
                "ERROR_CLASS=NoEffectAfterAction Browser paste clipboard has no clipboard text",
            ),
            Err(err) => ToolExecutionResult::failure(format!(
                "Browser paste clipboard failed: {}",
                err
            )),
        },
        AgentTool::BrowserFindText {
            query,
            scope,
            scroll,
        } => match exec
            .browser
            .find_text(&query, scope.as_deref(), scroll)
            .await
        {
            Ok(result) => {
                let payload = json!({
                    "query": query,
                    "result": result,
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser find_text failed: {}", e)),
        },
        AgentTool::BrowserCanvasSummary { selector } => {
            match exec.browser.selector_canvas_shape_summary(&selector).await {
                Ok(summary) if summary.found => {
                    let payload = json!({
                        "canvas": {
                            "selector": selector,
                            "summary": summary,
                        }
                    });
                    ToolExecutionResult::success(payload.to_string())
                }
                Ok(_) => ToolExecutionResult::failure(format!(
                    "Browser canvas summary failed: selector '{}' not found",
                    selector
                )),
                Err(e) => {
                    ToolExecutionResult::failure(format!("Browser canvas summary failed: {}", e))
                }
            }
        }
        AgentTool::BrowserScreenshot { full_page } => {
            match exec.browser.capture_tab_screenshot(full_page).await {
                Ok(image_bytes) => ToolExecutionResult::success_with_visual_observation(
                    format!(
                        "Captured browser screenshot (full_page={}, bytes={})",
                        full_page,
                        image_bytes.len()
                    ),
                    image_bytes,
                ),
                Err(e) => ToolExecutionResult::failure(format!("Browser screenshot failed: {}", e)),
            }
        }
        AgentTool::BrowserWait {
            ms,
            condition,
            selector,
            query,
            scope,
            timeout_ms,
            continue_with,
        } => {
            let normalized_condition = condition
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if normalized_condition.is_some() && ms.is_some() {
                return ToolExecutionResult::failure(
                    "Browser wait failed: provide either 'ms' or 'condition', not both.",
                );
            }

            let wait_payload = if let Some(condition) = normalized_condition {
                let timeout_ms = timeout_ms.unwrap_or(5_000);
                match exec
                    .browser
                    .wait_for_condition(
                        condition,
                        selector.as_deref(),
                        query.as_deref(),
                        scope.as_deref(),
                        timeout_ms,
                    )
                    .await
                {
                    Ok(result) if result.met => Ok(json!(result)),
                    Ok(result) => Err(ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TimeoutOrHang Browser wait condition '{}' not met within {}ms",
                        result.condition, result.elapsed_ms
                    ))),
                    Err(e) => Err(ToolExecutionResult::failure(format!(
                        "Browser wait failed: {}",
                        e
                    ))),
                }
            } else if let Some(ms) = ms {
                match exec.browser.wait_ms(ms).await {
                    Ok(waited_ms) => Ok(json!({
                        "condition": "fixed_ms",
                        "met": true,
                        "elapsed_ms": waited_ms
                    })),
                    Err(e) => Err(ToolExecutionResult::failure(format!(
                        "Browser wait failed: {}",
                        e
                    ))),
                }
            } else {
                Err(ToolExecutionResult::failure(
                    "Browser wait failed: provide either 'ms' or 'condition'.",
                ))
            };

            let wait_payload = match wait_payload {
                Ok(payload) => payload,
                Err(error) => return error,
            };

            if let Some(continue_with) = continue_with {
                let follow_up_result =
                    match execute_browser_wait_follow_up(exec, semantic_map, &continue_with).await {
                        Ok(result) => result,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser wait follow-up failed: {}",
                                reason
                            ))
                        }
                    };
                if !follow_up_result.success {
                    let payload = json!({
                        "wait": wait_payload,
                        "continue_with": {
                            "name": continue_with.name,
                            "arguments": continue_with.arguments,
                            "success": false,
                            "error": follow_up_result.error,
                        }
                    });
                    return ToolExecutionResult::failure(format!(
                        "Browser wait follow-up failed: {}",
                        payload
                    ));
                }

                let payload = json!({
                    "wait": wait_payload,
                    "continue_with": {
                        "name": continue_with.name,
                        "arguments": continue_with.arguments,
                        "success": true,
                        "result": history_entry_json_value(follow_up_result.history_entry.as_deref()),
                    }
                });
                if let Some(visual_observation) = follow_up_result.visual_observation {
                    ToolExecutionResult::success_with_visual_observation(
                        payload.to_string(),
                        visual_observation,
                    )
                } else {
                    ToolExecutionResult::success(payload.to_string())
                }
            } else {
                let payload = json!({
                    "wait": wait_payload
                });
                ToolExecutionResult::success(payload.to_string())
            }
        }
        AgentTool::BrowserUploadFile {
            paths,
            selector,
            som_id,
        } => {
            let scoped_paths =
                match resolve_scoped_upload_paths(&paths, exec.working_directory.as_deref()) {
                    Ok(paths) => paths,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=PathScopeViolation Browser upload failed: {}",
                            reason
                        ))
                    }
                };

            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if selector.is_some() && som_id.is_some() {
                return ToolExecutionResult::failure(
                    "Browser upload failed: provide either selector or som_id, not both.",
                );
            }

            if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser upload failed: {}",
                                reason
                            ))
                        }
                    };
                let Some(backend_dom_node_id) = target.backend_dom_node_id.as_deref() else {
                    return ToolExecutionResult::failure(format!(
                        "Browser upload failed: target for som_id={} has no backend DOM node id.",
                        som_id
                    ));
                };
                match exec
                    .browser
                    .upload_files_to_backend_node(backend_dom_node_id, &scoped_paths)
                    .await
                {
                    Ok(attached) => {
                        let payload = json!({
                            "som_id": som_id,
                            "attached_files": attached
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!("Browser upload failed: {}", e)),
                }
            } else {
                match exec.browser.upload_files(selector, &scoped_paths).await {
                    Ok(attached) => ToolExecutionResult::success(format!(
                        "Attached {} file(s) using selector {}",
                        attached,
                        selector.unwrap_or("input[type='file']")
                    )),
                    Err(e) => ToolExecutionResult::failure(format!("Browser upload failed: {}", e)),
                }
            }
        }
        AgentTool::BrowserDropdownOptions {
            id,
            selector,
            som_id,
        } => {
            let id = id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let locator_count = usize::from(id.is_some())
                + usize::from(selector.is_some())
                + usize::from(som_id.is_some());
            if locator_count != 1 {
                return ToolExecutionResult::failure(
                    "Browser dropdown options failed: provide exactly one of id, selector, or som_id.",
                );
            }

            if let Some(id) = id {
                let target = match resolve_browser_target_from_id(exec, id).await {
                    Ok(target) => target,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "Browser dropdown options failed: {}",
                            reason
                        ))
                    }
                };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: target for id='{}' has no geometry center.",
                        id
                    ));
                };
                match exec.browser.dropdown_options_at_point(x, y).await {
                    Ok(options) => {
                        let payload = json!({
                            "id": id,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else if let Some(selector) = selector {
                match exec.browser.dropdown_options(selector).await {
                    Ok(options) => {
                        let payload = json!({
                            "selector": selector,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser dropdown options failed: {}",
                                reason
                            ))
                        }
                    };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: target for som_id={} has no geometry center.",
                        som_id
                    ));
                };
                match exec.browser.dropdown_options_at_point(x, y).await {
                    Ok(options) => {
                        let payload = json!({
                            "som_id": som_id,
                            "options": options,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown options failed: {}",
                        e
                    )),
                }
            } else {
                ToolExecutionResult::failure(
                    "Browser dropdown options failed: provide id, selector, or som_id.",
                )
            }
        }
        AgentTool::BrowserSelectDropdown {
            id,
            selector,
            som_id,
            value,
            label,
        } => {
            let id = id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let selector = selector
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let locator_count = usize::from(id.is_some())
                + usize::from(selector.is_some())
                + usize::from(som_id.is_some());
            if locator_count != 1 {
                return ToolExecutionResult::failure(
                    "Browser dropdown select failed: provide exactly one of id, selector, or som_id.",
                );
            }

            if let Some(id) = id {
                let target = match resolve_browser_target_from_id(exec, id).await {
                    Ok(target) => target,
                    Err(reason) => {
                        return ToolExecutionResult::failure(format!(
                            "Browser dropdown select failed: {}",
                            reason
                        ))
                    }
                };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: target for id='{}' has no geometry center.",
                        id
                    ));
                };
                match exec
                    .browser
                    .select_dropdown_at_point(x, y, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "id": id,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else if let Some(selector) = selector {
                match exec
                    .browser
                    .select_dropdown(selector, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "selector": selector,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else if let Some(som_id) = som_id {
                let target =
                    match resolve_semantic_target_from_som(exec, som_id, semantic_map).await {
                        Ok(target) => target,
                        Err(reason) => {
                            return ToolExecutionResult::failure(format!(
                                "Browser dropdown select failed: {}",
                                reason
                            ))
                        }
                    };
                let Some((x, y)) = target.center_point else {
                    return ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: target for som_id={} has no geometry center.",
                        som_id
                    ));
                };
                match exec
                    .browser
                    .select_dropdown_at_point(x, y, value.as_deref(), label.as_deref())
                    .await
                {
                    Ok(selected) => {
                        let payload = json!({
                            "som_id": som_id,
                            "selected": selected,
                        });
                        ToolExecutionResult::success(payload.to_string())
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Browser dropdown select failed: {}",
                        e
                    )),
                }
            } else {
                ToolExecutionResult::failure(
                    "Browser dropdown select failed: provide id, selector, or som_id.",
                )
            }
        }
        AgentTool::BrowserGoBack { steps } => {
            let steps = steps.unwrap_or(1).max(1);
            match exec.browser.go_back(steps).await {
                Ok((moved, url)) => ToolExecutionResult::success(format!(
                    "Went back {} step(s). Active URL: {}",
                    moved, url
                )),
                Err(e) => ToolExecutionResult::failure(format!("Browser go_back failed: {}", e)),
            }
        }
        AgentTool::BrowserTabList {} => match exec.browser.list_tabs().await {
            Ok(tabs) => {
                let payload = json!({ "tabs": tabs });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser tab listing failed: {}", e)),
        },
        AgentTool::BrowserTabSwitch { tab_id } => match exec.browser.switch_tab(&tab_id).await {
            Ok(tab) => {
                let payload = json!({
                    "active_tab": tab,
                });
                ToolExecutionResult::success(payload.to_string())
            }
            Err(e) => ToolExecutionResult::failure(format!("Browser tab switch failed: {}", e)),
        },
        AgentTool::BrowserTabClose { tab_id, .. } => match exec.browser.close_tab(&tab_id).await {
            Ok(_) => ToolExecutionResult::success(format!("Closed tab '{}'", tab_id)),
            Err(e) => ToolExecutionResult::failure(format!("Browser tab close failed: {}", e)),
        },
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        browser_follow_up_activates_visible_control, browser_type_error_supports_selector_retry,
        browser_type_selector_fallbacks_for_target, browser_type_selector_lookup_token,
        history_entry_json_value, normalize_browser_follow_up, normalize_hover_tracking_window,
        resolve_hover_target_from_transformed_trees, resolve_scoped_upload_paths,
        should_use_browser_side_hover_tracking, BrowserSemanticTarget,
        DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS,
    };
    use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
    use ioi_types::app::agentic::AgentToolCall;
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ioi_browser_handler_{}_{}_{}",
            name,
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn resolve_scoped_upload_paths_resolves_relative_files_within_scope() {
        let scope_root = temp_dir("scope_ok");
        let nested = scope_root.join("docs");
        fs::create_dir_all(&nested).expect("create nested dir");
        let file_path = nested.join("invoice.txt");
        fs::write(&file_path, b"ok").expect("write test file");

        let resolved = resolve_scoped_upload_paths(
            &[String::from("docs/invoice.txt")],
            Some(scope_root.to_string_lossy().as_ref()),
        )
        .expect("paths should resolve");

        let expected = fs::canonicalize(&file_path).expect("canonical file");
        assert_eq!(resolved, vec![expected.to_string_lossy().to_string()]);

        let _ = fs::remove_dir_all(&scope_root);
    }

    #[test]
    fn resolve_scoped_upload_paths_rejects_absolute_paths_outside_scope() {
        let scope_root = temp_dir("scope_root");
        let outside_root = temp_dir("outside_root");
        let outside_file = outside_root.join("secret.txt");
        fs::write(&outside_file, b"nope").expect("write outside file");
        let outside_canonical = fs::canonicalize(&outside_file).expect("canonical outside file");

        let err = resolve_scoped_upload_paths(
            &[outside_canonical.to_string_lossy().to_string()],
            Some(scope_root.to_string_lossy().as_ref()),
        )
        .expect_err("outside path must fail");

        assert!(err.contains("outside allowed scope root"));

        let _ = fs::remove_dir_all(&scope_root);
        let _ = fs::remove_dir_all(&outside_root);
    }

    #[test]
    fn browser_type_selector_lookup_token_accepts_semantic_hash_reference() {
        assert_eq!(
            browser_type_selector_lookup_token("#inp_dispatch_note"),
            Some("inp_dispatch_note")
        );
    }

    #[test]
    fn browser_type_selector_lookup_token_rejects_complex_css() {
        assert_eq!(browser_type_selector_lookup_token("#note textarea"), None);
        assert_eq!(browser_type_selector_lookup_token("[id=\"note\"]"), None);
    }

    #[test]
    fn browser_type_selector_fallbacks_prefer_grounded_dom_selector_for_semantic_ids() {
        let target = BrowserSemanticTarget {
            semantic_id: Some("inp_dispatch_note".to_string()),
            dom_id: Some("note".to_string()),
            selector: Some("[id=\"note\"]".to_string()),
            ..Default::default()
        };

        let fallbacks = browser_type_selector_fallbacks_for_target("#inp_dispatch_note", &target);

        assert_eq!(fallbacks, vec!["[id=\"note\"]".to_string()]);
    }

    #[test]
    fn browser_type_focus_errors_retry_with_alternate_selectors() {
        assert!(browser_type_error_supports_selector_retry(
            "Failed to focus selector '#inp_dispatch_note'"
        ));
        assert!(browser_type_error_supports_selector_retry(
            "Selector focus failed for '#inp_dispatch_note': hidden"
        ));
        assert!(!browser_type_error_supports_selector_retry(
            "Type failed: session crashed"
        ));
    }

    #[test]
    fn normalize_browser_follow_up_accepts_click_element() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__click_element".to_string(),
                arguments: json!({ "id": "btn_two" }),
            },
            "browser__wait",
        )
        .expect("follow-up should normalize");

        match tool {
            ioi_types::app::agentic::AgentTool::BrowserClickElement {
                id,
                ids,
                delay_ms_between_ids,
                continue_with,
            } => {
                assert_eq!(id.as_deref(), Some("btn_two"));
                assert!(ids.is_empty());
                assert!(delay_ms_between_ids.is_none());
                assert!(continue_with.is_none());
            }
            other => panic!("expected BrowserClickElement, got {:?}", other),
        }
    }

    #[test]
    fn normalize_browser_follow_up_accepts_timed_click_element_sequence() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__click_element".to_string(),
                arguments: json!({
                    "ids": ["btn_one", "btn_two"],
                    "delay_ms_between_ids": 2_000
                }),
            },
            "browser__click_element",
        )
        .expect("follow-up should normalize");

        match tool {
            ioi_types::app::agentic::AgentTool::BrowserClickElement {
                id,
                ids,
                delay_ms_between_ids,
                continue_with,
            } => {
                assert!(id.is_none());
                assert_eq!(ids, vec!["btn_one".to_string(), "btn_two".to_string()]);
                assert_eq!(delay_ms_between_ids, Some(2_000));
                assert!(continue_with.is_none());
            }
            other => panic!("expected BrowserClickElement, got {:?}", other),
        }
    }

    #[test]
    fn normalize_browser_follow_up_accepts_wait_with_nested_click_element() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__wait".to_string(),
                arguments: json!({
                    "ms": 2_000,
                    "continue_with": {
                        "name": "browser__click_element",
                        "ids": ["btn_two"]
                    }
                }),
            },
            "browser__click_element",
        )
        .expect("follow-up should normalize");

        match tool {
            ioi_types::app::agentic::AgentTool::BrowserWait {
                ms,
                condition,
                selector,
                query,
                scope,
                timeout_ms,
                continue_with,
            } => {
                assert_eq!(ms, Some(2_000));
                assert!(condition.is_none());
                assert!(selector.is_none());
                assert!(query.is_none());
                assert!(scope.is_none());
                assert!(timeout_ms.is_none());
                let continue_with = continue_with.expect("nested click follow-up");
                assert_eq!(continue_with.name, "browser__click_element");
                assert_eq!(continue_with.arguments["ids"], json!(["btn_two"]));
            }
            other => panic!("expected BrowserWait, got {:?}", other),
        }
    }

    #[test]
    fn normalize_browser_follow_up_rejects_non_browser_action() {
        let err = normalize_browser_follow_up(
            &AgentToolCall {
                name: "agent__complete".to_string(),
                arguments: json!({ "result": "done" }),
            },
            "browser__synthetic_click",
        )
        .expect_err("non-browser follow-up must fail");

        assert!(err.contains("only supports immediate browser interaction tools"));
    }

    #[test]
    fn normalize_browser_follow_up_rejects_pointer_state_for_synthetic_click() {
        let err = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__mouse_down".to_string(),
                arguments: json!({}),
            },
            "browser__synthetic_click",
        )
        .expect_err("pointer-state follow-up must fail");

        assert!(err.contains("does not support pointer button state changes"));
    }

    #[test]
    fn normalize_browser_follow_up_accepts_nested_synthetic_click() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__synthetic_click".to_string(),
                arguments: json!({ "x": "85.012", "y": "105.824" }),
            },
            "browser__wait",
        )
        .expect("follow-up should normalize");

        match tool {
            ioi_types::app::agentic::AgentTool::BrowserSyntheticClick {
                x,
                y,
                continue_with,
            } => {
                assert!((x - 85.012).abs() < f64::EPSILON);
                assert!((y - 105.824).abs() < f64::EPSILON);
                assert!(continue_with.is_none());
            }
            other => panic!("expected BrowserSyntheticClick, got {:?}", other),
        }
    }

    #[test]
    fn browser_follow_up_activates_visible_control_for_direct_click_element() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__click_element".to_string(),
                arguments: json!({ "id": "btn_submit" }),
            },
            "browser__synthetic_click",
        )
        .expect("follow-up should normalize");

        assert!(browser_follow_up_activates_visible_control(&tool).expect("policy check"));
    }

    #[test]
    fn browser_follow_up_activates_visible_control_for_wait_wrapped_click_chain() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__wait".to_string(),
                arguments: json!({
                    "ms": 100,
                    "continue_with": {
                        "name": "browser__click_element",
                        "arguments": {
                            "id": "btn_submit"
                        }
                    }
                }),
            },
            "browser__synthetic_click",
        )
        .expect("follow-up should normalize");

        assert!(browser_follow_up_activates_visible_control(&tool).expect("policy check"));
    }

    #[test]
    fn browser_follow_up_activates_visible_control_ignores_geometry_only_chain() {
        let tool = normalize_browser_follow_up(
            &AgentToolCall {
                name: "browser__synthetic_click".to_string(),
                arguments: json!({ "x": 85.012, "y": 105.824 }),
            },
            "browser__synthetic_click",
        )
        .expect("follow-up should normalize");

        assert!(!browser_follow_up_activates_visible_control(&tool).expect("policy check"));
    }

    #[test]
    fn history_entry_json_value_preserves_json_and_falls_back_to_string() {
        assert_eq!(
            history_entry_json_value(Some("{\"clicked\":true}")),
            json!({ "clicked": true })
        );
        assert_eq!(
            history_entry_json_value(Some("Clicked element 'btn_two'")),
            json!("Clicked element 'btn_two'")
        );
    }

    #[test]
    fn resolve_hover_target_uses_recent_snapshot_when_current_tree_blinks() {
        let current_tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 160,
                height: 210,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };
        let recent_tree = AccessibilityNode {
            children: vec![AccessibilityNode {
                id: "grp_circ".to_string(),
                role: "generic".to_string(),
                name: Some("large circle centered at 110,103 radius 22".to_string()),
                value: None,
                rect: Rect {
                    x: 88,
                    y: 81,
                    width: 44,
                    height: 44,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([
                    ("dom_id".to_string(), "circ".to_string()),
                    ("selector".to_string(), "[id=\"circ\"]".to_string()),
                ]),
                som_id: None,
            }],
            ..current_tree.clone()
        };

        let resolved = resolve_hover_target_from_transformed_trees(
            "grp_circ",
            Some(&current_tree),
            Some(&recent_tree),
        )
        .expect("recent snapshot should resolve hover target");

        assert_eq!((resolved.x, resolved.y), (110.0, 103.0));
        assert_eq!(
            resolved
                .target
                .get("resolved_from")
                .and_then(serde_json::Value::as_str),
            Some("recent_accessibility_snapshot")
        );
    }

    #[test]
    fn hover_tracking_window_rejects_interval_without_duration() {
        let err = normalize_hover_tracking_window(None, Some(75))
            .expect_err("interval without duration must fail");
        assert!(err.contains("requires duration_ms"));
    }

    #[test]
    fn hover_tracking_window_defaults_resample_interval() {
        assert_eq!(
            normalize_hover_tracking_window(Some(2_500), None).expect("tracking window"),
            Some((2_500, DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS))
        );
    }

    #[test]
    fn browser_side_hover_tracking_prefers_explicit_zero_interval_without_pressed_buttons() {
        assert!(should_use_browser_side_hover_tracking(
            Some((30_000, 0)),
            Some("[id=\"circ\"]"),
            0,
        ));
    }

    #[test]
    fn browser_side_hover_tracking_skips_default_interval_drag_state_and_missing_selector() {
        assert!(!should_use_browser_side_hover_tracking(
            Some((30_000, 16)),
            Some("[id=\"circ\"]"),
            0,
        ));
        assert!(!should_use_browser_side_hover_tracking(
            Some((30_000, 0)),
            Some("[id=\"circ\"]"),
            1,
        ));
        assert!(!should_use_browser_side_hover_tracking(
            Some((30_000, DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS)),
            None,
            0,
        ));
    }
}
