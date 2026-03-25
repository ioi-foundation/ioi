use super::super::{ToolExecutionResult, ToolExecutor};
use super::selector_click::ensure_browser_focus_guard;
use super::tree::{
    apply_browser_auto_lens, apply_browser_auto_lens_with_som, render_browser_tree_xml,
};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration, Instant};

// Verification starts immediately after dispatch. Geometry-only targets do not have a stable
// DOM-backed identity to reconcile, so keep their tail shorter than DOM-backed targets while
// still allowing one medium recheck for slower semantic updates.
const CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY: [u64; 5] = [0, 80, 160, 320, 640];
const CLICK_DISPATCH_SETTLE_MS_DOM_BACKED: [u64; 4] = [0, 120, 240, 900];
const CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS: u64 = 240;
const CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT: Duration = Duration::from_millis(400);
// Keep the outer dispatch timeout slightly above the browser driver's per-request timeout so the
// driver can surface its own reset/retry signal instead of getting pre-empted by the wrapper.
const CLICK_DISPATCH_METHOD_TIMEOUT: Duration = Duration::from_millis(2_500);
const CLICK_ELEMENT_EXECUTION_BUDGET: Duration = Duration::from_millis(8_000);
const CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT: Duration = Duration::from_millis(1_500);
const LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA: usize = 4;
const NON_LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA: usize = 8;
const EXECUTION_PROMPT_OBSERVATION_CACHE_MAX_AGE: Duration = Duration::from_secs(90);
const RECENT_BROWSER_CLICK_SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(5_000);

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn browser_click_trace_enabled() -> bool {
    std::env::var("IOI_BROWSER_CLICK_TRACE_STDERR")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn emit_browser_click_trace(label: &str, details: impl AsRef<str>) {
    if browser_click_trace_enabled() {
        eprintln!("[browser-click] {label} {}", details.as_ref());
    }
}

async fn run_browser_dispatch_with_timeout_for<F, E>(
    dispatch_timeout: Duration,
    future: F,
) -> Result<(), String>
where
    F: Future<Output = Result<(), E>>,
    E: Display,
{
    match timeout(dispatch_timeout, future).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!(
            "dispatch timed out after {} ms. Retry the action.",
            dispatch_timeout.as_millis()
        )),
    }
}

#[cfg(test)]
async fn run_browser_tool_strategy_with_timeout_for<F>(
    strategy_timeout: Duration,
    future: F,
) -> Result<ToolExecutionResult, String>
where
    F: Future<Output = ToolExecutionResult>,
{
    match timeout(strategy_timeout, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err(format!(
            "strategy timed out after {} ms",
            strategy_timeout.as_millis()
        )),
    }
}

pub(super) async fn run_browser_dispatch_with_timeout<F, E>(future: F) -> Result<(), String>
where
    F: Future<Output = Result<(), E>>,
    E: Display,
{
    run_browser_dispatch_with_timeout_for(CLICK_DISPATCH_METHOD_TIMEOUT, future).await
}

fn remaining_click_element_budget(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

fn click_element_attempt_timeout(deadline: Instant) -> Option<Duration> {
    remaining_click_element_budget(deadline)
        .map(|remaining| remaining.min(CLICK_DISPATCH_METHOD_TIMEOUT))
}

fn browser_session_unstable_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("browser session reset")
        || lower.contains("browser connection lost")
        || lower.contains("browser accessibility snapshot timed out")
        || lower.contains("browser is cold")
        || lower.contains("no active page")
}

fn verify_marks_browser_session_unstable(verify: &serde_json::Value) -> bool {
    verify
        .get("browser_session_unstable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

async fn verification_post_url(
    exec: &ToolExecutor,
    browser_session_unstable: bool,
) -> Option<String> {
    if browser_session_unstable {
        // A fresh active_url() call goes through ensure_page() and can relaunch Chromium after a
        // session reset. During click verification we want the cached URL and a fast failure.
        exec.browser.known_active_url().await
    } else {
        exec.browser.active_url().await.ok()
    }
}

fn rect_center(rect: Rect) -> Option<(f64, f64)> {
    if rect.width <= 0 || rect.height <= 0 {
        return None;
    }

    Some((
        rect.x as f64 + (rect.width as f64 / 2.0),
        rect.y as f64 + (rect.height as f64 / 2.0),
    ))
}

fn browser_session_unstable_failure(
    id: &str,
    semantic_target: &BrowserSemanticTarget,
    click_errors: Vec<String>,
    attempt_verification: Vec<serde_json::Value>,
    dispatch_failures: Vec<serde_json::Value>,
    execution_started_at: Instant,
) -> ToolExecutionResult {
    let verify = json!({
        "id": id,
        "pre_target": semantic_target_verification_json(Some(semantic_target)),
        "attempts": attempt_verification,
        "click_errors": click_errors,
        "dispatch_failures": dispatch_failures,
        "browser_session_unstable": true,
        "retry_recommended": true,
        "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
    });
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=TimeoutOrHang Click element '{}' could not continue because the browser session became unavailable mid-action. verify={}",
        id, verify
    ))
}

fn semantic_target_is_actionable(target: &BrowserSemanticTarget) -> bool {
    target_has_grounded_dom_click_locator(target)
        || target.backend_dom_node_id.is_some()
        || target.cdp_node_id.is_some()
        || target.center_point.is_some()
}

fn same_semantic_control(left: &BrowserSemanticTarget, right: &BrowserSemanticTarget) -> bool {
    left.backend_dom_node_id
        .as_deref()
        .zip(right.backend_dom_node_id.as_deref())
        .is_some_and(|(left_id, right_id)| left_id == right_id)
        || left
            .element_hash
            .zip(right.element_hash)
            .is_some_and(|(left_hash, right_hash)| left_hash == right_hash)
        || left
            .cdp_node_id
            .as_deref()
            .zip(right.cdp_node_id.as_deref())
            .is_some_and(|(left_id, right_id)| left_id == right_id)
        || left
            .dom_id
            .as_deref()
            .zip(right.dom_id.as_deref())
            .is_some_and(|(left_id, right_id)| left_id == right_id)
        || left
            .stable_hash
            .zip(right.stable_hash)
            .is_some_and(|(left_hash, right_hash)| left_hash == right_hash)
        || left
            .x_path
            .as_deref()
            .zip(right.x_path.as_deref())
            .is_some_and(|(left_path, right_path)| left_path == right_path)
        || left
            .selector
            .as_deref()
            .zip(right.selector.as_deref())
            .is_some_and(|(left_selector, right_selector)| left_selector == right_selector)
        || left
            .semantic_id
            .as_deref()
            .zip(right.semantic_id.as_deref())
            .is_some_and(|(left_id, right_id)| left_id == right_id)
}

fn editable_control_value_committed(
    pre_control: Option<&BrowserSemanticTarget>,
    post_control: Option<&BrowserSemanticTarget>,
) -> bool {
    let (Some(pre_control), Some(post_control)) = (pre_control, post_control) else {
        return false;
    };
    if !pre_control.editable || !post_control.editable {
        return false;
    }
    if !same_semantic_control(pre_control, post_control) {
        return false;
    }

    let pre_value = pre_control
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let post_value = post_control
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    !post_value.is_empty() && pre_value != post_value
}

fn center_point_changed_meaningfully(left: Option<(f64, f64)>, right: Option<(f64, f64)>) -> bool {
    let (Some((left_x, left_y)), Some((right_x, right_y))) = (left, right) else {
        return false;
    };

    (left_x - right_x).abs() >= 2.0 || (left_y - right_y).abs() >= 2.0
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct BrowserSemanticTarget {
    pub(super) semantic_id: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) x_path: Option<String>,
    pub(super) tag_name: Option<String>,
    pub(super) dom_clickable: bool,
    pub(super) value: Option<String>,
    pub(super) identity_attributes: HashMap<String, String>,
    pub(super) element_hash: Option<u64>,
    pub(super) stable_hash: Option<u64>,
    pub(super) parent_branch_hash: Option<u64>,
    pub(super) ax_name: Option<String>,
    pub(super) cdp_node_id: Option<String>,
    pub(super) backend_dom_node_id: Option<String>,
    pub(super) target_id: Option<String>,
    pub(super) frame_id: Option<String>,
    pub(super) rect_bounds: Option<(i32, i32, i32, i32)>,
    pub(super) center_point: Option<(f64, f64)>,
    pub(super) focused: bool,
    pub(super) editable: bool,
    pub(super) checked: Option<bool>,
    pub(super) selected: Option<bool>,
    pub(super) scroll_top: Option<i32>,
    pub(super) scroll_height: Option<i32>,
    pub(super) client_height: Option<i32>,
    pub(super) can_scroll_up: Option<bool>,
    pub(super) can_scroll_down: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClickElementPostcondition {
    pub(super) target_disappeared: bool,
    pub(super) editable_focus_transition: bool,
    pub(super) tree_changed: bool,
    pub(super) url_changed: bool,
    pub(super) material_semantic_change: bool,
    pub(super) semantic_change_delta: usize,
}

impl ClickElementPostcondition {
    pub(super) fn met(&self) -> bool {
        self.target_disappeared
            || self.editable_focus_transition
            || self.tree_changed
            || self.url_changed
    }
}

fn xml_attr_value<'a>(fragment: &'a str, key: &str) -> Option<&'a str> {
    let key_start = fragment.find(key)?;
    let after_key = fragment.get(key_start + key.len()..)?;
    let after_equals = after_key.strip_prefix('=')?;
    let quote = after_equals.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value = after_equals.get(1..)?;
    let end_idx = value.find(quote)?;
    value.get(..end_idx)
}

fn semantic_name_signatures(
    xml: &str,
    target: &BrowserSemanticTarget,
) -> HashMap<(String, String), usize> {
    let mut signatures = HashMap::new();
    let mut cursor = xml;

    while let Some(start_idx) = cursor.find('<') {
        let rest = &cursor[start_idx + 1..];
        let Some(end_idx) = rest.find('>') else {
            break;
        };
        let fragment = &rest[..end_idx];
        cursor = &rest[end_idx + 1..];

        let trimmed = fragment.trim();
        if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.starts_with('!') {
            continue;
        }

        let tag = trimmed
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches('/');
        if tag.is_empty() || tag.eq_ignore_ascii_case("root") {
            continue;
        }

        let omitted = xml_attr_value(trimmed, "omitted")
            .is_some_and(|value| parse_attr_bool(value).unwrap_or(true));
        if omitted {
            continue;
        }

        let is_clicked_target = target
            .semantic_id
            .as_deref()
            .zip(xml_attr_value(trimmed, "id"))
            .is_some_and(|(target_id, node_id)| target_id == node_id)
            || target
                .dom_id
                .as_deref()
                .zip(xml_attr_value(trimmed, "dom_id"))
                .is_some_and(|(target_dom_id, node_dom_id)| target_dom_id == node_dom_id);
        if is_clicked_target {
            continue;
        }

        let Some(name) = xml_attr_value(trimmed, "name") else {
            continue;
        };
        let normalized_name = name.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized_name.is_empty() {
            continue;
        }

        let signature = (tag.to_ascii_lowercase(), normalized_name);
        *signatures.entry(signature).or_insert(0) += 1;
    }

    signatures
}

fn semantic_change_delta(
    pre_tree_xml: &str,
    post_tree_xml: &str,
    pre_target: &BrowserSemanticTarget,
) -> usize {
    let pre_signatures = semantic_name_signatures(pre_tree_xml, pre_target);
    let post_signatures = semantic_name_signatures(post_tree_xml, pre_target);
    let mut delta = 0;

    for (signature, pre_count) in &pre_signatures {
        let post_count = post_signatures.get(signature).copied().unwrap_or_default();
        delta += pre_count.abs_diff(post_count);
    }
    for (signature, post_count) in &post_signatures {
        if !pre_signatures.contains_key(signature) {
            delta += *post_count;
        }
    }

    delta
}

pub(super) fn click_element_postcondition_counts_as_success(
    pre_target: &BrowserSemanticTarget,
    pre_focused_control: Option<&BrowserSemanticTarget>,
    post_target: Option<&BrowserSemanticTarget>,
    focused_control: Option<&BrowserSemanticTarget>,
    postcondition: &ClickElementPostcondition,
) -> bool {
    let post_target_strengthened = post_target.is_some_and(|target| {
        target.selected != pre_target.selected
            || target.checked != pre_target.checked
            || center_point_changed_meaningfully(target.center_point, pre_target.center_point)
            || target.value != pre_target.value
    });
    let focused_editable_value_committed =
        editable_control_value_committed(pre_focused_control, focused_control);
    let transient_popup_dismissal_without_commit = postcondition.target_disappeared
        && pre_focused_control
            .zip(focused_control)
            .is_some_and(|(pre_control, post_control)| {
                pre_control.editable
                    && post_control.editable
                    && same_semantic_control(pre_control, post_control)
            })
        && !focused_editable_value_committed
        && !post_target_strengthened
        && !postcondition.material_semantic_change;
    if transient_popup_dismissal_without_commit {
        return false;
    }

    let stable_same_page_click = postcondition.tree_changed
        && !postcondition.url_changed
        && !postcondition.target_disappeared
        && !postcondition.editable_focus_transition;
    let link_like = matches!(pre_target.tag_name.as_deref(), Some("a"));
    if stable_same_page_click && link_like {
        if !post_target_strengthened && !postcondition.material_semantic_change {
            return false;
        }
    }
    if stable_same_page_click
        && pre_target.editable
        && !post_target_strengthened
        && !focused_editable_value_committed
    {
        return false;
    }
    if stable_same_page_click
        && !link_like
        && !post_target_strengthened
        && (!postcondition.material_semantic_change
            || postcondition.semantic_change_delta
                < NON_LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA)
    {
        return false;
    }

    postcondition.met()
}

fn parse_attr_bool(raw: &str) -> Option<bool> {
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn node_attr_flag(node: &AccessibilityNode, key: &str) -> Option<bool> {
    let value = node
        .attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())?;

    if value.trim().is_empty() {
        return Some(true);
    }

    parse_attr_bool(value).or(Some(true))
}

fn node_is_focused(node: &AccessibilityNode) -> bool {
    matches!(node_attr_flag(node, "focused"), Some(true))
}

fn node_is_editable(node: &AccessibilityNode) -> bool {
    let disabled = matches!(node_attr_flag(node, "disabled"), Some(true))
        || matches!(node_attr_flag(node, "aria_disabled"), Some(true));
    if disabled {
        return false;
    }

    let readonly = matches!(node_attr_flag(node, "readonly"), Some(true))
        || matches!(node_attr_flag(node, "aria_readonly"), Some(true))
        || matches!(node_attr_flag(node, "read_only"), Some(true));
    if readonly {
        return false;
    }

    if matches!(node_attr_flag(node, "editable"), Some(true))
        || matches!(node_attr_flag(node, "contenteditable"), Some(true))
    {
        return true;
    }

    matches!(
        node.role.trim().to_ascii_lowercase().as_str(),
        "textbox"
            | "text box"
            | "searchbox"
            | "search box"
            | "text"
            | "edit"
            | "entry"
            | "textarea"
            | "input"
    )
}

fn normalized_attr_lookup_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn attr_lookup_key_matches(candidate: &str, key: &str) -> bool {
    candidate.eq_ignore_ascii_case(key)
        || normalized_attr_lookup_key(candidate) == normalized_attr_lookup_key(key)
}

fn node_attr_value<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|(k, _)| attr_lookup_key_matches(k, key))
        .map(|(_, v)| v.as_str())
        .filter(|value| !value.trim().is_empty())
}

fn node_attr_i32(node: &AccessibilityNode, key: &str) -> Option<i32> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn node_attr_f64(node: &AccessibilityNode, key: &str) -> Option<f64> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn node_attr_u64(node: &AccessibilityNode, key: &str) -> Option<u64> {
    node_attr_value(node, key)?.trim().parse().ok()
}

fn semantic_target_center_point(node: &AccessibilityNode) -> Option<(f64, f64)> {
    let precise_x =
        node_attr_f64(node, "center_x_precise").or_else(|| node_attr_f64(node, "center_x"));
    let precise_y =
        node_attr_f64(node, "center_y_precise").or_else(|| node_attr_f64(node, "center_y"));
    match (precise_x, precise_y) {
        (Some(x), Some(y)) if x.is_finite() && y.is_finite() => Some((x, y)),
        _ => rect_center(node.rect),
    }
}

fn normalize_semantic_lookup_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn semantic_lookup_token_matches(token: &str, raw_query: &str, normalized_query: &str) -> bool {
    let token = token.trim();
    if token.is_empty() {
        return false;
    }

    token.eq_ignore_ascii_case(raw_query)
        || (!normalized_query.is_empty()
            && normalize_semantic_lookup_key(token) == normalized_query)
}

fn semantic_lookup_alias_candidates(raw_query: &str) -> Vec<String> {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut aliases = vec![trimmed.to_string()];
    if let Some((_, remainder)) = trimmed.split_once('_') {
        if !remainder.trim().is_empty() && !aliases.iter().any(|alias| alias == remainder.trim()) {
            aliases.push(remainder.trim().to_string());
        }
    }
    if let Some((_, suffix)) = trimmed.rsplit_once('_') {
        if !suffix.trim().is_empty() && !aliases.iter().any(|alias| alias == suffix.trim()) {
            aliases.push(suffix.trim().to_string());
        }
    }

    aliases
}

fn semantic_target_from_node(node: &AccessibilityNode) -> BrowserSemanticTarget {
    let mut identity_attributes = HashMap::new();
    for key in ["name", "id", "aria-label", "type"] {
        if let Some(value) = node_attr_value(node, key) {
            identity_attributes.insert(key.to_string(), value.to_string());
        }
    }

    BrowserSemanticTarget {
        semantic_id: Some(node.id.clone()).filter(|id| !id.trim().is_empty()),
        dom_id: node_attr_value(node, "dom_id")
            .or_else(|| node_attr_value(node, "id"))
            .map(|value| value.to_string()),
        selector: node_attr_value(node, "selector").map(|value| value.to_string()),
        x_path: node_attr_value(node, "x_path").map(|value| value.to_string()),
        tag_name: node_attr_value(node, "tag_name").map(|value| value.to_string()),
        dom_clickable: matches!(node_attr_flag(node, "dom_clickable"), Some(true)),
        value: node.value.clone(),
        identity_attributes,
        element_hash: node_attr_u64(node, "element_hash"),
        stable_hash: node_attr_u64(node, "stable_hash"),
        parent_branch_hash: node_attr_u64(node, "parent_branch_hash"),
        ax_name: node_attr_value(node, "ax_name")
            .map(|value| value.to_string())
            .or_else(|| node.name.clone()),
        cdp_node_id: node.attributes.get("cdp_node_id").cloned(),
        backend_dom_node_id: node.attributes.get("backend_dom_node_id").cloned(),
        target_id: node.attributes.get("target_id").cloned(),
        frame_id: node.attributes.get("frame_id").cloned(),
        rect_bounds: Some((node.rect.x, node.rect.y, node.rect.width, node.rect.height)),
        center_point: semantic_target_center_point(node),
        focused: node_is_focused(node),
        editable: node_is_editable(node),
        checked: node_attr_flag(node, "checked"),
        selected: node_attr_flag(node, "selected"),
        scroll_top: node_attr_i32(node, "scroll_top"),
        scroll_height: node_attr_i32(node, "scroll_height"),
        client_height: node_attr_i32(node, "client_height"),
        can_scroll_up: node_attr_flag(node, "can_scroll_up"),
        can_scroll_down: node_attr_flag(node, "can_scroll_down"),
    }
}

fn point_within_rect(bounds: (i32, i32, i32, i32), x: f64, y: f64) -> bool {
    let (left, top, width, height) = bounds;
    if width <= 0 || height <= 0 || !x.is_finite() || !y.is_finite() {
        return false;
    }

    let right = left.saturating_add(width);
    let bottom = top.saturating_add(height);
    x >= left as f64 && x <= right as f64 && y >= top as f64 && y <= bottom as f64
}

fn semantic_target_locator_strength(target: &BrowserSemanticTarget) -> u8 {
    let mut strength = 0u8;
    if target
        .backend_dom_node_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(4);
    }
    if target
        .cdp_node_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(3);
    }
    if target
        .dom_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(2);
    }
    if target.stable_hash.is_some() {
        strength = strength.saturating_add(2);
    }
    if target
        .x_path
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(1);
    }
    if target
        .selector
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        strength = strength.saturating_add(1);
    }
    strength
}

fn find_nearest_semantic_target_by_point_recursive(
    node: &AccessibilityNode,
    x: f64,
    y: f64,
    best: &mut Option<(bool, bool, f64, u8, i64, BrowserSemanticTarget)>,
) {
    let target = semantic_target_from_node(node);
    if let Some((center_x, center_y)) = target.center_point {
        let contains_point = target
            .rect_bounds
            .is_some_and(|bounds| point_within_rect(bounds, x, y));
        let actionable = semantic_target_is_actionable(&target);
        let distance_sq = (center_x - x).powi(2) + (center_y - y).powi(2);
        let locator_strength = semantic_target_locator_strength(&target);
        let rect_area = target
            .rect_bounds
            .map(|(_, _, width, height)| i64::from(width.max(0)) * i64::from(height.max(0)))
            .unwrap_or(i64::MAX);
        let candidate = (
            contains_point,
            actionable,
            distance_sq,
            locator_strength,
            rect_area,
            target,
        );

        let replace = match best.as_ref() {
            None => true,
            Some((best_contains, best_actionable, best_distance, best_locator, best_area, _)) => {
                (candidate.0, candidate.1) > (*best_contains, *best_actionable)
                    || ((candidate.0, candidate.1) == (*best_contains, *best_actionable)
                        && (candidate.2 < *best_distance
                            || (candidate.2 == *best_distance
                                && (candidate.3 > *best_locator
                                    || (candidate.3 == *best_locator
                                        && candidate.4 < *best_area)))))
            }
        };

        if replace {
            *best = Some(candidate);
        }
    }

    for child in &node.children {
        find_nearest_semantic_target_by_point_recursive(child, x, y, best);
    }
}

fn find_semantic_target_by_semantic_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    if node.id == target_id {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_semantic_id(child, target_id) {
            return Some(found);
        }
    }

    None
}

pub(super) fn find_semantic_target_by_som_id(
    node: &AccessibilityNode,
    target_som_id: u32,
) -> Option<BrowserSemanticTarget> {
    if node.som_id == Some(target_som_id) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_som_id(child, target_som_id) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_dom_id_or_attr_id(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
) -> Option<BrowserSemanticTarget> {
    if let Some(dom_id) = node_attr_value(node, "dom_id") {
        if semantic_lookup_token_matches(dom_id, raw_query, normalized_query) {
            return Some(semantic_target_from_node(node));
        }
    }

    if let Some(attr_id) = node_attr_value(node, "id") {
        if semantic_lookup_token_matches(attr_id, raw_query, normalized_query) {
            return Some(semantic_target_from_node(node));
        }
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_dom_id_or_attr_id(child, raw_query, normalized_query)
        {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_semantic_alias(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
) -> Option<BrowserSemanticTarget> {
    if let Some(aliases) = node.attributes.get("semantic_aliases") {
        if aliases
            .split_whitespace()
            .any(|alias| semantic_lookup_token_matches(alias, raw_query, normalized_query))
        {
            return Some(semantic_target_from_node(node));
        }
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_semantic_alias(child, raw_query, normalized_query)
        {
            return Some(found);
        }
    }

    None
}

fn collect_semantic_targets_by_name_or_data_index(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
    matches: &mut Vec<BrowserSemanticTarget>,
) {
    let name_match = node
        .name
        .as_deref()
        .is_some_and(|name| semantic_lookup_token_matches(name, raw_query, normalized_query));
    let data_index_match = node_attr_value(node, "data_index")
        .is_some_and(|value| semantic_lookup_token_matches(value, raw_query, normalized_query));
    if name_match || data_index_match {
        matches.push(semantic_target_from_node(node));
    }

    for child in &node.children {
        collect_semantic_targets_by_name_or_data_index(child, raw_query, normalized_query, matches);
    }
}

fn find_unique_semantic_target_by_name_or_data_index(
    node: &AccessibilityNode,
    raw_query: &str,
) -> Option<BrowserSemanticTarget> {
    for alias in semantic_lookup_alias_candidates(raw_query) {
        let normalized_alias = normalize_semantic_lookup_key(&alias);
        let mut matches = Vec::new();
        collect_semantic_targets_by_name_or_data_index(
            node,
            &alias,
            &normalized_alias,
            &mut matches,
        );
        if matches.len() == 1 {
            return matches.into_iter().next();
        }
    }

    None
}

fn find_focused_semantic_target(node: &AccessibilityNode) -> Option<BrowserSemanticTarget> {
    for child in &node.children {
        if let Some(found) = find_focused_semantic_target(child) {
            return Some(found);
        }
    }

    node_is_focused(node).then(|| semantic_target_from_node(node))
}

fn semantic_lookup_candidate_is_better(
    candidate: &BrowserSemanticTarget,
    candidate_alias_index: usize,
    best: Option<(&BrowserSemanticTarget, usize)>,
) -> bool {
    let candidate_rank = (
        semantic_target_is_actionable(candidate),
        target_has_grounded_dom_click_locator(candidate),
        semantic_target_locator_strength(candidate),
    );

    match best {
        None => true,
        Some((best_target, best_alias_index)) => {
            let best_rank = (
                semantic_target_is_actionable(best_target),
                target_has_grounded_dom_click_locator(best_target),
                semantic_target_locator_strength(best_target),
            );
            candidate_rank > best_rank
                || (candidate_rank == best_rank && candidate_alias_index < best_alias_index)
        }
    }
}

pub(super) fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    let target_id = target_id.trim();
    if target_id.is_empty() {
        return None;
    }

    if let Some(target) = find_semantic_target_by_semantic_id(node, target_id) {
        return Some(target);
    }

    if let Ok(target_som_id) = target_id.parse::<u32>() {
        if let Some(target) = find_semantic_target_by_som_id(node, target_som_id) {
            return Some(target);
        }
    }

    let mut best_match: Option<(BrowserSemanticTarget, usize)> = None;
    for (alias_index, alias) in semantic_lookup_alias_candidates(target_id)
        .into_iter()
        .enumerate()
    {
        let normalized_alias = normalize_semantic_lookup_key(&alias);
        for candidate in [
            find_semantic_target_by_dom_id_or_attr_id(node, &alias, &normalized_alias),
            find_semantic_target_by_semantic_alias(node, &alias, &normalized_alias),
        ]
        .into_iter()
        .flatten()
        {
            if semantic_lookup_candidate_is_better(
                &candidate,
                alias_index,
                best_match.as_ref().map(|(target, index)| (target, *index)),
            ) {
                best_match = Some((candidate, alias_index));
            }
        }
    }
    if let Some((target, _)) = best_match {
        return Some(target);
    }

    find_unique_semantic_target_by_name_or_data_index(node, target_id)
}

pub(super) fn resolve_semantic_target_from_current_or_prompt_tree(
    current_tree: Option<&AccessibilityNode>,
    prompt_tree: Option<&AccessibilityNode>,
    target_id: &str,
) -> Option<(BrowserSemanticTarget, &'static str)> {
    let current_target = current_tree.and_then(|tree| find_semantic_target_by_id(tree, target_id));
    let prompt_target = prompt_tree.and_then(|tree| find_semantic_target_by_id(tree, target_id));

    match (current_target, prompt_target) {
        (Some(current_target), Some(prompt_target)) => {
            let current_actionable = semantic_target_is_actionable(&current_target);
            let prompt_actionable = semantic_target_is_actionable(&prompt_target);
            if prompt_actionable && !current_actionable {
                return Some((prompt_target, "prompt_observation_tree"));
            }
            if current_actionable && !prompt_actionable {
                return Some((current_target, "current_accessibility_tree"));
            }

            let prompt_enriches_current =
                prompt_target_enriches_current(&current_target, &prompt_target);
            let merged_target = merge_semantic_target_metadata(&current_target, &prompt_target);
            Some((
                merged_target,
                if prompt_enriches_current {
                    "current_accessibility_tree+prompt_metadata"
                } else {
                    "current_accessibility_tree"
                },
            ))
        }
        (Some(current_target), None) => Some((current_target, "current_accessibility_tree")),
        (None, Some(prompt_target)) => Some((prompt_target, "prompt_observation_tree")),
        (None, None) => None,
    }
}

fn prompt_target_enriches_current(
    current_target: &BrowserSemanticTarget,
    prompt_target: &BrowserSemanticTarget,
) -> bool {
    (current_target.selector.is_none() && prompt_target.selector.is_some())
        || (current_target.x_path.is_none() && prompt_target.x_path.is_some())
        || (current_target.dom_id.is_none() && prompt_target.dom_id.is_some())
        || (current_target.tag_name.is_none() && prompt_target.tag_name.is_some())
        || (current_target.identity_attributes.is_empty()
            && !prompt_target.identity_attributes.is_empty())
        || (current_target.element_hash.is_none() && prompt_target.element_hash.is_some())
        || (current_target.stable_hash.is_none() && prompt_target.stable_hash.is_some())
        || (!current_target.dom_clickable && prompt_target.dom_clickable)
}

fn merge_semantic_target_metadata(
    current_target: &BrowserSemanticTarget,
    prompt_target: &BrowserSemanticTarget,
) -> BrowserSemanticTarget {
    let mut identity_attributes = prompt_target.identity_attributes.clone();
    for (key, value) in &current_target.identity_attributes {
        identity_attributes.insert(key.clone(), value.clone());
    }

    BrowserSemanticTarget {
        semantic_id: current_target
            .semantic_id
            .clone()
            .or_else(|| prompt_target.semantic_id.clone()),
        dom_id: current_target
            .dom_id
            .clone()
            .or_else(|| prompt_target.dom_id.clone()),
        selector: current_target
            .selector
            .clone()
            .or_else(|| prompt_target.selector.clone()),
        x_path: current_target
            .x_path
            .clone()
            .or_else(|| prompt_target.x_path.clone()),
        tag_name: current_target
            .tag_name
            .clone()
            .or_else(|| prompt_target.tag_name.clone()),
        dom_clickable: current_target.dom_clickable || prompt_target.dom_clickable,
        value: current_target
            .value
            .clone()
            .or_else(|| prompt_target.value.clone()),
        identity_attributes,
        element_hash: current_target.element_hash.or(prompt_target.element_hash),
        stable_hash: current_target.stable_hash.or(prompt_target.stable_hash),
        parent_branch_hash: current_target
            .parent_branch_hash
            .or(prompt_target.parent_branch_hash),
        ax_name: current_target
            .ax_name
            .clone()
            .or_else(|| prompt_target.ax_name.clone()),
        cdp_node_id: current_target
            .cdp_node_id
            .clone()
            .or_else(|| prompt_target.cdp_node_id.clone()),
        backend_dom_node_id: current_target
            .backend_dom_node_id
            .clone()
            .or_else(|| prompt_target.backend_dom_node_id.clone()),
        target_id: current_target
            .target_id
            .clone()
            .or_else(|| prompt_target.target_id.clone()),
        frame_id: current_target
            .frame_id
            .clone()
            .or_else(|| prompt_target.frame_id.clone()),
        rect_bounds: current_target.rect_bounds.or(prompt_target.rect_bounds),
        center_point: current_target.center_point.or(prompt_target.center_point),
        focused: current_target.focused,
        editable: current_target.editable || prompt_target.editable,
        checked: current_target.checked.or(prompt_target.checked),
        selected: current_target.selected.or(prompt_target.selected),
        scroll_top: current_target.scroll_top.or(prompt_target.scroll_top),
        scroll_height: current_target.scroll_height.or(prompt_target.scroll_height),
        client_height: current_target.client_height.or(prompt_target.client_height),
        can_scroll_up: current_target.can_scroll_up.or(prompt_target.can_scroll_up),
        can_scroll_down: current_target
            .can_scroll_down
            .or(prompt_target.can_scroll_down),
    }
}

pub(super) async fn capture_execution_prompt_browser_tree(
    exec: &ToolExecutor,
) -> Option<(AccessibilityNode, &'static str)> {
    if let Some((_, tree)) = exec
        .browser
        .recent_prompt_observation_snapshot(EXECUTION_PROMPT_OBSERVATION_CACHE_MAX_AGE)
        .await
    {
        return Some((
            apply_browser_auto_lens(tree),
            "recent_prompt_observation_snapshot",
        ));
    }

    exec.browser
        .get_prompt_observation_tree()
        .await
        .ok()
        .map(apply_browser_auto_lens)
        .map(|tree| (tree, "fresh_prompt_observation_tree"))
}

pub(super) fn find_nearest_semantic_target_by_point(
    node: &AccessibilityNode,
    x: f64,
    y: f64,
) -> Option<BrowserSemanticTarget> {
    let mut best = None;
    find_nearest_semantic_target_by_point_recursive(node, x, y, &mut best);
    best.map(|(_, _, _, _, _, target)| target)
}

pub(super) fn find_semantic_target_by_browser_ids(
    node: &AccessibilityNode,
    cdp_node_id: Option<&str>,
    backend_dom_node_id: Option<&str>,
) -> Option<BrowserSemanticTarget> {
    let node_cdp = node.attributes.get("cdp_node_id").map(String::as_str);
    let node_backend = node
        .attributes
        .get("backend_dom_node_id")
        .map(String::as_str);

    let cdp_match = cdp_node_id
        .filter(|id| !id.trim().is_empty())
        .is_some_and(|id| node_cdp == Some(id));
    let backend_match = backend_dom_node_id
        .filter(|id| !id.trim().is_empty())
        .is_some_and(|id| node_backend == Some(id));

    if cdp_match || backend_match {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) =
            find_semantic_target_by_browser_ids(child, cdp_node_id, backend_dom_node_id)
        {
            return Some(found);
        }
    }

    None
}

pub(super) fn find_semantic_target_by_dom_id(
    node: &AccessibilityNode,
    dom_id: &str,
) -> Option<BrowserSemanticTarget> {
    let dom_id = dom_id.trim();
    if dom_id.is_empty() {
        return None;
    }

    let node_dom_id = node_attr_value(node, "dom_id").or_else(|| node_attr_value(node, "id"));
    if node_dom_id == Some(dom_id) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_dom_id(child, dom_id) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_stable_hash(
    node: &AccessibilityNode,
    stable_hash: u64,
) -> Option<BrowserSemanticTarget> {
    if node_attr_u64(node, "stable_hash") == Some(stable_hash) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_stable_hash(child, stable_hash) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_element_hash(
    node: &AccessibilityNode,
    element_hash: u64,
) -> Option<BrowserSemanticTarget> {
    if node_attr_u64(node, "element_hash") == Some(element_hash) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_element_hash(child, element_hash) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_by_xpath(
    node: &AccessibilityNode,
    x_path: &str,
) -> Option<BrowserSemanticTarget> {
    if node_attr_value(node, "x_path").is_some_and(|value| value == x_path) {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_xpath(child, x_path) {
            return Some(found);
        }
    }

    None
}

fn candidate_tag_name_matches(node: &AccessibilityNode, expected_tag_name: Option<&str>) -> bool {
    expected_tag_name.is_none_or(|expected| {
        node_attr_value(node, "tag_name")
            .or_else(|| node_attr_value(node, "role"))
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(expected))
    })
}

fn find_semantic_target_by_ax_name(
    node: &AccessibilityNode,
    tag_name: Option<&str>,
    ax_name: &str,
) -> Option<BrowserSemanticTarget> {
    let tag_matches = candidate_tag_name_matches(node, tag_name);
    let ax_name_matches = node_attr_value(node, "ax_name")
        .or(node.name.as_deref())
        .is_some_and(|candidate| candidate == ax_name);
    if tag_matches && ax_name_matches {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_ax_name(child, tag_name, ax_name) {
            return Some(found);
        }
    }

    None
}

fn attribute_identity_candidates(target: &BrowserSemanticTarget) -> Vec<(&'static str, &str)> {
    let mut candidates = Vec::new();
    for key in ["name", "id", "aria-label"] {
        if let Some(value) = target.identity_attributes.get(key) {
            let value = value.trim();
            if !value.is_empty() {
                candidates.push((key, value));
            }
        }
    }
    if !target.identity_attributes.contains_key("id") {
        if let Some(dom_id) = target
            .dom_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            candidates.push(("id", dom_id));
        }
    }
    candidates
}

fn find_semantic_target_by_attribute_identity(
    node: &AccessibilityNode,
    tag_name: Option<&str>,
    attribute_key: &str,
    attribute_value: &str,
) -> Option<BrowserSemanticTarget> {
    if candidate_tag_name_matches(node, tag_name)
        && node_attr_value(node, attribute_key)
            .is_some_and(|candidate| candidate == attribute_value)
    {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_attribute_identity(
            child,
            tag_name,
            attribute_key,
            attribute_value,
        ) {
            return Some(found);
        }
    }

    None
}

fn find_semantic_target_for_verification(
    node: &AccessibilityNode,
    target: &BrowserSemanticTarget,
) -> Option<BrowserSemanticTarget> {
    find_semantic_target_by_browser_ids(
        node,
        target.cdp_node_id.as_deref(),
        target.backend_dom_node_id.as_deref(),
    )
    .or_else(|| {
        target
            .element_hash
            .and_then(|element_hash| find_semantic_target_by_element_hash(node, element_hash))
    })
    .or_else(|| {
        target
            .stable_hash
            .and_then(|stable_hash| find_semantic_target_by_stable_hash(node, stable_hash))
    })
    .or_else(|| {
        target
            .x_path
            .as_deref()
            .and_then(|x_path| find_semantic_target_by_xpath(node, x_path))
    })
    .or_else(|| {
        target.ax_name.as_deref().and_then(|ax_name| {
            find_semantic_target_by_ax_name(node, target.tag_name.as_deref(), ax_name)
        })
    })
    .or_else(|| {
        attribute_identity_candidates(target).into_iter().find_map(
            |(attribute_key, attribute_value)| {
                find_semantic_target_by_attribute_identity(
                    node,
                    target.tag_name.as_deref(),
                    attribute_key,
                    attribute_value,
                )
            },
        )
    })
    .or_else(|| {
        target
            .dom_id
            .as_deref()
            .and_then(|dom_id| find_semantic_target_by_dom_id(node, dom_id))
    })
    .or_else(|| {
        target
            .semantic_id
            .as_deref()
            .and_then(|semantic_id| find_semantic_target_by_id(node, semantic_id))
    })
}

pub(super) fn click_element_postcondition_met(
    pre_tree_xml: &str,
    pre_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    post_tree_xml: &str,
    post_target: Option<&BrowserSemanticTarget>,
    post_url: Option<&str>,
) -> ClickElementPostcondition {
    let has_verifiable_identity = pre_target
        .backend_dom_node_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty())
        || pre_target.element_hash.is_some()
        || pre_target
            .cdp_node_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || pre_target
            .dom_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || pre_target.stable_hash.is_some()
        || pre_target
            .x_path
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        || pre_target
            .ax_name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty());
    let has_geometry_only_identity = !has_verifiable_identity
        && pre_target
            .semantic_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty());
    let target_disappeared =
        (has_verifiable_identity || has_geometry_only_identity) && post_target.is_none();
    let editable_focus_transition = pre_target.editable
        && !pre_target.focused
        && post_target.is_some_and(|target| target.focused);
    let tree_changed = pre_tree_xml != post_tree_xml;
    let semantic_change_delta = if tree_changed {
        semantic_change_delta(pre_tree_xml, post_tree_xml, pre_target)
    } else {
        0
    };
    let material_semantic_change =
        semantic_change_delta >= LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA;
    let url_changed = pre_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .zip(post_url.map(str::trim).filter(|url| !url.is_empty()))
        .is_some_and(|(pre, post)| pre != post);

    ClickElementPostcondition {
        target_disappeared,
        editable_focus_transition,
        tree_changed,
        url_changed,
        material_semantic_change,
        semantic_change_delta,
    }
}

pub(super) fn semantic_target_verification_json(
    target: Option<&BrowserSemanticTarget>,
) -> serde_json::Value {
    match target {
        Some(target) => json!({
            "semantic_id": target.semantic_id,
            "dom_id": target.dom_id,
            "selector": target.selector,
            "x_path": target.x_path,
            "tag_name": target.tag_name,
            "dom_clickable": target.dom_clickable,
            "value": target.value,
            "identity_attributes": target.identity_attributes,
            "element_hash": target.element_hash,
            "stable_hash": target.stable_hash,
            "parent_branch_hash": target.parent_branch_hash,
            "ax_name": target.ax_name,
            "cdp_node_id": target.cdp_node_id,
            "backend_dom_node_id": target.backend_dom_node_id,
            "target_id": target.target_id,
            "frame_id": target.frame_id,
            "focused": target.focused,
            "editable": target.editable,
            "checked": target.checked,
            "selected": target.selected,
            "scroll_top": target.scroll_top,
            "scroll_height": target.scroll_height,
            "client_height": target.client_height,
            "can_scroll_up": target.can_scroll_up,
            "can_scroll_down": target.can_scroll_down,
            "center_point": target.center_point.map(|(x, y)| vec![x, y]),
        }),
        None => serde_json::Value::Null,
    }
}

fn target_has_grounded_dom_click_locator(target: &BrowserSemanticTarget) -> bool {
    target
        .selector
        .as_deref()
        .map(str::trim)
        .is_some_and(|selector| !selector.is_empty())
        || target
            .dom_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|dom_id| !dom_id.is_empty())
}

fn click_selector_fallback_locator(target: &BrowserSemanticTarget) -> Option<String> {
    target
        .selector
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
        .map(str::to_string)
        .or_else(|| {
            target
                .dom_id
                .as_deref()
                .map(str::trim)
                .filter(|dom_id| !dom_id.is_empty())
                .map(|dom_id| {
                    format!(
                        r#"[id="{}"]"#,
                        dom_id.replace('\\', r#"\\"#).replace('"', r#"\""#)
                    )
                })
        })
}

fn prefers_selector_click_path(target: &BrowserSemanticTarget) -> bool {
    if click_selector_fallback_locator(target).is_none() {
        return false;
    }

    if target.dom_clickable {
        return true;
    }

    let Some(tag_name) = target.tag_name.as_deref().map(str::trim) else {
        return false;
    };

    matches!(
        tag_name.to_ascii_lowercase().as_str(),
        "a" | "button" | "input" | "label" | "option" | "select" | "summary" | "textarea"
    )
}

fn uses_geometry_only_click_verification(target: &BrowserSemanticTarget) -> bool {
    target.center_point.is_some()
        && target
            .backend_dom_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target.element_hash.is_none()
        && target
            .cdp_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .dom_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target.identity_attributes.is_empty()
        && target.stable_hash.is_none()
        && target
            .x_path
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

fn safe_inset_click_point(target: &BrowserSemanticTarget) -> Option<(f64, f64)> {
    let tag_name = target.tag_name.as_deref()?.trim().to_ascii_lowercase();
    if !matches!(
        tag_name.as_str(),
        "div"
            | "span"
            | "li"
            | "td"
            | "tr"
            | "section"
            | "article"
            | "main"
            | "header"
            | "footer"
            | "p"
    ) {
        return None;
    }

    let (x, y, width, height) = target.rect_bounds?;
    if width < 100 || height < 100 {
        return None;
    }

    let inset_y = (height as f64 * 0.12).clamp(12.0, 24.0);
    Some((x as f64 + (width as f64 / 2.0), y as f64 + inset_y))
}

fn snapped_dom_click_coordinate(value: f64, origin: i32, extent: i32) -> f64 {
    if extent <= 0 {
        return value;
    }

    let min = if extent > 2 {
        origin as f64 + 1.0
    } else {
        origin as f64
    };
    let max = if extent > 2 {
        origin as f64 + (extent - 2) as f64
    } else {
        origin as f64 + (extent - 1).max(0) as f64
    };
    value.round().clamp(min, max)
}

fn geometry_dispatch_point(target: &BrowserSemanticTarget, point: (f64, f64)) -> (f64, f64) {
    if !prefers_selector_click_path(target) {
        return point;
    }

    let Some((x, y, width, height)) = target.rect_bounds else {
        return point;
    };
    if width <= 0 || height <= 0 {
        return point;
    }

    (
        snapped_dom_click_coordinate(point.0, x, width),
        snapped_dom_click_coordinate(point.1, y, height),
    )
}

#[derive(Debug)]
struct CurrentClickTreeRefresh {
    transformed: Option<AccessibilityNode>,
    source: &'static str,
    elapsed_ms: u64,
    error: Option<String>,
}

fn target_prefers_live_tree_refresh_before_dispatch(
    target: &BrowserSemanticTarget,
    resolved_from: &str,
) -> bool {
    resolved_from != "current_accessibility_tree"
        && prefers_selector_click_path(target)
        && target
            .backend_dom_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .cdp_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

async fn refresh_current_click_tree(
    exec: &ToolExecutor,
    id: &str,
    current_tree_refresh_timeout: Duration,
) -> CurrentClickTreeRefresh {
    let current_tree_started_at = Instant::now();
    emit_browser_click_trace("current_tree_refresh_start", format!("id={id}"));
    match timeout(
        current_tree_refresh_timeout,
        exec.browser.get_accessibility_tree(),
    )
    .await
    {
        Ok(Ok(raw_tree)) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_done",
                format!("elapsed_ms={elapsed_ms}"),
            );
            CurrentClickTreeRefresh {
                transformed: Some(apply_browser_auto_lens_with_som(&raw_tree)),
                source: "current_accessibility_tree",
                elapsed_ms,
                error: None,
            }
        }
        Ok(Err(error)) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_error",
                format!("elapsed_ms={elapsed_ms} error={error}"),
            );
            CurrentClickTreeRefresh {
                transformed: None,
                source: "current_accessibility_tree_error",
                elapsed_ms,
                error: Some(error.to_string()),
            }
        }
        Err(_) => {
            let elapsed_ms = current_tree_started_at.elapsed().as_millis() as u64;
            emit_browser_click_trace(
                "current_tree_refresh_timeout",
                format!(
                    "elapsed_ms={elapsed_ms} timeout_ms={}",
                    current_tree_refresh_timeout.as_millis()
                ),
            );
            CurrentClickTreeRefresh {
                transformed: None,
                source: "current_accessibility_tree_timeout",
                elapsed_ms,
                error: Some(format!(
                    "current accessibility tree refresh timed out after {}ms",
                    current_tree_refresh_timeout.as_millis()
                )),
            }
        }
    }
}

fn click_dispatch_settle_schedule(target: &BrowserSemanticTarget) -> &'static [u64] {
    if uses_geometry_only_click_verification(target) {
        &CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY
    } else {
        &CLICK_DISPATCH_SETTLE_MS_DOM_BACKED
    }
}

fn annotate_click_result_verify(
    mut result: ToolExecutionResult,
    annotations: &[(&str, serde_json::Value)],
) -> ToolExecutionResult {
    if annotations.is_empty() {
        return result;
    }

    let annotate_text = |text: &mut String| {
        let Some(verify_idx) = text.rfind(" verify=") else {
            return;
        };
        let prefix = text[..verify_idx].to_string();
        let verify_raw = text[verify_idx + " verify=".len()..].trim();
        let Ok(mut verify_value) = serde_json::from_str::<serde_json::Value>(verify_raw) else {
            return;
        };
        let Some(verify_obj) = verify_value.as_object_mut() else {
            return;
        };
        for (key, value) in annotations {
            verify_obj.insert((*key).to_string(), value.clone());
        }
        *text = format!("{prefix} verify={verify_value}");
    };

    if let Some(history_entry) = result.history_entry.as_mut() {
        annotate_text(history_entry);
    }
    if let Some(error) = result.error.as_mut() {
        annotate_text(error);
    }

    result
}

fn history_entry_verify_value(entry: Option<&str>) -> Option<serde_json::Value> {
    let entry = entry.map(str::trim).filter(|value| !value.is_empty())?;
    let (_, verify_raw) = entry.split_once(" verify=")?;
    serde_json::from_str(verify_raw).ok()
}

fn click_result_marks_browser_session_unstable(result: &ToolExecutionResult) -> bool {
    history_entry_verify_value(result.error.as_deref())
        .as_ref()
        .is_some_and(verify_marks_browser_session_unstable)
}

fn click_result_has_dispatch_timeout(result: &ToolExecutionResult) -> bool {
    history_entry_verify_value(result.error.as_deref())
        .and_then(|verify| {
            verify
                .get("dispatch_failures")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|error| error.contains("dispatch timed out"))
            })
        })
}

fn dispatch_error_is_timeout(error: &str) -> bool {
    error.contains("dispatch timed out")
}

fn should_refresh_recent_accessibility_snapshot_after_success(
    postcondition: &ClickElementPostcondition,
) -> bool {
    postcondition.material_semantic_change && !postcondition.editable_focus_transition
}

async fn refresh_recent_accessibility_snapshot_after_success(
    exec: &ToolExecutor,
    verify: &mut serde_json::Value,
    postcondition: &ClickElementPostcondition,
) {
    if !should_refresh_recent_accessibility_snapshot_after_success(postcondition) {
        return;
    }

    sleep(Duration::from_millis(
        CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
    ))
    .await;

    let refresh_started_at = Instant::now();
    let refresh = timeout(
        CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT,
        exec.browser.get_prompt_observation_tree(),
    )
    .await;

    verify["post_success_refresh"] = match refresh {
        Ok(Ok(_)) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": true,
            "timed_out": false,
            "updated": true,
        }),
        Ok(Err(error)) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": false,
            "timed_out": false,
            "updated": false,
            "error": error.to_string(),
        }),
        Err(_) => json!({
            "attempted": true,
            "delay_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS,
            "snapshot_elapsed_ms": refresh_started_at.elapsed().as_millis() as u64,
            "prompt_observation_updated": false,
            "timed_out": true,
            "timeout_ms": CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT.as_millis() as u64,
            "updated": false,
        }),
    };
}

async fn verify_click_dispatch(
    exec: &ToolExecutor,
    pre_tree_xml: &str,
    semantic_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    method: &str,
    center_point: Option<(f64, f64)>,
    pre_focused_control: Option<&BrowserSemanticTarget>,
    dispatch_started_at_ms: u64,
    dispatch_elapsed_ms: u64,
    execution_started_at: Instant,
    execution_deadline: Instant,
) -> (bool, serde_json::Value) {
    let verify_started_at = Instant::now();
    let verify_started_at_ms = unix_timestamp_ms_now();
    let settle_schedule = click_dispatch_settle_schedule(semantic_target);
    for (attempt_idx, settle_ms) in settle_schedule.iter().copied().enumerate() {
        let is_final_attempt = attempt_idx + 1 == settle_schedule.len();
        if settle_ms > 0 {
            sleep(Duration::from_millis(settle_ms)).await;
        }

        let Some(snapshot_timeout) = remaining_click_element_budget(execution_deadline) else {
            let mut verify = json!({
                "method": method,
                "dispatch_succeeded": true,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "postcondition": {
                    "met": false,
                },
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "settle_ms": settle_ms,
                "dispatch_started_at_ms": dispatch_started_at_ms,
                "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                "dispatch_elapsed_ms": dispatch_elapsed_ms,
                "verify_started_at_ms": verify_started_at_ms,
                "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
            });
            if let Some((x, y)) = center_point {
                verify["center_point"] = json!([x, y]);
            }
            return (false, verify);
        };

        let snapshot_started_at = Instant::now();
        match timeout(snapshot_timeout, exec.browser.get_accessibility_tree()).await {
            Ok(Ok(post_raw_tree)) => {
                let post_url = exec.browser.active_url().await.ok();
                let post_url_ref = post_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|url| !url.is_empty());
                let pre_url_ref = pre_url.map(str::trim).filter(|url| !url.is_empty());
                let post_transformed = apply_browser_auto_lens_with_som(&post_raw_tree);
                let post_tree_xml = render_browser_tree_xml(&post_transformed);
                let post_target =
                    find_semantic_target_for_verification(&post_transformed, semantic_target);
                let focused_control = find_focused_semantic_target(&post_transformed);
                let postcondition = click_element_postcondition_met(
                    pre_tree_xml,
                    semantic_target,
                    pre_url_ref,
                    &post_tree_xml,
                    post_target.as_ref(),
                    post_url_ref,
                );
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "pre_target": semantic_target_verification_json(Some(semantic_target)),
                    "post_target": semantic_target_verification_json(post_target.as_ref()),
                    "focused_control": semantic_target_verification_json(focused_control.as_ref()),
                    "postcondition": {
                        "met": postcondition.met(),
                        "target_disappeared": postcondition.target_disappeared,
                        "editable_focus_transition": postcondition.editable_focus_transition,
                        "tree_changed": postcondition.tree_changed,
                        "url_changed": postcondition.url_changed,
                        "material_semantic_change": postcondition.material_semantic_change,
                        "semantic_change_delta": postcondition.semantic_change_delta,
                    },
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                let success = click_element_postcondition_counts_as_success(
                    semantic_target,
                    pre_focused_control,
                    post_target.as_ref(),
                    focused_control.as_ref(),
                    &postcondition,
                );
                verify["postcondition"]["met"] = json!(success);
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if success {
                    refresh_recent_accessibility_snapshot_after_success(
                        exec,
                        &mut verify,
                        &postcondition,
                    )
                    .await;
                    return (true, verify);
                }
                if is_final_attempt {
                    return (false, verify);
                }
            }
            Ok(Err(e)) => {
                let error_text = e.to_string();
                let browser_session_unstable = browser_session_unstable_error(&error_text);
                let post_url = verification_post_url(exec, browser_session_unstable).await;
                let post_url_ref = post_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|url| !url.is_empty());
                let pre_url_ref = pre_url.map(str::trim).filter(|url| !url.is_empty());
                let url_changed = pre_url_ref
                    .zip(post_url_ref)
                    .is_some_and(|(pre, post)| pre != post);
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "postcondition": {
                        "met": url_changed,
                        "url_changed": url_changed,
                    },
                    "post_snapshot_error": error_text,
                    "browser_session_unstable": browser_session_unstable,
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if browser_session_unstable || url_changed || is_final_attempt {
                    return (url_changed, verify);
                }
            }
            Err(_) => {
                let mut verify = json!({
                    "method": method,
                    "dispatch_succeeded": true,
                    "postcondition": {
                        "met": false,
                    },
                    "post_snapshot_error": format!(
                        "execution budget exhausted before post-dispatch snapshot after {} ms",
                        CLICK_ELEMENT_EXECUTION_BUDGET.as_millis()
                    ),
                    "budget_exhausted": true,
                    "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                    "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                    "settle_ms": settle_ms,
                    "dispatch_started_at_ms": dispatch_started_at_ms,
                    "dispatch_finished_at_ms": dispatch_started_at_ms.saturating_add(dispatch_elapsed_ms),
                    "dispatch_elapsed_ms": dispatch_elapsed_ms,
                    "verify_started_at_ms": verify_started_at_ms,
                    "post_snapshot_elapsed_ms": snapshot_started_at.elapsed().as_millis() as u64,
                    "verify_elapsed_ms": verify_started_at.elapsed().as_millis() as u64,
                });
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                return (false, verify);
            }
        }
    }
    unreachable!("verification settle loop should return on the final attempt")
}

fn dispatch_failure_verify(
    method: &str,
    dispatch_elapsed_ms: u64,
    error: &str,
    center_point: Option<(f64, f64)>,
) -> serde_json::Value {
    let mut failure = json!({
        "method": method,
        "dispatch_elapsed_ms": dispatch_elapsed_ms,
        "error": error,
    });
    if let Some((x, y)) = center_point {
        failure["center_point"] = json!([x, y]);
    }
    failure
}

fn annotate_prior_click_attempts(
    verify: &mut serde_json::Value,
    prior_attempts: &[serde_json::Value],
    prior_dispatch_failures: &[serde_json::Value],
) {
    if !prior_attempts.is_empty() {
        verify["prior_attempts"] = json!(prior_attempts);
    }
    if !prior_dispatch_failures.is_empty() {
        verify["prior_dispatch_failures"] = json!(prior_dispatch_failures);
    }
}

async fn attempt_click_element_with_target(
    exec: &ToolExecutor,
    id: &str,
    semantic_target: &BrowserSemanticTarget,
    _target_resolution_source: &str,
    pre_tree_xml: &str,
    pre_url: Option<&str>,
    pre_focused_control: Option<&BrowserSemanticTarget>,
    execution_started_at: Instant,
    execution_deadline: Instant,
) -> ToolExecutionResult {
    let mut click_errors: Vec<String> = Vec::new();
    let mut attempt_verification: Vec<serde_json::Value> = Vec::new();
    let mut dispatch_failures: Vec<serde_json::Value> = Vec::new();
    let safe_inset_point = safe_inset_click_point(semantic_target);
    let selector_click_attempted_first = prefers_selector_click_path(semantic_target);

    let budget_exhausted_failure =
        |click_errors: Vec<String>,
         attempt_verification: Vec<serde_json::Value>,
         dispatch_failures: Vec<serde_json::Value>| {
            let verify = json!({
                "id": id,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "attempts": attempt_verification,
                "click_errors": click_errors,
                "dispatch_failures": dispatch_failures,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
            });
            ToolExecutionResult::failure(format!(
            "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget. verify={}",
            id,
            CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
            verify
        ))
        };
    let dispatch_timeout_failure =
        |click_errors: Vec<String>,
         attempt_verification: Vec<serde_json::Value>,
         dispatch_failures: Vec<serde_json::Value>| {
            let verify = json!({
                "id": id,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "attempts": attempt_verification,
                "click_errors": click_errors,
                "dispatch_failures": dispatch_failures,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
                id, verify
            ))
        };

    if selector_click_attempted_first {
        if let Some(selector) = click_selector_fallback_locator(semantic_target) {
            let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
                return budget_exhausted_failure(
                    click_errors,
                    attempt_verification,
                    dispatch_failures,
                );
            };
            emit_browser_click_trace(
                "selector_grounded_dispatch_start",
                format!("id={id} selector={selector}"),
            );
            let dispatch_started_at_ms = unix_timestamp_ms_now();
            let dispatch_started_at = Instant::now();
            match run_browser_dispatch_with_timeout_for(
                dispatch_timeout,
                exec.browser.click_selector_grounded(&selector),
            )
            .await
            {
                Ok(()) => {
                    emit_browser_click_trace(
                        "selector_grounded_dispatch_done",
                        format!(
                            "id={id} selector={selector} elapsed_ms={}",
                            dispatch_started_at.elapsed().as_millis()
                        ),
                    );
                    let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                    let (met, mut verify) = verify_click_dispatch(
                        exec,
                        pre_tree_xml,
                        semantic_target,
                        pre_url,
                        "selector_grounded",
                        None,
                        pre_focused_control,
                        dispatch_started_at_ms,
                        dispatch_elapsed_ms,
                        execution_started_at,
                        execution_deadline,
                    )
                    .await;
                    verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                    verify["selector"] = json!(selector);
                    if met {
                        annotate_prior_click_attempts(
                            &mut verify,
                            &attempt_verification,
                            &dispatch_failures,
                        );
                        return ToolExecutionResult::success(format!(
                            "Clicked element '{}' via selector path '{}'. verify={}",
                            id, selector, verify
                        ));
                    }
                    if verify_marks_browser_session_unstable(&verify) {
                        attempt_verification.push(verify);
                        return browser_session_unstable_failure(
                            id,
                            semantic_target,
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                            execution_started_at,
                        );
                    }
                    attempt_verification.push(verify);
                }
                Err(error) => {
                    emit_browser_click_trace(
                        "selector_grounded_dispatch_error",
                        format!(
                            "id={id} selector={selector} elapsed_ms={} error={error}",
                            dispatch_started_at.elapsed().as_millis()
                        ),
                    );
                    let browser_session_unstable = browser_session_unstable_error(&error);
                    let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                    click_errors.push(format!("selector_path={error}"));
                    let mut failure = dispatch_failure_verify(
                        "selector_grounded",
                        dispatch_elapsed_ms,
                        &error,
                        None,
                    );
                    failure["selector"] = json!(selector);
                    if browser_session_unstable {
                        failure["browser_session_unstable"] = json!(true);
                    }
                    dispatch_failures.push(failure);
                    if browser_session_unstable {
                        return browser_session_unstable_failure(
                            id,
                            semantic_target,
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                            execution_started_at,
                        );
                    }
                    if dispatch_error_is_timeout(&error) {
                        return dispatch_timeout_failure(
                            click_errors,
                            attempt_verification,
                            dispatch_failures,
                        );
                    }
                }
            }
        }
    }

    if let Some((x, y)) = safe_inset_point {
        let dispatch_point = geometry_dispatch_point(semantic_target, (x, y));
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .synthetic_click(dispatch_point.0, dispatch_point.1),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "geometry_safe_inset",
                    Some(dispatch_point),
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via safe inset geometry. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("geometry_safe_inset=({:.2},{:.2})={}", x, y, error));
                let mut failure = dispatch_failure_verify(
                    "geometry_safe_inset",
                    dispatch_elapsed_ms,
                    &error,
                    Some(dispatch_point),
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .click_backend_dom_node_in_target(backend_id, semantic_target.target_id.as_deref()),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "backend_dom_node_id",
                    None,
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("backend_dom_node_id={}", error));
                let mut failure = dispatch_failure_verify(
                    "backend_dom_node_id",
                    dispatch_elapsed_ms,
                    &error,
                    None,
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some(cdp_id) = semantic_target.cdp_node_id.as_deref() {
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .click_ax_node_in_target(cdp_id, semantic_target.target_id.as_deref()),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "cdp_node_id",
                    None,
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("cdp_node_id={}", error));
                let mut failure =
                    dispatch_failure_verify("cdp_node_id", dispatch_elapsed_ms, &error, None);
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    if let Some((x, y)) = semantic_target.center_point {
        let dispatch_point = geometry_dispatch_point(semantic_target, (x, y));
        let Some(dispatch_timeout) = click_element_attempt_timeout(execution_deadline) else {
            return budget_exhausted_failure(click_errors, attempt_verification, dispatch_failures);
        };
        let dispatch_started_at_ms = unix_timestamp_ms_now();
        let dispatch_started_at = Instant::now();
        match run_browser_dispatch_with_timeout_for(
            dispatch_timeout,
            exec.browser
                .synthetic_click(dispatch_point.0, dispatch_point.1),
        )
        .await
        {
            Ok(()) => {
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                let (met, mut verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    "geometry_center",
                    Some(dispatch_point),
                    pre_focused_control,
                    dispatch_started_at_ms,
                    dispatch_elapsed_ms,
                    execution_started_at,
                    execution_deadline,
                )
                .await;
                verify["attempt_index"] = json!((attempt_verification.len() + 1) as u64);
                if met {
                    annotate_prior_click_attempts(
                        &mut verify,
                        &attempt_verification,
                        &dispatch_failures,
                    );
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via geometry fallback. verify={}",
                        id, verify
                    ));
                }
                if verify_marks_browser_session_unstable(&verify) {
                    attempt_verification.push(verify);
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                let browser_session_unstable = browser_session_unstable_error(&error);
                let dispatch_elapsed_ms = dispatch_started_at.elapsed().as_millis() as u64;
                click_errors.push(format!("geometry_center=({:.2},{:.2})={}", x, y, error));
                let mut failure = dispatch_failure_verify(
                    "geometry_center",
                    dispatch_elapsed_ms,
                    &error,
                    Some(dispatch_point),
                );
                if browser_session_unstable {
                    failure["browser_session_unstable"] = json!(true);
                }
                dispatch_failures.push(failure);
                if browser_session_unstable {
                    return browser_session_unstable_failure(
                        id,
                        semantic_target,
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                        execution_started_at,
                    );
                }
                if dispatch_error_is_timeout(&error) {
                    return dispatch_timeout_failure(
                        click_errors,
                        attempt_verification,
                        dispatch_failures,
                    );
                }
            }
        }
    }

    let verify = json!({
        "id": id,
        "pre_target": semantic_target_verification_json(Some(semantic_target)),
        "attempts": attempt_verification,
        "click_errors": click_errors,
        "dispatch_failures": dispatch_failures,
    });
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
        id, verify
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        find_focused_semantic_target, find_nearest_semantic_target_by_point,
        semantic_target_verification_json, ToolExecutionResult,
    };
    use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
    use std::collections::HashMap;
    use tokio::time::{sleep, Duration};

    fn node(
        id: &str,
        role: &str,
        attrs: &[(&str, &str)],
        children: Vec<AccessibilityNode>,
    ) -> AccessibilityNode {
        AccessibilityNode {
            id: id.to_string(),
            role: role.to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 100,
                height: 20,
            },
            children,
            is_visible: true,
            attributes: attrs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
            som_id: None,
        }
    }

    #[test]
    fn click_dispatch_settle_schedule_includes_delayed_tail_probe() {
        assert_eq!(
            super::CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY,
            [0, 80, 160, 320, 640]
        );
        assert_eq!(
            super::CLICK_DISPATCH_SETTLE_MS_DOM_BACKED,
            [0, 120, 240, 900]
        );
    }

    #[tokio::test]
    async fn browser_tool_strategy_timeout_returns_error() {
        let result =
            super::run_browser_tool_strategy_with_timeout_for(Duration::from_millis(10), async {
                sleep(Duration::from_millis(25)).await;
                ToolExecutionResult::success("late")
            })
            .await;

        match result {
            Ok(result) => panic!("expected timeout error, got success: {result:?}"),
            Err(error) => assert_eq!(error, "strategy timed out after 10 ms"),
        }
    }

    #[tokio::test]
    async fn browser_tool_strategy_timeout_returns_completed_result() {
        let result =
            super::run_browser_tool_strategy_with_timeout_for(Duration::from_millis(25), async {
                sleep(Duration::from_millis(1)).await;
                ToolExecutionResult::success("done")
            })
            .await
            .expect("completed result");

        assert!(result.success);
        assert_eq!(result.history_entry.as_deref(), Some("done"));
        assert_eq!(result.error, None);
    }

    #[test]
    fn material_semantic_success_refreshes_recent_snapshot() {
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: true,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 11,
        };

        assert!(super::should_refresh_recent_accessibility_snapshot_after_success(&postcondition));
    }

    #[test]
    fn editable_focus_success_does_not_force_recent_snapshot_refresh() {
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: true,
            tree_changed: false,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 1,
        };

        assert!(!super::should_refresh_recent_accessibility_snapshot_after_success(&postcondition));
    }

    #[test]
    fn semantic_target_is_actionable_for_recent_geometry_only_targets() {
        let target = super::BrowserSemanticTarget {
            center_point: Some((63.0, 154.0)),
            selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
            ..Default::default()
        };

        assert!(super::semantic_target_is_actionable(&target));
    }

    #[test]
    fn semantic_target_is_actionable_for_selector_backed_targets() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"buy\"]".to_string()),
            dom_id: Some("buy".to_string()),
            ..Default::default()
        };

        assert!(super::semantic_target_is_actionable(&target));
    }

    #[test]
    fn geometry_only_targets_use_shorter_click_verification_tail() {
        let target = super::BrowserSemanticTarget {
            center_point: Some((52.0, 69.0)),
            selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
            tag_name: Some("rect".to_string()),
            ..Default::default()
        };

        assert!(super::uses_geometry_only_click_verification(&target));
        assert_eq!(
            super::click_dispatch_settle_schedule(&target),
            &[0, 80, 160, 320, 640]
        );
    }

    #[test]
    fn dom_backed_targets_keep_delayed_tail_probe() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("submit".to_string()),
            backend_dom_node_id: Some("backend-17".to_string()),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };

        assert!(!super::uses_geometry_only_click_verification(&target));
        assert_eq!(
            super::click_dispatch_settle_schedule(&target),
            &[0, 120, 240, 900]
        );
    }

    #[tokio::test]
    async fn browser_dispatch_timeout_returns_timeout_error() {
        let result =
            super::run_browser_dispatch_with_timeout_for(Duration::from_millis(10), async {
                sleep(Duration::from_millis(25)).await;
                Ok::<(), &'static str>(())
            })
            .await;

        let error = result.expect_err("dispatch should time out");
        assert!(
            error.contains("dispatch timed out after 10 ms. Retry the action."),
            "{error}"
        );
    }

    #[tokio::test]
    async fn browser_dispatch_timeout_preserves_underlying_error() {
        let result =
            super::run_browser_dispatch_with_timeout_for(Duration::from_millis(10), async {
                Err::<(), _>("backend failed")
            })
            .await;

        assert_eq!(result.unwrap_err(), "backend failed");
    }

    #[test]
    fn browser_session_unstable_error_matches_reset_retry_messages() {
        assert!(super::browser_session_unstable_error(
            "Browser accessibility snapshot timed out after 1.5s. Retry the action."
        ));
        assert!(super::browser_session_unstable_error(
            "selector click for '#buy' timed out after 2000ms. Browser session reset; retry the action."
        ));
        assert!(!super::browser_session_unstable_error(
            "dispatch timed out after 2000 ms. Retry the action."
        ));
        assert!(!super::browser_session_unstable_error(
            "Typing had no observable effect on '#email'"
        ));
    }

    #[test]
    fn click_result_marks_browser_session_unstable_from_verify_payload() {
        let result = ToolExecutionResult::failure(
            "ERROR_CLASS=TimeoutOrHang Click element 'btn_buy' could not continue. verify={\"browser_session_unstable\":true}",
        );

        assert!(super::click_result_marks_browser_session_unstable(&result));
    }

    #[test]
    fn click_result_does_not_mark_regular_noeffect_as_browser_unstable() {
        let result = ToolExecutionResult::failure(
            "ERROR_CLASS=NoEffectAfterAction Failed to click element 'btn_buy'. verify={\"browser_session_unstable\":false}",
        );

        assert!(!super::click_result_marks_browser_session_unstable(&result));
    }

    #[test]
    fn current_tree_actionable_target_beats_prompt_tree_locator_tie() {
        let mut current_target = node(
            "ax_buy",
            "button",
            &[
                ("backend_dom_node_id", "42"),
                ("tag_name", "button"),
                ("center_x_precise", "80"),
                ("center_y_precise", "25"),
            ],
            Vec::new(),
        );
        current_target.name = Some("Buy".to_string());

        let mut prompt_target = node(
            "btn_buy",
            "button",
            &[
                ("dom_id", "buy"),
                ("selector", "[id=\"buy\"]"),
                ("tag_name", "button"),
                ("center_x_precise", "80"),
                ("center_y_precise", "150"),
            ],
            Vec::new(),
        );
        prompt_target.name = Some("Buy".to_string());

        let current_tree = node("root", "root", &[], vec![current_target]);
        let prompt_tree = node("root", "root", &[], vec![prompt_target]);

        let (resolved, source) = super::resolve_semantic_target_from_current_or_prompt_tree(
            Some(&current_tree),
            Some(&prompt_tree),
            "buy",
        )
        .expect("buy should resolve from prompt or current tree");

        assert_eq!(source, "current_accessibility_tree");
        assert_eq!(resolved.backend_dom_node_id.as_deref(), Some("42"));
    }

    #[test]
    fn semantic_id_lookup_prefers_dom_id_before_earlier_semantic_alias_match() {
        let tree = node(
            "root",
            "root",
            &[],
            vec![
                node(
                    "grp_buy_yjv_stock_when_the_price_i",
                    "generic",
                    &[
                        ("dom_id", "query"),
                        ("semantic_aliases", "buy grp_buy_yjv_stock_when_the_price_i"),
                    ],
                    Vec::new(),
                ),
                node(
                    "btn_buy",
                    "button",
                    &[
                        ("dom_id", "buy"),
                        ("selector", "[id=\"buy\"]"),
                        ("tag_name", "button"),
                    ],
                    Vec::new(),
                ),
            ],
        );

        let target = super::find_semantic_target_by_id(&tree, "buy").expect("buy target");
        assert_eq!(target.semantic_id.as_deref(), Some("btn_buy"));
        assert_eq!(target.dom_id.as_deref(), Some("buy"));
        assert_eq!(target.selector.as_deref(), Some("[id=\"buy\"]"));
    }

    #[test]
    fn semantic_id_lookup_keeps_exact_semantic_id_over_alias_candidate() {
        let tree = node(
            "root",
            "root",
            &[],
            vec![
                node(
                    "btn_buy",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("center_x_precise", "80"),
                        ("center_y_precise", "25"),
                    ],
                    Vec::new(),
                ),
                node(
                    "ax_buy",
                    "button",
                    &[
                        ("dom_id", "buy"),
                        ("selector", "[id=\"buy\"]"),
                        ("tag_name", "button"),
                        ("center_x_precise", "80"),
                        ("center_y_precise", "150"),
                    ],
                    Vec::new(),
                ),
            ],
        );

        let target = super::find_semantic_target_by_id(&tree, "btn_buy").expect("buy target");
        assert_eq!(target.semantic_id.as_deref(), Some("btn_buy"));
        assert_eq!(target.dom_id.as_deref(), None);
        assert_eq!(target.selector.as_deref(), None);
    }

    #[test]
    fn semantic_id_lookup_does_not_replace_exact_button_with_instruction_alias() {
        let tree = node(
            "root",
            "root",
            &[],
            vec![
                node(
                    "grp_click_on_the_okay_button_dot",
                    "generic",
                    &[
                        ("dom_id", "query"),
                        ("selector", "#query"),
                        ("semantic_aliases", "okay btn_okay"),
                        ("center_x_precise", "80"),
                        ("center_y_precise", "25"),
                    ],
                    Vec::new(),
                ),
                node(
                    "btn_okay",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("center_x_precise", "25"),
                        ("center_y_precise", "137"),
                    ],
                    Vec::new(),
                ),
            ],
        );

        let target = super::find_semantic_target_by_id(&tree, "btn_okay").expect("okay button");
        assert_eq!(target.semantic_id.as_deref(), Some("btn_okay"));
        assert_eq!(target.tag_name.as_deref(), Some("button"));
    }

    #[test]
    fn large_container_targets_use_safe_inset_click_point() {
        let target = super::BrowserSemanticTarget {
            tag_name: Some("div".to_string()),
            rect_bounds: Some((0, 0, 160, 210)),
            center_point: Some((80.0, 105.0)),
            ..Default::default()
        };

        assert_eq!(super::safe_inset_click_point(&target), Some((80.0, 24.0)));
    }

    #[test]
    fn native_controls_do_not_use_safe_inset_click_point() {
        let target = super::BrowserSemanticTarget {
            tag_name: Some("button".to_string()),
            rect_bounds: Some((27, 84, 95, 31)),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };

        assert_eq!(super::safe_inset_click_point(&target), None);
    }

    #[test]
    fn resolve_semantic_target_from_current_or_prompt_tree_prefers_current_tree_when_equally_rich()
    {
        let current_tree = node(
            "root",
            "root",
            &[],
            vec![node(
                "btn_submit",
                "button",
                &[("dom_id", "subbtn"), ("tag_name", "button")],
                Vec::new(),
            )],
        );
        let prompt_tree = node(
            "root_prompt",
            "root",
            &[],
            vec![node(
                "btn_submit",
                "button",
                &[("dom_id", "old-subbtn"), ("tag_name", "button")],
                Vec::new(),
            )],
        );

        let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
            Some(&current_tree),
            Some(&prompt_tree),
            "btn_submit",
        )
        .expect("current tree target");

        assert_eq!(resolved_from, "current_accessibility_tree");
        assert_eq!(target.dom_id.as_deref(), Some("subbtn"));
    }

    #[test]
    fn resolve_semantic_target_from_current_or_prompt_tree_merges_prompt_dom_metadata() {
        let current_tree = node(
            "root",
            "root",
            &[],
            vec![node(
                "btn_buy",
                "button",
                &[("backend_dom_node_id", "backend-buy")],
                Vec::new(),
            )],
        );
        let prompt_tree = node(
            "root_prompt",
            "root",
            &[],
            vec![node(
                "btn_buy",
                "button",
                &[
                    ("dom_id", "buy"),
                    ("selector", "[id=\"buy\"]"),
                    ("tag_name", "button"),
                    ("dom_clickable", "true"),
                ],
                Vec::new(),
            )],
        );

        let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
            Some(&current_tree),
            Some(&prompt_tree),
            "btn_buy",
        )
        .expect("merged target");

        assert_eq!(resolved_from, "current_accessibility_tree+prompt_metadata");
        assert_eq!(target.backend_dom_node_id.as_deref(), Some("backend-buy"));
        assert_eq!(target.dom_id.as_deref(), Some("buy"));
        assert_eq!(target.selector.as_deref(), Some("[id=\"buy\"]"));
        assert_eq!(target.tag_name.as_deref(), Some("button"));
        assert!(target.dom_clickable);
    }

    #[test]
    fn resolve_semantic_target_from_current_or_prompt_tree_falls_back_to_prompt_tree() {
        let current_tree = node("root", "root", &[], Vec::new());
        let prompt_tree = node(
            "root_prompt",
            "root",
            &[],
            vec![node(
                "grp_start",
                "generic",
                &[
                    ("dom_id", "sync-task-cover"),
                    ("selector", "[id=\"sync-task-cover\"]"),
                    ("tag_name", "div"),
                ],
                Vec::new(),
            )],
        );

        let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
            Some(&current_tree),
            Some(&prompt_tree),
            "grp_start",
        )
        .expect("prompt tree fallback");

        assert_eq!(resolved_from, "prompt_observation_tree");
        assert_eq!(target.dom_id.as_deref(), Some("sync-task-cover"));
        assert_eq!(target.selector.as_deref(), Some("[id=\"sync-task-cover\"]"));
    }

    #[test]
    fn find_focused_semantic_target_prefers_focused_descendant_metadata() {
        let tree = node(
            "grp_scroll_wrapper",
            "generic",
            &[("dom_id", "wrap")],
            vec![node(
                "inp_text_area",
                "textbox",
                &[
                    ("dom_id", "text-area"),
                    ("selector", "[id=\"text-area\"]"),
                    ("tag_name", "textarea"),
                    ("focused", "true"),
                    ("scroll_top", "257"),
                    ("scroll_height", "565"),
                    ("client_height", "104"),
                    ("can_scroll_up", "true"),
                    ("can_scroll_down", "true"),
                ],
                Vec::new(),
            )],
        );

        let focused = find_focused_semantic_target(&tree).expect("focused descendant");
        assert_eq!(focused.dom_id.as_deref(), Some("text-area"));
        assert_eq!(focused.tag_name.as_deref(), Some("textarea"));
        assert_eq!(focused.scroll_top, Some(257));
        assert_eq!(focused.can_scroll_up, Some(true));
        assert_eq!(focused.can_scroll_down, Some(true));
    }

    #[test]
    fn semantic_target_verification_json_includes_focused_scroll_metadata() {
        let focused = find_focused_semantic_target(&node(
            "inp_text_area",
            "textbox",
            &[
                ("dom_id", "text-area"),
                ("selector", "[id=\"text-area\"]"),
                ("tag_name", "textarea"),
                ("focused", "true"),
                ("scroll_top", "0"),
                ("scroll_height", "565"),
                ("client_height", "104"),
                ("can_scroll_up", "false"),
                ("can_scroll_down", "true"),
            ],
            Vec::new(),
        ))
        .expect("focused node");

        let json = semantic_target_verification_json(Some(&focused));
        assert_eq!(json["dom_id"], "text-area");
        assert_eq!(json["selector"], "[id=\"text-area\"]");
        assert_eq!(json["tag_name"], "textarea");
        assert_eq!(json["scroll_top"], 0);
        assert_eq!(json["can_scroll_up"], false);
        assert_eq!(json["can_scroll_down"], true);
    }

    #[test]
    fn semantic_target_verification_json_includes_selection_state_metadata() {
        let target = super::find_semantic_target_by_id(
            &node(
                "radio_target",
                "radio",
                &[
                    ("dom_id", "choice-1"),
                    ("selector", "[id=\"choice-1\"]"),
                    ("tag_name", "input"),
                    ("checked", "true"),
                ],
                Vec::new(),
            ),
            "radio_target",
        )
        .expect("semantic target");

        let json = semantic_target_verification_json(Some(&target));
        assert_eq!(json["dom_id"], "choice-1");
        assert_eq!(json["checked"], true);
        assert_eq!(json["selected"], serde_json::Value::Null);
    }

    #[test]
    fn verification_prefers_exact_element_hash_match_before_weaker_locators() {
        let tree = node(
            "root",
            "root",
            &[],
            vec![
                node(
                    "btn_stable_only",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("stable_hash", "111"),
                        ("element_hash", "999"),
                    ],
                    Vec::new(),
                ),
                node(
                    "btn_exact_hash",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("stable_hash", "111"),
                        ("element_hash", "222"),
                    ],
                    Vec::new(),
                ),
            ],
        );

        let target = super::BrowserSemanticTarget {
            tag_name: Some("button".to_string()),
            element_hash: Some(222),
            stable_hash: Some(111),
            ..Default::default()
        };

        let found = super::find_semantic_target_for_verification(&tree, &target).expect("target");
        assert_eq!(found.semantic_id.as_deref(), Some("btn_exact_hash"));
    }

    #[test]
    fn verification_falls_back_to_attribute_identity_when_hashes_and_xpath_fail() {
        let tree = node(
            "root",
            "root",
            &[],
            vec![
                node(
                    "btn_other",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("aria-label", "Cancel"),
                        ("name", "cancel"),
                    ],
                    Vec::new(),
                ),
                node(
                    "btn_submit",
                    "button",
                    &[
                        ("tag_name", "button"),
                        ("aria-label", "Submit"),
                        ("name", "submit"),
                    ],
                    Vec::new(),
                ),
            ],
        );

        let mut target = super::BrowserSemanticTarget {
            tag_name: Some("button".to_string()),
            x_path: Some("/html/body/div[9]/button[2]".to_string()),
            ax_name: Some("Mismatched accessible name".to_string()),
            ..Default::default()
        };
        target
            .identity_attributes
            .insert("aria-label".to_string(), "Submit".to_string());

        let found = super::find_semantic_target_for_verification(&tree, &target).expect("target");
        assert_eq!(found.semantic_id.as_deref(), Some("btn_submit"));
    }

    #[test]
    fn semantic_target_verification_json_includes_browser_use_identity_attributes() {
        let target = super::find_semantic_target_by_id(
            &node(
                "btn_submit",
                "button",
                &[
                    ("tag_name", "button"),
                    ("name", "submit"),
                    ("aria-label", "Submit"),
                    ("element_hash", "222"),
                ],
                Vec::new(),
            ),
            "btn_submit",
        )
        .expect("semantic target");

        let json = semantic_target_verification_json(Some(&target));
        assert_eq!(json["identity_attributes"]["name"], "submit");
        assert_eq!(json["identity_attributes"]["aria-label"], "Submit");
        assert_eq!(json["element_hash"], 222);
    }

    #[test]
    fn nearest_semantic_target_by_point_prefers_contained_geometry_target() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 200,
                height: 200,
            },
            children: vec![
                AccessibilityNode {
                    id: "btn_submit".to_string(),
                    role: "button".to_string(),
                    name: Some("Submit".to_string()),
                    value: None,
                    rect: Rect {
                        x: 70,
                        y: 180,
                        width: 60,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("dom_id".to_string(), "subbtn".to_string()),
                        ("selector".to_string(), "#subbtn".to_string()),
                        ("tag_name".to_string(), "button".to_string()),
                    ]),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "grp_blue_circle".to_string(),
                    role: "generic".to_string(),
                    name: Some("blue circle".to_string()),
                    value: None,
                    rect: Rect {
                        x: 49,
                        y: 114,
                        width: 8,
                        height: 8,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("selector".to_string(), "#blue-circle".to_string()),
                        ("tag_name".to_string(), "circle".to_string()),
                    ]),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = find_nearest_semantic_target_by_point(&tree, 51.0, 116.0).expect("target");
        assert_eq!(target.semantic_id.as_deref(), Some("grp_blue_circle"));
        assert_eq!(target.selector.as_deref(), Some("#blue-circle"));
    }

    #[test]
    fn nearest_semantic_target_by_point_prefers_grounded_locator_when_centers_tie() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 200,
                height: 200,
            },
            children: vec![
                AccessibilityNode {
                    id: "grp_vertex_alias".to_string(),
                    role: "generic".to_string(),
                    name: Some("vertex alias".to_string()),
                    value: None,
                    rect: Rect {
                        x: 27,
                        y: 104,
                        width: 8,
                        height: 8,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([("tag_name".to_string(), "circle".to_string())]),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "grp_blue_circle".to_string(),
                    role: "generic".to_string(),
                    name: Some("blue circle".to_string()),
                    value: None,
                    rect: Rect {
                        x: 27,
                        y: 104,
                        width: 8,
                        height: 8,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("dom_id".to_string(), "blue-circle".to_string()),
                        ("selector".to_string(), "#blue-circle".to_string()),
                        ("tag_name".to_string(), "circle".to_string()),
                    ]),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = find_nearest_semantic_target_by_point(&tree, 31.0, 108.0).expect("target");
        assert_eq!(target.semantic_id.as_deref(), Some("grp_blue_circle"));
        assert_eq!(target.dom_id.as_deref(), Some("blue-circle"));
    }

    #[test]
    fn stale_semantic_id_recovers_unique_data_index_target() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 160,
                height: 160,
            },
            children: vec![
                AccessibilityNode {
                    id: "grp_rect_a".to_string(),
                    role: "generic".to_string(),
                    name: Some("4".to_string()),
                    value: None,
                    rect: Rect {
                        x: 40,
                        y: 60,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("data_index".to_string(), "4".to_string()),
                        ("shape_kind".to_string(), "rectangle".to_string()),
                    ]),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "grp_rect_b".to_string(),
                    role: "generic".to_string(),
                    name: Some("5".to_string()),
                    value: None,
                    rect: Rect {
                        x: 70,
                        y: 90,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("data_index".to_string(), "5".to_string()),
                        ("shape_kind".to_string(), "rectangle".to_string()),
                    ]),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = super::find_semantic_target_by_id(&tree, "grp_4").expect("target");
        assert_eq!(target.semantic_id.as_deref(), Some("grp_rect_a"));
        assert_eq!(target.center_point, Some((50.0, 70.0)));
    }

    #[test]
    fn semantic_target_prefers_precise_center_point_attributes_over_rect_center() {
        let node = AccessibilityNode {
            id: "grp_precise_center_target".to_string(),
            role: "generic".to_string(),
            name: Some("precise center target".to_string()),
            value: None,
            rect: Rect {
                x: 85,
                y: 101,
                width: 8,
                height: 8,
            },
            children: Vec::new(),
            is_visible: true,
            attributes: HashMap::from([
                ("center_x".to_string(), "89".to_string()),
                ("center_y".to_string(), "105".to_string()),
                ("center_x_precise".to_string(), "88.804735".to_string()),
                ("center_y_precise".to_string(), "105.372527".to_string()),
            ]),
            som_id: None,
        };

        let target =
            super::find_semantic_target_by_id(&node, "grp_precise_center_target").expect("target");
        assert_eq!(target.center_point, Some((88.804735, 105.372527)));
    }

    #[test]
    fn stale_semantic_id_recovers_unique_hyphenated_data_index_target() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 160,
                height: 160,
            },
            children: vec![
                AccessibilityNode {
                    id: "grp_rect_a".to_string(),
                    role: "generic".to_string(),
                    name: None,
                    value: None,
                    rect: Rect {
                        x: 40,
                        y: 60,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("data-index".to_string(), "4".to_string()),
                        ("shape_kind".to_string(), "rectangle".to_string()),
                    ]),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "grp_rect_b".to_string(),
                    role: "generic".to_string(),
                    name: None,
                    value: None,
                    rect: Rect {
                        x: 70,
                        y: 90,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::from([
                        ("data-index".to_string(), "5".to_string()),
                        ("shape_kind".to_string(), "rectangle".to_string()),
                    ]),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = super::find_semantic_target_by_id(&tree, "grp_4").expect("target");
        assert_eq!(target.semantic_id.as_deref(), Some("grp_rect_a"));
        assert_eq!(target.center_point, Some((50.0, 70.0)));
    }

    #[test]
    fn stale_semantic_id_does_not_guess_ambiguous_name_alias() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 160,
                height: 160,
            },
            children: vec![
                AccessibilityNode {
                    id: "grp_submit_primary".to_string(),
                    role: "button".to_string(),
                    name: Some("Submit".to_string()),
                    value: None,
                    rect: Rect {
                        x: 10,
                        y: 10,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::new(),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "grp_submit_secondary".to_string(),
                    role: "button".to_string(),
                    name: Some("Submit".to_string()),
                    value: None,
                    rect: Rect {
                        x: 40,
                        y: 10,
                        width: 20,
                        height: 20,
                    },
                    children: Vec::new(),
                    is_visible: true,
                    attributes: HashMap::new(),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        assert!(super::find_semantic_target_by_id(&tree, "btn_submit").is_none());
    }

    #[test]
    fn click_element_postcondition_rejects_stable_button_tree_change_without_semantic_delta() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_stable_button_tree_change_without_activation_signal() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 1,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_button_focus_loss_without_other_change() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: true,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: false,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_button_focus_gain_without_other_change() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: false,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: true,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_accepts_stable_button_material_change_without_focus_activation()
    {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((49.5, 180.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            center_point: Some((50.0, 180.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 28,
        };

        assert!(super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_small_non_link_material_change_without_activation_signal(
    ) {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_buy".to_string()),
            dom_id: Some("buy".to_string()),
            selector: Some("#buy".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((70.5, 150.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_buy".to_string()),
            dom_id: Some("buy".to_string()),
            selector: Some("#buy".to_string()),
            tag_name: Some("button".to_string()),
            center_point: Some((70.5, 150.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 4,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_stable_editable_material_change_without_focus_or_commit()
    {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("inp_tt".to_string()),
            dom_id: Some("tt".to_string()),
            selector: Some("#tt".to_string()),
            tag_name: Some("input".to_string()),
            editable: true,
            center_point: Some((76.0, 123.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("inp_tt".to_string()),
            dom_id: Some("tt".to_string()),
            selector: Some("#tt".to_string()),
            tag_name: Some("input".to_string()),
            editable: true,
            center_point: Some((76.0, 123.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 6,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_accepts_editable_focus_transition() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("inp_query".to_string()),
            dom_id: Some("query".to_string()),
            selector: Some("#query".to_string()),
            tag_name: Some("input".to_string()),
            editable: true,
            focused: false,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("inp_query".to_string()),
            dom_id: Some("query".to_string()),
            selector: Some("#query".to_string()),
            tag_name: Some("input".to_string()),
            editable: true,
            focused: true,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: true,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_accepts_stable_button_material_change_with_focus_activation() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: false,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let post_target = super::BrowserSemanticTarget {
            semantic_id: Some("btn_submit".to_string()),
            dom_id: Some("subbtn".to_string()),
            selector: Some("#subbtn".to_string()),
            tag_name: Some("button".to_string()),
            focused: true,
            center_point: Some((74.5, 99.5)),
            ..Default::default()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: false,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: true,
            semantic_change_delta: 29,
        };

        assert!(super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            Some(&post_target),
            Some(&post_target),
            &postcondition,
        ));
    }

    #[test]
    fn geometry_only_target_disappearance_counts_as_postcondition() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("grp_2".to_string()),
            selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
            tag_name: Some("rect".to_string()),
            center_point: Some((40.0, 110.0)),
            ..Default::default()
        };

        let postcondition = super::click_element_postcondition_met(
            "<root><generic id=\"grp_2\" name=\"2\" /></root>",
            &pre_target,
            Some("file:///tmp/miniwob/ascending-numbers.1.html"),
            "<root><generic id=\"grp_3\" name=\"3\" /></root>",
            None,
            Some("file:///tmp/miniwob/ascending-numbers.1.html"),
        );

        assert!(postcondition.target_disappeared);
        assert!(super::click_element_postcondition_counts_as_success(
            &pre_target,
            None,
            None,
            None,
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_rejects_popup_dismissal_without_editable_value_commit() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("grp_williston".to_string()),
            selector: Some("#ui-id-2 > li".to_string()),
            tag_name: Some("li".to_string()),
            center_point: Some((60.5, 137.5)),
            ..Default::default()
        };
        let pre_focused_control = super::BrowserSemanticTarget {
            semantic_id: Some("inp_to".to_string()),
            dom_id: Some("flight-to".to_string()),
            selector: Some("#flight-to".to_string()),
            tag_name: Some("input".to_string()),
            value: Some("ISN".to_string()),
            focused: true,
            editable: true,
            center_point: Some((67.0, 117.5)),
            ..Default::default()
        };
        let post_focused_control = pre_focused_control.clone();
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: true,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(!super::click_element_postcondition_counts_as_success(
            &pre_target,
            Some(&pre_focused_control),
            None,
            Some(&post_focused_control),
            &postcondition,
        ));
    }

    #[test]
    fn click_element_postcondition_accepts_popup_commit_when_editable_value_changes() {
        let pre_target = super::BrowserSemanticTarget {
            semantic_id: Some("grp_williston".to_string()),
            selector: Some("#ui-id-2 > li".to_string()),
            tag_name: Some("li".to_string()),
            center_point: Some((60.5, 137.5)),
            ..Default::default()
        };
        let pre_focused_control = super::BrowserSemanticTarget {
            semantic_id: Some("inp_to".to_string()),
            dom_id: Some("flight-to".to_string()),
            selector: Some("#flight-to".to_string()),
            tag_name: Some("input".to_string()),
            value: Some("ISN".to_string()),
            focused: true,
            editable: true,
            center_point: Some((67.0, 117.5)),
            ..Default::default()
        };
        let post_focused_control = super::BrowserSemanticTarget {
            value: Some("Williston, ND (ISN)".to_string()),
            ..pre_focused_control.clone()
        };
        let postcondition = super::ClickElementPostcondition {
            target_disappeared: true,
            editable_focus_transition: false,
            tree_changed: true,
            url_changed: false,
            material_semantic_change: false,
            semantic_change_delta: 0,
        };

        assert!(super::click_element_postcondition_counts_as_success(
            &pre_target,
            Some(&pre_focused_control),
            None,
            Some(&post_focused_control),
            &postcondition,
        ));
    }

    #[test]
    fn click_selector_fallback_locator_prefers_explicit_selector() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"subbtn\"]".to_string()),
            dom_id: Some("subbtn".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::click_selector_fallback_locator(&target).as_deref(),
            Some("[id=\"subbtn\"]"),
        );
    }

    #[test]
    fn click_selector_fallback_locator_derives_selector_from_dom_id() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("subbtn".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::click_selector_fallback_locator(&target).as_deref(),
            Some("[id=\"subbtn\"]"),
        );
    }

    #[test]
    fn prefers_selector_click_path_for_native_dom_control() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("buy".to_string()),
            tag_name: Some("button".to_string()),
            ..Default::default()
        };

        assert!(super::prefers_selector_click_path(&target));
    }

    #[test]
    fn does_not_prefer_selector_click_path_for_non_dom_custom_target() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"chart\"]".to_string()),
            tag_name: Some("canvas".to_string()),
            ..Default::default()
        };

        assert!(!super::prefers_selector_click_path(&target));
    }

    #[test]
    fn dispatch_error_timeout_detection_matches_click_wrapper_timeout() {
        assert!(super::dispatch_error_is_timeout(
            "dispatch timed out after 2500 ms. Retry the action."
        ));
        assert!(!super::dispatch_error_is_timeout(
            "selector click failed: Element not found"
        ));
    }

    #[test]
    fn live_tree_refresh_preferred_for_cached_native_dom_target_without_execution_ids() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("buy".to_string()),
            tag_name: Some("button".to_string()),
            dom_clickable: true,
            ..Default::default()
        };

        assert!(super::target_prefers_live_tree_refresh_before_dispatch(
            &target,
            "recent_accessibility_snapshot",
        ));
    }

    #[test]
    fn live_tree_refresh_not_preferred_for_geometry_only_canvas_target() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"chart\"]".to_string()),
            tag_name: Some("canvas".to_string()),
            center_point: Some((70.5, 150.5)),
            ..Default::default()
        };

        assert!(!super::target_prefers_live_tree_refresh_before_dispatch(
            &target,
            "recent_accessibility_snapshot",
        ));
    }

    #[test]
    fn geometry_dispatch_point_snaps_native_dom_targets_to_integral_pixels() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("buy".to_string()),
            tag_name: Some("button".to_string()),
            dom_clickable: true,
            rect_bounds: Some((20, 100, 101, 51)),
            ..Default::default()
        };

        assert_eq!(
            super::geometry_dispatch_point(&target, (70.5, 150.5)),
            (71.0, 149.0),
        );
    }

    #[test]
    fn geometry_dispatch_point_preserves_fractional_geometry_only_targets() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"chart\"]".to_string()),
            tag_name: Some("canvas".to_string()),
            rect_bounds: Some((20, 100, 101, 51)),
            ..Default::default()
        };

        assert_eq!(
            super::geometry_dispatch_point(&target, (70.5, 150.5)),
            (70.5, 150.5),
        );
    }
}

pub(super) async fn handle_browser_click_element(
    exec: &ToolExecutor,
    id: &str,
) -> ToolExecutionResult {
    if let Some(blocked) = ensure_browser_focus_guard(exec) {
        return blocked;
    }

    let pre_url = exec.browser.known_active_url().await;
    let execution_started_at = Instant::now();
    let execution_deadline = execution_started_at + CLICK_ELEMENT_EXECUTION_BUDGET;
    emit_browser_click_trace("start", format!("id={id}"));

    let prompt_tree_started_at = Instant::now();
    let (prompt_tree, prompt_observation_source) =
        match capture_execution_prompt_browser_tree(exec).await {
            Some((tree, source)) => (Some(tree), source),
            None => (None, "prompt_observation_unavailable"),
        };
    let prompt_observation_elapsed_ms = prompt_tree_started_at.elapsed().as_millis() as u64;
    emit_browser_click_trace(
        "prompt_tree",
        format!("source={prompt_observation_source} elapsed_ms={prompt_observation_elapsed_ms}"),
    );

    let recent_tree = exec
        .browser
        .recent_accessibility_snapshot(RECENT_BROWSER_CLICK_SNAPSHOT_MAX_AGE)
        .await
        .map(|(_, tree)| apply_browser_auto_lens_with_som(&tree));
    let mut current_tree_source = "recent_accessibility_snapshot";
    let mut current_tree_elapsed_ms = 0u64;
    let mut prompt_observation_failure: Option<ToolExecutionResult> = None;
    let mut current_tree_failure: Option<ToolExecutionResult> = None;

    let mut transformed = recent_tree;
    let mut current_tree_error: Option<String> = None;
    let mut current_target = transformed
        .as_ref()
        .and_then(|tree| find_semantic_target_by_id(tree, id));
    let mut actionable_current_target = current_target
        .as_ref()
        .filter(|target| semantic_target_is_actionable(target));
    let mut current_tree_attempted_in_initial_dispatch = false;

    if let Some((semantic_target, resolved_from)) =
        resolve_semantic_target_from_current_or_prompt_tree(
            transformed.as_ref(),
            prompt_tree.as_ref(),
            id,
        )
        .filter(|(target, _)| semantic_target_is_actionable(target))
    {
        let mut semantic_target = semantic_target;
        let mut resolved_from = resolved_from;
        emit_browser_click_trace(
            "target_resolved",
            format!(
                "source={resolved_from} selector={:?} dom_id={:?} tag={:?} dom_clickable={} backend_id={:?} cdp_id={:?} center_point={:?}",
                semantic_target.selector,
                semantic_target.dom_id,
                semantic_target.tag_name,
                semantic_target.dom_clickable,
                semantic_target.backend_dom_node_id,
                semantic_target.cdp_node_id,
                semantic_target.center_point,
            ),
        );
        if target_prefers_live_tree_refresh_before_dispatch(&semantic_target, resolved_from) {
            if let Some(current_tree_refresh_timeout) =
                remaining_click_element_budget(execution_deadline)
                    .map(|remaining| remaining.min(CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT))
            {
                let refreshed_tree =
                    refresh_current_click_tree(exec, id, current_tree_refresh_timeout).await;
                current_tree_source = refreshed_tree.source;
                current_tree_elapsed_ms = refreshed_tree.elapsed_ms;
                current_tree_error = refreshed_tree.error;
                transformed = refreshed_tree.transformed;
                current_target = transformed
                    .as_ref()
                    .and_then(|tree| find_semantic_target_by_id(tree, id));
                actionable_current_target = current_target
                    .as_ref()
                    .filter(|target| semantic_target_is_actionable(target));
                if let Some(current_semantic_target) = actionable_current_target.cloned() {
                    semantic_target = current_semantic_target;
                    resolved_from = current_tree_source;
                    current_tree_attempted_in_initial_dispatch = true;
                    emit_browser_click_trace(
                        "target_rebound_from_live_tree",
                        format!(
                            "source={resolved_from} selector={:?} dom_id={:?} tag={:?}",
                            semantic_target.selector,
                            semantic_target.dom_id,
                            semantic_target.tag_name,
                        ),
                    );
                }
            }
        }
        let (pre_tree, target_resolution_source, pre_focused_control) =
            if resolved_from == "prompt_observation_tree" {
                let tree = prompt_tree
                    .as_ref()
                    .expect("prompt tree must exist when prompt target resolves");
                (
                    tree,
                    "prompt_observation_tree",
                    prompt_tree
                        .as_ref()
                        .and_then(|candidate| find_focused_semantic_target(candidate)),
                )
            } else {
                let tree = transformed
                    .as_ref()
                    .expect("recent current tree must exist when current target resolves");
                (
                    tree,
                    current_tree_source,
                    transformed
                        .as_ref()
                        .and_then(|candidate| find_focused_semantic_target(candidate)),
                )
            };
        let pre_tree_xml = render_browser_tree_xml(pre_tree);
        let initial_result = attempt_click_element_with_target(
            exec,
            id,
            &semantic_target,
            target_resolution_source,
            &pre_tree_xml,
            pre_url.as_deref(),
            pre_focused_control.as_ref(),
            execution_started_at,
            execution_deadline,
        )
        .await;
        let initial_result = annotate_click_result_verify(
            initial_result,
            &[
                ("target_resolution_source", json!(target_resolution_source)),
                (
                    "prompt_observation_source",
                    json!(prompt_observation_source),
                ),
                ("current_tree_elapsed_ms", json!(current_tree_elapsed_ms)),
                (
                    "prompt_observation_elapsed_ms",
                    json!(prompt_observation_elapsed_ms),
                ),
            ],
        );
        if initial_result.success {
            return initial_result;
        }
        if click_result_marks_browser_session_unstable(&initial_result) {
            return initial_result;
        }
        if click_result_has_dispatch_timeout(&initial_result) {
            if current_tree_attempted_in_initial_dispatch {
                emit_browser_click_trace(
                    "skip_current_tree_refresh",
                    format!("id={id} reason=dispatch_timeout_current_tree_already_attempted"),
                );
                return initial_result;
            }
            emit_browser_click_trace(
                "defer_dispatch_timeout_to_current_tree_retry",
                format!("id={id} reason=dispatch_timeout"),
            );
        }
        if resolved_from == "prompt_observation_tree" {
            prompt_observation_failure = Some(initial_result);
        } else {
            current_tree_failure = Some(initial_result);
        }
    }

    if current_tree_attempted_in_initial_dispatch {
        if let Some(current_tree_failure) = current_tree_failure {
            return current_tree_failure;
        }
    }

    if remaining_click_element_budget(execution_deadline).is_none() {
        return current_tree_failure.or(prompt_observation_failure).unwrap_or_else(|| {
            let verify = json!({
                "id": id,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "prompt_observation_source": prompt_observation_source,
                "current_tree_source": current_tree_source,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget before live tree refresh. verify={}",
                id,
                CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
                verify
            ))
        });
    }

    let Some(current_tree_refresh_timeout) = remaining_click_element_budget(execution_deadline)
        .map(|remaining| remaining.min(CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT))
    else {
        return current_tree_failure.or(prompt_observation_failure).unwrap_or_else(|| {
            let verify = json!({
                "id": id,
                "budget_exhausted": true,
                "execution_budget_ms": CLICK_ELEMENT_EXECUTION_BUDGET.as_millis() as u64,
                "execution_elapsed_ms": execution_started_at.elapsed().as_millis() as u64,
                "prompt_observation_source": prompt_observation_source,
                "current_tree_source": current_tree_source,
            });
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Click element '{}' exhausted {}ms execution budget before current tree refresh. verify={}",
                id,
                CLICK_ELEMENT_EXECUTION_BUDGET.as_millis(),
                verify
            ))
        });
    };

    let refreshed_tree = refresh_current_click_tree(exec, id, current_tree_refresh_timeout).await;
    current_tree_source = refreshed_tree.source;
    current_tree_elapsed_ms = refreshed_tree.elapsed_ms;
    current_tree_error = refreshed_tree.error;
    transformed = refreshed_tree.transformed;
    current_target = transformed
        .as_ref()
        .and_then(|tree| find_semantic_target_by_id(tree, id));
    actionable_current_target = current_target
        .as_ref()
        .filter(|target| semantic_target_is_actionable(target));

    if !current_tree_attempted_in_initial_dispatch {
        if let Some(semantic_target) = actionable_current_target {
            let pre_tree_xml = render_browser_tree_xml(
                transformed
                    .as_ref()
                    .expect("current tree must exist when current target resolves"),
            );
            let pre_focused_control = transformed
                .as_ref()
                .and_then(|tree| find_focused_semantic_target(tree));
            let current_result = attempt_click_element_with_target(
                exec,
                id,
                semantic_target,
                current_tree_source,
                &pre_tree_xml,
                pre_url.as_deref(),
                pre_focused_control.as_ref(),
                execution_started_at,
                execution_deadline,
            )
            .await;
            let current_result = annotate_click_result_verify(
                current_result,
                &[
                    ("target_resolution_source", json!(current_tree_source)),
                    (
                        "prompt_observation_source",
                        json!(prompt_observation_source),
                    ),
                    ("current_tree_elapsed_ms", json!(current_tree_elapsed_ms)),
                    (
                        "prompt_observation_elapsed_ms",
                        json!(prompt_observation_elapsed_ms),
                    ),
                ],
            );
            if current_result.success {
                return current_result;
            }
            current_tree_failure = Some(current_result);
        }
    }

    if let Some(current_tree_failure) = current_tree_failure {
        return current_tree_failure;
    }

    match current_tree_error {
        Some(error) => prompt_observation_failure.unwrap_or_else(|| {
            ToolExecutionResult::failure(format!(
                "Failed to fetch browser accessibility tree: {}",
                error
            ))
        }),
        None => match current_target {
            Some(_) => prompt_observation_failure.unwrap_or_else(|| {
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
                    id
                ))
            }),
            None => prompt_observation_failure.unwrap_or_else(|| {
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__snapshot` again and retry with a fresh ID.",
                    id
                ))
            }),
        },
    }
}
