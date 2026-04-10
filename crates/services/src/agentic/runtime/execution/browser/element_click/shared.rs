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

