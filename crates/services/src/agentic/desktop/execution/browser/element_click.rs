use super::super::{ToolExecutionResult, ToolExecutor};
use super::selector_click::ensure_browser_focus_guard;
use super::tree::{apply_browser_auto_lens, render_browser_tree_xml};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use serde_json::json;
use tokio::time::{sleep, Duration};

fn rect_center(rect: Rect) -> Option<(f64, f64)> {
    if rect.width <= 0 || rect.height <= 0 {
        return None;
    }

    Some((
        rect.x as f64 + (rect.width as f64 / 2.0),
        rect.y as f64 + (rect.height as f64 / 2.0),
    ))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct BrowserSemanticTarget {
    pub(super) cdp_node_id: Option<String>,
    pub(super) backend_dom_node_id: Option<String>,
    pub(super) center_point: Option<(f64, f64)>,
    pub(super) focused: bool,
    pub(super) editable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClickElementPostcondition {
    pub(super) target_disappeared: bool,
    pub(super) editable_focus_transition: bool,
    pub(super) tree_changed: bool,
}

impl ClickElementPostcondition {
    pub(super) fn met(&self) -> bool {
        self.target_disappeared || self.editable_focus_transition || self.tree_changed
    }
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

fn semantic_target_from_node(node: &AccessibilityNode) -> BrowserSemanticTarget {
    BrowserSemanticTarget {
        cdp_node_id: node.attributes.get("cdp_node_id").cloned(),
        backend_dom_node_id: node.attributes.get("backend_dom_node_id").cloned(),
        center_point: rect_center(node.rect),
        focused: node_is_focused(node),
        editable: node_is_editable(node),
    }
}

pub(super) fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    if node.id == target_id {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_id(child, target_id) {
            return Some(found);
        }
    }

    None
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

pub(super) fn click_element_postcondition_met(
    pre_tree_xml: &str,
    pre_target: &BrowserSemanticTarget,
    post_tree_xml: &str,
    post_target: Option<&BrowserSemanticTarget>,
) -> ClickElementPostcondition {
    let has_browser_ids =
        pre_target.backend_dom_node_id.is_some() || pre_target.cdp_node_id.is_some();
    let target_disappeared = has_browser_ids && post_target.is_none();
    let editable_focus_transition = pre_target.editable
        && !pre_target.focused
        && post_target.is_some_and(|target| target.focused);
    let tree_changed = pre_tree_xml != post_tree_xml;

    ClickElementPostcondition {
        target_disappeared,
        editable_focus_transition,
        tree_changed,
    }
}

fn semantic_target_verification_json(target: Option<&BrowserSemanticTarget>) -> serde_json::Value {
    match target {
        Some(target) => json!({
            "cdp_node_id": target.cdp_node_id,
            "backend_dom_node_id": target.backend_dom_node_id,
            "focused": target.focused,
            "editable": target.editable,
            "center_point": target.center_point.map(|(x, y)| vec![x, y]),
        }),
        None => serde_json::Value::Null,
    }
}

async fn verify_click_dispatch(
    exec: &ToolExecutor,
    pre_tree_xml: &str,
    semantic_target: &BrowserSemanticTarget,
    method: &str,
    center_point: Option<(f64, f64)>,
) -> (bool, serde_json::Value) {
    match exec.browser.get_accessibility_tree().await {
        Ok(post_raw_tree) => {
            let post_transformed = apply_browser_auto_lens(post_raw_tree);
            let post_tree_xml = render_browser_tree_xml(&post_transformed);
            let post_target = find_semantic_target_by_browser_ids(
                &post_transformed,
                semantic_target.cdp_node_id.as_deref(),
                semantic_target.backend_dom_node_id.as_deref(),
            );
            let postcondition = click_element_postcondition_met(
                pre_tree_xml,
                semantic_target,
                &post_tree_xml,
                post_target.as_ref(),
            );
            let mut verify = json!({
                "method": method,
                "dispatch_succeeded": true,
                "pre_target": semantic_target_verification_json(Some(semantic_target)),
                "post_target": semantic_target_verification_json(post_target.as_ref()),
                "postcondition": {
                    "met": postcondition.met(),
                    "target_disappeared": postcondition.target_disappeared,
                    "editable_focus_transition": postcondition.editable_focus_transition,
                    "tree_changed": postcondition.tree_changed,
                },
            });
            if let Some((x, y)) = center_point {
                verify["center_point"] = json!([x, y]);
            }
            (postcondition.met(), verify)
        }
        Err(e) => {
            let mut verify = json!({
                "method": method,
                "dispatch_succeeded": true,
                "postcondition": { "met": false },
                "post_snapshot_error": e.to_string(),
            });
            if let Some((x, y)) = center_point {
                verify["center_point"] = json!([x, y]);
            }
            (false, verify)
        }
    }
}

pub(super) async fn handle_browser_click_element(
    exec: &ToolExecutor,
    id: &str,
) -> ToolExecutionResult {
    if let Some(blocked) = ensure_browser_focus_guard(exec) {
        return blocked;
    }

    let raw_tree = match exec.browser.get_accessibility_tree().await {
        Ok(tree) => tree,
        Err(e) => {
            return ToolExecutionResult::failure(format!(
                "Failed to fetch browser accessibility tree: {}",
                e
            ))
        }
    };

    let transformed = apply_browser_auto_lens(raw_tree);
    let semantic_target = match find_semantic_target_by_id(&transformed, id) {
        Some(target) => target,
        None => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__snapshot` again and retry with a fresh ID.",
                id
            ))
        }
    };

    if semantic_target.backend_dom_node_id.is_none()
        && semantic_target.cdp_node_id.is_none()
        && semantic_target.center_point.is_none()
    {
        return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
            id
        ));
    }

    let pre_tree_xml = render_browser_tree_xml(&transformed);
    let mut click_errors: Vec<String> = Vec::new();
    let mut attempt_verification: Vec<serde_json::Value> = Vec::new();

    if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
        match exec.browser.click_backend_dom_node(backend_id).await {
            Ok(()) => {
                sleep(Duration::from_millis(120)).await;
                let (met, verify) = verify_click_dispatch(
                    exec,
                    &pre_tree_xml,
                    &semantic_target,
                    "backend_dom_node_id",
                    None,
                )
                .await;
                if met {
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                attempt_verification.push(verify);
            }
            Err(e) => click_errors.push(format!("backend_dom_node_id={}", e)),
        }
    }

    if let Some(cdp_id) = semantic_target.cdp_node_id.as_deref() {
        match exec.browser.click_ax_node(cdp_id).await {
            Ok(()) => {
                sleep(Duration::from_millis(120)).await;
                let (met, verify) = verify_click_dispatch(
                    exec,
                    &pre_tree_xml,
                    &semantic_target,
                    "cdp_node_id",
                    None,
                )
                .await;
                if met {
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}'. verify={}",
                        id, verify
                    ));
                }
                attempt_verification.push(verify);
            }
            Err(e) => click_errors.push(format!("cdp_node_id={}", e)),
        }
    }

    if let Some((x, y)) = semantic_target.center_point {
        match exec.browser.synthetic_click(x, y).await {
            Ok(()) => {
                sleep(Duration::from_millis(120)).await;
                let (met, verify) = verify_click_dispatch(
                    exec,
                    &pre_tree_xml,
                    &semantic_target,
                    "geometry_center",
                    Some((x, y)),
                )
                .await;
                if met {
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via geometry fallback. verify={}",
                        id, verify
                    ));
                }
                attempt_verification.push(verify);
            }
            Err(e) => click_errors.push(format!("geometry_center=({:.2},{:.2})={}", x, y, e)),
        }
    }

    let verify = json!({
        "id": id,
        "pre_target": semantic_target_verification_json(Some(&semantic_target)),
        "attempts": attempt_verification,
        "click_errors": click_errors,
    });
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
        id, verify
    ))
}
