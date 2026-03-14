use super::super::{ToolExecutionResult, ToolExecutor};
use super::selector_click::{ensure_browser_focus_guard, handle_browser_click};
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
    pub(super) semantic_id: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) tag_name: Option<String>,
    pub(super) cdp_node_id: Option<String>,
    pub(super) backend_dom_node_id: Option<String>,
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
}

impl ClickElementPostcondition {
    pub(super) fn met(&self) -> bool {
        self.target_disappeared
            || self.editable_focus_transition
            || self.tree_changed
            || self.url_changed
    }
}

pub(super) fn click_element_postcondition_counts_as_success(
    pre_target: &BrowserSemanticTarget,
    post_target: Option<&BrowserSemanticTarget>,
    postcondition: &ClickElementPostcondition,
) -> bool {
    let link_like = matches!(pre_target.tag_name.as_deref(), Some("a"));
    if link_like
        && postcondition.tree_changed
        && !postcondition.url_changed
        && !postcondition.target_disappeared
    {
        let post_target_strengthened = post_target.is_some_and(|target| {
            target.focused != pre_target.focused
                || target.selected != pre_target.selected
                || target.checked != pre_target.checked
        });
        if !post_target_strengthened {
            return false;
        }
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

fn node_attr_value<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|value| !value.trim().is_empty())
}

fn node_attr_i32(node: &AccessibilityNode, key: &str) -> Option<i32> {
    node_attr_value(node, key)?.trim().parse().ok()
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

fn semantic_target_from_node(node: &AccessibilityNode) -> BrowserSemanticTarget {
    BrowserSemanticTarget {
        semantic_id: Some(node.id.clone()).filter(|id| !id.trim().is_empty()),
        dom_id: node_attr_value(node, "dom_id")
            .or_else(|| node_attr_value(node, "id"))
            .map(|value| value.to_string()),
        selector: node_attr_value(node, "selector").map(|value| value.to_string()),
        tag_name: node_attr_value(node, "tag_name").map(|value| value.to_string()),
        cdp_node_id: node.attributes.get("cdp_node_id").cloned(),
        backend_dom_node_id: node.attributes.get("backend_dom_node_id").cloned(),
        center_point: rect_center(node.rect),
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

fn find_semantic_target_by_alias(
    node: &AccessibilityNode,
    raw_query: &str,
    normalized_query: &str,
) -> Option<BrowserSemanticTarget> {
    if semantic_lookup_token_matches(&node.id, raw_query, normalized_query) {
        return Some(semantic_target_from_node(node));
    }

    if let Some(dom_id) = node_attr_value(node, "dom_id") {
        if semantic_lookup_token_matches(dom_id, raw_query, normalized_query) {
            return Some(semantic_target_from_node(node));
        }
    }

    if let Some(aliases) = node.attributes.get("semantic_aliases") {
        if aliases
            .split_whitespace()
            .any(|alias| semantic_lookup_token_matches(alias, raw_query, normalized_query))
        {
            return Some(semantic_target_from_node(node));
        }
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_alias(child, raw_query, normalized_query) {
            return Some(found);
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

pub(super) fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    let target_id = target_id.trim();
    if target_id.is_empty() {
        return None;
    }

    if node.id == target_id {
        return Some(semantic_target_from_node(node));
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_id(child, target_id) {
            return Some(found);
        }
    }

    find_semantic_target_by_alias(node, target_id, &normalize_semantic_lookup_key(target_id))
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
        || pre_target
            .cdp_node_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || pre_target
            .dom_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty());
    let target_disappeared = has_verifiable_identity && post_target.is_none();
    let editable_focus_transition = pre_target.editable
        && !pre_target.focused
        && post_target.is_some_and(|target| target.focused);
    let tree_changed = pre_tree_xml != post_tree_xml;
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
    }
}

fn semantic_target_verification_json(target: Option<&BrowserSemanticTarget>) -> serde_json::Value {
    match target {
        Some(target) => json!({
            "semantic_id": target.semantic_id,
            "dom_id": target.dom_id,
            "selector": target.selector,
            "tag_name": target.tag_name,
            "cdp_node_id": target.cdp_node_id,
            "backend_dom_node_id": target.backend_dom_node_id,
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

fn escape_css_attr_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(super) fn selector_fallback_candidates(target: &BrowserSemanticTarget) -> Vec<String> {
    let mut selectors = Vec::new();

    if let Some(selector) = target
        .selector
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
    {
        selectors.push(selector.to_string());
    }

    if let Some(dom_id) = target
        .dom_id
        .as_deref()
        .map(str::trim)
        .filter(|dom_id| !dom_id.is_empty())
    {
        let selector = format!("[id=\"{}\"]", escape_css_attr_literal(dom_id));
        if !selectors.iter().any(|candidate| candidate == &selector) {
            selectors.push(selector);
        }
    }

    selectors
}

async fn verify_click_dispatch(
    exec: &ToolExecutor,
    pre_tree_xml: &str,
    semantic_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    method: &str,
    center_point: Option<(f64, f64)>,
) -> (bool, serde_json::Value) {
    for settle_ms in [0_u64, 180, 360] {
        if settle_ms > 0 {
            sleep(Duration::from_millis(settle_ms)).await;
        }

        match exec.browser.get_accessibility_tree().await {
            Ok(post_raw_tree) => {
                let post_url = exec.browser.active_url().await.ok();
                let post_url_ref = post_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|url| !url.is_empty());
                let pre_url_ref = pre_url.map(str::trim).filter(|url| !url.is_empty());
                let post_transformed = apply_browser_auto_lens(post_raw_tree);
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
                    },
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                });
                let success = click_element_postcondition_counts_as_success(
                    semantic_target,
                    post_target.as_ref(),
                    &postcondition,
                );
                verify["postcondition"]["met"] = json!(success);
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if success {
                    return (true, verify);
                }
                if settle_ms == 360 {
                    return (false, verify);
                }
            }
            Err(e) => {
                let post_url = exec.browser.active_url().await.ok();
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
                    "post_snapshot_error": e.to_string(),
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                });
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if url_changed || settle_ms == 360 {
                    return (url_changed, verify);
                }
            }
        }
    }
    unreachable!("verification settle loop should return on the final attempt")
}

#[cfg(test)]
mod tests {
    use super::{find_focused_semantic_target, semantic_target_verification_json};
    use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
    use std::collections::HashMap;

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
    fn selector_fallback_candidates_prefer_explicit_selector_then_dom_id() {
        let target = super::BrowserSemanticTarget {
            selector: Some("[id=\"ticket-link-t-204\"]".to_string()),
            dom_id: Some("ticket-link-t-204".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::selector_fallback_candidates(&target),
            vec!["[id=\"ticket-link-t-204\"]".to_string()]
        );
    }

    #[test]
    fn selector_fallback_candidates_escape_dom_ids_without_selector_metadata() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("ticket\"link\\204".to_string()),
            ..Default::default()
        };

        assert_eq!(
            super::selector_fallback_candidates(&target),
            vec!["[id=\"ticket\\\"link\\\\204\"]".to_string()]
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
    let pre_url = exec.browser.active_url().await.ok();
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
                    pre_url.as_deref(),
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
                    pre_url.as_deref(),
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
                    pre_url.as_deref(),
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

    for selector in selector_fallback_candidates(&semantic_target) {
        let result = handle_browser_click(exec, &selector).await;
        if result.success {
            let detail = result
                .history_entry
                .unwrap_or_else(|| format!("Selector fallback '{}' succeeded.", selector));
            return ToolExecutionResult::success(format!(
                "Clicked element '{}' via selector fallback '{}'. {}",
                id, selector, detail
            ));
        }

        if let Some(error) = result.error {
            click_errors.push(format!("selector_fallback({})={}", selector, error));
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
