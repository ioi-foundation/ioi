use super::super::{ToolExecutionResult, ToolExecutor};
use super::selector_click::ensure_browser_focus_guard;
use super::tree::{apply_browser_auto_lens, render_browser_tree_xml};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use serde_json::json;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

// Verification starts immediately after dispatch. Geometry-only targets do not have a stable
// DOM-backed identity to reconcile, so keep their tail shorter than DOM-backed targets while
// still allowing one medium recheck for slower semantic updates.
const CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY: [u64; 5] = [0, 80, 160, 320, 640];
const CLICK_DISPATCH_SETTLE_MS_DOM_BACKED: [u64; 4] = [0, 120, 240, 900];
const LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA: usize = 4;
const RECENT_BROWSER_SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(5_000);

fn rect_center(rect: Rect) -> Option<(f64, f64)> {
    if rect.width <= 0 || rect.height <= 0 {
        return None;
    }

    Some((
        rect.x as f64 + (rect.width as f64 / 2.0),
        rect.y as f64 + (rect.height as f64 / 2.0),
    ))
}

fn semantic_target_is_actionable(target: &BrowserSemanticTarget) -> bool {
    target.backend_dom_node_id.is_some()
        || target.cdp_node_id.is_some()
        || target.center_point.is_some()
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
    post_target: Option<&BrowserSemanticTarget>,
    focused_control: Option<&BrowserSemanticTarget>,
    postcondition: &ClickElementPostcondition,
) -> bool {
    let post_target_strengthened = post_target.is_some_and(|target| {
        target.selected != pre_target.selected
            || target.checked != pre_target.checked
            || target.center_point != pre_target.center_point
            || target.dom_id != pre_target.dom_id
            || target.cdp_node_id != pre_target.cdp_node_id
            || target.backend_dom_node_id != pre_target.backend_dom_node_id
    });
    let target_focus_activation = post_target
        .is_some_and(|target| target.focused && !pre_target.focused)
        || focused_control.is_some_and(|focused| {
            focused.focused
                && focused.semantic_id == pre_target.semantic_id
                && focused.dom_id == pre_target.dom_id
        });
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
        && !link_like
        && !post_target_strengthened
        && !(target_focus_activation && postcondition.material_semantic_change)
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

fn find_semantic_target_by_id_or_alias_recursive(
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
        if let Some(found) = find_semantic_target_by_id_or_alias_recursive(child, target_id) {
            return Some(found);
        }
    }

    find_semantic_target_by_alias(node, target_id, &normalize_semantic_lookup_key(target_id))
}

pub(super) fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    find_semantic_target_by_id_or_alias_recursive(node, target_id)
        .or_else(|| find_unique_semantic_target_by_name_or_data_index(node, target_id))
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

fn selector_is_positionally_fragile(selector: &str) -> bool {
    let normalized = selector.trim().to_ascii_lowercase();
    normalized.contains(":nth-of-type(") || normalized.contains(":nth-child(")
}

fn selector_fallback_is_safe_for_native_dom_control(target: &BrowserSemanticTarget) -> bool {
    matches!(
        target
            .tag_name
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("button" | "a" | "input" | "textarea" | "select" | "option" | "label" | "summary")
    )
}

pub(super) fn selector_fallback_candidates(target: &BrowserSemanticTarget) -> Vec<String> {
    let mut selectors = Vec::new();

    if let Some(selector) = target
        .selector
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
    {
        if !(uses_geometry_only_click_verification(target)
            && selector_is_positionally_fragile(selector))
            || selector_fallback_is_safe_for_native_dom_control(target)
        {
            selectors.push(selector.to_string());
        }
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

fn uses_geometry_only_click_verification(target: &BrowserSemanticTarget) -> bool {
    target.center_point.is_some()
        && target
            .backend_dom_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .cdp_node_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && target
            .dom_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
}

fn click_dispatch_settle_schedule(target: &BrowserSemanticTarget) -> &'static [u64] {
    if uses_geometry_only_click_verification(target) {
        &CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY
    } else {
        &CLICK_DISPATCH_SETTLE_MS_DOM_BACKED
    }
}

async fn verify_click_dispatch(
    exec: &ToolExecutor,
    pre_tree_xml: &str,
    semantic_target: &BrowserSemanticTarget,
    pre_url: Option<&str>,
    method: &str,
    center_point: Option<(f64, f64)>,
) -> (bool, serde_json::Value) {
    let settle_schedule = click_dispatch_settle_schedule(semantic_target);
    for (attempt_idx, settle_ms) in settle_schedule.iter().copied().enumerate() {
        let is_final_attempt = attempt_idx + 1 == settle_schedule.len();
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
                        "material_semantic_change": postcondition.material_semantic_change,
                        "semantic_change_delta": postcondition.semantic_change_delta,
                    },
                    "pre_url": pre_url_ref,
                    "post_url": post_url_ref,
                    "settle_ms": settle_ms,
                });
                let success = click_element_postcondition_counts_as_success(
                    semantic_target,
                    post_target.as_ref(),
                    focused_control.as_ref(),
                    &postcondition,
                );
                verify["postcondition"]["met"] = json!(success);
                if let Some((x, y)) = center_point {
                    verify["center_point"] = json!([x, y]);
                }
                if success {
                    return (true, verify);
                }
                if is_final_attempt {
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
                if url_changed || is_final_attempt {
                    return (url_changed, verify);
                }
            }
        }
    }
    unreachable!("verification settle loop should return on the final attempt")
}

async fn attempt_click_element_with_target(
    exec: &ToolExecutor,
    id: &str,
    semantic_target: &BrowserSemanticTarget,
    pre_tree_xml: &str,
    pre_url: Option<&str>,
) -> ToolExecutionResult {
    let mut click_errors: Vec<String> = Vec::new();
    let mut attempt_verification: Vec<serde_json::Value> = Vec::new();

    if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
        match exec.browser.click_backend_dom_node(backend_id).await {
            Ok(()) => {
                let (met, verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
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
                let (met, verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
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
                let (met, verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
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

    for selector in selector_fallback_candidates(semantic_target) {
        match exec.browser.click_selector(&selector).await {
            Ok(()) => {
                let (met, verify) = verify_click_dispatch(
                    exec,
                    pre_tree_xml,
                    semantic_target,
                    pre_url,
                    &format!("selector_fallback:{selector}"),
                    None,
                )
                .await;
                if met {
                    return ToolExecutionResult::success(format!(
                        "Clicked element '{}' via selector fallback '{}'. verify={}",
                        id, selector, verify
                    ));
                }
                attempt_verification.push(verify);
            }
            Err(error) => {
                click_errors.push(format!("selector_fallback({})={}", selector, error));
            }
        }
    }

    let verify = json!({
        "id": id,
        "pre_target": semantic_target_verification_json(Some(semantic_target)),
        "attempts": attempt_verification,
        "click_errors": click_errors,
    });
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}'. verify={}",
        id, verify
    ))
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

    #[test]
    fn geometry_only_targets_skip_positionally_fragile_selector_fallbacks() {
        let target = super::BrowserSemanticTarget {
            center_point: Some((52.0, 69.0)),
            selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
            tag_name: Some("rect".to_string()),
            ..Default::default()
        };

        assert!(super::selector_fallback_candidates(&target).is_empty());
    }

    #[test]
    fn dom_backed_targets_keep_positionally_fragile_selector_when_it_is_their_identity() {
        let target = super::BrowserSemanticTarget {
            dom_id: Some("listbox".to_string()),
            selector: Some("#listbox > li:nth-of-type(1)".to_string()),
            center_point: Some((30.0, 55.0)),
            ..Default::default()
        };

        assert_eq!(
            super::selector_fallback_candidates(&target),
            vec![
                "#listbox > li:nth-of-type(1)".to_string(),
                "[id=\"listbox\"]".to_string()
            ]
        );
    }

    #[test]
    fn native_dom_controls_keep_positionally_fragile_selector_fallback_without_dom_id() {
        let target = super::BrowserSemanticTarget {
            selector: Some(
                "#results > div:nth-of-type(5) > div:nth-of-type(4) > button".to_string(),
            ),
            center_point: Some((75.0, 577.0)),
            tag_name: Some("button".to_string()),
            ..Default::default()
        };

        assert!(super::uses_geometry_only_click_verification(&target));
        assert_eq!(
            super::selector_fallback_candidates(&target),
            vec!["#results > div:nth-of-type(5) > div:nth-of-type(4) > button".to_string()]
        );
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
            &postcondition,
        ));
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
    let mut recent_snapshot_failure: Option<ToolExecutionResult> = None;

    if let Some((_snapshot_url, cached_tree)) = exec
        .browser
        .recent_accessibility_snapshot(RECENT_BROWSER_SNAPSHOT_MAX_AGE)
        .await
    {
        let cached_tree = apply_browser_auto_lens(cached_tree);
        if let Some(cached_target) = find_semantic_target_by_id(&cached_tree, id) {
            if semantic_target_is_actionable(&cached_target) {
                let cached_pre_tree_xml = render_browser_tree_xml(&cached_tree);
                let cached_result = attempt_click_element_with_target(
                    exec,
                    id,
                    &cached_target,
                    &cached_pre_tree_xml,
                    pre_url.as_deref(),
                )
                .await;
                if cached_result.success {
                    return cached_result;
                }
                recent_snapshot_failure = Some(cached_result);
            }
        }
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
            return recent_snapshot_failure.unwrap_or_else(|| {
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__snapshot` again and retry with a fresh ID.",
                    id
                ))
            })
        }
    };

    if !semantic_target_is_actionable(&semantic_target) {
        return recent_snapshot_failure.unwrap_or_else(|| {
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
                id
            ))
        });
    }

    let pre_tree_xml = render_browser_tree_xml(&transformed);
    attempt_click_element_with_target(
        exec,
        id,
        &semantic_target,
        &pre_tree_xml,
        pre_url.as_deref(),
    )
    .await
}
