use super::super::*;
use std::collections::HashSet;

const ACCESSIBILITY_TREE_TIMEOUT: Duration = Duration::from_millis(1_500);
const PROMPT_OBSERVATION_CACHE_MAX_AGE: Duration = Duration::from_millis(2_500);

#[derive(Debug, serde::Deserialize)]
struct DomFallbackRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DomFallbackNode {
    id: String,
    role: String,
    name: Option<String>,
    value: Option<String>,
    rect: DomFallbackRect,
    #[serde(default)]
    is_visible: Option<bool>,
    #[serde(default)]
    attributes: HashMap<String, String>,
    #[serde(default)]
    children: Vec<DomFallbackNode>,
}

fn clamp_coord(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32
}

fn clamp_extent(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(0.0, i32::MAX as f64) as i32
}

fn allow_dom_fallback_for_ax_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("uninteresting")
        || lower.contains("empty accessibility tree")
        || lower.contains("empty tree")
        || lower.contains("notrendered")
        || lower.contains("not rendered")
        || lower.contains("labelfor")
}

fn node_attr_value<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.trim().is_empty())
}

fn rect_contains(outer: &AccessibilityRect, inner: &AccessibilityRect) -> bool {
    if outer.width <= 0 || outer.height <= 0 || inner.width <= 0 || inner.height <= 0 {
        return false;
    }

    let tolerance = 1;
    let outer_right = outer.x.saturating_add(outer.width);
    let outer_bottom = outer.y.saturating_add(outer.height);
    let inner_right = inner.x.saturating_add(inner.width);
    let inner_bottom = inner.y.saturating_add(inner.height);

    inner.x >= outer.x.saturating_sub(tolerance)
        && inner.y >= outer.y.saturating_sub(tolerance)
        && inner_right <= outer_right.saturating_add(tolerance)
        && inner_bottom <= outer_bottom.saturating_add(tolerance)
}

fn normalized_text_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn node_text_tokens(node: &AccessibilityNode) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for text in [node.name.as_deref(), node.value.as_deref()]
        .into_iter()
        .flatten()
    {
        for token in normalized_text_tokens(text) {
            tokens.insert(token);
        }
    }
    tokens
}

fn normalize_exact_prompt_text(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn node_contains_visible_start_gate(node: &AccessibilityNode) -> bool {
    let semantic_role = node.role.trim().to_ascii_lowercase();
    let role_allows_gate = matches!(
        semantic_role.as_str(),
        "button"
            | "link"
            | "menuitem"
            | "statictext"
            | "text"
            | "label"
            | "labeltext"
            | "generic"
            | "group"
            | "presentation"
    );
    let dom_id_is_cover = node_attr_value(node, "dom_id")
        .is_some_and(|dom_id| dom_id.eq_ignore_ascii_case("sync-task-cover"));
    let label_matches = [node.name.as_deref(), node.value.as_deref()]
        .into_iter()
        .flatten()
        .map(normalize_exact_prompt_text)
        .any(|text| matches!(text.as_str(), "start" | "begin" | "continue"));

    if node.is_visible && (dom_id_is_cover || (role_allows_gate && label_matches)) {
        return true;
    }

    node.children.iter().any(node_contains_visible_start_gate)
}

fn node_contains_grounded_prompt_target(node: &AccessibilityNode) -> bool {
    let dom_id_is_cover = node_attr_value(node, "dom_id")
        .is_some_and(|dom_id| dom_id.eq_ignore_ascii_case("sync-task-cover"));
    let has_locator =
        node_attr_value(node, "selector").is_some() || node_attr_value(node, "dom_id").is_some();
    let has_shape_target = node_attr_value(node, "shape_kind").is_some() && has_locator;
    let has_interactive_target = node.is_interactive() && has_locator;

    if node.is_visible && !dom_id_is_cover && (has_shape_target || has_interactive_target) {
        return true;
    }

    node.children
        .iter()
        .any(node_contains_grounded_prompt_target)
}

fn should_cache_prompt_observation_warmup(tree: &AccessibilityNode) -> bool {
    if node_attr_value(tree, "snapshot_fallback_cause") != Some("navigate_warmup") {
        return true;
    }

    if !node_contains_visible_start_gate(tree) {
        return true;
    }

    node_contains_grounded_prompt_target(tree)
}

fn is_semantic_dom_hint_token(token: &str) -> bool {
    if token.len() <= 1 || token.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    !matches!(
        token,
        "ui" | "btn"
            | "button"
            | "icon"
            | "img"
            | "image"
            | "item"
            | "row"
            | "col"
            | "container"
            | "content"
            | "wrapper"
            | "wrap"
            | "name"
            | "username"
            | "details"
            | "detail"
            | "body"
            | "media"
            | "controls"
            | "control"
            | "toolbar"
            | "actions"
            | "action"
            | "spacer"
            | "time"
            | "left"
            | "right"
            | "top"
            | "bottom"
            | "current"
            | "selected"
            | "clicked"
            | "active"
            | "inactive"
            | "disabled"
            | "enabled"
            | "hover"
    )
}

fn dom_fallback_semantic_name(attributes: &HashMap<String, String>) -> Option<String> {
    let mut seen = HashSet::new();
    let mut tokens = Vec::new();

    for key in ["dom_id", "class_name"] {
        let Some(raw) = attributes.get(key) else {
            continue;
        };
        for token in normalized_text_tokens(raw) {
            if !is_semantic_dom_hint_token(&token) || !seen.insert(token.clone()) {
                continue;
            }
            tokens.push(token);
            if tokens.len() >= 3 {
                return Some(tokens.join(" "));
            }
        }
    }

    (!tokens.is_empty()).then(|| tokens.join(" "))
}

fn is_dom_fallback_aggregate_candidate(node: &AccessibilityNode) -> bool {
    if node_attr_value(node, "dom_fallback") != Some("true") || node.is_interactive() {
        return false;
    }

    let role = node.role.trim().to_ascii_lowercase();
    if !matches!(role.as_str(), "generic" | "group" | "presentation") {
        return false;
    }

    let tag_name = node_attr_value(node, "tag_name")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        tag_name.as_str(),
        "div" | "section" | "main" | "article" | "form" | "fieldset" | "td"
    ) {
        return false;
    }

    ![
        "focused",
        "checked",
        "selected",
        "scroll_top",
        "scroll_height",
        "client_height",
        "can_scroll_up",
        "can_scroll_down",
        "autocomplete",
    ]
    .iter()
    .any(|key| node_attr_value(node, key).is_some())
}

fn is_redundant_dom_fallback_aggregate(
    candidate: &AccessibilityNode,
    siblings: &[AccessibilityNode],
) -> bool {
    if !is_dom_fallback_aggregate_candidate(candidate) {
        return false;
    }

    let candidate_tokens = node_text_tokens(candidate);
    if candidate_tokens.is_empty() {
        return false;
    }

    let mut descendant_tokens = HashSet::new();
    let mut interactive_descendants = 0usize;
    let mut contained_descendants = 0usize;

    for sibling in siblings {
        if sibling.id == candidate.id || !sibling.is_visible {
            continue;
        }
        if !rect_contains(&candidate.rect, &sibling.rect) {
            continue;
        }

        contained_descendants += 1;
        descendant_tokens.extend(node_text_tokens(sibling));
        if sibling.is_interactive() {
            interactive_descendants += 1;
        }
    }

    contained_descendants > 0
        && interactive_descendants > 0
        && candidate_tokens
            .iter()
            .all(|token| descendant_tokens.contains(token))
}

fn prune_redundant_dom_fallback_aggregates(mut root: AccessibilityNode) -> AccessibilityNode {
    if node_attr_value(&root, "snapshot_fallback") != Some("dom") {
        return root;
    }

    let snapshot = root.children.clone();
    let before = root.children.len();
    root.children
        .retain(|node| !is_redundant_dom_fallback_aggregate(node, &snapshot));
    let pruned = before.saturating_sub(root.children.len());
    if pruned > 0 {
        root.attributes.insert(
            "dom_fallback_pruned_aggregate_count".to_string(),
            pruned.to_string(),
        );
    }

    root
}

fn rects_are_equivalent_or_nested(left: &AccessibilityRect, right: &AccessibilityRect) -> bool {
    if rect_contains(left, right) || rect_contains(right, left) {
        return true;
    }

    let left_center_x = left.x.saturating_add(left.width / 2);
    let left_center_y = left.y.saturating_add(left.height / 2);
    let right_center_x = right.x.saturating_add(right.width / 2);
    let right_center_y = right.y.saturating_add(right.height / 2);

    (left_center_x - right_center_x).abs() <= 12
        && (left_center_y - right_center_y).abs() <= 12
        && (left.width - right.width).abs() <= 24
        && (left.height - right.height).abs() <= 24
}

fn node_locator_hint(node: &AccessibilityNode, key: &str) -> Option<String> {
    node_attr_value(node, key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn dom_fallback_locator_matches(
    candidate: &AccessibilityNode,
    existing: &AccessibilityNode,
) -> bool {
    for key in ["dom_id", "selector"] {
        let Some(candidate_hint) = node_locator_hint(candidate, key) else {
            continue;
        };
        let Some(existing_hint) = node_locator_hint(existing, key) else {
            continue;
        };
        if candidate_hint == existing_hint {
            return true;
        }
    }

    false
}

fn nodes_semantically_overlap(candidate: &AccessibilityNode, existing: &AccessibilityNode) -> bool {
    if !existing.is_visible {
        return false;
    }

    if dom_fallback_locator_matches(candidate, existing) {
        return true;
    }

    let candidate_tokens = node_text_tokens(candidate);
    if candidate_tokens.is_empty() {
        return false;
    }
    let existing_tokens = node_text_tokens(existing);
    if existing_tokens.is_empty() || candidate_tokens != existing_tokens {
        return false;
    }

    let candidate_role = candidate.role.trim().to_ascii_lowercase();
    let existing_role = existing.role.trim().to_ascii_lowercase();
    if candidate_role != existing_role && !(candidate.is_interactive() && existing.is_interactive())
    {
        return false;
    }

    rects_are_equivalent_or_nested(&candidate.rect, &existing.rect)
}

fn should_merge_dom_fallback_candidate(node: &AccessibilityNode) -> bool {
    if node_attr_value(node, "dom_fallback") != Some("true") || !node.is_visible {
        return false;
    }

    if is_dom_fallback_aggregate_candidate(node) {
        return false;
    }

    node.is_interactive()
        || [
            "focused",
            "checked",
            "selected",
            "scroll_top",
            "scroll_height",
            "client_height",
            "can_scroll_up",
            "can_scroll_down",
            "autocomplete",
        ]
        .iter()
        .any(|key| node_attr_value(node, key).is_some())
}

fn collect_visible_nodes(node: &AccessibilityNode, out: &mut Vec<AccessibilityNode>) {
    if node.is_visible {
        out.push(node.clone());
    }
    for child in &node.children {
        collect_visible_nodes(child, out);
    }
}

fn merge_missing_dom_fallback_nodes(
    mut ax_tree: AccessibilityNode,
    dom_tree: AccessibilityNode,
) -> AccessibilityNode {
    if node_attr_value(&dom_tree, "snapshot_fallback") != Some("dom") {
        return ax_tree;
    }

    let mut existing_nodes = Vec::new();
    collect_visible_nodes(&ax_tree, &mut existing_nodes);

    let mut merged = 0usize;
    for candidate in dom_tree.children {
        if !should_merge_dom_fallback_candidate(&candidate) {
            continue;
        }
        if existing_nodes
            .iter()
            .any(|existing| nodes_semantically_overlap(&candidate, existing))
        {
            continue;
        }

        existing_nodes.push(candidate.clone());
        ax_tree.children.push(candidate);
        merged += 1;
    }

    if merged > 0 {
        ax_tree
            .attributes
            .insert("dom_fallback_overlay_count".to_string(), merged.to_string());
    }

    ax_tree
}

impl DomFallbackNode {
    fn into_accessibility(self) -> AccessibilityNode {
        let synthesized_name = dom_fallback_semantic_name(&self.attributes);
        AccessibilityNode {
            id: if self.id.trim().is_empty() {
                "dom-node".to_string()
            } else {
                self.id
            },
            role: if self.role.trim().is_empty() {
                "generic".to_string()
            } else {
                self.role.to_ascii_lowercase()
            },
            name: self
                .name
                .and_then(|v| {
                    let trimmed = v.trim().to_string();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    }
                })
                .or(synthesized_name),
            value: self.value.and_then(|v| {
                let trimmed = v.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }),
            rect: AccessibilityRect {
                x: clamp_coord(self.rect.x),
                y: clamp_coord(self.rect.y),
                width: clamp_extent(self.rect.width),
                height: clamp_extent(self.rect.height),
            },
            children: self
                .children
                .into_iter()
                .map(DomFallbackNode::into_accessibility)
                .collect(),
            is_visible: self.is_visible.unwrap_or(true),
            attributes: self.attributes,
            som_id: None,
        }
    }
}

impl BrowserDriver {
    async fn remember_accessibility_snapshot_with_url(
        &self,
        url: Option<String>,
        tree: &AccessibilityNode,
    ) {
        let mut cache = self.last_accessibility_snapshot.lock().await;
        *cache = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url,
            tree: tree.clone(),
        });
    }

    async fn remember_accessibility_snapshot(&self, tree: &AccessibilityNode) {
        let url = self.known_active_url().await;
        self.remember_accessibility_snapshot_with_url(url, tree)
            .await;
    }

    pub(crate) async fn invalidate_accessibility_snapshot(&self) {
        let mut cache = self.last_accessibility_snapshot.lock().await;
        *cache = None;
    }

    pub(crate) fn warm_prompt_observation_after_navigation(&self, page: Page, url: Option<String>) {
        let cache = self.last_accessibility_snapshot.clone();
        tokio::spawn(async move {
            let tree =
                match BrowserDriver::dom_fallback_tree_for_page(&page, "navigate_warmup").await {
                    Ok(tree) => tree,
                    Err(error) => {
                        log::debug!(
                            target: "browser",
                            "Prompt observation warmup after navigation failed: {}",
                            error
                        );
                        return;
                    }
                };
            if !should_cache_prompt_observation_warmup(&tree) {
                log::debug!(
                    target: "browser",
                    "Skipping prompt observation warmup cache because the snapshot still exposes a visible start gate."
                );
                return;
            }
            let mut guard = cache.lock().await;
            *guard = Some(RecentAccessibilitySnapshot {
                captured_at: Instant::now(),
                url,
                tree,
            });
        });
    }

    pub async fn recent_accessibility_snapshot(
        &self,
        max_age: Duration,
    ) -> Option<(Option<String>, AccessibilityNode)> {
        let current_url = self.known_active_url().await;
        let cache = self.last_accessibility_snapshot.lock().await;
        let snapshot = cache.as_ref()?;
        if snapshot.captured_at.elapsed() > max_age {
            return None;
        }

        let current_url = current_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty());
        let snapshot_url = snapshot
            .url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty());
        if current_url
            .zip(snapshot_url)
            .is_some_and(|(current, cached)| current != cached)
        {
            return None;
        }

        Some((snapshot.url.clone(), snapshot.tree.clone()))
    }

    pub(crate) async fn dom_fallback_tree_for_page(
        page: &Page,
        cause: &str,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        let script = r#"(() => {
            const MAX_CANDIDATES = 220;
            const normalize = (value) =>
                (value || "").replace(/\s+/g, " ").trim();
            const normalizedHintTokens = (value) => {
                const raw = normalize(value).toLowerCase();
                if (!raw) return [];
                return raw
                    .split(/[^a-z0-9]+/g)
                    .map((token) => token.trim())
                    .filter(Boolean);
            };
            const isSemanticHintToken = (token) => {
                if (!token || token.length <= 1 || /^[0-9]+$/.test(token)) {
                    return false;
                }
                return ![
                    "ui",
                    "btn",
                    "button",
                    "icon",
                    "img",
                    "image",
                    "item",
                    "row",
                    "col",
                    "container",
                    "content",
                    "wrapper",
                    "wrap",
                    "name",
                    "username",
                    "details",
                    "detail",
                    "body",
                    "media",
                    "controls",
                    "control",
                    "toolbar",
                    "actions",
                    "action",
                    "spacer",
                    "time",
                    "left",
                    "right",
                    "top",
                    "bottom",
                    "current",
                    "selected",
                    "clicked",
                    "active",
                    "inactive",
                    "disabled",
                    "enabled",
                    "hover",
                ].includes(token);
            };
            const semanticHintNameFor = (el) => {
                if (!el) return null;
                const seen = new Set();
                const tokens = [];
                for (const raw of [normalize(el.id), normalize(String(el.className || ""))]) {
                    for (const token of normalizedHintTokens(raw)) {
                        if (!isSemanticHintToken(token) || seen.has(token)) {
                            continue;
                        }
                        seen.add(token);
                        tokens.push(token);
                        if (tokens.length >= 3) {
                            return tokens.join(" ");
                        }
                    }
                }
                return tokens.length > 0 ? tokens.join(" ") : null;
            };
            const controlContextHint = (raw) =>
                normalizedHintTokens(raw).some((token) =>
                    [
                        "control",
                        "controls",
                        "toolbar",
                        "action",
                        "actions",
                        "button",
                        "buttons",
                    ].includes(token)
                );
            const escapeCssIdent = (value) => {
                const normalized = normalize(value);
                if (!normalized) return "";
                try {
                    if (window.CSS && typeof window.CSS.escape === "function") {
                        return window.CSS.escape(normalized);
                    }
                } catch (_e) {}
                return normalized.replace(/[^a-zA-Z0-9_-]/g, (char) => `\\${char}`);
            };
            const selectorFor = (el) => {
                if (!el || !el.tagName) return null;
                const parts = [];
                let current = el;
                let guard = 0;
                while (current && current.tagName && guard < 12) {
                    const tag = String(current.tagName || "").toLowerCase();
                    if (!tag || tag === "html") break;

                    const domId = normalize(current.id);
                    if (domId) {
                        parts.unshift(`#${escapeCssIdent(domId)}`);
                        break;
                    }

                    let part = tag;
                    const parent = current.parentElement;
                    if (parent) {
                        let sameTagIndex = 0;
                        let sameTagCount = 0;
                        for (const sibling of Array.from(parent.children || [])) {
                            if (!sibling || !sibling.tagName) continue;
                            if (String(sibling.tagName || "").toLowerCase() !== tag) continue;
                            sameTagCount += 1;
                            if (sibling === current) {
                                sameTagIndex = sameTagCount;
                            }
                        }
                        if (sameTagCount > 1 && sameTagIndex > 0) {
                            part += `:nth-of-type(${sameTagIndex})`;
                        }
                    }

                    parts.unshift(part);
                    if (tag === "body") break;
                    current = parent;
                    guard += 1;
                }
                return parts.length > 0 ? parts.join(" > ") : null;
            };
            const deepActiveElement = () => {
                let active = document.activeElement;
                let guard = 0;
                while (active && guard < 32) {
                    let next = null;
                    try {
                        if (active.shadowRoot && active.shadowRoot.activeElement) {
                            next = active.shadowRoot.activeElement;
                        } else if ((active.tagName || "").toLowerCase() === "iframe") {
                            const childDoc = active.contentDocument;
                            if (childDoc && childDoc.activeElement) {
                                next = childDoc.activeElement;
                            }
                        }
                    } catch (_e) {}
                    if (!next || next === active) {
                        break;
                    }
                    active = next;
                    guard += 1;
                }
                return active;
            };
            const toRole = (el) => {
                if (!el) return "generic";
                const ariaRole = normalize(el.getAttribute("role")).toLowerCase();
                if (ariaRole) return ariaRole;
                const tag = (el.tagName || "").toLowerCase();
                switch (tag) {
                    case "a": return "link";
                    case "button": return "button";
                    case "input": {
                        const type = normalize(el.getAttribute("type")).toLowerCase();
                        if (type === "checkbox") return "checkbox";
                        if (type === "radio") return "radio";
                        if (type === "button" || type === "submit" || type === "reset") return "button";
                        return "textbox";
                    }
                    case "textarea": return "textbox";
                    case "select": return "combobox";
                    case "option": return "option";
                    case "label": return "label";
                    case "output": return "status";
                    case "h1":
                    case "h2":
                    case "h3":
                    case "h4":
                    case "h5":
                    case "h6":
                        return "heading";
                    default:
                        return "generic";
                }
            };
            const isInteractive = (el, role) => {
                if (!el) return false;
                if (typeof el.matches === "function" && el.matches(
                    "button, a[href], input, textarea, select, [role='button'], [role='link'], [role='menuitem'], [tabindex]"
                )) {
                    return true;
                }
                return ["button", "link", "checkbox", "radio", "combobox", "textbox"].includes(role);
            };
            const isVisible = (el, rect) => {
                if (!el || !rect) return false;
                if (!(rect.width > 1 && rect.height > 1)) return false;
                let style = null;
                try {
                    style = window.getComputedStyle(el);
                } catch (_e) {}
                if (style) {
                    if (style.display === "none" || style.visibility === "hidden") return false;
                    const opacity = parseFloat(style.opacity || "1");
                    if (Number.isFinite(opacity) && opacity <= 0.01) return false;
                    if (style.pointerEvents === "none") return false;
                }
                return true;
            };
            const hasSemanticControlStripContext = (el) => {
                if (!el || !el.parentElement) return false;
                const parent = el.parentElement;
                if (
                    controlContextHint(String(parent.className || ""))
                    || controlContextHint(String(parent.id || ""))
                ) {
                    return true;
                }

                let siblingSemanticControls = 0;
                for (const sibling of Array.from(parent.children || [])) {
                    if (!sibling || sibling === el || !sibling.tagName) continue;
                    const siblingTag = String(sibling.tagName || "").toLowerCase();
                    if (!["span", "div", "i", "img", "svg"].includes(siblingTag)) {
                        continue;
                    }

                    let siblingRect = null;
                    try {
                        siblingRect = sibling.getBoundingClientRect();
                    } catch (_e) {
                        continue;
                    }

                    if (!isVisible(sibling, siblingRect)) continue;
                    if (!(siblingRect.width > 0 && siblingRect.height > 0)) continue;
                    if (siblingRect.width > 40 || siblingRect.height > 40) continue;
                    if (!semanticHintNameFor(sibling)) continue;

                    siblingSemanticControls += 1;
                    if (siblingSemanticControls >= 1) {
                        return true;
                    }
                }

                return false;
            };
            const SVG_LEAF_TAGS = new Set([
                "rect",
                "circle",
                "ellipse",
                "polygon",
                "polyline",
                "path",
                "line",
                "text",
            ]);
            const svgKindFor = (tag, text) => {
                switch (tag) {
                    case "rect":
                        return "rectangle";
                    case "circle":
                        return "circle";
                    case "line":
                        return "line";
                    case "polygon":
                        return "triangle";
                    case "text":
                        if (text.length === 1 && /^[0-9]$/.test(text)) return "digit";
                        if (text.length === 1 && /^[a-z]$/i.test(text)) return "letter";
                        return null;
                    default:
                        return null;
                }
            };
            const svgSizeFor = (el, tag, rect) => {
                if (!el || !rect) return null;
                if (tag === "text") {
                    const fontSize = parseFloat(normalize(el.getAttribute("font-size")));
                    if (Number.isFinite(fontSize)) {
                        return fontSize >= 15 ? "large" : "small";
                    }
                    const textHeight = Number(rect.height || 0);
                    return textHeight >= 15 ? "large" : "small";
                }
                const extent = Math.max(Number(rect.width || 0), Number(rect.height || 0));
                if (!(extent > 0)) return null;
                return extent >= 15 ? "large" : "small";
            };
            const svgColorFor = (el) => {
                if (!el || typeof el.getAttribute !== "function") return null;
                const fill = normalize(el.getAttribute("fill")).toLowerCase();
                if (fill && fill !== "none") return fill.slice(0, 120);
                const stroke = normalize(el.getAttribute("stroke")).toLowerCase();
                if (stroke && stroke !== "none") return stroke.slice(0, 120);
                return null;
            };
            const svgIndexFor = (el) => {
                if (!el || typeof el.getAttribute !== "function") return null;
                const dataIndex = normalize(el.getAttribute("data-index"));
                return dataIndex ? dataIndex.slice(0, 120) : null;
            };
            const svgNumberAttr = (el, attr) => {
                if (!el || typeof el.getAttribute !== "function") return null;
                const raw = parseFloat(normalize(el.getAttribute(attr)));
                return Number.isFinite(raw) ? raw : null;
            };
            const roundedSvgCoord = (value) => {
                if (!Number.isFinite(value)) return null;
                return String(Math.round(value));
            };
            const preciseSvgCoord = (value) => {
                if (!Number.isFinite(value)) return null;
                const rounded = Math.round(value * 10) / 10;
                return Number.isInteger(rounded)
                    ? String(rounded.toFixed(0))
                    : String(rounded);
            };
            const highPrecisionSvgCoord = (value) => {
                if (!Number.isFinite(value)) return null;
                const rounded = Math.round(value * 1000) / 1000;
                return Number.isInteger(rounded)
                    ? String(rounded.toFixed(0))
                    : String(rounded);
            };
            const normalizedSvgLineAngle = (value) => {
                if (!Number.isFinite(value)) return null;
                let angle = value;
                while (angle > 90) angle -= 180;
                while (angle <= -90) angle += 180;
                return angle;
            };
            const svgDistance = (x1, y1, x2, y2) => {
                if (
                    !Number.isFinite(x1)
                    || !Number.isFinite(y1)
                    || !Number.isFinite(x2)
                    || !Number.isFinite(y2)
                ) {
                    return null;
                }
                return Math.hypot(x2 - x1, y2 - y1);
            };
            const svgViewportPointFor = (el, x, y) => {
                if (!el || !Number.isFinite(x) || !Number.isFinite(y)) return null;
                const svg =
                    el.ownerSVGElement
                    || ((el.tagName || "").toLowerCase() === "svg" ? el : null);
                if (!svg || typeof svg.getBoundingClientRect !== "function") return null;

                try {
                    const svgRect = svg.getBoundingClientRect();
                    if (
                        Number.isFinite(svgRect.left)
                        && Number.isFinite(svgRect.top)
                        && Number.isFinite(svgRect.width)
                        && Number.isFinite(svgRect.height)
                    ) {
                        const ctm = typeof el.getCTM === "function" ? el.getCTM() : null;
                        if (
                            ctm
                            && Number.isFinite(ctm.a)
                            && Number.isFinite(ctm.b)
                            && Number.isFinite(ctm.c)
                            && Number.isFinite(ctm.d)
                            && Number.isFinite(ctm.e)
                            && Number.isFinite(ctm.f)
                        ) {
                            return {
                                x: svgRect.left + x * ctm.a + y * ctm.c + ctm.e,
                                y: svgRect.top + x * ctm.b + y * ctm.d + ctm.f,
                            };
                        }

                        const viewBox = svg.viewBox && svg.viewBox.baseVal;
                        if (
                            viewBox
                            && Number.isFinite(viewBox.width)
                            && viewBox.width > 0
                            && Number.isFinite(viewBox.height)
                            && viewBox.height > 0
                        ) {
                            return {
                                x: svgRect.left + ((x - viewBox.x) / viewBox.width) * svgRect.width,
                                y: svgRect.top + ((y - viewBox.y) / viewBox.height) * svgRect.height,
                            };
                        }

                        return {
                            x: svgRect.left + x,
                            y: svgRect.top + y,
                        };
                    }
                } catch (_e) {}

                return null;
            };
            const svgGeometryFor = (el, tag, rect) => {
                if (!el || !tag) return null;
                if (tag === "circle") {
                    const localCenterX = svgNumberAttr(el, "cx");
                    const localCenterY = svgNumberAttr(el, "cy");
                    const viewportCenter =
                        Number.isFinite(localCenterX) && Number.isFinite(localCenterY)
                            ? svgViewportPointFor(el, localCenterX, localCenterY)
                            : null;
                    const radius = svgNumberAttr(el, "r");
                    return {
                        centerX:
                            viewportCenter && Number.isFinite(viewportCenter.x)
                                ? viewportCenter.x
                                : rect.left + rect.width / 2,
                        centerY:
                            viewportCenter && Number.isFinite(viewportCenter.y)
                                ? viewportCenter.y
                                : rect.top + rect.height / 2,
                        radius: Number.isFinite(radius) ? radius : Math.max(rect.width, rect.height) / 2,
                    };
                }
                if (tag === "ellipse") {
                    const localCenterX = svgNumberAttr(el, "cx");
                    const localCenterY = svgNumberAttr(el, "cy");
                    const viewportCenter =
                        Number.isFinite(localCenterX) && Number.isFinite(localCenterY)
                            ? svgViewportPointFor(el, localCenterX, localCenterY)
                            : null;
                    const radiusX = svgNumberAttr(el, "rx");
                    const radiusY = svgNumberAttr(el, "ry");
                    return {
                        centerX:
                            viewportCenter && Number.isFinite(viewportCenter.x)
                                ? viewportCenter.x
                                : rect.left + rect.width / 2,
                        centerY:
                            viewportCenter && Number.isFinite(viewportCenter.y)
                                ? viewportCenter.y
                                : rect.top + rect.height / 2,
                        radiusX,
                        radiusY,
                    };
                }
                if (tag === "line") {
                    const x1 = svgNumberAttr(el, "x1");
                    const y1 = svgNumberAttr(el, "y1");
                    const x2 = svgNumberAttr(el, "x2");
                    const y2 = svgNumberAttr(el, "y2");
                    if (
                        Number.isFinite(x1)
                        && Number.isFinite(y1)
                        && Number.isFinite(x2)
                        && Number.isFinite(y2)
                    ) {
                        const start = svgViewportPointFor(el, x1, y1);
                        const end = svgViewportPointFor(el, x2, y2);
                        const resolvedX1 =
                            start && Number.isFinite(start.x)
                                ? start.x
                                : x1;
                        const resolvedY1 =
                            start && Number.isFinite(start.y)
                                ? start.y
                                : y1;
                        const resolvedX2 =
                            end && Number.isFinite(end.x)
                                ? end.x
                                : x2;
                        const resolvedY2 =
                            end && Number.isFinite(end.y)
                                ? end.y
                                : y2;
                        return {
                            x1: resolvedX1,
                            y1: resolvedY1,
                            x2: resolvedX2,
                            y2: resolvedY2,
                            length: svgDistance(resolvedX1, resolvedY1, resolvedX2, resolvedY2),
                            angleDeg: (
                                Number.isFinite(resolvedX1)
                                && Number.isFinite(resolvedY1)
                                && Number.isFinite(resolvedX2)
                                && Number.isFinite(resolvedY2)
                            )
                                ? normalizedSvgLineAngle(
                                    (Math.atan2(resolvedY2 - resolvedY1, resolvedX2 - resolvedX1) * 180) / Math.PI
                                )
                                : null,
                        };
                    }
                }
                return null;
            };
            const svgConnectedLineCountFor = (el, geometry) => {
                if (
                    !el
                    || !el.ownerSVGElement
                    || !geometry
                    || !Number.isFinite(geometry.centerX)
                    || !Number.isFinite(geometry.centerY)
                ) {
                    return null;
                }

                const tolerance = Math.max(
                    Number.isFinite(geometry.radius) ? geometry.radius + 3 : 0,
                    Number.isFinite(geometry.radiusX) ? geometry.radiusX + 3 : 0,
                    Number.isFinite(geometry.radiusY) ? geometry.radiusY + 3 : 0,
                    6,
                );
                let connectedLines = 0;

                try {
                    for (const lineEl of Array.from(el.ownerSVGElement.querySelectorAll("line"))) {
                        const lineRect =
                            typeof lineEl.getBoundingClientRect === "function"
                                ? lineEl.getBoundingClientRect()
                                : { left: 0, top: 0, width: 0, height: 0 };
                        const lineGeometry = svgGeometryFor(lineEl, "line", lineRect);
                        if (!lineGeometry) continue;

                        const touchesStart = (() => {
                            const distance = svgDistance(
                                geometry.centerX,
                                geometry.centerY,
                                lineGeometry.x1,
                                lineGeometry.y1,
                            );
                            return Number.isFinite(distance) && distance <= tolerance;
                        })();
                        const touchesEnd = (() => {
                            const distance = svgDistance(
                                geometry.centerX,
                                geometry.centerY,
                                lineGeometry.x2,
                                lineGeometry.y2,
                            );
                            return Number.isFinite(distance) && distance <= tolerance;
                        })();

                        if (touchesStart || touchesEnd) {
                            connectedLines += 1;
                        }
                    }
                } catch (_e) {
                    return null;
                }

                return connectedLines;
            };
            const svgConnectedLineRelationsFor = (el, geometry) => {
                if (
                    !el
                    || !el.ownerSVGElement
                    || !geometry
                    || !Number.isFinite(geometry.centerX)
                    || !Number.isFinite(geometry.centerY)
                ) {
                    return null;
                }

                const tolerance = Math.max(
                    Number.isFinite(geometry.radius) ? geometry.radius + 3 : 0,
                    Number.isFinite(geometry.radiusX) ? geometry.radiusX + 3 : 0,
                    Number.isFinite(geometry.radiusY) ? geometry.radiusY + 3 : 0,
                    6,
                );
                const relations = [];

                try {
                    for (const lineEl of Array.from(el.ownerSVGElement.querySelectorAll("line"))) {
                        const lineRect =
                            typeof lineEl.getBoundingClientRect === "function"
                                ? lineEl.getBoundingClientRect()
                                : { left: 0, top: 0, width: 0, height: 0 };
                        const lineGeometry = svgGeometryFor(lineEl, "line", lineRect);
                        if (!lineGeometry) continue;

                        const touchesStart = (() => {
                            const distance = svgDistance(
                                geometry.centerX,
                                geometry.centerY,
                                lineGeometry.x1,
                                lineGeometry.y1,
                            );
                            return Number.isFinite(distance) && distance <= tolerance;
                        })();
                        const touchesEnd = (() => {
                            const distance = svgDistance(
                                geometry.centerX,
                                geometry.centerY,
                                lineGeometry.x2,
                                lineGeometry.y2,
                            );
                            return Number.isFinite(distance) && distance <= tolerance;
                        })();

                        if (!touchesStart && !touchesEnd) continue;

                        const otherX = touchesStart ? lineGeometry.x2 : lineGeometry.x1;
                        const otherY = touchesStart ? lineGeometry.y2 : lineGeometry.y1;
                        const angleDeg =
                            Number.isFinite(lineGeometry.angleDeg)
                                ? normalizedSvgLineAngle(
                                    touchesStart
                                        ? lineGeometry.angleDeg
                                        : lineGeometry.angleDeg + 180
                                )
                                : null;

                        relations.push({
                            otherX,
                            otherY,
                            angleDeg,
                        });
                    }
                } catch (_e) {
                    return null;
                }

                relations.sort((left, right) => {
                    const leftAngle = Number.isFinite(left.angleDeg) ? left.angleDeg : 9999;
                    const rightAngle = Number.isFinite(right.angleDeg) ? right.angleDeg : 9999;
                    if (leftAngle !== rightAngle) return leftAngle - rightAngle;
                    if (left.otherX !== right.otherX) return left.otherX - right.otherX;
                    return left.otherY - right.otherY;
                });

                const seen = new Set();
                const unique = [];
                for (const relation of relations) {
                    const pointX = roundedSvgCoord(relation.otherX);
                    const pointY = roundedSvgCoord(relation.otherY);
                    const angle =
                        Number.isFinite(relation.angleDeg)
                            ? roundedSvgCoord(relation.angleDeg)
                            : "na";
                    const key = `${pointX},${pointY},${angle}`;
                    if (seen.has(key)) continue;
                    seen.add(key);
                    unique.push(relation);
                }

                return unique.length > 0 ? unique : null;
            };
            const svgAngleDelta = (from, to) => {
                if (!Number.isFinite(from) || !Number.isFinite(to)) return null;
                return normalizedSvgLineAngle(to - from);
            };
            const svgAngleMidpoint = (from, to) => {
                const delta = svgAngleDelta(from, to);
                if (!Number.isFinite(delta)) return null;
                return normalizedSvgLineAngle(from + delta / 2);
            };
            const svgGeometryLabel = (kind, size, color, geometry) => {
                if (!kind) return null;
                const parts = [];
                if (size) parts.push(size);
                if (color) parts.push(color);
                parts.push(kind);

                const prefix = normalize(parts.join(" "));
                if (!prefix) return null;

                if (
                    geometry
                    && Number.isFinite(geometry.x1)
                    && Number.isFinite(geometry.y1)
                    && Number.isFinite(geometry.x2)
                    && Number.isFinite(geometry.y2)
                ) {
                    return `${prefix} from ${roundedSvgCoord(geometry.x1)},${roundedSvgCoord(geometry.y1)} to ${roundedSvgCoord(geometry.x2)},${roundedSvgCoord(geometry.y2)}`.slice(0, 120);
                }

                if (geometry && Number.isFinite(geometry.centerX) && Number.isFinite(geometry.centerY)) {
                    const coordinatePhrase = size === "large" ? "centered at" : "at";
                    const radius =
                        Number.isFinite(geometry.radius)
                            ? ` radius ${roundedSvgCoord(geometry.radius)}`
                            : "";
                    return `${prefix} ${coordinatePhrase} ${roundedSvgCoord(geometry.centerX)},${roundedSvgCoord(geometry.centerY)}${radius}`.slice(0, 120);
                }

                return prefix.slice(0, 120);
            };
            const svgLeafMetadata = (el, rect) => {
                if (!el || !el.ownerSVGElement) return null;
                const tag = (el.tagName || "").toLowerCase();
                if (!SVG_LEAF_TAGS.has(tag)) return null;

                const text = normalize(el.textContent || "");
                const dataIndex = svgIndexFor(el);
                const kind = svgKindFor(tag, text);
                const size = svgSizeFor(el, tag, rect);
                const color = svgColorFor(el);
                const geometry = svgGeometryFor(el, tag, rect);
                const connectedLineRelations =
                    kind === "circle" || kind === "ellipse"
                        ? svgConnectedLineRelationsFor(el, geometry)
                        : null;
                const connectedLines =
                    connectedLineRelations && connectedLineRelations.length > 0
                        ? connectedLineRelations.length
                        : kind === "circle" || kind === "ellipse"
                            ? svgConnectedLineCountFor(el, geometry)
                        : null;
                const geometryRole =
                    Number.isFinite(connectedLines) && connectedLines > 1
                        ? "vertex"
                        : Number.isFinite(connectedLines) && connectedLines > 0
                            ? "endpoint"
                            : null;
                const connectedLineAngles =
                    Array.isArray(connectedLineRelations)
                        ? connectedLineRelations
                            .map((relation) => relation.angleDeg)
                            .filter((angle) => Number.isFinite(angle))
                        : [];
                const angleMidDeg =
                    connectedLineAngles.length === 2
                        ? svgAngleMidpoint(connectedLineAngles[0], connectedLineAngles[1])
                        : null;
                const angleSpanDeg =
                    connectedLineAngles.length === 2
                        ? Math.abs(svgAngleDelta(connectedLineAngles[0], connectedLineAngles[1]))
                        : null;
                const labelCandidates = [
                    normalize(el.getAttribute("aria-label")),
                    normalize(el.getAttribute("title")),
                    normalize(el.getAttribute("data-label")),
                    normalize(el.getAttribute("data-name")),
                    normalize(el.getAttribute("data-value")),
                    dataIndex,
                    text,
                ].filter(Boolean);

                let label = labelCandidates.length > 0 ? labelCandidates[0].slice(0, 120) : null;
                if (!label && kind) {
                    label = svgGeometryLabel(kind, size, color, geometry);
                }

                return {
                    kind,
                    size,
                    color,
                    dataIndex,
                    geometry,
                    label,
                    connectedLines,
                    connectedLineRelations,
                    geometryRole,
                    angleMidDeg,
                    angleSpanDeg,
                };
            };
            const svgAttrsFor = (el, rect) => {
                const metadata = svgLeafMetadata(el, rect);
                if (!metadata) return null;

                const attrs = {};
                if (metadata.kind) attrs.shape_kind = metadata.kind;
                if (metadata.size) attrs.shape_size = metadata.size;
                if (metadata.color) attrs.shape_color = metadata.color;
                if (metadata.dataIndex) attrs.data_index = metadata.dataIndex;
                if (metadata.geometryRole) attrs.geometry_role = metadata.geometryRole;
                if (Number.isFinite(metadata.connectedLines) && metadata.connectedLines > 0) {
                    attrs.connected_lines = String(metadata.connectedLines);
                }
                if (
                    Array.isArray(metadata.connectedLineRelations)
                    && metadata.connectedLineRelations.length > 0
                ) {
                    const connectedPoints = metadata.connectedLineRelations
                        .map((relation) => {
                            const pointX = roundedSvgCoord(relation.otherX);
                            const pointY = roundedSvgCoord(relation.otherY);
                            return `${pointX},${pointY}`;
                        })
                        .join("|");
                    if (connectedPoints) attrs.connected_points = connectedPoints;
                    const connectedPointsPrecise = metadata.connectedLineRelations
                        .map((relation) => {
                            const pointX = highPrecisionSvgCoord(relation.otherX);
                            const pointY = highPrecisionSvgCoord(relation.otherY);
                            return `${pointX},${pointY}`;
                        })
                        .join("|");
                    if (connectedPointsPrecise) {
                        attrs.connected_points_precise = connectedPointsPrecise;
                    }

                    const connectedLineAngles = metadata.connectedLineRelations
                        .map((relation) =>
                            Number.isFinite(relation.angleDeg)
                                ? roundedSvgCoord(relation.angleDeg)
                                : null
                        )
                        .filter(Boolean)
                        .join("|");
                    if (connectedLineAngles) {
                        attrs.connected_line_angles_deg = connectedLineAngles;
                    }
                    const connectedLineAnglesPrecise = metadata.connectedLineRelations
                        .map((relation) =>
                            Number.isFinite(relation.angleDeg)
                                ? highPrecisionSvgCoord(relation.angleDeg)
                                : null
                        )
                        .filter(Boolean)
                        .join("|");
                    if (connectedLineAnglesPrecise) {
                        attrs.connected_line_angles_deg_precise = connectedLineAnglesPrecise;
                    }
                }
                if (Number.isFinite(metadata.angleMidDeg)) {
                    attrs.angle_mid_deg = roundedSvgCoord(metadata.angleMidDeg);
                }
                if (Number.isFinite(metadata.angleSpanDeg)) {
                    attrs.angle_span_deg = roundedSvgCoord(metadata.angleSpanDeg);
                }
                if (metadata.geometry && Number.isFinite(metadata.geometry.radius)) {
                    attrs.radius = roundedSvgCoord(metadata.geometry.radius);
                }
                if (metadata.geometry) {
                    if (Number.isFinite(metadata.geometry.centerX)) {
                        attrs.center_x_precise = highPrecisionSvgCoord(metadata.geometry.centerX);
                    }
                    if (Number.isFinite(metadata.geometry.centerY)) {
                        attrs.center_y_precise = highPrecisionSvgCoord(metadata.geometry.centerY);
                    }
                    if (Number.isFinite(metadata.geometry.x1)) attrs.line_x1 = roundedSvgCoord(metadata.geometry.x1);
                    if (Number.isFinite(metadata.geometry.y1)) attrs.line_y1 = roundedSvgCoord(metadata.geometry.y1);
                    if (Number.isFinite(metadata.geometry.x2)) attrs.line_x2 = roundedSvgCoord(metadata.geometry.x2);
                    if (Number.isFinite(metadata.geometry.y2)) attrs.line_y2 = roundedSvgCoord(metadata.geometry.y2);
                    if (Number.isFinite(metadata.geometry.length)) {
                        attrs.line_length = roundedSvgCoord(metadata.geometry.length);
                    }
                    if (Number.isFinite(metadata.geometry.angleDeg)) {
                        attrs.line_angle_deg = roundedSvgCoord(metadata.geometry.angleDeg);
                    }
                }
                return Object.keys(attrs).length > 0 ? attrs : null;
            };
            const isSemanticSvgLeaf = (el, rect) => {
                const metadata = svgLeafMetadata(el, rect);
                return !!metadata && (!!metadata.label || !!metadata.kind);
            };
            const elementName = (el, rect) => {
                const parts = [
                    normalize(el.getAttribute("aria-label")),
                    normalize(el.getAttribute("title")),
                    normalize(el.getAttribute("placeholder")),
                ].filter(Boolean);
                if (parts.length > 0) {
                    return parts[0].slice(0, 120);
                }
                const tag = (el.tagName || "").toLowerCase();
                const inputType =
                    tag === "input"
                        ? normalize(el.getAttribute("type")).toLowerCase()
                        : "";
                const associatedLabelText = (() => {
                    const labels = [];
                    const seen = new Set();
                    const pushLabel = (candidate) => {
                        const text = normalize(
                            candidate ? (candidate.innerText || candidate.textContent || "") : ""
                        );
                        if (!text || seen.has(text)) return;
                        seen.add(text);
                        labels.push(text);
                    };

                    try {
                        if (el.labels && typeof el.labels.length === "number") {
                            for (const labelEl of Array.from(el.labels)) {
                                pushLabel(labelEl);
                            }
                        }
                    } catch (_e) {}

                    const domId = normalize(el.id);
                    if (labels.length === 0 && domId) {
                        for (const labelEl of Array.from(document.querySelectorAll("label"))) {
                            if (normalize(labelEl.getAttribute("for")) === domId) {
                                pushLabel(labelEl);
                            }
                        }
                    }

                    return labels.length > 0 ? labels.join(" ").slice(0, 120) : null;
                })();

                if (
                    associatedLabelText &&
                    tag === "input" &&
                    (inputType === "checkbox" || inputType === "radio")
                ) {
                    return associatedLabelText;
                }
                if (tag === "input" || tag === "textarea" || tag === "select") {
                    if (associatedLabelText) {
                        return associatedLabelText;
                    }
                    const controlText = normalize(el.value || "");
                    if (
                        controlText &&
                        !(tag === "input"
                            && (inputType === "checkbox" || inputType === "radio")
                            && controlText.toLowerCase() === "on")
                    ) {
                        return controlText.slice(0, 120);
                    }
                }
                const svgMetadata = svgLeafMetadata(el, rect);
                if (svgMetadata && svgMetadata.label) {
                    return svgMetadata.label;
                }
                const text = normalize(el.innerText || el.textContent || "");
                if (!text) return null;
                return text.slice(0, 120);
            };
            const elementValue = (el) => {
                const tag = (el.tagName || "").toLowerCase();
                if (tag === "input") {
                    const type = normalize(el.getAttribute("type")).toLowerCase();
                    if (type === "checkbox" || type === "radio") {
                        const controlText = normalize(el.value || "");
                        return controlText && controlText.toLowerCase() !== "on"
                            ? controlText.slice(0, 120)
                            : null;
                    }
                }
                if (tag === "input" || tag === "textarea" || tag === "select") {
                    const controlText = normalize(el.value || "");
                    return controlText ? controlText.slice(0, 120) : null;
                }
                if (tag === "output") {
                    const outputText = normalize(el.innerText || el.textContent || "");
                    return outputText ? outputText.slice(0, 120) : null;
                }
                return null;
            };
            const scrollStateFor = (el) => {
                if (!el) return null;
                const scrollHeight = Number(el.scrollHeight || 0);
                const clientHeight = Number(el.clientHeight || 0);
                const scrollTop = Number(el.scrollTop || 0);
                if (!(scrollHeight > clientHeight + 1)) {
                    return null;
                }
                return {
                    scroll_top: String(Math.round(scrollTop)),
                    scroll_height: String(Math.round(scrollHeight)),
                    client_height: String(Math.round(clientHeight)),
                    can_scroll_up: scrollTop > 1 ? "true" : "false",
                    can_scroll_down:
                        scrollTop + clientHeight + 1 < scrollHeight ? "true" : "false",
                };
            };
            const controlStateFor = (el) => {
                if (!el || !el.tagName) return null;
                const tag = (el.tagName || "").toLowerCase();
                const state = {};
                const ariaReadonly =
                    normalize(el.getAttribute("aria-readonly")).toLowerCase() === "true";
                if (typeof el.disabled === "boolean" && !!el.disabled) {
                    state.disabled = "true";
                }
                if (
                    ["input", "textarea", "select"].includes(tag)
                    && ((typeof el.readOnly === "boolean" && !!el.readOnly) || ariaReadonly)
                ) {
                    state.readonly = "true";
                }
                if (tag === "input") {
                    const type = normalize(el.getAttribute("type")).toLowerCase();
                    if ((type === "checkbox" || type === "radio") && !!el.checked) {
                        state.checked = "true";
                    }
                }
                if (tag === "option" && !!el.selected) {
                    state.selected = "true";
                }
                return Object.keys(state).length > 0 ? state : null;
            };
            const firstIdToken = (value) => {
                const tokens = normalize(value).split(/\s+/).filter(Boolean);
                return tokens.length > 0 ? tokens[0] : "";
            };
            const relatedElementIds = (el) => {
                if (!el || typeof el.getAttribute !== "function") {
                    return [];
                }
                const ids = [];
                const seen = new Set();
                for (const attr of [
                    "aria-controls",
                    "aria-owns",
                    "aria-describedby",
                    "aria-activedescendant",
                ]) {
                    const raw = normalize(el.getAttribute(attr));
                    if (!raw) continue;
                    for (const token of raw.split(/\s+/).filter(Boolean)) {
                        if (seen.has(token)) continue;
                        seen.add(token);
                        ids.push(token);
                    }
                }
                return ids;
            };
            const hasAutocompleteSemantics = (el) => {
                if (!el || typeof el.getAttribute !== "function") {
                    return false;
                }
                const autocomplete = normalize(el.getAttribute("aria-autocomplete")).toLowerCase();
                if (autocomplete) return true;
                if (normalize(el.getAttribute("aria-controls"))) return true;
                if (normalize(el.getAttribute("aria-activedescendant"))) return true;
                const className = normalize(String(el.className || "")).toLowerCase();
                return className.includes("autocomplete");
            };
            const assistiveText = (el) =>
                normalize(el ? (el.innerText || el.textContent || "") : "");
            const assistiveRole = (el) => {
                const explicitRole = normalize(
                    el && typeof el.getAttribute === "function"
                        ? el.getAttribute("role")
                        : ""
                ).toLowerCase();
                if (explicitRole) return explicitRole;
                const ariaLive = normalize(
                    el && typeof el.getAttribute === "function"
                        ? el.getAttribute("aria-live")
                        : ""
                ).toLowerCase();
                if (ariaLive) return "status";
                const className = normalize(String((el && el.className) || "")).toLowerCase();
                if (className.includes("ui-helper-hidden-accessible")) return "status";
                return toRole(el);
            };

            const bodyRect = {
                x: 0,
                y: 0,
                width: Math.max(1, Math.round(window.innerWidth || 1)),
                height: Math.max(1, Math.round(window.innerHeight || 1)),
            };
            const activeElement = deepActiveElement();

            const root = {
                id: "dom-root",
                role: "root",
                name: "DOM fallback tree",
                value: null,
                rect: bodyRect,
                is_visible: true,
                attributes: { snapshot_fallback: "dom" },
                children: [],
            };

            const all = Array.from(document.querySelectorAll("body *"));
            for (let i = 0; i < all.length && root.children.length < MAX_CANDIDATES; i++) {
                const el = all[i];
                if (!el || !el.tagName) continue;
                let rect = null;
                try {
                    rect = el.getBoundingClientRect();
                } catch (_e) {
                    continue;
                }
                if (!isVisible(el, rect)) continue;

                const tag = (el.tagName || "").toLowerCase();
                const role = toRole(el);
                const explicitName = elementName(el, rect);
                const value = elementValue(el);
                const semanticHintName = semanticHintNameFor(el);
                const name = explicitName || semanticHintName;
                const domId = normalize(el.id);
                const className = normalize(String(el.className || ""));
                const selector = selectorFor(el);
                const hasInlineClick = !!normalize(el.getAttribute("onclick")) || typeof el.onclick === "function";
                const baseDomClickable = isInteractive(el, role) || hasInlineClick || (() => {
                    let style = null;
                    try {
                        style = window.getComputedStyle(el);
                    } catch (_e) {}
                    return !!style && style.cursor === "pointer";
                })();
                const likelySemanticIconControl =
                    !!semanticHintName
                    && !explicitName
                    && !value
                    && ["span", "div", "i", "img", "svg"].includes(tag)
                    && rect.width <= 40
                    && rect.height <= 40;
                const semanticControlStrip =
                    likelySemanticIconControl && hasSemanticControlStripContext(el);
                const domClickable = baseDomClickable || semanticControlStrip;
                const semanticRole =
                    role === "generic" && likelySemanticIconControl && domClickable
                        ? "button"
                        : role;
                const svgAttrs = svgAttrsFor(el, rect);
                const keep =
                    domClickable
                    || !!name
                    || !!value
                    || !!svgAttrs
                    || (tag === "svg" && !!domId)
                    || isSemanticSvgLeaf(el, rect);
                if (!keep) continue;
                const focused = activeElement === el;
                const autocomplete = normalize(el.getAttribute("aria-autocomplete")).toLowerCase();
                const controlsDomId = firstIdToken(el.getAttribute("aria-controls"));
                const activeDescendantDomId = firstIdToken(
                    el.getAttribute("aria-activedescendant")
                );
                const scrollState = scrollStateFor(el);
                const stableId = domId
                    ? `dom-id-${domId}`
                    : `dom-node-${root.children.length + 1}`;

                root.children.push({
                    id: stableId,
                    role: semanticRole,
                    name,
                    value,
                    rect: {
                        x: Math.round(rect.left),
                        y: Math.round(rect.top),
                        width: Math.round(rect.width),
                        height: Math.round(rect.height),
                    },
                    is_visible: true,
                    attributes: {
                        dom_fallback: "true",
                        dom_id: domId,
                        ...(selector ? { selector: selector.slice(0, 240) } : {}),
                        ...(className ? { class_name: className.slice(0, 120) } : {}),
                        tag_name: (el.tagName || "").toLowerCase(),
                        ...(domClickable ? { dom_clickable: "true" } : {}),
                        ...(focused ? { focused: "true" } : {}),
                        ...(autocomplete ? { autocomplete } : {}),
                        ...(controlsDomId ? { controls_dom_id: controlsDomId } : {}),
                        ...(activeDescendantDomId
                            ? { active_descendant_dom_id: activeDescendantDomId }
                            : {}),
                        ...(controlStateFor(el) || {}),
                        ...(scrollState || {}),
                        ...(svgAttrs || {}),
                    },
                    children: [],
                });
            }

            if (activeElement && root.children.length < MAX_CANDIDATES) {
                const assistiveSeen = new Set();
                const pushAssistiveHint = (el, reason) => {
                    if (!el || !el.tagName || root.children.length >= MAX_CANDIDATES) {
                        return;
                    }

                    const text = assistiveText(el);
                    if (!text) return;

                    const domId = normalize(el.id);
                    const key = domId || `${reason}:${text}`;
                    if (assistiveSeen.has(key)) return;
                    assistiveSeen.add(key);

                    let rect = null;
                    try {
                        rect = el.getBoundingClientRect();
                    } catch (_e) {}

                    const hintRole = assistiveRole(el) || "status";
                    const stableId = domId
                        ? `assistive-${domId}`
                        : `assistive-${root.children.length + 1}`;

                    root.children.push({
                        id: stableId,
                        role: hintRole,
                        name: text.slice(0, 120),
                        value: null,
                        rect: {
                            x: Math.round(rect && Number.isFinite(rect.left) ? rect.left : -1),
                            y: Math.round(rect && Number.isFinite(rect.top) ? rect.top : -1),
                            width: Math.max(
                                1,
                                Math.round(rect && Number.isFinite(rect.width) ? rect.width : 1)
                            ),
                            height: Math.max(
                                1,
                                Math.round(rect && Number.isFinite(rect.height) ? rect.height : 1)
                            ),
                        },
                        is_visible: false,
                        attributes: {
                            dom_fallback: "true",
                            dom_id: domId,
                            tag_name: (el.tagName || "").toLowerCase(),
                            assistive_hint: "true",
                            assistive_reason: reason,
                        },
                        children: [],
                    });
                };

                for (const refId of relatedElementIds(activeElement)) {
                    pushAssistiveHint(document.getElementById(refId), "aria_reference");
                }

                if (hasAutocompleteSemantics(activeElement)) {
                    const assistiveRegions = document.querySelectorAll(
                        "[role='status'], [role='alert'], [role='log'], [aria-live], .ui-helper-hidden-accessible"
                    );
                    for (const assistiveRegion of assistiveRegions) {
                        pushAssistiveHint(assistiveRegion, "assistive_live_region");
                    }
                }
            }

            if (root.children.length === 0) {
                const summary = normalize(
                    (document.body && (document.body.innerText || document.body.textContent)) || ""
                );
                root.name = summary ? summary.slice(0, 120) : "DOM fallback tree";
                root.attributes.fallback_reason = "empty_candidate_set";
            }

            return root;
        })()"#;

        let node = page
            .evaluate(script)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM fallback JS eval failed: {}", e)))?
            .into_value::<DomFallbackNode>()
            .map_err(|e| BrowserError::Internal(format!("DOM fallback decode failed: {}", e)))?;

        let mut tree = prune_redundant_dom_fallback_aggregates(node.into_accessibility());
        tree.attributes
            .insert("snapshot_fallback_cause".to_string(), cause.to_string());
        Ok(tree)
    }

    async fn dom_fallback_tree(
        &self,
        page: &Page,
        cause: &str,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        Self::dom_fallback_tree_for_page(page, cause).await
    }

    pub async fn get_accessibility_tree(
        &self,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        let p = page.ok_or(BrowserError::NoActivePage)?;

        match tokio::time::timeout(
            ACCESSIBILITY_TREE_TIMEOUT,
            self.get_accessibility_tree_inner(&p),
        )
        .await
        {
            Ok(result) => match result {
                Ok(tree) => {
                    self.remember_accessibility_snapshot(&tree).await;
                    Ok(tree)
                }
                Err(error) => Err(error),
            },
            Err(_) => {
                log::warn!(
                    target: "browser",
                    "Browser accessibility snapshot timed out after {:?}; forcing session reset.",
                    ACCESSIBILITY_TREE_TIMEOUT
                );
                self.force_reset().await;
                Err(BrowserError::Internal(format!(
                    "Browser accessibility snapshot timed out after {:?}. Retry the action.",
                    ACCESSIBILITY_TREE_TIMEOUT
                )))
            }
        }
    }

    pub async fn get_prompt_observation_tree(
        &self,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        if let Some((_, tree)) = self
            .recent_accessibility_snapshot(PROMPT_OBSERVATION_CACHE_MAX_AGE)
            .await
        {
            return Ok(tree);
        }

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let tree = self.dom_fallback_tree(&page, "prompt_observation").await?;
        self.remember_accessibility_snapshot(&tree).await;
        Ok(tree)
    }

    async fn get_accessibility_tree_inner(
        &self,
        p: &Page,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        p.execute(accessibility::EnableParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes_vec = match p.execute(GetFullAxTreeParams::default()).await {
            Ok(snapshot) => snapshot.nodes.clone(),
            Err(e) => {
                let err_msg = e.to_string();
                if allow_dom_fallback_for_ax_error(&err_msg) {
                    log::warn!(
                        target: "browser",
                        "CDP AX snapshot unavailable ({}); falling back to DOM snapshot.",
                        err_msg
                    );
                    return self
                        .dom_fallback_tree(&p, &format!("ax_error:{}", err_msg))
                        .await;
                }
                return Err(BrowserError::Internal(format!(
                    "CDP GetAxTree failed: {}",
                    e
                )));
            }
        };

        if nodes_vec.is_empty() {
            log::warn!(
                target: "browser",
                "CDP AX snapshot returned an empty tree; falling back to DOM snapshot."
            );
            return self.dom_fallback_tree(&p, "ax_empty_tree").await;
        }

        let root_ax = &nodes_vec[0];
        let rect_lookup = self.collect_ax_node_rects(&p, &nodes_vec).await;
        let ax_tree = self.convert_ax_node(root_ax, &nodes_vec, &rect_lookup);
        let enriched_tree = match self.dom_fallback_tree(&p, "ax_overlay_enrichment").await {
            Ok(dom_tree) => merge_missing_dom_fallback_nodes(ax_tree, dom_tree),
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "DOM overlay enrichment skipped after AX snapshot: {}",
                    error
                );
                ax_tree
            }
        };
        Ok(enriched_tree)
    }

    pub async fn get_visual_tree(&self) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(accessibility::EnableParams::default())
            .await
            .ok();

        let snapshot = page
            .execute(accessibility::GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("GetFullAxTree failed: {}", e)))?;

        let nodes = snapshot.nodes.clone();

        if nodes.is_empty() {
            return Err(BrowserError::Internal("Empty tree".into()));
        }

        let rect_lookup = self.collect_ax_node_rects(&page, &nodes).await;
        Ok(self.convert_ax_node(&nodes[0], &nodes, &rect_lookup))
    }

    fn convert_ax_node(
        &self,
        ax_node: &accessibility::AxNode,
        all_nodes: &[accessibility::AxNode],
        rect_lookup: &HashMap<String, AccessibilityRect>,
    ) -> AccessibilityNode {
        let mut children = Vec::new();
        if let Some(child_ids) = &ax_node.child_ids {
            for cid in child_ids {
                if let Some(child_ax) = all_nodes.iter().find(|n| &n.node_id == cid) {
                    children.push(self.convert_ax_node(child_ax, all_nodes, rect_lookup));
                }
            }
        }

        fn extract_string(val_opt: &Option<accessibility::AxValue>) -> Option<String> {
            val_opt.as_ref().and_then(|v| {
                if let Some(inner) = &v.value {
                    if let Some(s) = inner.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = inner.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = inner.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }

        let name = extract_string(&ax_node.name);
        let mut value = extract_string(&ax_node.value);
        let role = extract_string(&ax_node.role)
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "generic".to_string());

        let is_visible = !ax_node.ignored;
        let id_string: String = ax_node.node_id.clone().into();

        let mut attributes = HashMap::new();
        // Preserve the raw CDP AX node ID even after semantic lenses rewrite `node.id`.
        attributes.insert("cdp_node_id".to_string(), id_string.clone());
        if let Some(backend_id) = ax_node.backend_dom_node_id {
            attributes.insert(
                "backend_dom_node_id".to_string(),
                backend_id.inner().to_string(),
            );
        }
        if let Some(desc) = extract_string(&ax_node.description) {
            attributes.insert("description".to_string(), desc.clone());
            if value.is_none() {
                value = Some(desc);
            }
        }
        if let Some(chrome_role) = extract_string(&ax_node.chrome_role) {
            attributes.insert("chrome_role".to_string(), chrome_role);
        }

        if let Some(props) = &ax_node.properties {
            for prop in props {
                let key = prop.name.as_ref().to_ascii_lowercase();
                if key.is_empty() {
                    continue;
                }
                if let Some(raw_val) = &prop.value.value {
                    let parsed = if let Some(s) = raw_val.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = raw_val.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = raw_val.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    };

                    if let Some(parsed_val) = parsed {
                        attributes.insert(key.clone(), parsed_val.clone());
                        if value.is_none()
                            && matches!(key.as_str(), "valuetext" | "roledescription")
                        {
                            value = Some(parsed_val);
                        }
                    }
                }
            }
        }

        let rect = rect_lookup
            .get(&id_string)
            .copied()
            .unwrap_or(AccessibilityRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            });

        AccessibilityNode {
            id: id_string,
            role,
            name,
            value,
            rect,
            children,
            is_visible,
            attributes,
            som_id: None,
        }
    }

    fn rect_from_dom_quad(quad: &[f64]) -> Option<(AccessibilityRect, f64)> {
        if quad.len() < 8 {
            return None;
        }

        let xs = [quad[0], quad[2], quad[4], quad[6]];
        let ys = [quad[1], quad[3], quad[5], quad[7]];
        if xs.iter().any(|v| !v.is_finite()) || ys.iter().any(|v| !v.is_finite()) {
            return None;
        }

        let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min);
        let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let width = max_x - min_x;
        let height = max_y - min_y;
        if width <= 1.0 || height <= 1.0 {
            return None;
        }

        let rect = AccessibilityRect {
            x: min_x.floor().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            y: min_y.floor().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            width: width.ceil().clamp(1.0, i32::MAX as f64) as i32,
            height: height.ceil().clamp(1.0, i32::MAX as f64) as i32,
        };

        Some((rect, width * height))
    }

    async fn resolve_backend_node_rect(
        page: &Page,
        backend_node_id: chromiumoxide::cdp::browser_protocol::dom::BackendNodeId,
    ) -> Option<AccessibilityRect> {
        let quad_rect = page
            .execute(
                GetContentQuadsParams::builder()
                    .backend_node_id(backend_node_id)
                    .build(),
            )
            .await
            .ok()
            .and_then(|quads| {
                quads
                    .quads
                    .iter()
                    .filter_map(|q| Self::rect_from_dom_quad(q.inner().as_slice()))
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(rect, _)| rect)
            });

        if quad_rect.is_some() {
            return quad_rect;
        }

        page.execute(
            GetBoxModelParams::builder()
                .backend_node_id(backend_node_id)
                .build(),
        )
        .await
        .ok()
        .and_then(|model| Self::rect_from_dom_quad(model.model.border.inner().as_slice()))
        .map(|(rect, _)| rect)
    }

    async fn collect_ax_node_rects(
        &self,
        page: &Page,
        nodes: &[accessibility::AxNode],
    ) -> HashMap<String, AccessibilityRect> {
        let mut rects_by_node = HashMap::new();
        let mut rects_by_backend = HashMap::new();

        for ax_node in nodes {
            let backend_node_id = match ax_node.backend_dom_node_id {
                Some(id) => id,
                None => continue,
            };
            let backend_key = *backend_node_id.inner();

            let rect = if let Some(cached) = rects_by_backend.get(&backend_key).copied() {
                Some(cached)
            } else {
                let resolved = Self::resolve_backend_node_rect(page, backend_node_id).await;
                if let Some(found) = resolved {
                    rects_by_backend.insert(backend_key, found);
                }
                resolved
            };

            if let Some(found) = rect {
                let node_id: String = ax_node.node_id.clone().into();
                rects_by_node.insert(node_id, found);
            }
        }

        rects_by_node
    }

    fn quad_center(quad: &[f64]) -> Option<(f64, f64, f64)> {
        if quad.len() < 8 {
            return None;
        }

        let xs = [quad[0], quad[2], quad[4], quad[6]];
        let ys = [quad[1], quad[3], quad[5], quad[7]];

        let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min);
        let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let width = max_x - min_x;
        let height = max_y - min_y;
        if !width.is_finite() || !height.is_finite() || width <= 1.0 || height <= 1.0 {
            return None;
        }

        let cx = xs.iter().sum::<f64>() / 4.0;
        let cy = ys.iter().sum::<f64>() / 4.0;
        if !cx.is_finite() || !cy.is_finite() {
            return None;
        }

        Some((cx, cy, width * height))
    }

    async fn resolve_click_center_for_backend_node(
        page: &Page,
        backend_node_id: chromiumoxide::cdp::browser_protocol::dom::BackendNodeId,
    ) -> std::result::Result<(f64, f64), BrowserError> {
        let content_quads = page
            .execute(
                GetContentQuadsParams::builder()
                    .backend_node_id(backend_node_id)
                    .build(),
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP getContentQuads failed: {}", e)))?;

        let mut best_center = content_quads
            .quads
            .iter()
            .filter_map(|q| Self::quad_center(q.inner().as_slice()))
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(x, y, _)| (x, y));

        if best_center.is_none() {
            let model = page
                .execute(
                    GetBoxModelParams::builder()
                        .backend_node_id(backend_node_id)
                        .build(),
                )
                .await
                .map_err(|e| BrowserError::Internal(format!("CDP getBoxModel failed: {}", e)))?;
            best_center =
                Self::quad_center(model.model.border.inner().as_slice()).map(|(x, y, _)| (x, y));
        }

        best_center.ok_or_else(|| {
            BrowserError::Internal(format!(
                "Backend DOM node '{}' has no visible clickable geometry",
                backend_node_id.inner()
            ))
        })
    }

    pub async fn click_backend_dom_node(
        &self,
        backend_dom_node_id: &str,
    ) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let parsed_backend_id = backend_dom_node_id.trim().parse::<i64>().map_err(|e| {
            BrowserError::Internal(format!(
                "Backend DOM node id '{}' is not a valid integer: {}",
                backend_dom_node_id, e
            ))
        })?;
        let backend_node_id =
            chromiumoxide::cdp::browser_protocol::dom::BackendNodeId::new(parsed_backend_id);

        let (x, y) = Self::resolve_click_center_for_backend_node(&page, backend_node_id).await?;
        self.synthetic_click(x, y).await
    }

    /// Click an element by raw CDP Accessibility node id.
    ///
    /// This is used by semantic browser interaction:
    /// semantic_id -> cdp_node_id -> backend_dom_node_id -> DOM quad center.
    pub async fn click_ax_node(
        &self,
        target_cdp_id: &str,
    ) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(accessibility::EnableParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes = page
            .execute(GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        let target_node = nodes
            .iter()
            .find(|node| node.node_id.as_ref() == target_cdp_id)
            .ok_or_else(|| {
                BrowserError::Internal(format!(
                    "Element with CDP node id '{}' not found in current accessibility tree",
                    target_cdp_id
                ))
            })?;

        let backend_node_id = target_node.backend_dom_node_id.ok_or_else(|| {
            BrowserError::Internal(format!(
                "Element '{}' is not backed by a DOM node and cannot be clicked",
                target_cdp_id
            ))
        })?;

        let (x, y) = Self::resolve_click_center_for_backend_node(&page, backend_node_id)
            .await
            .map_err(|e| {
                BrowserError::Internal(format!(
                    "Failed to resolve click center for element '{}': {}",
                    target_cdp_id, e
                ))
            })?;

        self.synthetic_click(x, y).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        merge_missing_dom_fallback_nodes, node_contains_visible_start_gate,
        prune_redundant_dom_fallback_aggregates, should_cache_prompt_observation_warmup,
        BrowserDriver, DomFallbackNode, DomFallbackRect,
    };
    use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
    use std::collections::HashMap;

    #[test]
    fn rect_from_dom_quad_builds_bounds() {
        let quad = [10.2, 20.8, 50.0, 20.1, 49.6, 60.4, 10.1, 60.9];
        let (rect, area) = BrowserDriver::rect_from_dom_quad(&quad).expect("quad should resolve");
        assert_eq!(rect.x, 10);
        assert_eq!(rect.y, 20);
        assert_eq!(rect.width, 40);
        assert_eq!(rect.height, 41);
        assert!(area > 1500.0);
    }

    #[test]
    fn rect_from_dom_quad_rejects_degenerate_geometry() {
        let tiny = [10.0, 10.0, 10.5, 10.0, 10.5, 10.4, 10.0, 10.4];
        assert!(BrowserDriver::rect_from_dom_quad(&tiny).is_none());
    }

    #[test]
    fn rect_from_dom_quad_rejects_non_finite_values() {
        let bad = [10.0, 10.0, f64::NAN, 10.0, 50.0, 50.0, 10.0, 50.0];
        assert!(BrowserDriver::rect_from_dom_quad(&bad).is_none());
    }

    #[test]
    fn dom_fallback_is_allowed_for_not_rendered_ax_errors() {
        assert!(super::allow_dom_fallback_for_ax_error(
            "CDP GetAxTree failed: notRendered"
        ));
        assert!(super::allow_dom_fallback_for_ax_error(
            "AX snapshot failed because the page is not rendered"
        ));
    }

    #[test]
    fn dom_fallback_is_allowed_for_label_for_ax_errors() {
        assert!(super::allow_dom_fallback_for_ax_error(
            "CDP GetAxTree failed: labelFor"
        ));
    }

    fn dom_node(
        id: &str,
        role: &str,
        name: Option<&str>,
        rect: (f64, f64, f64, f64),
        attrs: &[(&str, &str)],
    ) -> DomFallbackNode {
        DomFallbackNode {
            id: id.to_string(),
            role: role.to_string(),
            name: name.map(str::to_string),
            value: None,
            rect: DomFallbackRect {
                x: rect.0,
                y: rect.1,
                width: rect.2,
                height: rect.3,
            },
            is_visible: Some(true),
            attributes: attrs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
            children: Vec::new(),
        }
    }

    fn ax_node(
        id: &str,
        role: &str,
        name: Option<&str>,
        rect: (i32, i32, i32, i32),
        attrs: &[(&str, &str)],
    ) -> AccessibilityNode {
        AccessibilityNode {
            id: id.to_string(),
            role: role.to_string(),
            name: name.map(str::to_string),
            value: None,
            rect: AccessibilityRect {
                x: rect.0,
                y: rect.1,
                width: rect.2,
                height: rect.3,
            },
            children: Vec::new(),
            is_visible: true,
            attributes: attrs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
            som_id: None,
        }
    }

    #[test]
    fn dom_fallback_icon_control_synthesizes_name_from_class_hint() {
        let node = dom_node(
            "dom-node-1",
            "generic",
            None,
            (120.0, 57.0, 12.0, 12.0),
            &[
                ("dom_fallback", "true"),
                ("tag_name", "span"),
                ("class_name", "trash"),
                ("dom_clickable", "true"),
            ],
        )
        .into_accessibility();

        assert_eq!(node.name.as_deref(), Some("trash"));
        assert!(node.is_interactive());
    }

    #[test]
    fn dom_fallback_icon_control_synthesizes_name_from_dom_id_hint() {
        let node = dom_node(
            "dom-node-2",
            "generic",
            None,
            (2.0, 56.0, 12.0, 12.0),
            &[
                ("dom_fallback", "true"),
                ("tag_name", "span"),
                ("dom_id", "close-email"),
                ("dom_clickable", "true"),
            ],
        )
        .into_accessibility();

        assert_eq!(node.name.as_deref(), Some("close email"));
        assert!(node.is_interactive());
    }

    #[test]
    fn dom_fallback_semantic_hint_ignores_structural_class_tokens() {
        let node = dom_node(
            "dom-node-3",
            "generic",
            None,
            (2.0, 56.0, 12.0, 12.0),
            &[
                ("dom_fallback", "true"),
                ("tag_name", "span"),
                ("class_name", "controls spacer details"),
            ],
        )
        .into_accessibility();

        assert_eq!(node.name.as_deref(), None);
        assert!(!node.is_interactive());
    }

    #[test]
    fn visible_start_gate_is_detected_from_sync_cover_node() {
        let mut root = ax_node(
            "root",
            "root",
            Some("DOM fallback tree"),
            (0, 0, 800, 600),
            &[("snapshot_fallback_cause", "navigate_warmup")],
        );
        root.children.push(ax_node(
            "grp_start",
            "generic",
            Some("START"),
            (0, 0, 160, 210),
            &[("dom_id", "sync-task-cover")],
        ));

        assert!(node_contains_visible_start_gate(&root));
        assert!(!should_cache_prompt_observation_warmup(&root));
    }

    #[test]
    fn warmup_cache_is_kept_when_start_gate_coexists_with_grounded_target() {
        let mut root = ax_node(
            "root",
            "root",
            Some("DOM fallback tree"),
            (0, 0, 800, 600),
            &[("snapshot_fallback_cause", "navigate_warmup")],
        );
        root.children.push(ax_node(
            "grp_start",
            "generic",
            Some("START"),
            (0, 0, 160, 210),
            &[("dom_id", "sync-task-cover")],
        ));
        root.children.push(ax_node(
            "grp_circ",
            "generic",
            Some("large circle"),
            (62, 119, 44, 44),
            &[
                ("dom_id", "circ"),
                ("selector", "[id=\"circ\"]"),
                ("shape_kind", "circle"),
            ],
        ));

        assert!(node_contains_visible_start_gate(&root));
        assert!(should_cache_prompt_observation_warmup(&root));
    }

    #[test]
    fn warmup_cache_is_kept_for_started_task_surface() {
        let mut root = ax_node(
            "root",
            "root",
            Some("DOM fallback tree"),
            (0, 0, 800, 600),
            &[("snapshot_fallback_cause", "navigate_warmup")],
        );
        root.children.push(ax_node(
            "grp_circ",
            "generic",
            Some("large circle"),
            (62, 119, 44, 44),
            &[
                ("dom_id", "circ"),
                ("selector", "[id=\"circ\"]"),
                ("shape_kind", "circle"),
            ],
        ));

        assert!(!node_contains_visible_start_gate(&root));
        assert!(should_cache_prompt_observation_warmup(&root));
    }

    #[test]
    fn dom_fallback_script_declares_selector_helper_before_use() {
        let source = include_str!("accessibility.rs");
        let helper_idx = source
            .find("const selectorFor = (el) =>")
            .expect("DOM fallback script should declare selectorFor");
        let use_idx = source
            .find("const selector = selectorFor(el);")
            .expect("DOM fallback script should use selectorFor for selector attrs");

        assert!(helper_idx < use_idx);
    }

    #[test]
    fn dom_fallback_script_surfaces_svg_geometry_roles_and_line_metrics() {
        let source = include_str!("accessibility.rs");

        assert!(
            source.contains("attrs.geometry_role = metadata.geometryRole;"),
            "{source}"
        );
        assert!(
            source.contains("attrs.connected_lines = String(metadata.connectedLines);"),
            "{source}"
        );
        assert!(
            source.contains("attrs.connected_points = connectedPoints;"),
            "{source}"
        );
        assert!(
            source.contains("attrs.connected_points_precise = connectedPointsPrecise;"),
            "{source}"
        );
        assert!(
            source.contains("attrs.connected_line_angles_deg = connectedLineAngles;"),
            "{source}"
        );
        assert!(
            source
                .contains("attrs.connected_line_angles_deg_precise = connectedLineAnglesPrecise;"),
            "{source}"
        );
        assert!(
            source.contains("attrs.angle_mid_deg = roundedSvgCoord(metadata.angleMidDeg);"),
            "{source}"
        );
        assert!(
            source.contains("attrs.angle_span_deg = roundedSvgCoord(metadata.angleSpanDeg);"),
            "{source}"
        );
        assert!(
            source.contains("attrs.line_length = roundedSvgCoord(metadata.geometry.length);"),
            "{source}"
        );
        assert!(
            source.contains("attrs.line_angle_deg = roundedSvgCoord(metadata.geometry.angleDeg);"),
            "{source}"
        );
        assert!(
            source.contains(
                "attrs.center_x_precise = highPrecisionSvgCoord(metadata.geometry.centerX);"
            ),
            "{source}"
        );
        assert!(
            source.contains(
                "attrs.center_y_precise = highPrecisionSvgCoord(metadata.geometry.centerY);"
            ),
            "{source}"
        );
    }

    #[test]
    fn prune_redundant_dom_fallback_aggregates_drops_flat_container_noise() {
        let root = DomFallbackNode {
            id: "dom-root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: DomFallbackRect {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 600.0,
            },
            is_visible: Some(true),
            attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
            children: vec![
                dom_node(
                    "grp_wrap",
                    "generic",
                    Some("Select TeCSlMn and click Submit. TeCSlMn Submit"),
                    (0.0, 0.0, 160.0, 210.0),
                    &[("dom_fallback", "true"), ("tag_name", "div")],
                ),
                dom_node(
                    "grp_query",
                    "generic",
                    Some("Select TeCSlMn and click Submit."),
                    (0.0, 0.0, 160.0, 50.0),
                    &[("dom_fallback", "true"), ("tag_name", "div")],
                ),
                dom_node(
                    "grp_area",
                    "generic",
                    Some("TeCSlMn Submit"),
                    (0.0, 50.0, 160.0, 136.0),
                    &[("dom_fallback", "true"), ("tag_name", "div")],
                ),
                dom_node(
                    "radio_tecslmn",
                    "radio",
                    Some("TeCSlMn"),
                    (7.0, 55.0, 20.0, 13.0),
                    &[("dom_fallback", "true"), ("tag_name", "input")],
                ),
                dom_node(
                    "btn_submit",
                    "button",
                    Some("Submit"),
                    (2.0, 153.0, 95.0, 31.0),
                    &[("dom_fallback", "true"), ("tag_name", "button")],
                ),
            ],
        }
        .into_accessibility();

        let pruned = prune_redundant_dom_fallback_aggregates(root);
        let child_ids = pruned
            .children
            .iter()
            .map(|child| child.id.as_str())
            .collect::<Vec<_>>();

        assert!(!child_ids.contains(&"grp_wrap"));
        assert!(!child_ids.contains(&"grp_area"));
        assert!(child_ids.contains(&"grp_query"));
        assert!(child_ids.contains(&"radio_tecslmn"));
        assert!(child_ids.contains(&"btn_submit"));
        assert_eq!(
            pruned
                .attributes
                .get("dom_fallback_pruned_aggregate_count")
                .map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn prune_redundant_dom_fallback_aggregates_keeps_scrollable_container_state() {
        let root = DomFallbackNode {
            id: "dom-root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: DomFallbackRect {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 600.0,
            },
            is_visible: Some(true),
            attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
            children: vec![
                dom_node(
                    "grp_scroll_region",
                    "generic",
                    Some("Messages Submit"),
                    (0.0, 0.0, 160.0, 210.0),
                    &[
                        ("dom_fallback", "true"),
                        ("tag_name", "div"),
                        ("scroll_top", "12"),
                    ],
                ),
                dom_node(
                    "btn_submit",
                    "button",
                    Some("Submit"),
                    (2.0, 153.0, 95.0, 31.0),
                    &[("dom_fallback", "true"), ("tag_name", "button")],
                ),
            ],
        }
        .into_accessibility();

        let pruned = prune_redundant_dom_fallback_aggregates(root);
        let child_ids = pruned
            .children
            .iter()
            .map(|child| child.id.as_str())
            .collect::<Vec<_>>();

        assert!(child_ids.contains(&"grp_scroll_region"));
        assert!(pruned
            .attributes
            .get("dom_fallback_pruned_aggregate_count")
            .is_none());
    }

    #[test]
    fn prune_redundant_dom_fallback_aggregates_drops_table_cell_wrapper_for_link_child() {
        let root = DomFallbackNode {
            id: "dom-root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: DomFallbackRect {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 600.0,
            },
            is_visible: Some(true),
            attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
            children: vec![
                dom_node(
                    "grp_t_215",
                    "generic",
                    Some("T-215"),
                    (66.0, 850.0, 73.0, 91.0),
                    &[("dom_fallback", "true"), ("tag_name", "td")],
                ),
                dom_node(
                    "lnk_t_215",
                    "link",
                    Some("T-215"),
                    (78.0, 884.0, 41.0, 22.0),
                    &[
                        ("dom_fallback", "true"),
                        ("tag_name", "a"),
                        ("dom_id", "ticket-link-t-215"),
                    ],
                ),
            ],
        }
        .into_accessibility();

        let pruned = prune_redundant_dom_fallback_aggregates(root);
        let child_ids = pruned
            .children
            .iter()
            .map(|child| child.id.as_str())
            .collect::<Vec<_>>();

        assert!(!child_ids.contains(&"grp_t_215"));
        assert!(child_ids.contains(&"lnk_t_215"));
        assert_eq!(
            pruned
                .attributes
                .get("dom_fallback_pruned_aggregate_count")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn merge_missing_dom_fallback_nodes_adds_clickable_overlay_without_duplicate_submit() {
        let ax_tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: Some("AX tree".to_string()),
            value: None,
            rect: AccessibilityRect {
                x: 0,
                y: 0,
                width: 160,
                height: 210,
            },
            children: vec![
                ax_node(
                    "btn_submit",
                    "button",
                    Some("Submit"),
                    (30, 178, 95, 31),
                    &[("dom_id", "subbtn"), ("selector", "#subbtn")],
                ),
                ax_node(
                    "grp_svg_grid",
                    "generic",
                    Some("svg grid object"),
                    (2, 52, 150, 130),
                    &[("dom_id", "svg-grid"), ("selector", "#svg-grid")],
                ),
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let dom_tree = DomFallbackNode {
            id: "dom-root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: DomFallbackRect {
                x: 0.0,
                y: 0.0,
                width: 160.0,
                height: 210.0,
            },
            is_visible: Some(true),
            attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
            children: vec![
                dom_node(
                    "dom-id-subbtn",
                    "button",
                    Some("Submit"),
                    (30.0, 178.0, 95.0, 31.0),
                    &[
                        ("dom_fallback", "true"),
                        ("tag_name", "button"),
                        ("dom_id", "subbtn"),
                        ("selector", "#subbtn"),
                        ("dom_clickable", "true"),
                    ],
                ),
                dom_node(
                    "dom-id-sync-task-cover",
                    "generic",
                    Some("START"),
                    (0.0, 0.0, 160.0, 210.0),
                    &[
                        ("dom_fallback", "true"),
                        ("tag_name", "div"),
                        ("dom_id", "sync-task-cover"),
                        ("selector", "#sync-task-cover"),
                        ("dom_clickable", "true"),
                    ],
                ),
            ],
        }
        .into_accessibility();

        let merged = merge_missing_dom_fallback_nodes(ax_tree, dom_tree);
        let child_ids = merged
            .children
            .iter()
            .map(|child| child.id.as_str())
            .collect::<Vec<_>>();

        assert!(child_ids.contains(&"dom-id-sync-task-cover"));
        assert_eq!(
            child_ids
                .iter()
                .filter(|child_id| **child_id == "btn_submit")
                .count(),
            1
        );
        assert_eq!(
            merged
                .attributes
                .get("dom_fallback_overlay_count")
                .map(String::as_str),
            Some("1")
        );
    }
}
