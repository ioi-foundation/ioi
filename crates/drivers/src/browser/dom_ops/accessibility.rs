use super::super::*;
use std::collections::HashSet;

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

impl DomFallbackNode {
    fn into_accessibility(self) -> AccessibilityNode {
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
            name: self.name.and_then(|v| {
                let trimmed = v.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }),
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
    async fn dom_fallback_tree(
        &self,
        page: &Page,
        cause: &str,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        let script = r#"(() => {
            const MAX_CANDIDATES = 220;
            const normalize = (value) =>
                (value || "").replace(/\s+/g, " ").trim();
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
            const elementName = (el) => {
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
                if (tag === "input") {
                    const type = normalize(el.getAttribute("type")).toLowerCase();
                    if ((type === "checkbox" || type === "radio") && !!el.checked) {
                        return { checked: "true" };
                    }
                }
                if (tag === "option" && !!el.selected) {
                    return { selected: "true" };
                }
                return null;
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

                const role = toRole(el);
                const name = elementName(el);
                const value = elementValue(el);
                const keep = isInteractive(el, role) || !!name || !!value;
                if (!keep) continue;

                const domId = normalize(el.id);
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
                    role,
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
                        tag_name: (el.tagName || "").toLowerCase(),
                        ...(focused ? { focused: "true" } : {}),
                        ...(autocomplete ? { autocomplete } : {}),
                        ...(controlsDomId ? { controls_dom_id: controlsDomId } : {}),
                        ...(activeDescendantDomId
                            ? { active_descendant_dom_id: activeDescendantDomId }
                            : {}),
                        ...(controlStateFor(el) || {}),
                        ...(scrollState || {}),
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

    pub async fn get_accessibility_tree(
        &self,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        let p = page.ok_or(BrowserError::NoActivePage)?;

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
        Ok(self.convert_ax_node(root_ax, &nodes_vec, &rect_lookup))
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
        prune_redundant_dom_fallback_aggregates, BrowserDriver, DomFallbackNode, DomFallbackRect,
    };
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
}
