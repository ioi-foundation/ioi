use super::*;

impl BrowserDriver {
    pub async fn get_content_frame(
        &self,
    ) -> std::result::Result<BrowserContentFrame, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        #[derive(serde::Deserialize)]
        struct FrameEval {
            x: f64,
            y: f64,
            chrome_top: f64,
            width: f64,
            height: f64,
        }

        let result: FrameEval = page
            .evaluate(
                r#"(() => ({
                    x: window.screenX || 0,
                    y: window.screenY || 0,
                    chrome_top: Math.max(0, (window.outerHeight || 0) - (window.innerHeight || 0)),
                    width: window.innerWidth || 0,
                    height: window.innerHeight || 0
                }))()"#,
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("Frame JS eval failed: {}", e)))?
            .into_value()
            .map_err(|e| BrowserError::Internal(format!("Frame JS decode failed: {}", e)))?;

        Ok(BrowserContentFrame {
            rect: GeoRect::new(
                result.x,
                result.y + result.chrome_top,
                result.width,
                result.height,
                CoordinateSpace::ScreenLogical,
            ),
            chrome_top: result.chrome_top,
        })
    }

    pub async fn get_selector_rect_window_logical(
        &self,
        selector: &str,
    ) -> std::result::Result<GeoRect, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let element = page
            .find_element(selector)
            .await
            .map_err(|e| BrowserError::Internal(format!("Element not found: {}", e)))?;

        let bounds = element
            .bounding_box()
            .await
            .map_err(|e| BrowserError::Internal(format!("Bounding box failed: {}", e)))?;

        Ok(GeoRect::new(
            bounds.x,
            bounds.y,
            bounds.width,
            bounds.height,
            CoordinateSpace::WindowLogical,
        ))
    }

    pub async fn resolve_selector_screen_point(
        &self,
        selector: &str,
    ) -> std::result::Result<Point, BrowserError> {
        let frame = self.get_content_frame().await?;
        let element_rect = self.get_selector_rect_window_logical(selector).await?;
        let center = element_rect.center();
        Ok(Point::new(
            frame.rect.x + center.x,
            frame.rect.y + center.y,
            CoordinateSpace::ScreenLogical,
        ))
    }

    pub async fn get_content_offset(&self) -> std::result::Result<(i32, i32), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let metrics = page
            .execute(GetLayoutMetricsParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to get layout metrics: {}", e)))?;

        let x = metrics.css_visual_viewport.page_x;
        let y = metrics.css_visual_viewport.page_y;

        Ok((x as i32, y as i32))
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

        let nodes_vec = p
            .execute(GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        if nodes_vec.is_empty() {
            return Err(BrowserError::Internal(
                "Empty accessibility tree returned".into(),
            ));
        }

        let root_ax = &nodes_vec[0];
        Ok(self.convert_ax_node(root_ax, &nodes_vec))
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

        Ok(self.convert_ax_node(&nodes[0], &nodes))
    }

    fn convert_ax_node(
        &self,
        ax_node: &accessibility::AxNode,
        all_nodes: &[accessibility::AxNode],
    ) -> AccessibilityNode {
        let mut children = Vec::new();
        if let Some(child_ids) = &ax_node.child_ids {
            for cid in child_ids {
                if let Some(child_ax) = all_nodes.iter().find(|n| &n.node_id == cid) {
                    children.push(self.convert_ax_node(child_ax, all_nodes));
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

        let rect = AccessibilityRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };

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
            .filter_map(|q| quad_center(q.inner().as_slice()))
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
                quad_center(model.model.border.inner().as_slice()).map(|(x, y, _)| (x, y));
        }

        let (x, y) = best_center.ok_or_else(|| {
            BrowserError::Internal(format!(
                "Element '{}' has no visible clickable geometry",
                target_cdp_id
            ))
        })?;

        self.synthetic_click(x, y).await
    }

    async fn evaluate_js<T: DeserializeOwned>(&self, script: &str) -> Result<T, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.evaluate(script)
            .await
            .map_err(|e| BrowserError::Internal(format!("JS evaluation failed: {}", e)))?
            .into_value::<T>()
            .map_err(|e| BrowserError::Internal(format!("JS decode failed: {}", e)))
    }

    fn deep_dom_helper_js() -> &'static str {
        r#"
                const deepQuerySelector = (selector) => {
                    const queue = [document];
                    const visited = new Set();
                    while (queue.length > 0) {
                        const root = queue.shift();
                        if (!root || visited.has(root)) {
                            continue;
                        }
                        visited.add(root);

                        const matchEl = root.querySelector(selector);
                        if (matchEl) {
                            return matchEl;
                        }

                        let nodes = [];
                        try {
                            nodes = root.querySelectorAll("*");
                        } catch (_e) {}

                        for (const node of nodes) {
                            if (node && node.shadowRoot) {
                                queue.push(node.shadowRoot);
                            }
                        }
                    }
                    return null;
                };

                const deepElementFromPoint = (x, y) => {
                    let current = document.elementFromPoint(x, y);
                    let guard = 0;
                    while (current && current.shadowRoot && guard < 32) {
                        const inner = current.shadowRoot.elementFromPoint(x, y);
                        if (!inner || inner === current) {
                            break;
                        }
                        current = inner;
                        guard += 1;
                    }
                    return current;
                };

                const composedContains = (ancestor, node) => {
                    if (!ancestor || !node) {
                        return false;
                    }
                    let current = node;
                    const visited = new Set();
                    while (current && !visited.has(current)) {
                        visited.add(current);
                        if (current === ancestor) {
                            return true;
                        }
                        if (typeof ancestor.contains === "function" && ancestor.contains(current)) {
                            return true;
                        }
                        const root = current.getRootNode ? current.getRootNode() : null;
                        if (root && root.host) {
                            current = root.host;
                        } else {
                            current = current.parentElement;
                        }
                    }
                    return false;
                };

                const deepActiveElement = () => {
                    let active = document.activeElement;
                    const visited = new Set();
                    while (active && !visited.has(active)) {
                        visited.add(active);
                        if (active.shadowRoot && active.shadowRoot.activeElement) {
                            active = active.shadowRoot.activeElement;
                            continue;
                        }
                        break;
                    }
                    return active;
                };
        "#
    }

    fn selector_probe_script(selector: &str) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r##"(() => {{
                const selector = {selector_json};
                const url = window.location.href || "";
                {helpers}
                const el = deepQuerySelector(selector);
                if (!el) {{
                    return {{
                        url,
                        found: false,
                        visible: false,
                        inside_viewport: false,
                        topmost: false,
                        focused: false,
                        editable: false,
                        blocked_by: null,
                        tag: "",
                        role: ""
                    }};
                }}

                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                const hasBox = rect.width > 0 && rect.height > 0;
                const inViewport =
                    hasBox &&
                    rect.bottom >= 0 &&
                    rect.right >= 0 &&
                    rect.top <= (window.innerHeight || 0) &&
                    rect.left <= (window.innerWidth || 0);
                const visible =
                    !!(
                        inViewport &&
                        style &&
                        style.visibility !== "hidden" &&
                        style.display !== "none" &&
                        parseFloat(style.opacity || "1") > 0.01
                    );

                const cx = rect.left + (rect.width / 2);
                const cy = rect.top + (rect.height / 2);
                let topEl = null;
                if (hasBox) {{
                    const maxX = Math.max(0, (window.innerWidth || 1) - 1);
                    const maxY = Math.max(0, (window.innerHeight || 1) - 1);
                    const px = Math.max(0, Math.min(maxX, cx));
                    const py = Math.max(0, Math.min(maxY, cy));
                    topEl = deepElementFromPoint(px, py);
                }}

                const topmost = !!topEl && (composedContains(el, topEl) || composedContains(topEl, el));
                const focused = deepActiveElement() === el;
                const tag = (el.tagName || "").toLowerCase();
                const role = (el.getAttribute && (el.getAttribute("role") || "").toLowerCase()) || "";
                const editable =
                    !!(
                        el.isContentEditable ||
                        tag === "input" ||
                        tag === "textarea" ||
                        tag === "select" ||
                        role === "textbox" ||
                        el.getAttribute("contenteditable") === "true"
                    );
                const blockedBy = topEl && !topmost
                    ? (topEl.id ? ("#" + topEl.id) : ((topEl.tagName || "unknown").toLowerCase()))
                    : null;

                return {{
                    url,
                    found: true,
                    visible,
                    inside_viewport: inViewport,
                    topmost,
                    focused,
                    editable,
                    blocked_by: blockedBy,
                    tag,
                    role
                }};
            }})()"##,
            selector_json = selector_json,
            helpers = helpers
        ))
    }

    pub async fn probe_selector(
        &self,
        selector: &str,
    ) -> std::result::Result<SelectorProbe, BrowserError> {
        let script = Self::selector_probe_script(selector)?;
        self.evaluate_js(&script).await
    }

    pub async fn focus_selector(&self, selector: &str) -> std::result::Result<bool, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const el = deepQuerySelector(selector);
                if (!el) return false;
                try {{
                    el.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                }} catch (_e) {{}}
                try {{
                    if (typeof el.focus === "function") {{
                        el.focus({{ preventScroll: true }});
                    }}
                }} catch (_e) {{}}
                return deepActiveElement() === el;
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    pub async fn focus_first_selector(
        &self,
        selectors: &[&str],
    ) -> std::result::Result<Option<String>, BrowserError> {
        let selectors_json = serde_json::to_string(selectors)
            .map_err(|e| BrowserError::Internal(format!("Selector list encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selectors = {selectors_json};
                {helpers}
                for (const selector of selectors) {{
                    const el = deepQuerySelector(selector);
                    if (!el) continue;

                    const style = window.getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    const visible =
                        rect.width > 0 &&
                        rect.height > 0 &&
                        style &&
                        style.visibility !== "hidden" &&
                        style.display !== "none" &&
                        parseFloat(style.opacity || "1") > 0.01;
                    if (!visible) continue;

                    try {{
                        el.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                    }} catch (_e) {{}}
                    try {{
                        if (typeof el.focus === "function") {{
                            el.focus({{ preventScroll: true }});
                        }}
                    }} catch (_e) {{}}
                    if (deepActiveElement() === el) {{
                        return selector;
                    }}
                }}
                return null;
            }})()"#,
            selectors_json = selectors_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    pub(crate) async fn click_selector_deep(
        &self,
        selector: &str,
    ) -> std::result::Result<(), BrowserError> {
        #[derive(Deserialize)]
        struct SelectorClickResult {
            found: bool,
            clicked: bool,
            reason: Option<String>,
        }

        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const el = deepQuerySelector(selector);
                if (!el) {{
                    return {{ found: false, clicked: false, reason: "not_found" }};
                }}

                try {{
                    el.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                }} catch (_e) {{}}

                const rect = el.getBoundingClientRect();
                if (!(rect.width > 0 && rect.height > 0)) {{
                    return {{ found: true, clicked: false, reason: "zero_sized_target" }};
                }}

                try {{
                    if (typeof el.click === "function") {{
                        el.click();
                    }} else {{
                        const evt = new MouseEvent("click", {{
                            bubbles: true,
                            cancelable: true,
                            composed: true
                        }});
                        el.dispatchEvent(evt);
                    }}
                    return {{ found: true, clicked: true, reason: null }};
                }} catch (e) {{
                    return {{ found: true, clicked: false, reason: String(e) }};
                }}
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        let result: SelectorClickResult = self.evaluate_js(&script).await?;
        if !result.found {
            return Err(BrowserError::Internal(format!(
                "Element '{}' not found in document or open shadow roots",
                selector
            )));
        }
        if result.clicked {
            return Ok(());
        }

        Err(BrowserError::Internal(format!(
            "Click failed for '{}': {}",
            selector,
            result.reason.unwrap_or_else(|| "unknown error".to_string())
        )))
    }

    pub async fn is_active_element_editable(&self) -> std::result::Result<bool, BrowserError> {
        let helpers = Self::deep_dom_helper_js();
        let script = [
            "(() => {\n",
            helpers,
            r#"
            const el = deepActiveElement();
            if (!el) return false;
            const tag = (el.tagName || "").toLowerCase();
            if (el.isContentEditable) return true;
            if (tag === "textarea" || tag === "select") return true;
            if (tag === "input") {
                const type = (el.getAttribute("type") || "").toLowerCase();
                const nonEditable = [
                    "button", "submit", "checkbox", "radio",
                    "range", "color", "file", "image", "reset"
                ];
                return !nonEditable.includes(type);
            }
            const role = (el.getAttribute && (el.getAttribute("role") || "").toLowerCase()) || "";
            return role === "textbox";
        })()"#,
        ]
        .concat();

        self.evaluate_js(&script).await
    }
}
