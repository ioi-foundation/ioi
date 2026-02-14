use super::super::*;

impl BrowserDriver {
    pub(super) async fn evaluate_js<T: DeserializeOwned>(
        &self,
        script: &str,
    ) -> Result<T, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.evaluate(script)
            .await
            .map_err(|e| BrowserError::Internal(format!("JS evaluation failed: {}", e)))?
            .into_value::<T>()
            .map_err(|e| BrowserError::Internal(format!("JS decode failed: {}", e)))
    }

    pub(super) fn deep_dom_helper_js() -> &'static str {
        r#"
                const enqueueFrameDocument = (node, queue) => {
                    if (!node || !node.tagName || node.tagName.toLowerCase() !== "iframe") {
                        return;
                    }
                    try {
                        if (node.contentDocument) {
                            queue.push(node.contentDocument);
                        }
                    } catch (_e) {}
                };

                const elementCenterInTopWindow = (el) => {
                    if (!el || typeof el.getBoundingClientRect !== "function") {
                        return null;
                    }

                    let rect = null;
                    try {
                        rect = el.getBoundingClientRect();
                    } catch (_e) {
                        return null;
                    }

                    if (!rect || !(rect.width > 0 && rect.height > 0)) {
                        return null;
                    }

                    let cx = rect.left + (rect.width / 2);
                    let cy = rect.top + (rect.height / 2);
                    let ownerDoc = el.ownerDocument;
                    let guard = 0;
                    while (ownerDoc && guard < 32) {
                        const frameEl =
                            ownerDoc.defaultView && ownerDoc.defaultView.frameElement
                                ? ownerDoc.defaultView.frameElement
                                : null;
                        if (!frameEl) {
                            break;
                        }
                        const frameRect = frameEl.getBoundingClientRect();
                        cx += frameRect.left;
                        cy += frameRect.top;
                        ownerDoc = frameEl.ownerDocument;
                        guard += 1;
                    }

                    if (!Number.isFinite(cx) || !Number.isFinite(cy)) {
                        return null;
                    }

                    const maxX = Math.max(0, (window.innerWidth || 1) - 1);
                    const maxY = Math.max(0, (window.innerHeight || 1) - 1);
                    return {
                        x: Math.max(0, Math.min(maxX, cx)),
                        y: Math.max(0, Math.min(maxY, cy))
                    };
                };

                const isElementVisibleCandidate = (el) => {
                    if (!el || typeof el.getBoundingClientRect !== "function") {
                        return false;
                    }

                    let rect = null;
                    try {
                        rect = el.getBoundingClientRect();
                    } catch (_e) {
                        return false;
                    }

                    if (!rect || !(rect.width > 0 && rect.height > 0)) {
                        return false;
                    }

                    const ownerWin =
                        el.ownerDocument && el.ownerDocument.defaultView
                            ? el.ownerDocument.defaultView
                            : window;

                    let style = null;
                    try {
                        style = ownerWin.getComputedStyle(el);
                    } catch (_e) {}

                    if (style) {
                        if (style.visibility === "hidden" || style.display === "none") {
                            return false;
                        }
                        const opacity = parseFloat(style.opacity || "1");
                        if (!Number.isFinite(opacity) || opacity <= 0.01) {
                            return false;
                        }
                        if (style.pointerEvents === "none") {
                            return false;
                        }
                    }

                    const viewportHeight = ownerWin.innerHeight || 0;
                    const viewportWidth = ownerWin.innerWidth || 0;
                    return (
                        rect.bottom >= 0 &&
                        rect.right >= 0 &&
                        rect.top <= viewportHeight &&
                        rect.left <= viewportWidth
                    );
                };

                const isElementTopmostCandidate = (el) => {
                    const center = elementCenterInTopWindow(el);
                    if (!center) {
                        return false;
                    }
                    const topEl = deepElementFromPoint(center.x, center.y);
                    return !!topEl && (composedContains(el, topEl) || composedContains(topEl, el));
                };

                const deepQuerySelector = (selector) => {
                    const queue = [document];
                    const visited = new Set();
                    let firstMatch = null;
                    let firstVisible = null;
                    while (queue.length > 0) {
                        const root = queue.shift();
                        if (!root || visited.has(root)) {
                            continue;
                        }
                        visited.add(root);

                        let matches = [];
                        try {
                            matches = root.querySelectorAll(selector);
                        } catch (_e) {}

                        for (const candidate of matches) {
                            if (!candidate) {
                                continue;
                            }
                            if (!firstMatch) {
                                firstMatch = candidate;
                            }
                            if (isElementVisibleCandidate(candidate)) {
                                if (!firstVisible) {
                                    firstVisible = candidate;
                                }
                                if (isElementTopmostCandidate(candidate)) {
                                    return candidate;
                                }
                            }
                        }

                        let nodes = [];
                        try {
                            nodes = root.querySelectorAll("*");
                        } catch (_e) {}

                        for (const node of nodes) {
                            if (node && node.shadowRoot) {
                                queue.push(node.shadowRoot);
                            }
                            enqueueFrameDocument(node, queue);
                        }
                    }
                    if (firstVisible) {
                        return firstVisible;
                    }
                    return firstMatch;
                };

                const deepElementFromPoint = (x, y) => {
                    let doc = document;
                    let px = x;
                    let py = y;
                    let current = null;
                    let guard = 0;

                    while (doc && guard < 32) {
                        let next = null;
                        try {
                            next = doc.elementFromPoint(px, py);
                        } catch (_e) {
                            break;
                        }

                        if (!next) {
                            break;
                        }

                        current = next;

                        let shadowGuard = 0;
                        while (current && current.shadowRoot && shadowGuard < 32) {
                            const inner = current.shadowRoot.elementFromPoint(px, py);
                            if (!inner || inner === current) {
                                break;
                            }
                            current = inner;
                            shadowGuard += 1;
                        }

                        if (current && current.tagName && current.tagName.toLowerCase() === "iframe") {
                            try {
                                const frameDoc = current.contentDocument;
                                const frameRect = current.getBoundingClientRect();
                                if (!frameDoc || !frameRect) {
                                    break;
                                }
                                px = px - frameRect.left;
                                py = py - frameRect.top;
                                doc = frameDoc;
                                guard += 1;
                                continue;
                            } catch (_e) {
                                break;
                            }
                        }

                        break;
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
                            continue;
                        }

                        const ownerDoc = current.ownerDocument || (current.nodeType === 9 ? current : null);
                        const frameEl =
                            ownerDoc &&
                            ownerDoc.defaultView &&
                            ownerDoc.defaultView.frameElement
                                ? ownerDoc.defaultView.frameElement
                                : null;
                        if (frameEl) {
                            current = frameEl;
                            continue;
                        }

                        current = current.parentElement;
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
                        if (active.tagName && active.tagName.toLowerCase() === "iframe") {
                            try {
                                if (active.contentDocument && active.contentDocument.activeElement) {
                                    active = active.contentDocument.activeElement;
                                    continue;
                                }
                            } catch (_e) {}
                        }
                        break;
                    }
                    return active;
                };
        "#
    }

    pub(super) fn selector_probe_script(selector: &str) -> Result<String, BrowserError> {
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

    pub(super) fn selector_rect_script(selector: &str) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const el = deepQuerySelector(selector);
                if (!el) {{
                    return {{
                        found: false,
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                        reason: "not_found"
                    }};
                }}

                const rect = el.getBoundingClientRect();
                if (!rect) {{
                    return {{
                        found: true,
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                        reason: "missing_bounding_client_rect"
                    }};
                }}

                let frameOffsetX = 0;
                let frameOffsetY = 0;
                let ownerDoc = el.ownerDocument;
                let guard = 0;
                while (ownerDoc && guard < 32) {{
                    const frameEl =
                        ownerDoc.defaultView && ownerDoc.defaultView.frameElement
                            ? ownerDoc.defaultView.frameElement
                            : null;
                    if (!frameEl) {{
                        break;
                    }}

                    const frameRect = frameEl.getBoundingClientRect();
                    frameOffsetX += frameRect.left;
                    frameOffsetY += frameRect.top;
                    ownerDoc = frameEl.ownerDocument;
                    guard += 1;
                }}

                return {{
                    found: true,
                    x: rect.left + frameOffsetX,
                    y: rect.top + frameOffsetY,
                    width: rect.width,
                    height: rect.height,
                    reason: null
                }};
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::BrowserDriver;

    #[test]
    fn deep_dom_helpers_include_iframe_traversal() {
        let helpers = BrowserDriver::deep_dom_helper_js();
        assert!(helpers.contains("enqueueFrameDocument"));
        assert!(helpers.contains("contentDocument"));
        assert!(helpers.contains("frameElement"));
    }

    #[test]
    fn selector_rect_script_accumulates_iframe_offsets() {
        let script = BrowserDriver::selector_rect_script("button.primary")
            .expect("selector rect script should serialize selector");
        assert!(script.contains("deepQuerySelector(selector)"));
        assert!(script.contains("frameOffsetX"));
        assert!(script.contains("frameElement"));
        assert!(script.contains("getBoundingClientRect"));
    }

    #[test]
    fn deep_dom_helpers_rank_visible_topmost_matches() {
        let helpers = BrowserDriver::deep_dom_helper_js();
        assert!(helpers.contains("isElementVisibleCandidate"));
        assert!(helpers.contains("isElementTopmostCandidate"));
        assert!(helpers.contains("querySelectorAll(selector)"));
        assert!(helpers.contains("return firstVisible"));
    }
}
