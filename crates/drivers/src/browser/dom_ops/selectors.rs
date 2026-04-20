use super::super::*;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use image::{load_from_memory, RgbaImage};

#[derive(Deserialize)]
struct CanvasRasterReadback {
    found: bool,
    target_kind: String,
    width: u32,
    height: u32,
    data_url: Option<String>,
    error: Option<String>,
}

impl BrowserDriver {
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

    pub async fn is_selector_hovered(
        &self,
        selector: &str,
    ) -> std::result::Result<bool, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const el = deepQuerySelector(selector);
                if (!el || typeof el.matches !== "function") {{
                    return false;
                }}
                try {{
                    return !!el.matches(":hover");
                }} catch (_e) {{
                    return false;
                }}
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    pub async fn selector_texts(
        &self,
        selector: &str,
    ) -> std::result::Result<Vec<String>, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const normalizeText = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const queue = [document];
                const visited = new Set();
                const texts = [];
                while (queue.length > 0) {{
                    const root = queue.shift();
                    if (!root || visited.has(root)) {{
                        continue;
                    }}
                    visited.add(root);

                    let matches = [];
                    try {{
                        matches = root.querySelectorAll(selector);
                    }} catch (_e) {{}}

                    for (const candidate of matches) {{
                        if (!candidate || !isElementVisibleCandidate(candidate)) {{
                            continue;
                        }}
                        const text = normalizeText(candidate.innerText || candidate.textContent || "");
                        if (text) {{
                            texts.push(text);
                        }}
                    }}

                    let nodes = [];
                    try {{
                        nodes = root.querySelectorAll("*");
                    }} catch (_e) {{}}

                    for (const node of nodes) {{
                        if (node && node.shadowRoot) {{
                            queue.push(node.shadowRoot);
                        }}
                        enqueueFrameDocument(node, queue);
                    }}
                }}
                return texts;
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    pub async fn selector_text(
        &self,
        selector: &str,
    ) -> std::result::Result<Option<String>, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const normalizeText = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const candidate = deepQuerySelector(selector);
                if (!candidate) {{
                    return null;
                }}
                const text = normalizeText(candidate.innerText || candidate.textContent || "");
                return text.length > 0 ? text : null;
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    pub async fn selector_texts_all(
        &self,
        selector: &str,
    ) -> std::result::Result<Vec<String>, BrowserError> {
        let script = Self::selector_texts_all_script(selector)?;
        self.evaluate_js(&script).await
    }

    fn selector_texts_all_script(selector: &str) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const normalizeText = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const queue = [document];
                const visited = new Set();
                const texts = [];
                while (queue.length > 0) {{
                    const root = queue.shift();
                    if (!root || visited.has(root)) {{
                        continue;
                    }}
                    visited.add(root);

                    let matches = [];
                    try {{
                        matches = root.querySelectorAll(selector);
                    }} catch (_e) {{}}

                    for (const candidate of matches) {{
                        if (!candidate) {{
                            continue;
                        }}
                        const text = normalizeText(candidate.innerText || candidate.textContent || "");
                        if (text) {{
                            texts.push(text);
                        }}
                    }}

                    let nodes = [];
                    try {{
                        nodes = root.querySelectorAll("*");
                    }} catch (_e) {{}}

                    for (const node of nodes) {{
                        if (node && node.shadowRoot) {{
                            queue.push(node.shadowRoot);
                        }}
                        enqueueFrameDocument(node, queue);
                    }}
                }}
                return texts;
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        ))
    }

    pub async fn selector_elements(
        &self,
        selector: &str,
    ) -> std::result::Result<Vec<BrowserDomElementSummary>, BrowserError> {
        let script = Self::selector_elements_script(selector)?;
        self.evaluate_js(&script).await
    }

    pub async fn selector_canvas_shape_summary(
        &self,
        selector: &str,
    ) -> std::result::Result<BrowserCanvasShapeSummary, BrowserError> {
        let script = Self::selector_canvas_raster_script(selector)?;
        let readback: CanvasRasterReadback = self.evaluate_js(&script).await?;
        Ok(analyze_canvas_readback(readback))
    }

    fn selector_elements_script(selector: &str) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const normalizeText = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const queue = [document];
                const visited = new Set();
                const summaries = [];

                const summarize = (candidate) => {{
                    let rect = null;
                    try {{
                        rect = candidate.getBoundingClientRect();
                    }} catch (_e) {{}}

                    const attributes = {{}};
                    try {{
                        const names =
                            typeof candidate.getAttributeNames === "function"
                                ? candidate.getAttributeNames()
                                : [];
                        for (const name of names) {{
                            const value = candidate.getAttribute(name);
                            attributes[name] = value === null ? "" : String(value);
                        }}
                    }} catch (_e) {{}}

                    const center = elementCenterInTopWindow(candidate);
                    const tag = String(candidate.tagName || "").toLowerCase();
                    if (!attributes.value && typeof candidate.value === "string") {{
                        attributes.value = String(candidate.value);
                    }}

                    return {{
                        tag,
                        text: normalizeText(candidate.innerText || candidate.textContent || ""),
                        visible: isElementVisibleCandidate(candidate),
                        attributes,
                        x: rect && Number.isFinite(rect.left) ? rect.left : 0,
                        y: rect && Number.isFinite(rect.top) ? rect.top : 0,
                        width: rect && Number.isFinite(rect.width) ? rect.width : 0,
                        height: rect && Number.isFinite(rect.height) ? rect.height : 0,
                        center_x: center && Number.isFinite(center.x)
                            ? center.x
                            : (rect && Number.isFinite(rect.left) && Number.isFinite(rect.width)
                                ? rect.left + rect.width / 2
                                : 0),
                        center_y: center && Number.isFinite(center.y)
                            ? center.y
                            : (rect && Number.isFinite(rect.top) && Number.isFinite(rect.height)
                                ? rect.top + rect.height / 2
                                : 0)
                    }};
                }};

                while (queue.length > 0) {{
                    const root = queue.shift();
                    if (!root || visited.has(root)) {{
                        continue;
                    }}
                    visited.add(root);

                    let matches = [];
                    try {{
                        matches = root.querySelectorAll(selector);
                    }} catch (_e) {{}}

                    for (const candidate of matches) {{
                        if (!candidate) {{
                            continue;
                        }}
                        summaries.push(summarize(candidate));
                    }}

                    let nodes = [];
                    try {{
                        nodes = root.querySelectorAll("*");
                    }} catch (_e) {{}}

                    for (const node of nodes) {{
                        if (node && node.shadowRoot) {{
                            queue.push(node.shadowRoot);
                        }}
                        enqueueFrameDocument(node, queue);
                    }}
                }}
                return summaries;
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        ))
    }

    fn selector_canvas_raster_script(selector: &str) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const target = deepQuerySelector(selector);
                if (!target) {{
                    return {{
                        found: false,
                        target_kind: "none",
                        width: 0,
                        height: 0,
                        data_url: null,
                        error: null
                    }};
                }}

                const targetTag = String(target.tagName || "").toLowerCase();
                const canvas =
                    targetTag === "canvas"
                        ? target
                        : (typeof target.querySelector === "function"
                            ? target.querySelector("canvas")
                            : null);
                if (!canvas || typeof canvas.toDataURL !== "function") {{
                    return {{
                        found: true,
                        target_kind: targetTag,
                        width: 0,
                        height: 0,
                        data_url: null,
                        error: "selector did not resolve to a readable canvas"
                    }};
                }}

                try {{
                    return {{
                        found: true,
                        target_kind: "canvas",
                        width: Number.isFinite(canvas.width) ? canvas.width : 0,
                        height: Number.isFinite(canvas.height) ? canvas.height : 0,
                        data_url: canvas.toDataURL("image/png"),
                        error: null
                    }};
                }} catch (error) {{
                    return {{
                        found: true,
                        target_kind: "canvas",
                        width: Number.isFinite(canvas.width) ? canvas.width : 0,
                        height: Number.isFinite(canvas.height) ? canvas.height : 0,
                        data_url: null,
                        error: String(error)
                    }};
                }}
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        ))
    }

    pub async fn select_text(
        &self,
        selector: Option<&str>,
        start_offset: Option<u32>,
        end_offset: Option<u32>,
    ) -> std::result::Result<BrowserSelectionResult, BrowserError> {
        let script = Self::select_text_script(selector, start_offset, end_offset)?;
        self.evaluate_js(&script).await
    }

    pub async fn read_selection(
        &self,
    ) -> std::result::Result<BrowserSelectionResult, BrowserError> {
        let script = Self::read_selection_script();
        self.evaluate_js(&script).await
    }

    pub async fn focus_first_selector(
        &self,
        selectors: &[&str],
    ) -> std::result::Result<Option<String>, BrowserError> {
        let script = Self::focus_first_selector_script(selectors)?;

        self.evaluate_js(&script).await
    }

    fn focus_first_selector_script(selectors: &[&str]) -> Result<String, BrowserError> {
        let selectors_json = serde_json::to_string(selectors)
            .map_err(|e| BrowserError::Internal(format!("Selector list encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selectors = {selectors_json};
                {helpers}
                for (const selector of selectors) {{
                    const el = deepQuerySelector(selector);
                    if (!el) continue;
                    if (!isElementVisibleCandidate(el)) continue;

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
        ))
    }

    fn select_text_script(
        selector: Option<&str>,
        start_offset: Option<u32>,
        end_offset: Option<u32>,
    ) -> Result<String, BrowserError> {
        let selector_json = serde_json::to_string(&selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let start_offset_json = serde_json::to_string(&start_offset)
            .map_err(|e| BrowserError::Internal(format!("Start offset encode failed: {}", e)))?;
        let end_offset_json = serde_json::to_string(&end_offset)
            .map_err(|e| BrowserError::Internal(format!("End offset encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();

        Ok(format!(
            r#"(() => {{
                const selector = {selector_json};
                const requestedStart = {start_offset_json};
                const requestedEnd = {end_offset_json};
                {helpers}

                const emptyResult = {{
                    found: false,
                    target_kind: "none",
                    selected_text: "",
                    start_offset: 0,
                    end_offset: 0,
                    text_length: 0,
                    focused: false,
                    collapsed: true
                }};

                const clampOffset = (value, max) => {{
                    if (typeof value !== "number" || !Number.isFinite(value)) {{
                        return 0;
                    }}
                    return Math.max(0, Math.min(max, Math.trunc(value)));
                }};

                const collectTextSegments = (root) => {{
                    const ownerDoc = root && root.ownerDocument ? root.ownerDocument : document;
                    const ownerWin = ownerDoc && ownerDoc.defaultView ? ownerDoc.defaultView : window;
                    const nodeFilter = ownerWin.NodeFilter || window.NodeFilter;
                    const walker = ownerDoc.createTreeWalker(root, nodeFilter.SHOW_TEXT, {{
                        acceptNode(node) {{
                            const text = String((node && node.nodeValue) || "");
                            return text.length > 0
                                ? nodeFilter.FILTER_ACCEPT
                                : nodeFilter.FILTER_REJECT;
                        }}
                    }});

                    const segments = [];
                    let totalLength = 0;
                    let current = walker.nextNode();
                    while (current) {{
                        const text = String(current.nodeValue || "");
                        segments.push({{
                            node: current,
                            start: totalLength,
                            end: totalLength + text.length,
                            text_length: text.length
                        }});
                        totalLength += text.length;
                        current = walker.nextNode();
                    }}
                    return {{ segments, totalLength }};
                }};

                const resolveBoundary = (segments, offset, preferEnd) => {{
                    if (!segments.length) {{
                        return null;
                    }}
                    if (offset <= 0) {{
                        return {{ node: segments[0].node, offset: 0 }};
                    }}
                    for (const segment of segments) {{
                        if (offset < segment.end || (preferEnd && offset === segment.end)) {{
                            return {{
                                node: segment.node,
                                offset: Math.max(0, Math.min(segment.text_length, offset - segment.start))
                            }};
                        }}
                    }}
                    const last = segments[segments.length - 1];
                    return {{ node: last.node, offset: last.text_length }};
                }};

                const target = selector ? deepQuerySelector(selector) : deepActiveElement();
                if (!target) {{
                    return emptyResult;
                }}

                try {{
                    target.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                }} catch (_e) {{}}
                try {{
                    if (typeof target.focus === "function") {{
                        target.focus({{ preventScroll: true }});
                    }}
                }} catch (_e) {{}}

                const focused = deepActiveElement() === target;
                const tag = String(target.tagName || "").toLowerCase();
                if (tag === "textarea" || tag === "input") {{
                    const value = String(target.value || "");
                    const textLength = value.length;
                    const start = clampOffset(
                        requestedStart === null ? 0 : requestedStart,
                        textLength
                    );
                    const defaultEnd = requestedEnd === null ? textLength : requestedEnd;
                    const end = Math.max(start, clampOffset(defaultEnd, textLength));
                    try {{
                        if (typeof target.setSelectionRange === "function") {{
                            target.setSelectionRange(start, end, "forward");
                        }}
                    }} catch (_e) {{}}

                    const actualStart =
                        typeof target.selectionStart === "number" ? target.selectionStart : start;
                    const actualEnd =
                        typeof target.selectionEnd === "number" ? target.selectionEnd : end;

                    return {{
                        found: true,
                        target_kind: tag,
                        selected_text: value.slice(actualStart, actualEnd),
                        start_offset: actualStart,
                        end_offset: actualEnd,
                        text_length: textLength,
                        focused,
                        collapsed: actualStart === actualEnd
                    }};
                }}

                const ownerDoc = target.ownerDocument || document;
                const ownerWin = ownerDoc && ownerDoc.defaultView ? ownerDoc.defaultView : window;
                const selection = ownerWin.getSelection ? ownerWin.getSelection() : null;
                if (!selection) {{
                    return {{
                        found: true,
                        target_kind: "dom",
                        selected_text: "",
                        start_offset: 0,
                        end_offset: 0,
                        text_length: 0,
                        focused,
                        collapsed: true
                    }};
                }}

                const {{ segments, totalLength }} = collectTextSegments(target);
                const start = clampOffset(
                    requestedStart === null ? 0 : requestedStart,
                    totalLength
                );
                const defaultEnd = requestedEnd === null ? totalLength : requestedEnd;
                const end = Math.max(start, clampOffset(defaultEnd, totalLength));

                if (!segments.length) {{
                    try {{
                        const range = ownerDoc.createRange();
                        range.selectNodeContents(target);
                        selection.removeAllRanges();
                        selection.addRange(range);
                    }} catch (_e) {{}}
                    const selectedText = selection.toString();
                    return {{
                        found: true,
                        target_kind: "dom",
                        selected_text: selectedText,
                        start_offset: 0,
                        end_offset: selectedText.length,
                        text_length: selectedText.length,
                        focused,
                        collapsed: selectedText.length === 0
                    }};
                }}

                const startBoundary = resolveBoundary(segments, start, false);
                const endBoundary = resolveBoundary(segments, end, true);
                if (!startBoundary || !endBoundary) {{
                    return {{
                        found: true,
                        target_kind: "dom",
                        selected_text: "",
                        start_offset: start,
                        end_offset: end,
                        text_length: totalLength,
                        focused,
                        collapsed: true
                    }};
                }}

                try {{
                    const range = ownerDoc.createRange();
                    range.setStart(startBoundary.node, startBoundary.offset);
                    range.setEnd(endBoundary.node, endBoundary.offset);
                    selection.removeAllRanges();
                    selection.addRange(range);
                }} catch (_e) {{}}

                return {{
                    found: true,
                    target_kind: "dom",
                    selected_text: selection.toString(),
                    start_offset: start,
                    end_offset: end,
                    text_length: totalLength,
                    focused,
                    collapsed: selection.isCollapsed
                }};
            }})()"#,
            selector_json = selector_json,
            start_offset_json = start_offset_json,
            end_offset_json = end_offset_json,
            helpers = helpers
        ))
    }

    fn read_selection_script() -> String {
        let helpers = Self::deep_dom_helper_js();

        format!(
            r#"(() => {{
                {helpers}

                const emptyResult = {{
                    found: false,
                    target_kind: "none",
                    selected_text: "",
                    start_offset: 0,
                    end_offset: 0,
                    text_length: 0,
                    focused: false,
                    collapsed: true
                }};

                const snapshotEditableSelection = (el) => {{
                    if (!el) {{
                        return null;
                    }}
                    const tag = String(el.tagName || "").toLowerCase();
                    if (tag !== "textarea" && tag !== "input") {{
                        return null;
                    }}
                    const value = String(el.value || "");
                    const start =
                        typeof el.selectionStart === "number" ? el.selectionStart : 0;
                    const end = typeof el.selectionEnd === "number" ? el.selectionEnd : start;
                    return {{
                        found: true,
                        target_kind: tag,
                        selected_text: value.slice(start, end),
                        start_offset: start,
                        end_offset: end,
                        text_length: value.length,
                        focused: deepActiveElement() === el,
                        collapsed: start === end
                    }};
                }};

                const activeSelection = snapshotEditableSelection(deepActiveElement());
                if (activeSelection && (!activeSelection.collapsed || activeSelection.text_length > 0)) {{
                    return activeSelection;
                }}

                const queue = [document];
                const visited = new Set();
                while (queue.length > 0) {{
                    const root = queue.shift();
                    if (!root || visited.has(root)) {{
                        continue;
                    }}
                    visited.add(root);

                    const ownerWin = root.defaultView || window;
                    const selection = ownerWin.getSelection ? ownerWin.getSelection() : null;
                    if (selection && selection.rangeCount > 0) {{
                        const selectedText = selection.toString();
                        if (selectedText.length > 0 || !selection.isCollapsed) {{
                            return {{
                                found: true,
                                target_kind: "dom",
                                selected_text: selectedText,
                                start_offset: 0,
                                end_offset: selectedText.length,
                                text_length: selectedText.length,
                                focused: false,
                                collapsed: selection.isCollapsed
                            }};
                        }}
                    }}

                    let nodes = [];
                    try {{
                        nodes = root.querySelectorAll("*");
                    }} catch (_e) {{}}

                    for (const node of nodes) {{
                        enqueueFrameDocument(node, queue);
                    }}
                }}

                return activeSelection || emptyResult;
            }})()"#,
            helpers = helpers
        )
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
            return isElementEditable(el);
        })()"#,
        ]
        .concat();

        self.evaluate_js(&script).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CanvasPoint {
    x: i32,
    y: i32,
}

fn analyze_canvas_readback(readback: CanvasRasterReadback) -> BrowserCanvasShapeSummary {
    let empty = || BrowserCanvasShapeSummary {
        found: readback.found,
        readable: false,
        target_kind: readback.target_kind.clone(),
        width: readback.width,
        height: readback.height,
        dark_pixel_count: 0,
        component_count: 0,
        dominant_component_pixels: 0,
        dominant_component_ratio: 0.0,
        bounding_box_x: 0,
        bounding_box_y: 0,
        bounding_box_width: 0,
        bounding_box_height: 0,
        convex_hull_vertices: 0,
        estimated_sides: None,
        analysis_error: readback.error.clone(),
    };

    if !readback.found {
        return empty();
    }

    let Some(data_url) = readback.data_url.as_deref() else {
        return empty();
    };
    let png_bytes = match decode_png_data_url(data_url) {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut summary = empty();
            summary.analysis_error = Some(error);
            return summary;
        }
    };
    let image = match load_from_memory(&png_bytes) {
        Ok(image) => image.to_rgba8(),
        Err(error) => {
            let mut summary = empty();
            summary.analysis_error = Some(format!("canvas PNG decode failed: {}", error));
            return summary;
        }
    };

    analyze_canvas_shape_image(
        &image,
        BrowserCanvasShapeSummary {
            found: true,
            readable: true,
            target_kind: readback.target_kind,
            width: readback.width,
            height: readback.height,
            dark_pixel_count: 0,
            component_count: 0,
            dominant_component_pixels: 0,
            dominant_component_ratio: 0.0,
            bounding_box_x: 0,
            bounding_box_y: 0,
            bounding_box_width: 0,
            bounding_box_height: 0,
            convex_hull_vertices: 0,
            estimated_sides: None,
            analysis_error: None,
        },
    )
}

fn decode_png_data_url(data_url: &str) -> Result<Vec<u8>, String> {
    let encoded = data_url
        .strip_prefix("data:image/png;base64,")
        .ok_or_else(|| "canvas data URL was not PNG/base64".to_string())?;
    BASE64_STANDARD
        .decode(encoded)
        .map_err(|error| format!("canvas base64 decode failed: {}", error))
}

fn analyze_canvas_shape_image(
    image: &RgbaImage,
    mut summary: BrowserCanvasShapeSummary,
) -> BrowserCanvasShapeSummary {
    let width = image.width();
    let height = image.height();
    let mask = build_dark_pixel_mask(image);
    let dark_pixel_count = mask.iter().filter(|pixel| **pixel).count();
    summary.dark_pixel_count = dark_pixel_count as u32;
    if dark_pixel_count == 0 {
        summary.readable = false;
        summary.analysis_error = Some("canvas contained no dark foreground pixels".to_string());
        return summary;
    }

    let (component_count, dominant_points, bbox) = dominant_dark_component(&mask, width, height);
    summary.component_count = component_count as u32;
    summary.dominant_component_pixels = dominant_points.len() as u32;
    summary.dominant_component_ratio = dominant_points.len() as f64 / dark_pixel_count as f64;
    if let Some((x0, y0, x1, y1)) = bbox {
        summary.bounding_box_x = x0;
        summary.bounding_box_y = y0;
        summary.bounding_box_width = x1.saturating_sub(x0).saturating_add(1);
        summary.bounding_box_height = y1.saturating_sub(y0).saturating_add(1);
    }
    if dominant_points.len() < 3 {
        summary.readable = false;
        summary.analysis_error =
            Some("canvas dominant component had fewer than 3 pixels".to_string());
        return summary;
    }

    let hull = convex_hull(&dominant_points);
    summary.convex_hull_vertices = hull.len() as u32;
    if hull.len() < 3 {
        summary.readable = false;
        summary.analysis_error = Some("canvas convex hull was degenerate".to_string());
        return summary;
    }

    let bbox_span = summary
        .bounding_box_width
        .max(summary.bounding_box_height)
        .max(1) as f64;
    let epsilon = (bbox_span * 0.035).clamp(1.5, 5.0);
    let simplified = simplify_convex_hull(hull, epsilon, 168.0);
    let simplified = if simplified.len() > 7 {
        simplify_convex_hull(simplified, epsilon * 1.35, 160.0)
    } else {
        simplified
    };

    let radial_estimate = estimate_polygon_side_count(&dominant_points, bbox_span);
    let hull_estimate = (3..=12)
        .contains(&simplified.len())
        .then_some(simplified.len() as u32);
    let estimated_sides = match (radial_estimate, hull_estimate) {
        (Some(radial), Some(hull)) if hull > radial && hull % radial == 0 => Some(hull),
        (Some(radial), _) => Some(radial),
        (None, Some(hull)) => Some(hull),
        (None, None) => None,
    };

    if let Some(estimated_sides) = estimated_sides {
        summary.estimated_sides = Some(estimated_sides);
    } else {
        summary.analysis_error = Some(format!(
            "canvas polygon simplification was inconclusive ({} vertices)",
            simplified.len()
        ));
    }

    summary
}

fn build_dark_pixel_mask(image: &RgbaImage) -> Vec<bool> {
    image
        .pixels()
        .map(|pixel| {
            let [r, g, b, a] = pixel.0;
            if a <= 16 {
                return false;
            }
            let luminance = 0.2126 * f64::from(r) + 0.7152 * f64::from(g) + 0.0722 * f64::from(b);
            luminance <= 240.0
        })
        .collect()
}

fn dominant_dark_component(
    mask: &[bool],
    width: u32,
    height: u32,
) -> (usize, Vec<CanvasPoint>, Option<(u32, u32, u32, u32)>) {
    let width_usize = width as usize;
    let height_usize = height as usize;
    let mut visited = vec![false; mask.len()];
    let mut component_count = 0usize;
    let mut largest_points = Vec::new();
    let mut largest_bbox = None;

    for y in 0..height_usize {
        for x in 0..width_usize {
            let index = y * width_usize + x;
            if !mask.get(index).copied().unwrap_or(false) || visited[index] {
                continue;
            }

            component_count += 1;
            let mut queue = std::collections::VecDeque::from([(x as i32, y as i32)]);
            visited[index] = true;
            let mut points = Vec::new();
            let mut min_x = x as u32;
            let mut min_y = y as u32;
            let mut max_x = x as u32;
            let mut max_y = y as u32;

            while let Some((cx, cy)) = queue.pop_front() {
                points.push(CanvasPoint { x: cx, y: cy });
                min_x = min_x.min(cx as u32);
                min_y = min_y.min(cy as u32);
                max_x = max_x.max(cx as u32);
                max_y = max_y.max(cy as u32);

                for delta_y in -1..=1 {
                    for delta_x in -1..=1 {
                        if delta_x == 0 && delta_y == 0 {
                            continue;
                        }
                        let nx = cx + delta_x;
                        let ny = cy + delta_y;
                        if nx < 0 || ny < 0 || nx >= width as i32 || ny >= height as i32 {
                            continue;
                        }
                        let neighbor_index = ny as usize * width_usize + nx as usize;
                        if visited[neighbor_index]
                            || !mask.get(neighbor_index).copied().unwrap_or(false)
                        {
                            continue;
                        }
                        visited[neighbor_index] = true;
                        queue.push_back((nx, ny));
                    }
                }
            }

            if points.len() > largest_points.len() {
                largest_bbox = Some((min_x, min_y, max_x, max_y));
                largest_points = points;
            }
        }
    }

    (component_count, largest_points, largest_bbox)
}

fn convex_hull(points: &[CanvasPoint]) -> Vec<CanvasPoint> {
    let mut sorted = points.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() <= 1 {
        return sorted;
    }

    let mut lower = Vec::new();
    for point in &sorted {
        while lower.len() >= 2 && cross(lower[lower.len() - 2], lower[lower.len() - 1], *point) <= 0
        {
            lower.pop();
        }
        lower.push(*point);
    }

    let mut upper = Vec::new();
    for point in sorted.iter().rev() {
        while upper.len() >= 2 && cross(upper[upper.len() - 2], upper[upper.len() - 1], *point) <= 0
        {
            upper.pop();
        }
        upper.push(*point);
    }

    lower.pop();
    upper.pop();
    lower.extend(upper);
    lower
}

fn simplify_convex_hull(
    mut hull: Vec<CanvasPoint>,
    epsilon: f64,
    angle_threshold: f64,
) -> Vec<CanvasPoint> {
    let mut iterations = 0usize;
    while hull.len() > 3 && iterations < 256 {
        iterations += 1;
        let mut removed = false;
        for index in 0..hull.len() {
            let len = hull.len();
            let prev = hull[(index + len - 1) % len];
            let current = hull[index];
            let next = hull[(index + 1) % len];
            let prev_edge = point_distance(prev, current);
            let next_edge = point_distance(current, next);
            let angle = interior_angle(prev, current, next);
            let distance = point_line_distance(current, prev, next);
            if prev_edge <= 1.25
                || next_edge <= 1.25
                || distance <= epsilon
                || angle >= angle_threshold
            {
                hull.remove(index);
                removed = true;
                break;
            }
        }
        if !removed {
            break;
        }
    }
    hull
}

fn cross(origin: CanvasPoint, a: CanvasPoint, b: CanvasPoint) -> i64 {
    i64::from(a.x - origin.x) * i64::from(b.y - origin.y)
        - i64::from(a.y - origin.y) * i64::from(b.x - origin.x)
}

fn point_distance(a: CanvasPoint, b: CanvasPoint) -> f64 {
    let delta_x = f64::from(a.x - b.x);
    let delta_y = f64::from(a.y - b.y);
    (delta_x * delta_x + delta_y * delta_y).sqrt()
}

fn point_line_distance(point: CanvasPoint, line_a: CanvasPoint, line_b: CanvasPoint) -> f64 {
    if line_a == line_b {
        return point_distance(point, line_a);
    }

    let ax = f64::from(line_a.x);
    let ay = f64::from(line_a.y);
    let bx = f64::from(line_b.x);
    let by = f64::from(line_b.y);
    let px = f64::from(point.x);
    let py = f64::from(point.y);

    let numerator = ((by - ay) * px - (bx - ax) * py + bx * ay - by * ax).abs();
    let denominator = ((by - ay).powi(2) + (bx - ax).powi(2)).sqrt();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn interior_angle(prev: CanvasPoint, current: CanvasPoint, next: CanvasPoint) -> f64 {
    let ax = f64::from(prev.x - current.x);
    let ay = f64::from(prev.y - current.y);
    let bx = f64::from(next.x - current.x);
    let by = f64::from(next.y - current.y);
    let denominator = (ax * ax + ay * ay).sqrt() * (bx * bx + by * by).sqrt();
    if denominator == 0.0 {
        return 180.0;
    }
    let cosine = ((ax * bx + ay * by) / denominator).clamp(-1.0, 1.0);
    cosine.acos().to_degrees()
}

fn estimate_polygon_side_count(points: &[CanvasPoint], _bbox_span: f64) -> Option<u32> {
    if points.len() < 3 {
        return None;
    }

    let centroid_x =
        points.iter().map(|point| f64::from(point.x)).sum::<f64>() / points.len() as f64;
    let centroid_y =
        points.iter().map(|point| f64::from(point.y)).sum::<f64>() / points.len() as f64;
    let bin_count = 420usize;
    let mut profile = vec![0.0_f64; bin_count];

    for point in points {
        let delta_x = f64::from(point.x) - centroid_x;
        let delta_y = f64::from(point.y) - centroid_y;
        let angle = delta_y.atan2(delta_x);
        let normalized = (angle + std::f64::consts::PI) / (2.0 * std::f64::consts::PI);
        let index = ((normalized * bin_count as f64).floor() as usize) % bin_count;
        let radius = (delta_x * delta_x + delta_y * delta_y).sqrt();
        profile[index] = profile[index].max(radius);
    }

    fill_radial_profile_gaps(&mut profile);
    let smoothed = circular_moving_average(&profile, 4);
    let mean = smoothed.iter().sum::<f64>() / smoothed.len() as f64;
    let centered = smoothed
        .iter()
        .map(|value| value - mean)
        .collect::<Vec<_>>();
    let energy = centered.iter().map(|value| value * value).sum::<f64>();
    if energy <= f64::EPSILON {
        return None;
    }
    let mut best = None;
    let mut second_best = 0.0;

    for candidate in 3..=12usize {
        let shift = ((bin_count as f64) / candidate as f64).round() as usize;
        if shift == 0 || shift >= bin_count {
            continue;
        }

        let mut dot = 0.0;
        for index in 0..bin_count {
            dot += centered[index] * centered[(index + shift) % bin_count];
        }
        let score = dot / energy;
        if let Some((_, best_score)) = best {
            if score > best_score {
                second_best = best_score;
                best = Some((candidate as u32, score));
            } else if score > second_best {
                second_best = score;
            }
        } else {
            best = Some((candidate as u32, score));
        }
    }

    let (candidate, score) = best?;
    if score >= 0.70 || score - second_best >= 0.05 {
        Some(candidate)
    } else {
        None
    }
}

fn fill_radial_profile_gaps(profile: &mut [f64]) {
    if profile.is_empty() {
        return;
    }
    let Some(first_nonzero) = profile.iter().copied().find(|value| *value > 0.0) else {
        return;
    };

    let mut last_value = first_nonzero;
    for value in profile.iter_mut() {
        if *value > 0.0 {
            last_value = *value;
        } else {
            *value = last_value;
        }
    }

    let mut trailing_value = *profile.last().unwrap_or(&first_nonzero);
    for value in profile.iter_mut().rev() {
        if *value > 0.0 {
            trailing_value = *value;
        } else {
            *value = trailing_value;
        }
    }
}

fn circular_moving_average(values: &[f64], radius: usize) -> Vec<f64> {
    let len = values.len();
    if len == 0 {
        return Vec::new();
    }
    (0..len)
        .map(|index| {
            let mut sum = 0.0;
            let mut count = 0usize;
            for offset in -(radius as isize)..=(radius as isize) {
                let position = (index as isize + offset).rem_euclid(len as isize) as usize;
                sum += values[position];
                count += 1;
            }
            sum / count as f64
        })
        .collect()
}

#[cfg(test)]
#[path = "selectors/tests.rs"]
mod tests;
