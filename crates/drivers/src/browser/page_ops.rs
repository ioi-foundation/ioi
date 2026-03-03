use super::*;
use chromiumoxide::cdp::browser_protocol::dom::{
    BackendNodeId, GetDocumentParams, QuerySelectorParams, SetFileInputFilesParams,
};
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, InsertTextParams,
};
use chromiumoxide::cdp::browser_protocol::page::{
    GetNavigationHistoryParams, NavigateToHistoryEntryParams,
};
use chromiumoxide::keys;
use std::time::Instant;

impl BrowserDriver {
    pub async fn navigate(&self, url: &str) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        if let Some(p) = page {
            p.bring_to_front()
                .await
                .map_err(|e| BrowserError::Internal(e.to_string()))?;

            self.check_connection_error(p.goto(url).await)
                .await?
                .wait_for_navigation()
                .await
                .map_err(|e| BrowserError::NavigateFailed {
                    url: url.into(),
                    details: e.to_string(),
                })?;

            let content = self.check_connection_error(p.content().await).await?;
            Ok(content)
        } else {
            Err(BrowserError::NoActivePage)
        }
    }

    /// Navigate a dedicated background page used for deterministic retrieval operations.
    ///
    /// This intentionally does not call `bring_to_front()` so it won't steal focus from
    /// the user's active application window.
    pub async fn navigate_retrieval(&self, url: &str) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_retrieval_page().await?;

        let page = { self.retrieval_page.lock().await.clone() };
        if let Some(p) = page {
            self.check_connection_error(p.goto(url).await)
                .await?
                .wait_for_navigation()
                .await
                .map_err(|e| BrowserError::NavigateFailed {
                    url: url.into(),
                    details: e.to_string(),
                })?;

            let content = self.check_connection_error(p.content().await).await?;
            Ok(content)
        } else {
            Err(BrowserError::NoActivePage)
        }
    }

    pub async fn extract_dom(&self) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        if let Some(p) = page {
            self.check_connection_error(p.content().await).await
        } else {
            Err(BrowserError::NoActivePage)
        }
    }

    pub async fn wait_ms(&self, ms: u64) -> std::result::Result<u64, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        if ms == 0 || ms > 30_000 {
            return Err(BrowserError::Internal(
                "browser__wait ms must be between 1 and 30000".to_string(),
            ));
        }

        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(ms)
    }

    pub async fn wait_for_condition(
        &self,
        condition: &str,
        selector: Option<&str>,
        query: Option<&str>,
        scope: Option<&str>,
        timeout_ms: u64,
    ) -> std::result::Result<BrowserWaitResult, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        if timeout_ms == 0 || timeout_ms > 30_000 {
            return Err(BrowserError::Internal(
                "browser__wait timeout_ms must be between 1 and 30000".to_string(),
            ));
        }

        let condition = condition.trim().to_ascii_lowercase();
        if condition.is_empty() {
            return Err(BrowserError::Internal(
                "browser__wait condition cannot be empty".to_string(),
            ));
        }

        let start = Instant::now();
        let mut stable_samples = 0u8;
        let mut last_fingerprint: Option<String> = None;

        loop {
            let met = match condition.as_str() {
                "selector_visible" => {
                    let selector = selector
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            BrowserError::Internal(
                                "browser__wait condition=selector_visible requires selector"
                                    .to_string(),
                            )
                        })?;
                    self.selector_visible(selector).await?
                }
                "text_present" => {
                    let query = query
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            BrowserError::Internal(
                                "browser__wait condition=text_present requires query".to_string(),
                            )
                        })?;
                    self.find_text(query, scope, false).await?.found
                }
                "dom_stable" => {
                    let fingerprint = self.dom_stability_fingerprint().await?;
                    match last_fingerprint {
                        Some(ref previous) if previous == &fingerprint => {
                            stable_samples = stable_samples.saturating_add(1);
                        }
                        _ => {
                            stable_samples = 1;
                            last_fingerprint = Some(fingerprint);
                        }
                    }
                    stable_samples >= 3
                }
                other => {
                    return Err(BrowserError::Internal(format!(
                        "browser__wait condition '{}' is unsupported",
                        other
                    )))
                }
            };

            if met {
                return Ok(BrowserWaitResult {
                    condition,
                    met: true,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                });
            }

            let elapsed_ms = start.elapsed().as_millis() as u64;
            if elapsed_ms >= timeout_ms {
                return Ok(BrowserWaitResult {
                    condition,
                    met: false,
                    elapsed_ms: elapsed_ms.min(timeout_ms),
                });
            }

            let remaining_ms = timeout_ms.saturating_sub(elapsed_ms);
            let sleep_ms = remaining_ms.min(125);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }

    async fn selector_visible(&self, selector: &str) -> std::result::Result<bool, BrowserError> {
        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const element = deepQuerySelector(selector);
                return !!element && isElementVisibleCandidate(element);
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );
        self.evaluate_js(&script).await
    }

    async fn dom_stability_fingerprint(&self) -> std::result::Result<String, BrowserError> {
        let script = r#"(() => {
            const root = document.body || document.documentElement;
            if (!root) {
                return "dom:none";
            }
            const nodeCount = root.querySelectorAll("*").length;
            const interactiveCount = root.querySelectorAll(
                "a,button,input,select,textarea,[role='button'],[role='link'],[role='textbox'],[tabindex]"
            ).length;
            const attrs = [
                location.href || "",
                document.title || "",
                document.readyState || "",
                nodeCount,
                interactiveCount,
                root.childElementCount || 0,
                root.scrollHeight || 0,
                root.scrollWidth || 0
            ];
            return attrs.join("|");
        })()"#;
        self.evaluate_js(script).await
    }

    pub async fn find_text(
        &self,
        query: &str,
        scope: Option<&str>,
        scroll: bool,
    ) -> std::result::Result<BrowserFindTextResult, BrowserError> {
        #[derive(Deserialize)]
        struct FindTextJsResult {
            found: bool,
            count: u32,
            scope: String,
            scrolled: bool,
            first_snippet: Option<String>,
        }

        let query = query.trim();
        if query.is_empty() {
            return Err(BrowserError::Internal(
                "browser__find_text query cannot be empty".to_string(),
            ));
        }

        let scope_normalized = scope
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("visible")
            .to_ascii_lowercase();
        if scope_normalized != "visible" && scope_normalized != "document" {
            return Err(BrowserError::Internal(
                "browser__find_text scope must be 'visible' or 'document'".to_string(),
            ));
        }

        let query_json = serde_json::to_string(query)
            .map_err(|e| BrowserError::Internal(format!("Query encode failed: {}", e)))?;
        let scope_json = serde_json::to_string(&scope_normalized)
            .map_err(|e| BrowserError::Internal(format!("Scope encode failed: {}", e)))?;
        let scroll_json = serde_json::to_string(&scroll)
            .map_err(|e| BrowserError::Internal(format!("Scroll encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const query = {query_json};
                const scope = {scope_json};
                const shouldScroll = {scroll_json};
                {helpers}

                const root = document.body || document.documentElement;
                if (!root) {{
                    return {{
                        found: false,
                        count: 0,
                        scope,
                        scrolled: false,
                        first_snippet: null
                    }};
                }}

                const needle = query.toLowerCase();
                const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
                let count = 0;
                let scrolled = false;
                let firstSnippet = null;

                const countOccurrences = (haystack, token) => {{
                    if (!token.length || !haystack.length) {{
                        return 0;
                    }}
                    let idx = haystack.indexOf(token);
                    let hits = 0;
                    while (idx !== -1) {{
                        hits += 1;
                        idx = haystack.indexOf(token, idx + token.length);
                    }}
                    return hits;
                }};

                let node = walker.nextNode();
                while (node) {{
                    const rawText = String(node.nodeValue || "");
                    const normalized = rawText.toLowerCase();
                    if (normalized.includes(needle)) {{
                        const parent = node.parentElement || (node.parentNode && node.parentNode.nodeType === 1 ? node.parentNode : null);
                        if (scope === "document" || (parent && isElementVisibleCandidate(parent))) {{
                            const hits = countOccurrences(normalized, needle);
                            count += hits;
                            if (firstSnippet === null) {{
                                firstSnippet = rawText.trim().slice(0, 160);
                                if (shouldScroll && parent) {{
                                    try {{
                                        parent.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                                        scrolled = true;
                                    }} catch (_e) {{}}
                                }}
                            }}
                        }}
                    }}
                    node = walker.nextNode();
                }}

                return {{
                    found: count > 0,
                    count,
                    scope,
                    scrolled,
                    first_snippet: firstSnippet
                }};
            }})()"#,
            query_json = query_json,
            scope_json = scope_json,
            scroll_json = scroll_json,
            helpers = helpers
        );

        let result: FindTextJsResult = self.evaluate_js(&script).await?;
        Ok(BrowserFindTextResult {
            found: result.found,
            count: result.count,
            scope: result.scope,
            scrolled: result.scrolled,
            first_snippet: result.first_snippet,
        })
    }

    pub async fn upload_files(
        &self,
        selector: Option<&str>,
        paths: &[String],
    ) -> std::result::Result<usize, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let validated_paths = Self::validate_upload_paths(paths)?;

        let target_selector = selector
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("input[type='file']");
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let root = self
            .check_connection_error(page.execute(GetDocumentParams::default()).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.getDocument failed: {}", e)))?;

        let query = self
            .check_connection_error(
                page.execute(QuerySelectorParams::new(root.root.node_id, target_selector))
                    .await,
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.querySelector failed: {}", e)))?;

        if *query.node_id.inner() == 0 {
            return Err(BrowserError::Internal(format!(
                "File input selector '{}' was not found",
                target_selector
            )));
        }

        let params = SetFileInputFilesParams::builder()
            .files(validated_paths.clone())
            .node_id(query.node_id)
            .build()
            .map_err(BrowserError::Internal)?;

        self.check_connection_error(page.execute(params).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.setFileInputFiles failed: {}", e)))?;

        Ok(validated_paths.len())
    }

    pub async fn upload_files_to_backend_node(
        &self,
        backend_dom_node_id: &str,
        paths: &[String],
    ) -> std::result::Result<usize, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let validated_paths = Self::validate_upload_paths(paths)?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let parsed_backend_id = backend_dom_node_id.trim().parse::<i64>().map_err(|e| {
            BrowserError::Internal(format!(
                "Backend DOM node id '{}' is not a valid integer: {}",
                backend_dom_node_id, e
            ))
        })?;
        let backend_node_id = BackendNodeId::new(parsed_backend_id);

        let params = SetFileInputFilesParams::builder()
            .files(validated_paths.clone())
            .backend_node_id(backend_node_id)
            .build()
            .map_err(BrowserError::Internal)?;

        self.check_connection_error(page.execute(params).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.setFileInputFiles failed: {}", e)))?;

        Ok(validated_paths.len())
    }

    fn validate_upload_paths(paths: &[String]) -> std::result::Result<Vec<String>, BrowserError> {
        if paths.is_empty() {
            return Err(BrowserError::Internal(
                "browser__upload_file requires at least one path".to_string(),
            ));
        }

        paths
            .iter()
            .map(|raw| {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(BrowserError::Internal(
                        "browser__upload_file paths cannot be empty".to_string(),
                    ));
                }
                let path = std::path::Path::new(trimmed);
                if !path.is_absolute() {
                    return Err(BrowserError::Internal(format!(
                        "Upload path must be an absolute scoped file path: '{}'",
                        trimmed
                    )));
                }
                if !path.is_file() {
                    return Err(BrowserError::Internal(format!(
                        "Upload path is not a file: '{}'",
                        trimmed
                    )));
                }
                Ok(trimmed.to_string())
            })
            .collect::<Result<Vec<String>, BrowserError>>()
    }

    pub async fn dropdown_options(
        &self,
        selector: &str,
    ) -> std::result::Result<Vec<BrowserDropdownOption>, BrowserError> {
        #[derive(Deserialize)]
        struct DropdownOptionsResult {
            found: bool,
            reason: Option<String>,
            options: Vec<BrowserDropdownOption>,
        }

        let selector = selector.trim();
        if selector.is_empty() {
            return Err(BrowserError::Internal(
                "browser__dropdown_options selector cannot be empty".to_string(),
            ));
        }

        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const root = deepQuerySelector(selector);
                const select = root && root.tagName && root.tagName.toLowerCase() === "select"
                    ? root
                    : (root && typeof root.closest === "function" ? root.closest("select") : null);
                if (!select) {{
                    return {{ found: false, reason: "select_not_found", options: [] }};
                }}

                const options = Array.from(select.options || []).map((opt) => {{
                    const label = (opt.label || opt.textContent || "").trim();
                    const value = (opt.value || "").trim();
                    return {{
                        value,
                        label,
                        selected: !!opt.selected
                    }};
                }});
                return {{ found: true, reason: null, options }};
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        let result: DropdownOptionsResult = self.evaluate_js(&script).await?;
        if !result.found {
            return Err(BrowserError::Internal(format!(
                "browser__dropdown_options failed: {}",
                result.reason.unwrap_or_else(|| "unknown error".to_string())
            )));
        }
        Ok(result.options)
    }

    pub async fn dropdown_options_at_point(
        &self,
        x: f64,
        y: f64,
    ) -> std::result::Result<Vec<BrowserDropdownOption>, BrowserError> {
        #[derive(Deserialize)]
        struct DropdownOptionsResult {
            found: bool,
            reason: Option<String>,
            options: Vec<BrowserDropdownOption>,
        }

        let x_json = serde_json::to_string(&x)
            .map_err(|e| BrowserError::Internal(format!("Point X encode failed: {}", e)))?;
        let y_json = serde_json::to_string(&y)
            .map_err(|e| BrowserError::Internal(format!("Point Y encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const x = {x_json};
                const y = {y_json};
                {helpers}
                const target = deepElementFromPoint(x, y);
                const select = target && target.tagName && target.tagName.toLowerCase() === "select"
                    ? target
                    : (target && typeof target.closest === "function" ? target.closest("select") : null);
                if (!select) {{
                    return {{ found: false, reason: "select_not_found_at_point", options: [] }};
                }}
                const options = Array.from(select.options || []).map((opt) => {{
                    const label = (opt.label || opt.textContent || "").trim();
                    const value = (opt.value || "").trim();
                    return {{
                        value,
                        label,
                        selected: !!opt.selected
                    }};
                }});
                return {{ found: true, reason: null, options }};
            }})()"#,
            x_json = x_json,
            y_json = y_json,
            helpers = helpers
        );

        let result: DropdownOptionsResult = self.evaluate_js(&script).await?;
        if !result.found {
            return Err(BrowserError::Internal(format!(
                "browser__dropdown_options failed: {}",
                result.reason.unwrap_or_else(|| "unknown error".to_string())
            )));
        }
        Ok(result.options)
    }

    pub async fn select_dropdown(
        &self,
        selector: &str,
        value: Option<&str>,
        label: Option<&str>,
    ) -> std::result::Result<BrowserDropdownSelection, BrowserError> {
        #[derive(Deserialize)]
        struct DropdownSelectResult {
            selected: bool,
            reason: Option<String>,
            value: Option<String>,
            label: Option<String>,
        }

        let selector = selector.trim();
        if selector.is_empty() {
            return Err(BrowserError::Internal(
                "browser__select_dropdown selector cannot be empty".to_string(),
            ));
        }

        let normalized_value = value
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string);
        let normalized_label = label
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string);

        if normalized_value.is_some() == normalized_label.is_some() {
            return Err(BrowserError::Internal(
                "browser__select_dropdown requires exactly one of value or label".to_string(),
            ));
        }

        let selector_json = serde_json::to_string(selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let value_json = serde_json::to_string(&normalized_value)
            .map_err(|e| BrowserError::Internal(format!("Value encode failed: {}", e)))?;
        let label_json = serde_json::to_string(&normalized_label)
            .map_err(|e| BrowserError::Internal(format!("Label encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                const requestedValue = {value_json};
                const requestedLabel = {label_json};
                {helpers}
                const root = deepQuerySelector(selector);
                const select = root && root.tagName && root.tagName.toLowerCase() === "select"
                    ? root
                    : (root && typeof root.closest === "function" ? root.closest("select") : null);
                if (!select) {{
                    return {{
                        selected: false,
                        reason: "select_not_found",
                        value: null,
                        label: null
                    }};
                }}

                const options = Array.from(select.options || []);
                let index = -1;
                if (requestedValue !== null) {{
                    index = options.findIndex((opt) => String(opt.value || "").trim() === requestedValue);
                }} else if (requestedLabel !== null) {{
                    index = options.findIndex((opt) => String(opt.label || opt.textContent || "").trim() === requestedLabel);
                }}

                if (index < 0) {{
                    return {{
                        selected: false,
                        reason: "option_not_found",
                        value: null,
                        label: null
                    }};
                }}

                select.selectedIndex = index;
                const selected = select.options[index];
                if (!selected) {{
                    return {{
                        selected: false,
                        reason: "option_not_resolved",
                        value: null,
                        label: null
                    }};
                }}

                try {{
                    select.dispatchEvent(new Event("input", {{ bubbles: true }}));
                    select.dispatchEvent(new Event("change", {{ bubbles: true }}));
                }} catch (_e) {{}}

                return {{
                    selected: true,
                    reason: null,
                    value: String(selected.value || "").trim(),
                    label: String(selected.label || selected.textContent || "").trim()
                }};
            }})()"#,
            selector_json = selector_json,
            value_json = value_json,
            label_json = label_json,
            helpers = helpers
        );

        let result: DropdownSelectResult = self.evaluate_js(&script).await?;
        if !result.selected {
            return Err(BrowserError::Internal(format!(
                "browser__select_dropdown failed: {}",
                result.reason.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        Ok(BrowserDropdownSelection {
            value: result.value.unwrap_or_default(),
            label: result.label.unwrap_or_default(),
        })
    }

    pub async fn select_dropdown_at_point(
        &self,
        x: f64,
        y: f64,
        value: Option<&str>,
        label: Option<&str>,
    ) -> std::result::Result<BrowserDropdownSelection, BrowserError> {
        #[derive(Deserialize)]
        struct DropdownSelectResult {
            selected: bool,
            reason: Option<String>,
            value: Option<String>,
            label: Option<String>,
        }

        let normalized_value = value
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string);
        let normalized_label = label
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string);

        if normalized_value.is_some() == normalized_label.is_some() {
            return Err(BrowserError::Internal(
                "browser__select_dropdown requires exactly one of value or label".to_string(),
            ));
        }

        let x_json = serde_json::to_string(&x)
            .map_err(|e| BrowserError::Internal(format!("Point X encode failed: {}", e)))?;
        let y_json = serde_json::to_string(&y)
            .map_err(|e| BrowserError::Internal(format!("Point Y encode failed: {}", e)))?;
        let value_json = serde_json::to_string(&normalized_value)
            .map_err(|e| BrowserError::Internal(format!("Value encode failed: {}", e)))?;
        let label_json = serde_json::to_string(&normalized_label)
            .map_err(|e| BrowserError::Internal(format!("Label encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const x = {x_json};
                const y = {y_json};
                const requestedValue = {value_json};
                const requestedLabel = {label_json};
                {helpers}
                const target = deepElementFromPoint(x, y);
                const select = target && target.tagName && target.tagName.toLowerCase() === "select"
                    ? target
                    : (target && typeof target.closest === "function" ? target.closest("select") : null);
                if (!select) {{
                    return {{
                        selected: false,
                        reason: "select_not_found_at_point",
                        value: null,
                        label: null
                    }};
                }}

                const options = Array.from(select.options || []);
                let index = -1;
                if (requestedValue !== null) {{
                    index = options.findIndex((opt) => String(opt.value || "").trim() === requestedValue);
                }} else if (requestedLabel !== null) {{
                    index = options.findIndex((opt) => String(opt.label || opt.textContent || "").trim() === requestedLabel);
                }}

                if (index < 0) {{
                    return {{
                        selected: false,
                        reason: "option_not_found",
                        value: null,
                        label: null
                    }};
                }}

                select.selectedIndex = index;
                const selected = select.options[index];
                if (!selected) {{
                    return {{
                        selected: false,
                        reason: "option_not_resolved",
                        value: null,
                        label: null
                    }};
                }}

                try {{
                    select.dispatchEvent(new Event("input", {{ bubbles: true }}));
                    select.dispatchEvent(new Event("change", {{ bubbles: true }}));
                }} catch (_e) {{}}

                return {{
                    selected: true,
                    reason: null,
                    value: String(selected.value || "").trim(),
                    label: String(selected.label || selected.textContent || "").trim()
                }};
            }})()"#,
            x_json = x_json,
            y_json = y_json,
            value_json = value_json,
            label_json = label_json,
            helpers = helpers
        );

        let result: DropdownSelectResult = self.evaluate_js(&script).await?;
        if !result.selected {
            return Err(BrowserError::Internal(format!(
                "browser__select_dropdown failed: {}",
                result.reason.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        Ok(BrowserDropdownSelection {
            value: result.value.unwrap_or_default(),
            label: result.label.unwrap_or_default(),
        })
    }

    pub async fn go_back(&self, steps: u32) -> std::result::Result<(u32, String), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let target_steps = if steps == 0 { 1 } else { steps };
        let mut moved = 0u32;

        while moved < target_steps {
            let history = self
                .check_connection_error(page.execute(GetNavigationHistoryParams::default()).await)
                .await
                .map_err(|e| {
                    BrowserError::Internal(format!("Failed to fetch navigation history: {}", e))
                })?;

            if history.current_index <= 0 {
                break;
            }

            let prev_index = (history.current_index - 1) as usize;
            let Some(entry) = history.entries.get(prev_index) else {
                break;
            };

            self.check_connection_error(
                page.execute(NavigateToHistoryEntryParams::new(entry.id))
                    .await,
            )
            .await
            .map_err(|e| {
                BrowserError::Internal(format!(
                    "Failed to navigate to history entry {}: {}",
                    entry.id, e
                ))
            })?;

            page.wait_for_navigation().await.map_err(|e| {
                BrowserError::Internal(format!("Back navigation wait failed: {}", e))
            })?;

            moved += 1;
        }

        let current_url = self
            .check_connection_error(page.url().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query active URL: {}", e)))?
            .unwrap_or_default();

        Ok((moved, current_url))
    }

    pub async fn list_tabs(&self) -> std::result::Result<Vec<BrowserTabInfo>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let browser = { self.browser.lock().await.clone() }.ok_or_else(|| {
            BrowserError::Internal("Browser session is not initialized".to_string())
        })?;
        let pages = self.check_connection_error(browser.pages().await).await?;

        let active_target_id = {
            self.active_page
                .lock()
                .await
                .as_ref()
                .map(|page| page.target_id().as_ref().to_string())
        };
        let retrieval_target_id = {
            self.retrieval_page
                .lock()
                .await
                .as_ref()
                .map(|page| page.target_id().as_ref().to_string())
        };

        let mut tabs = Vec::<BrowserTabInfo>::new();
        for page in pages {
            let tab_id = page.target_id().as_ref().to_string();
            if retrieval_target_id.as_deref() == Some(tab_id.as_str()) {
                continue;
            }

            let title = self
                .check_connection_error(page.get_title().await)
                .await
                .map_err(|e| BrowserError::Internal(format!("Failed to query tab title: {}", e)))?
                .unwrap_or_default();

            let url = self
                .check_connection_error(page.url().await)
                .await
                .map_err(|e| BrowserError::Internal(format!("Failed to query tab URL: {}", e)))?
                .unwrap_or_default();

            tabs.push(BrowserTabInfo {
                active: active_target_id.as_deref() == Some(tab_id.as_str()),
                tab_id,
                title,
                url,
            });
        }

        tabs.sort_by(|a, b| a.tab_id.cmp(&b.tab_id));
        Ok(tabs)
    }

    pub async fn switch_tab(
        &self,
        tab_id: &str,
    ) -> std::result::Result<BrowserTabInfo, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let target_tab = tab_id.trim();
        if target_tab.is_empty() {
            return Err(BrowserError::Internal("tab_id cannot be empty".to_string()));
        }

        let retrieval_target_id = {
            self.retrieval_page
                .lock()
                .await
                .as_ref()
                .map(|page| page.target_id().as_ref().to_string())
        };

        if retrieval_target_id.as_deref() == Some(target_tab) {
            return Err(BrowserError::Internal(
                "Cannot switch to retrieval tab".to_string(),
            ));
        }

        let browser = { self.browser.lock().await.clone() }.ok_or_else(|| {
            BrowserError::Internal("Browser session is not initialized".to_string())
        })?;
        let pages = self.check_connection_error(browser.pages().await).await?;
        let page = pages
            .into_iter()
            .find(|entry| entry.target_id().as_ref() == target_tab)
            .ok_or_else(|| BrowserError::Internal(format!("Tab '{}' not found", target_tab)))?;

        page.bring_to_front()
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to switch tab: {}", e)))?;
        *self.active_page.lock().await = Some(page.clone());

        let title = self
            .check_connection_error(page.get_title().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query tab title: {}", e)))?
            .unwrap_or_default();
        let url = self
            .check_connection_error(page.url().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query tab URL: {}", e)))?
            .unwrap_or_default();

        Ok(BrowserTabInfo {
            tab_id: target_tab.to_string(),
            title,
            url,
            active: true,
        })
    }

    pub async fn close_tab(&self, tab_id: &str) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let target_tab = tab_id.trim();
        if target_tab.is_empty() {
            return Err(BrowserError::Internal("tab_id cannot be empty".to_string()));
        }

        let retrieval_target_id = {
            self.retrieval_page
                .lock()
                .await
                .as_ref()
                .map(|page| page.target_id().as_ref().to_string())
        };
        if retrieval_target_id.as_deref() == Some(target_tab) {
            return Err(BrowserError::Internal(
                "Cannot close retrieval tab".to_string(),
            ));
        }

        let active_target_id = {
            self.active_page
                .lock()
                .await
                .as_ref()
                .map(|page| page.target_id().as_ref().to_string())
        };

        let browser = { self.browser.lock().await.clone() }.ok_or_else(|| {
            BrowserError::Internal("Browser session is not initialized".to_string())
        })?;
        let pages = self.check_connection_error(browser.pages().await).await?;
        let page = pages
            .into_iter()
            .find(|entry| entry.target_id().as_ref() == target_tab)
            .ok_or_else(|| BrowserError::Internal(format!("Tab '{}' not found", target_tab)))?;

        page.close()
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to close tab: {}", e)))?;

        if active_target_id.as_deref() == Some(target_tab) {
            *self.active_page.lock().await = None;

            let remaining = self.check_connection_error(browser.pages().await).await?;
            let mut candidates: Vec<Page> = remaining
                .into_iter()
                .filter(|entry| {
                    retrieval_target_id
                        .as_deref()
                        .is_none_or(|rid| entry.target_id().as_ref() != rid)
                })
                .collect();
            candidates.sort_by(|a, b| a.target_id().as_ref().cmp(b.target_id().as_ref()));

            if let Some(next_page) = candidates.into_iter().next() {
                next_page.bring_to_front().await.map_err(|e| {
                    BrowserError::Internal(format!("Failed to focus next tab: {}", e))
                })?;
                *self.active_page.lock().await = Some(next_page);
            }
        }

        Ok(())
    }

    pub async fn capture_tab_screenshot(
        &self,
        full_page: bool,
    ) -> std::result::Result<Vec<u8>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let params = CaptureScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Jpeg)
            .quality(80)
            .capture_beyond_viewport(full_page)
            .build();
        let bytes = page
            .screenshot(params)
            .await
            .map_err(|e| BrowserError::Internal(format!("Tab screenshot failed: {}", e)))?;
        Ok(bytes)
    }

    pub async fn synthetic_click_with_button(
        &self,
        x: f64,
        y: f64,
        button: MouseButton,
    ) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let cmd_move = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseMoved)
            .x(x)
            .y(y)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_move).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse move dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        let cmd_down = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MousePressed)
            .button(button.clone())
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_down).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse press dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        let cmd_up = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseReleased)
            .button(button)
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_up).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse release dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        Ok(())
    }

    pub async fn synthetic_click(&self, x: f64, y: f64) -> std::result::Result<(), BrowserError> {
        self.synthetic_click_with_button(x, y, MouseButton::Left)
            .await
    }

    pub async fn scroll(
        &self,
        delta_x: i32,
        delta_y: i32,
    ) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let metrics = page
            .execute(GetLayoutMetricsParams::default())
            .await
            .map_err(|e| {
                BrowserError::Internal(format!("Failed to get layout for scroll: {}", e))
            })?;

        let viewport = &metrics.css_layout_viewport;
        let cx = viewport.client_width as f64 / 2.0;
        let cy = viewport.client_height as f64 / 2.0;

        let cmd = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseWheel)
            .x(cx)
            .y(cy)
            .delta_x(delta_x as f64)
            .delta_y(delta_y as f64)
            .build()
            .map_err(BrowserError::Internal)?;

        page.execute(cmd)
            .await
            .map_err(|e| BrowserError::Internal(format!("Scroll failed: {}", e)))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    pub async fn type_text(
        &self,
        text: &str,
        selector: Option<&str>,
    ) -> std::result::Result<(), BrowserError> {
        if let Some(sel) = selector {
            match self.focus_selector(sel).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(BrowserError::Internal(format!(
                        "Failed to focus selector '{}'",
                        sel
                    )))
                }
                Err(e) => {
                    return Err(BrowserError::Internal(format!(
                        "Selector focus failed for '{}': {}",
                        sel, e
                    )))
                }
            }
        }

        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(InsertTextParams::new(text))
            .await
            .map_err(|e| BrowserError::Internal(format!("Type failed: {}", e)))?;

        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    pub async fn press_key(&self, key: &str) -> std::result::Result<(), BrowserError> {
        let key = key.trim();
        if key.is_empty() {
            return Err(BrowserError::Internal("Key cannot be empty".to_string()));
        }

        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let key_definition = keys::get_key_definition(key)
            .or_else(|| {
                keys::USKEYBOARD_LAYOUT
                    .iter()
                    .find(|definition| definition.key.eq_ignore_ascii_case(key))
            })
            .ok_or_else(|| BrowserError::Internal(format!("Unsupported key '{}'", key)))?;

        let mut cmd = DispatchKeyEventParams::builder();
        let key_down_event_type = if let Some(text) = key_definition.text {
            cmd = cmd.text(text);
            DispatchKeyEventType::KeyDown
        } else if key_definition.key.len() == 1 {
            cmd = cmd.text(key_definition.key);
            DispatchKeyEventType::KeyDown
        } else {
            DispatchKeyEventType::RawKeyDown
        };

        cmd = cmd
            .r#type(DispatchKeyEventType::KeyDown)
            .key(key_definition.key)
            .code(key_definition.code)
            .windows_virtual_key_code(key_definition.key_code)
            .native_virtual_key_code(key_definition.key_code);

        let key_down = cmd
            .clone()
            .r#type(key_down_event_type)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(key_down)
            .await
            .map_err(|e| BrowserError::Internal(format!("Key down failed: {}", e)))?;

        let key_up = cmd
            .r#type(DispatchKeyEventType::KeyUp)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(key_up)
            .await
            .map_err(|e| BrowserError::Internal(format!("Key up failed: {}", e)))?;

        tokio::time::sleep(Duration::from_millis(40)).await;
        Ok(())
    }

    pub async fn click_selector(&self, selector: &str) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };

        if let Some(p) = page {
            let primary_click_result = match p.find_element(selector).await {
                Ok(element) => match element.click().await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("Click failed: {}", e)),
                },
                Err(e) => Err(format!("Element not found: {}", e)),
            };
            if let Err(primary_error) = primary_click_result {
                if let Err(deep_error) = self.click_selector_deep(selector).await {
                    // Tier-2 fallback: resolve element geometry across open shadow roots/iframes,
                    // then issue a real pointer-style click via CDP coordinates.
                    match self.get_selector_rect_window_logical(selector).await {
                        Ok(rect) => {
                            let center = rect.center();
                            if let Err(geometry_error) =
                                self.synthetic_click(center.x, center.y).await
                            {
                                return Err(BrowserError::Internal(format!(
                                    "Primary click failed ({primary_error}); deep selector fallback failed: {deep_error}; geometry click fallback failed: {geometry_error}"
                                )));
                            }
                        }
                        Err(geometry_error) => {
                            return Err(BrowserError::Internal(format!(
                                "Primary click failed ({primary_error}); deep selector fallback failed: {deep_error}; geometry resolution failed: {geometry_error}"
                            )));
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        } else {
            Err(BrowserError::NoActivePage)
        }
    }
}
