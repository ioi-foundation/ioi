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
