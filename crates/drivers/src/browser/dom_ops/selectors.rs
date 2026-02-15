use super::super::*;

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

#[cfg(test)]
mod tests {
    use super::BrowserDriver;

    #[test]
    fn focus_first_selector_script_uses_deep_visibility_checks() {
        let script = BrowserDriver::focus_first_selector_script(&["input[name='q']"])
            .expect("selector focus script should serialize selector list");
        assert!(script.contains("deepQuerySelector(selector)"));
        assert!(script.contains("isElementVisibleCandidate(el)"));
        assert!(!script.contains("window.getComputedStyle(el)"));
    }

    #[test]
    fn focus_first_selector_script_returns_matched_selector_when_focused() {
        let script = BrowserDriver::focus_first_selector_script(&["input[type='search']"])
            .expect("selector focus script should serialize selector list");
        assert!(script.contains("if (deepActiveElement() === el) {"));
        assert!(script.contains("return selector;"));
    }
}
