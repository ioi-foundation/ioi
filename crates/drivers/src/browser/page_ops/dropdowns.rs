impl BrowserDriver {
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
}
