impl BrowserDriver {
    pub async fn wait_ms(&self, ms: u64) -> std::result::Result<u64, BrowserError> {
        self.require_runtime()?;

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
}

#[cfg(test)]
#[path = "waits/wait_tests.rs"]
mod wait_tests;
