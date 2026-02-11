use super::*;

impl BrowserDriver {
    pub async fn navigate(
        &self,
        url: &str,
        context_type: &str,
    ) -> std::result::Result<String, BrowserError> {
        let ctx = self.get_context(context_type).await?;

        match ctx {
            BrowserContext::Hermetic => {
                // Reuse existing single-page logic for Hermetic
                self.require_runtime()?;
                // self.ensure_page().await?; // Handled by get_context

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
            BrowserContext::Local(facade) => {
                facade
                    .navigate(url)
                    .await
                    .map_err(|e| BrowserError::NavigateFailed {
                        url: url.into(),
                        details: e.to_string(),
                    })?;
                Ok("Navigated local browser".to_string())
            }
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

    pub async fn capture_tab_screenshot(&self) -> std::result::Result<Vec<u8>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let params = CaptureScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Jpeg)
            .quality(80)
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
        page.execute(cmd_move).await.ok();

        let cmd_down = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MousePressed)
            .button(button.clone())
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_down).await.ok();

        let cmd_up = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseReleased)
            .button(button)
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_up).await.ok();

        Ok(())
    }

    pub async fn synthetic_click(&self, x: f64, y: f64) -> std::result::Result<(), BrowserError> {
        self.synthetic_click_with_button(x, y, MouseButton::Left)
            .await
    }
    pub async fn click_selector(&self, selector: &str) -> std::result::Result<(), BrowserError> {
        if let Some(local) = { self.local_browser.lock().await.clone() } {
            #[derive(Debug, Deserialize)]
            struct LocalClickResult {
                ok: bool,
                #[serde(default)]
                reason: String,
            }

            let selector_json = serde_json::to_string(selector)
                .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
            let script = format!(
                r#"(() => {{
                    const selector = {selector_json};
                    const el = document.querySelector(selector);
                    if (!el) return {{ ok: false, reason: "Element not found" }};
                    try {{
                        el.scrollIntoView({{ block: "center", inline: "center", behavior: "instant" }});
                    }} catch (_e) {{}}
                    try {{
                        if (typeof el.focus === "function") {{
                            el.focus({{ preventScroll: true }});
                        }}
                    }} catch (_e) {{}}
                    try {{
                        if (typeof el.click === "function") {{
                            el.click();
                            return {{ ok: true, reason: "" }};
                        }}
                        return {{ ok: false, reason: "click method unavailable" }};
                    }} catch (e) {{
                        return {{ ok: false, reason: String(e) }};
                    }}
                }})()"#
            );

            let result: LocalClickResult = local
                .evaluate_js(&script)
                .await
                .map_err(|e| BrowserError::Internal(format!("Local click failed: {}", e)))?;
            if !result.ok {
                return Err(BrowserError::Internal(format!(
                    "Click failed for selector '{}': {}",
                    selector,
                    if result.reason.is_empty() {
                        "unknown error".to_string()
                    } else {
                        result.reason
                    }
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Ok(());
        }

        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };

        if let Some(p) = page {
            let element = p
                .find_element(selector)
                .await
                .map_err(|e| BrowserError::Internal(format!("Element not found: {}", e)))?;

            element
                .click()
                .await
                .map_err(|e| BrowserError::Internal(format!("Click failed: {}", e)))?;

            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        } else {
            Err(BrowserError::NoActivePage)
        }
    }
}
