use super::*;
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, InsertTextParams,
};
use chromiumoxide::keys;

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

        if let Some(local) = { self.local_browser.lock().await.clone() } {
            #[derive(Debug, Deserialize)]
            struct LocalTypeResult {
                ok: bool,
                #[serde(default)]
                reason: String,
            }

            let text_json = serde_json::to_string(text)
                .map_err(|e| BrowserError::Internal(format!("Text encode failed: {}", e)))?;
            let script = format!(
                r#"(() => {{
                    const text = {text_json};
                    const el = document.activeElement;
                    if (!el) return {{ ok: false, reason: "No active element" }};
                    const tag = (el.tagName || "").toLowerCase();
                    const type = ((el.getAttribute && el.getAttribute("type")) || "").toLowerCase();
                    const nonEditable = ["button", "submit", "checkbox", "radio", "range", "color", "file", "image", "reset"];
                    const editable = !!(el.isContentEditable || tag === "textarea" || (tag === "input" && !nonEditable.includes(type)));
                    if (!editable) return {{ ok: false, reason: "Active element is not editable" }};
                    try {{
                        if (typeof el.setRangeText === "function" &&
                            typeof el.selectionStart === "number" &&
                            typeof el.selectionEnd === "number") {{
                            el.setRangeText(text, el.selectionStart, el.selectionEnd, "end");
                        }} else if ("value" in el) {{
                            el.value = String(el.value ?? "") + text;
                        }} else if (typeof document.execCommand === "function") {{
                            document.execCommand("insertText", false, text);
                        }} else {{
                            return {{ ok: false, reason: "No text insertion method available" }};
                        }}

                        try {{
                            el.dispatchEvent(new InputEvent("input", {{ bubbles: true, data: text, inputType: "insertText" }}));
                        }} catch (_e) {{
                            const evt = document.createEvent("Event");
                            evt.initEvent("input", true, false);
                            el.dispatchEvent(evt);
                        }}

                        return {{ ok: true, reason: "" }};
                    }} catch (e) {{
                        return {{ ok: false, reason: String(e) }};
                    }}
                }})()"#
            );

            let result: LocalTypeResult = local
                .evaluate_js(&script)
                .await
                .map_err(|e| BrowserError::Internal(format!("Local type failed: {}", e)))?;
            if !result.ok {
                return Err(BrowserError::Internal(format!(
                    "Typing failed in local browser: {}",
                    if result.reason.is_empty() {
                        "unknown error".to_string()
                    } else {
                        result.reason
                    }
                )));
            }
            return Ok(());
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

        if let Some(local) = { self.local_browser.lock().await.clone() } {
            #[derive(Debug, Deserialize)]
            struct LocalKeyResult {
                ok: bool,
                #[serde(default)]
                reason: String,
            }

            let key_json = serde_json::to_string(key)
                .map_err(|e| BrowserError::Internal(format!("Key encode failed: {}", e)))?;
            let script = format!(
                r#"(() => {{
                    const key = {key_json};
                    const target = document.activeElement || document.body || document.documentElement;
                    if (!target) return {{ ok: false, reason: "No active element" }};
                    try {{
                        const down = new KeyboardEvent("keydown", {{ key, code: key, bubbles: true, cancelable: true }});
                        target.dispatchEvent(down);
                        const up = new KeyboardEvent("keyup", {{ key, code: key, bubbles: true, cancelable: true }});
                        target.dispatchEvent(up);
                        return {{ ok: true, reason: "" }};
                    }} catch (e) {{
                        return {{ ok: false, reason: String(e) }};
                    }}
                }})()"#
            );

            let result: LocalKeyResult = local
                .evaluate_js(&script)
                .await
                .map_err(|e| BrowserError::Internal(format!("Local key press failed: {}", e)))?;
            if !result.ok {
                return Err(BrowserError::Internal(format!(
                    "Key press failed in local browser: {}",
                    if result.reason.is_empty() {
                        "unknown error".to_string()
                    } else {
                        result.reason
                    }
                )));
            }
            return Ok(());
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
