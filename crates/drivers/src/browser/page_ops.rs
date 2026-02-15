use super::*;
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, InsertTextParams,
};
use chromiumoxide::keys;

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
