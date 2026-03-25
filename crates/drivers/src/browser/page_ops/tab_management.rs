fn browsergym_screenshot_scale_factor() -> f64 {
    std::env::var("IOI_BROWSER_SNAPSHOT_SCALE_FACTOR")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(1.5)
}

impl BrowserDriver {
    pub async fn reset_active_page_for_navigation(&self) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;

        if let Some(page) = { self.active_page.lock().await.clone() } {
            page.close().await.map_err(|e| {
                BrowserError::Internal(format!("Failed to close active tab for reset: {}", e))
            })?;
        }

        *self.active_page.lock().await = None;
        *self.active_page_url.lock().await = None;
        self.reset_pointer_state().await;
        self.invalidate_accessibility_snapshot().await;
        Ok(())
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
        *self.active_page_url.lock().await = Some(url.clone());
        self.record_browser_use_event(
            "SwitchTabEvent",
            Some(target_tab.to_string()),
            Some(url.clone()),
            None,
        )
        .await;

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
        self.record_browser_use_event("CloseTabEvent", Some(target_tab.to_string()), None, None)
            .await;

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
                let next_url = self
                    .check_connection_error(next_page.url().await)
                    .await
                    .map_err(|e| {
                        BrowserError::Internal(format!("Failed to query next tab URL: {}", e))
                    })?
                    .unwrap_or_default();
                *self.active_page_url.lock().await = Some(next_url);
                *self.active_page.lock().await = Some(next_page);
            } else {
                *self.active_page_url.lock().await = None;
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
        let scale_factor = browsergym_screenshot_scale_factor();

        let metrics = self
            .check_connection_error(page.layout_metrics().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Tab screenshot metrics failed: {}", e)))?;
        let width = metrics.css_visual_viewport.client_width.round().max(1.0) as i64;
        let height = metrics.css_visual_viewport.client_height.round().max(1.0) as i64;

        self.check_connection_error(page.execute(
            chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams::new(
                width,
                height,
                scale_factor,
                false,
            ),
        )
        .await)
        .await
        .map_err(|e| {
            BrowserError::Internal(format!(
                "Tab screenshot metrics override failed: {}",
                e
            ))
        })?;

        let mut params = CaptureScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .capture_beyond_viewport(full_page)
            .build();

        if full_page {
            params.clip = Some(chromiumoxide::cdp::browser_protocol::page::Viewport {
                x: 0.0,
                y: 0.0,
                width: metrics.css_content_size.width,
                height: metrics.css_content_size.height,
                scale: 1.0,
            });
        }

        let capture_result = self
            .check_connection_error(page.execute(params).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Tab screenshot failed: {}", e)))
            .and_then(|response| {
                use base64::Engine as _;

                let encoded: &str = response.result.data.as_ref();
                base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|e| {
                        BrowserError::Internal(format!(
                            "Tab screenshot decode failed: {}",
                            e
                        ))
                    })
            });

        let _ = self
            .check_connection_error(page.execute(
                chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams::new(
                    width, height, 1.0, false,
                ),
            )
            .await)
            .await;

        capture_result
    }
}
