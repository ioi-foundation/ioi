impl BrowserDriver {
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
}
