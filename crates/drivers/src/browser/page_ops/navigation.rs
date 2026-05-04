impl BrowserDriver {
    pub async fn active_page_title(&self) -> std::result::Result<Option<String>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        self.check_connection_error(page.get_title().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query active page title: {}", e)))
    }

    pub async fn navigate(&self, url: &str) -> std::result::Result<String, BrowserError> {
        crate::authority::assert_raw_driver_allowed("browser", "navigate")
            .map_err(|error| BrowserError::Internal(error.to_string()))?;
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

            self.reset_pointer_state().await;
            let current_url = self
                .check_connection_error(p.url().await)
                .await
                .map_err(|e| BrowserError::Internal(format!("Failed to query active URL: {}", e)))?
                .unwrap_or_else(|| url.to_string());
            *self.active_page_url.lock().await = Some(current_url.clone());
            self.record_browser_use_event(
                "NavigateToUrlEvent",
                None,
                Some(current_url.clone()),
                None,
            )
            .await;
            self.warm_prompt_observation_after_navigation(p.clone(), Some(current_url));
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

            let current_url = self
                .check_connection_error(p.url().await)
                .await
                .map_err(|e| {
                    BrowserError::Internal(format!("Failed to query retrieval URL: {}", e))
                })?
                .unwrap_or_else(|| url.to_string());
            *self.retrieval_page_url.lock().await = Some(current_url);
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
}
