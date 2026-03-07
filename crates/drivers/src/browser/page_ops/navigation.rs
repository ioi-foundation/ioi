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
