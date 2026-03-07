impl BrowserDriver {
    pub async fn upload_files(
        &self,
        selector: Option<&str>,
        paths: &[String],
    ) -> std::result::Result<usize, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let validated_paths = Self::validate_upload_paths(paths)?;

        let target_selector = selector
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("input[type='file']");
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let root = self
            .check_connection_error(page.execute(GetDocumentParams::default()).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.getDocument failed: {}", e)))?;

        let query = self
            .check_connection_error(
                page.execute(QuerySelectorParams::new(root.root.node_id, target_selector))
                    .await,
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.querySelector failed: {}", e)))?;

        if *query.node_id.inner() == 0 {
            return Err(BrowserError::Internal(format!(
                "File input selector '{}' was not found",
                target_selector
            )));
        }

        let params = SetFileInputFilesParams::builder()
            .files(validated_paths.clone())
            .node_id(query.node_id)
            .build()
            .map_err(BrowserError::Internal)?;

        self.check_connection_error(page.execute(params).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.setFileInputFiles failed: {}", e)))?;

        Ok(validated_paths.len())
    }

    pub async fn upload_files_to_backend_node(
        &self,
        backend_dom_node_id: &str,
        paths: &[String],
    ) -> std::result::Result<usize, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let validated_paths = Self::validate_upload_paths(paths)?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let parsed_backend_id = backend_dom_node_id.trim().parse::<i64>().map_err(|e| {
            BrowserError::Internal(format!(
                "Backend DOM node id '{}' is not a valid integer: {}",
                backend_dom_node_id, e
            ))
        })?;
        let backend_node_id = BackendNodeId::new(parsed_backend_id);

        let params = SetFileInputFilesParams::builder()
            .files(validated_paths.clone())
            .backend_node_id(backend_node_id)
            .build()
            .map_err(BrowserError::Internal)?;

        self.check_connection_error(page.execute(params).await)
            .await
            .map_err(|e| BrowserError::Internal(format!("DOM.setFileInputFiles failed: {}", e)))?;

        Ok(validated_paths.len())
    }
}
