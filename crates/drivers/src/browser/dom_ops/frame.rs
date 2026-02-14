use super::super::*;

impl BrowserDriver {
    pub async fn get_content_frame(
        &self,
    ) -> std::result::Result<BrowserContentFrame, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        #[derive(serde::Deserialize)]
        struct FrameEval {
            x: f64,
            y: f64,
            chrome_top: f64,
            width: f64,
            height: f64,
        }

        let result: FrameEval = page
            .evaluate(
                r#"(() => ({
                    x: window.screenX || 0,
                    y: window.screenY || 0,
                    chrome_top: Math.max(0, (window.outerHeight || 0) - (window.innerHeight || 0)),
                    width: window.innerWidth || 0,
                    height: window.innerHeight || 0
                }))()"#,
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("Frame JS eval failed: {}", e)))?
            .into_value()
            .map_err(|e| BrowserError::Internal(format!("Frame JS decode failed: {}", e)))?;

        Ok(BrowserContentFrame {
            rect: GeoRect::new(
                result.x,
                result.y + result.chrome_top,
                result.width,
                result.height,
                CoordinateSpace::ScreenLogical,
            ),
            chrome_top: result.chrome_top,
        })
    }

    pub async fn get_selector_rect_window_logical(
        &self,
        selector: &str,
    ) -> std::result::Result<GeoRect, BrowserError> {
        #[derive(Deserialize)]
        struct SelectorRect {
            found: bool,
            x: f64,
            y: f64,
            width: f64,
            height: f64,
            reason: Option<String>,
        }

        let script = Self::selector_rect_script(selector)?;
        let result: SelectorRect = self.evaluate_js(&script).await?;

        if !result.found {
            return Err(BrowserError::Internal(format!(
                "Element '{}' not found in document or open shadow roots",
                selector
            )));
        }

        if !result.width.is_finite()
            || !result.height.is_finite()
            || !result.x.is_finite()
            || !result.y.is_finite()
            || result.width <= 0.0
            || result.height <= 0.0
        {
            return Err(BrowserError::Internal(format!(
                "Element '{}' has invalid clickable geometry: {}",
                selector,
                result
                    .reason
                    .unwrap_or_else(|| "non-finite or zero-sized bounding box".to_string())
            )));
        }

        Ok(GeoRect::new(
            result.x,
            result.y,
            result.width,
            result.height,
            CoordinateSpace::WindowLogical,
        ))
    }

    pub async fn resolve_selector_screen_point(
        &self,
        selector: &str,
    ) -> std::result::Result<Point, BrowserError> {
        let frame = self.get_content_frame().await?;
        let element_rect = self.get_selector_rect_window_logical(selector).await?;
        let center = element_rect.center();
        Ok(Point::new(
            frame.rect.x + center.x,
            frame.rect.y + center.y,
            CoordinateSpace::ScreenLogical,
        ))
    }

    pub async fn get_content_offset(&self) -> std::result::Result<(i32, i32), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let metrics = page
            .execute(GetLayoutMetricsParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to get layout metrics: {}", e)))?;

        let x = metrics.css_visual_viewport.page_x;
        let y = metrics.css_visual_viewport.page_y;

        Ok((x as i32, y as i32))
    }
}
