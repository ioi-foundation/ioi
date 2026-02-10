// Path: crates/drivers/src/browser/context.rs

use anyhow::{anyhow, Result};
use chromiumoxide::Browser;
use chromiumoxide::Page;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::gui::geometry::{CoordinateSpace, Rect as GeoRect};

/// The execution context for a browser action.
#[derive(Clone)]
pub enum BrowserContext {
    /// A hermetic, disposable browser instance.
    Hermetic,

    /// A connection to the user's existing, privileged browser instance via CDP.
    Local(Arc<LocalBrowserFacade>),
}

/// A restricted interface for interacting with the Local (Privileged) Browser.
/// This limits what the agent can do to the user's main browser.
pub struct LocalBrowserFacade {
    browser: Arc<Mutex<Browser>>,
}

#[derive(Debug, Clone, Copy)]
pub struct BrowserContentFrame {
    pub rect: GeoRect,
    pub chrome_top: f64,
}

impl LocalBrowserFacade {
    pub fn new(browser: Arc<Mutex<Browser>>) -> Self {
        Self { browser }
    }

    pub async fn navigate(&self, url: &str) -> Result<()> {
        let browser = self.browser.lock().await;
        let pages = browser
            .pages()
            .await
            .map_err(|e| anyhow!("Failed to get pages: {}", e))?;

        // Use active tab if available, otherwise create new
        if let Some(page) = pages.first() {
            page.goto(url)
                .await
                .map_err(|e| anyhow!("Navigation failed: {}", e))?;
        } else {
            browser
                .new_page(url)
                .await
                .map_err(|e| anyhow!("Failed to create page: {}", e))?;
        }
        Ok(())
    }

    async fn active_page(&self) -> Result<Page> {
        let browser = self.browser.lock().await;
        let pages = browser
            .pages()
            .await
            .map_err(|e| anyhow!("Failed to get pages: {}", e))?;
        pages
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("No active page in local browser"))
    }

    pub async fn evaluate_js<T: DeserializeOwned>(&self, script: &str) -> Result<T> {
        let page = self.active_page().await?;
        let value = page
            .evaluate(script)
            .await
            .map_err(|e| anyhow!("JS evaluation failed: {}", e))?
            .into_value::<T>()
            .map_err(|e| anyhow!("Failed to decode JS result: {}", e))?;
        Ok(value)
    }

    pub async fn get_content_frame(&self) -> Result<BrowserContentFrame> {
        #[derive(serde::Deserialize)]
        struct FrameEval {
            x: f64,
            y: f64,
            chrome_top: f64,
            width: f64,
            height: f64,
        }

        let result: FrameEval = self
            .evaluate_js(
                r#"(() => ({
                    x: window.screenX || 0,
                    y: window.screenY || 0,
                    chrome_top: Math.max(0, (window.outerHeight || 0) - (window.innerHeight || 0)),
                    width: window.innerWidth || 0,
                    height: window.innerHeight || 0
                }))()"#,
            )
            .await?;

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
}
