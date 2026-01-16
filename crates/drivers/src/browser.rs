// Path: crates/drivers/src/browser.rs

use chromiumoxide::{Browser, BrowserConfig, Page};
use futures::StreamExt;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

/// A driver for controlling a headless Chrome instance via CDP.
pub struct BrowserDriver {
    browser: Arc<Mutex<Option<Browser>>>,
    active_page: Arc<Mutex<Option<Page>>>,
}

impl BrowserDriver {
    pub fn new() -> Self {
        Self {
            browser: Arc::new(Mutex::new(None)),
            active_page: Arc::new(Mutex::new(None)),
        }
    }

    fn require_runtime(&self) -> Result<()> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(anyhow!("Browser driver requires a Tokio runtime"));
        }
        Ok(())
    }

    /// Launches the browser instance if not already running.
    pub async fn launch(&self) -> Result<()> {
        self.require_runtime()?;
        let mut guard = self.browser.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let (browser, mut handler) = Browser::launch(
            BrowserConfig::builder()
                .with_head() // Run headless by default? Config says headless usually.
                .build()
                .map_err(|e| anyhow!("Failed to build browser config: {}", e))?
        ).await.map_err(|e| anyhow!("Failed to launch browser: {}", e))?;
        
        // Spawn the handler in the background to process CDP events.
        // Use tokio when available, otherwise fall back to a std thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                while let Some(h) = handler.next().await {
                    if h.is_err() {
                        break;
                    }
                }
            });
        } else {
            std::thread::spawn(move || {
                futures::executor::block_on(async move {
                    while let Some(h) = handler.next().await {
                        if h.is_err() {
                            break;
                        }
                    }
                });
            });
        }

        *guard = Some(browser);
        Ok(())
    }

    /// Navigates to a URL and waits for load.
    pub async fn navigate(&self, url: &str) -> Result<String> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page_guard = self.active_page.lock().await;
        if let Some(page) = page_guard.as_ref() {
            page.goto(url)
                .await
                .map_err(|e| anyhow!("Navigation failed: {}", e))?
                .wait_for_navigation()
                .await
                .map_err(|e| anyhow!("Wait for navigation failed: {}", e))?;
            
            let content = page.content().await.map_err(|e| anyhow!("Failed to get content: {}", e))?;
            Ok(content)
        } else {
            Err(anyhow!("No active page"))
        }
    }

    /// Extracts the DOM (outer HTML) of the current page.
    pub async fn extract_dom(&self) -> Result<String> {
        self.require_runtime()?;
        let page_guard = self.active_page.lock().await;
        if let Some(page) = page_guard.as_ref() {
            // For MVP, return raw HTML. In future, we might return accessibility tree.
            page.content().await.map_err(|e| anyhow!("Failed to extract DOM: {}", e))
        } else {
            Err(anyhow!("No active page"))
        }
    }

    /// Clicks an element matching a CSS selector.
    pub async fn click_selector(&self, selector: &str) -> Result<()> {
        self.require_runtime()?;
        let page_guard = self.active_page.lock().await;
        if let Some(page) = page_guard.as_ref() {
             let element = page.find_element(selector)
                .await
                .map_err(|e| anyhow!("Element not found: {}", e))?;
             
             element.click()
                .await
                .map_err(|e| anyhow!("Click failed: {}", e))?;
                
             // Small delay for UI update
             if tokio::runtime::Handle::try_current().is_ok() {
                 tokio::time::sleep(Duration::from_millis(100)).await;
             } else {
                 std::thread::sleep(Duration::from_millis(100));
             }
             Ok(())
        } else {
            Err(anyhow!("No active page"))
        }
    }

    /// Helper to ensure a page exists.
    async fn ensure_page(&self) -> Result<()> {
        // Ensure browser is running
        self.launch().await?;

        let mut page_guard = self.active_page.lock().await;
        if page_guard.is_none() {
            let browser_guard = self.browser.lock().await;
            if let Some(browser) = browser_guard.as_ref() {
                let page = browser.new_page("about:blank")
                    .await
                    .map_err(|e| anyhow!("Failed to create page: {}", e))?;
                *page_guard = Some(page);
            }
        }
        Ok(())
    }
}
