// Path: crates/drivers/src/browser/mod.rs

use chromiumoxide::{Browser, BrowserConfig, Page};
use chromiumoxide::cdp::browser_protocol::accessibility::{self, GetFullAxTreeParams};
use chromiumoxide_fetcher::{BrowserFetcher, BrowserFetcherOptions};
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration; 
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use thiserror::Error;
use std::collections::HashMap; // [NEW] Import HashMap

// Reuse the kernel's canonical Accessibility types
use crate::gui::accessibility::{AccessibilityNode, Rect};

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("No active page")]
    NoActivePage,

    #[error("Tokio runtime required")]
    NoTokioRuntime,

    #[error("Failed to extract DOM: {0}")]
    ExtractFailed(String),

    #[error("Failed to navigate to {url}: {details}")]
    NavigateFailed {
        url: String,
        details: String, 
    },

    #[error("Driver internal error: {0}")]
    Internal(String),
}

/// A driver for controlling a headless Chrome instance via CDP.
pub struct BrowserDriver {
    browser: Arc<Mutex<Option<Arc<Browser>>>>,
    active_page: Arc<Mutex<Option<Page>>>,
}

impl BrowserDriver {
    pub fn new() -> Self {
        Self {
            browser: Arc::new(Mutex::new(None)),
            active_page: Arc::new(Mutex::new(None)),
        }
    }

    fn require_runtime(&self) -> std::result::Result<(), BrowserError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(BrowserError::NoTokioRuntime);
        }
        Ok(())
    }

    /// Verifies if a path points to a real ELF binary, not a wrapper script.
    #[cfg(target_os = "linux")]
    fn is_executable_binary(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;

        let real_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if !real_path.is_file() { return false; }

        if let Ok(meta) = real_path.metadata() {
            if meta.permissions().mode() & 0o111 == 0 { return false; }
        } else {
            return false;
        }

        let mut f = match fs::File::open(&real_path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_err() { return false; }

        magic == [0x7f, b'E', b'L', b'F']
    }

    #[cfg(not(target_os = "linux"))]
    fn is_executable_binary(path: &Path) -> bool {
        path.exists()
    }

    /// Attempts to locate a "real" Chrome/Chromium binary.
    fn find_chrome_binary() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("CHROME_BIN") {
            let p = PathBuf::from(path);
            if Self::is_executable_binary(&p) { 
                return Some(p); 
            }
        }

        let candidates = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            
            // Prioritize native packages over Snap to avoid GLIBC issues.
            // Snap ELF paths are moved to the bottom as last resort.
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            
            "/snap/chromium/current/usr/lib/chromium-browser/chrome",
            "/snap/chromium/stable/usr/lib/chromium-browser/chrome",
        ];

        for path in candidates {
            let p = PathBuf::from(path);
            if Self::is_executable_binary(&p) {
                return Some(p);
            }
        }
        None
    }

    /// Launches the browser instance if not already running.
    pub async fn launch(&self) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        
        let mut guard = self.browser.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        // 1. Resolve Binary
        let bin_path = Self::find_chrome_binary();
        if let Some(ref p) = bin_path {
             log::info!(target: "browser", "Resolved system Chrome binary: {:?}", p);
        } else {
             log::warn!(target: "browser", "No verified system binary found. Preparing to fetch...");
        }

        // 2. Define Delta Args (Applied to both attempts)
        let mut delta_args = vec![
            "--disable-dev-shm-usage", // Container stability
            "--disable-gpu",           // Often safer headless
        ];

        if std::env::var("HEADLESS").unwrap_or_else(|_| "true".to_string()) != "false" {
            if std::env::var("HEADLESS_MODE").ok().as_deref() == Some("new") {
                delta_args.push("--headless=new");
            } else {
                delta_args.push("--headless");
            }
        }
        
        if std::env::var("CI").is_ok() || std::env::var("NO_SANDBOX").is_ok() {
            delta_args.push("--no-sandbox");
        }

        // Closure to encapsulate launch attempt logic.
        // [FIX] Pass owned Vec<String> and use async move to avoid lifetime issues.
        let run_launch_attempt = |bin: Option<PathBuf>, extra_args: Vec<String>| async move {
            let args_owned = extra_args; 

            // Log attempt
            log::info!(target: "browser", "Launching chromium (bin={:?}) args_count={}", bin, args_owned.len());

            // Attempt A: Standard Launch
            let config_res = {
                let mut builder = BrowserConfig::builder();
                if let Some(ref b) = bin {
                    builder = builder.chrome_executable(b);
                }
                builder.args(args_owned.clone()).build()
            };

            match config_res {
                Ok(cfg) => {
                    match Browser::launch(cfg).await {
                        Ok(tuple) => return Ok(tuple),
                        Err(e) => {
                             let msg = e.to_string();
                             // If error is not a wrapper flag rejection, propagate it (might trigger fetch)
                             if !msg.contains("unknown flag") && !msg.contains("disable-background-networking") {
                                 return Err(msg);
                             }
                             log::warn!(target: "browser", "Wrapper rejected flags ({}). Retrying with sanitized flags...", msg);
                        }
                    }
                },
                Err(e) => return Err(format!("Config failed: {}", e)),
            }

            // Attempt B: Surgical Fallback (No Defaults)
            // [FIX] Use Vec<String> to own data and ensure all elements are strings.
            let mut fallback_args: Vec<String> = vec![
                // Standard defaults MINUS the offender
                "--disable-background-timer-throttling".to_string(),
                "--disable-backgrounding-occluded-windows".to_string(),
                "--disable-breakpad".to_string(),
                "--disable-client-side-phishing-detection".to_string(),
                "--disable-component-extensions-with-background-pages".to_string(),
                "--disable-default-apps".to_string(),
                "--disable-extensions".to_string(),
                "--disable-features=Translate".to_string(), // Dropped UI from disable list
                "--disable-hang-monitor".to_string(),
                "--disable-ipc-flooding-protection".to_string(),
                "--disable-popup-blocking".to_string(),
                "--disable-prompt-on-repost".to_string(),
                "--disable-renderer-backgrounding".to_string(),
                "--disable-sync".to_string(),
                "--force-color-profile=srgb".to_string(), // [FIX] Added .to_string()
                "--metrics-recording-only".to_string(),
                "--no-first-run".to_string(),
                "--enable-automation".to_string(),
                "--password-store=basic".to_string(),
                "--use-mock-keychain".to_string(),
            ];
            
            // [FIX] Append owned strings
            for arg in args_owned {
                fallback_args.push(arg);
            }
            
            let mut fallback_builder = BrowserConfig::builder();
            // [FIX] Only set executable if explicit path is provided.
            // If bin is None, let chromiumoxide use its internal PATH lookup logic.
            if let Some(ref b) = bin {
                fallback_builder = fallback_builder.chrome_executable(b);
            }
            
            let config_fallback = fallback_builder
                .disable_default_args()
                .args(fallback_args)
                .build()
                .map_err(|e| format!("Fallback config failed: {}", e))?;

            Browser::launch(config_fallback).await.map_err(|e| e.to_string())
        };

        // 3. Try System Binary
        // [FIX] Convert delta_args to owned Vec<String> before passing
        let delta_args_owned: Vec<String> = delta_args.iter().map(|s| s.to_string()).collect();
        let mut launch_result = run_launch_attempt(bin_path.clone(), delta_args_owned.clone()).await;

        // 4. Handle GLIBC / Missing Binary / Crash (Fetch Strategy)
        if let Err(ref e) = launch_result {
            // [FIX] Expanded error detection for early exit/crash scenarios
            let is_early_exit = e.contains("before websocket URL could be resolved") ||
                                e.contains("unexpected end of stream") ||
                                e.contains("Input/Output error while resolving websocket URL") ||
                                e.contains("exited with status"); // Added ExitStatus check
                                
            let is_exec_missing = e.contains("No such file") || e.contains("not found") || e.contains("ENOENT");
            let is_glibc = e.contains("GLIBC"); 
            let missing = bin_path.is_none();

            if is_early_exit || is_exec_missing || is_glibc || missing {
                log::warn!(target: "browser", "System browser failed or missing (Error: {}). Fetching compatible Chromium...", e);
                
                // Deterministic Fetch using chromiumoxide_fetcher
                let cache_path = PathBuf::from("./ioi-data/browser_cache");
                
                // [FIX] Ensure cache directory exists
                std::fs::create_dir_all(&cache_path)
                    .map_err(|e| BrowserError::Internal(format!("Failed to create cache dir: {}", e)))?;

                // [FIX] Handle Result from builder
                let options = BrowserFetcherOptions::builder()
                    .with_path(cache_path)
                    .build()
                    .map_err(|err| BrowserError::Internal(format!("Failed to build fetcher options: {}", err)))?;

                let fetcher = BrowserFetcher::new(options);
                
                match fetcher.fetch().await {
                    Ok(info) => {
                        log::info!(target: "browser", "Fetched Chromium at {:?}", info.executable_path);
                        // Retry with the guaranteed compatible binary
                        launch_result = run_launch_attempt(Some(info.executable_path), delta_args_owned).await;
                    },
                    Err(fe) => {
                        log::error!(target: "browser", "Failed to fetch Chromium: {}", fe);
                        // launch_result remains the previous error
                    }
                }
            }
        }

        let (browser, mut handler) = launch_result.map_err(|e| BrowserError::Internal(e))?;
        
        // Spawn the handler task
        tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() { break; }
            }
        });

        *guard = Some(Arc::new(browser));
        Ok(())
    }

    /// Navigates to a URL and waits for load.
    pub async fn navigate(&self, url: &str) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        
        let page = {
            let guard = self.active_page.lock().await;
            guard.clone()
        };

        if let Some(p) = page {
            p.goto(url)
                .await
                .map_err(|e| BrowserError::NavigateFailed { url: url.to_string(), details: e.to_string() })?
                .wait_for_navigation()
                .await
                .map_err(|e| BrowserError::NavigateFailed { url: url.to_string(), details: e.to_string() })?;
            
            let content = p.content().await.map_err(|e| BrowserError::ExtractFailed(e.to_string()))?;
            Ok(content)
        } else {
            Err(BrowserError::Internal("ensure_page succeeded but active_page is None".into()))
        }
    }

    /// Extracts the DOM (outer HTML).
    pub async fn extract_dom(&self) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        
        let page = {
            let guard = self.active_page.lock().await;
            guard.clone()
        };

        if let Some(p) = page {
            p.content().await.map_err(|e| BrowserError::ExtractFailed(e.to_string()))
        } else {
            Err(BrowserError::NoActivePage)
        }
    }

    /// Retrieves the semantic Accessibility Tree via CDP.
    pub async fn get_accessibility_tree(&self) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        
        let page = {
            let guard = self.active_page.lock().await;
            guard.clone()
        };

        let p = page.ok_or(BrowserError::NoActivePage)?;

        p.execute(accessibility::EnableParams::default()).await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes = p.execute(GetFullAxTreeParams::default()).await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        if nodes.is_empty() {
            return Err(BrowserError::Internal("Empty accessibility tree returned".into()));
        }

        let root_ax = &nodes[0];
        Ok(self.convert_ax_node(root_ax, &nodes))
    }

    // Helper: Recursive converter (CPU-bound, no locks needed)
    fn convert_ax_node(&self, ax_node: &accessibility::AxNode, all_nodes: &[accessibility::AxNode]) -> AccessibilityNode {
        let mut children = Vec::new();
        if let Some(child_ids) = &ax_node.child_ids {
            for cid in child_ids {
                if let Some(child_ax) = all_nodes.iter().find(|n| &n.node_id == cid) {
                    children.push(self.convert_ax_node(child_ax, all_nodes));
                }
            }
        }

        fn extract_string(val_opt: &Option<accessibility::AxValue>) -> Option<String> {
            val_opt.as_ref().and_then(|v| {
                if let Some(inner) = &v.value {
                    if let Some(s) = inner.as_str() {
                        if s.is_empty() { None } else { Some(s.to_string()) }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }

        let name = extract_string(&ax_node.name);
        let value = extract_string(&ax_node.value);
        let role = extract_string(&ax_node.role)
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "generic".to_string());

        let is_visible = !ax_node.ignored;
        let id_string: String = ax_node.node_id.clone().into();
        let rect = Rect { x: 0, y: 0, width: 0, height: 0 }; 

        // [NEW] Capture attributes from CDP node.
        // For basic AX support, we can pull additional properties into the map.
        // For this implementation, we initialize an empty map as CDP AX properties map poorly to raw string attributes.
        // In a fuller implementation, we would iterate properties.
        let attributes = HashMap::new();

        AccessibilityNode {
            id: id_string,
            role,
            name,
            value,
            rect,
            children,
            is_visible,
            attributes, // [NEW] Added attributes field
        }
    }

    pub async fn click_selector(&self, selector: &str) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        
        let page = {
            let guard = self.active_page.lock().await;
            guard.clone()
        };

        if let Some(p) = page {
             let element = p.find_element(selector)
                .await
                .map_err(|e| BrowserError::Internal(format!("Element not found: {}", e)))?;
             
             element.click()
                .await
                .map_err(|e| BrowserError::Internal(format!("Click failed: {}", e)))?;
                
             tokio::time::sleep(Duration::from_millis(100)).await;
             Ok(())
        } else {
            Err(BrowserError::NoActivePage)
        }
    }

    /// Internal helper to ensure a page exists.
    async fn ensure_page(&self) -> std::result::Result<(), BrowserError> {
        {
            let guard = self.active_page.lock().await;
            if guard.is_some() { return Ok(()); }
        }

        self.launch().await?;

        let browser: Option<Arc<Browser>> = {
            let guard = self.browser.lock().await;
            guard.clone() 
        };

        if let Some(b) = browser {
            let page = b.new_page("about:blank").await
                .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
            
            let mut guard = self.active_page.lock().await;
            if guard.is_none() {
                *guard = Some(page);
            }
            Ok(())
        } else {
            Err(BrowserError::Internal("Browser initialized but handle missing".into()))
        }
    }
}