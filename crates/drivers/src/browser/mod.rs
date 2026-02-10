// Path: crates/drivers/src/browser/mod.rs

use chromiumoxide::cdp::browser_protocol::accessibility::{self, GetFullAxTreeParams};
use chromiumoxide::{Browser, BrowserConfig, Page};
use chromiumoxide_fetcher::{BrowserFetcher, BrowserFetcherOptions};
use futures::StreamExt;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::gui::accessibility::{AccessibilityNode, Rect};
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchMouseEventParams, DispatchMouseEventType, MouseButton,
};
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, CaptureScreenshotParams, GetLayoutMetricsParams,
};

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("No active page")]
    NoActivePage,
    #[error("Tokio runtime required")]
    NoTokioRuntime,
    #[error("Failed to extract DOM: {0}")]
    ExtractFailed(String),
    #[error("Failed to navigate to {url}: {details}")]
    NavigateFailed { url: String, details: String },
    #[error("Driver internal error: {0}")]
    Internal(String),
}

pub struct BrowserDriver {
    browser: Arc<Mutex<Option<Arc<Browser>>>>,
    active_page: Arc<Mutex<Option<Page>>>,
    // Tracks if the background websocket handler loop is running
    handler_alive: Arc<AtomicBool>,

    // [NEW] Lease for demand-driven activation.
    // If false, the driver stays cold and will NOT restart on failure.
    // This prevents the watchdog from spawning headed Chromium during non-browser tasks.
    lease_active: Arc<AtomicBool>,
}

impl BrowserDriver {
    pub fn new() -> Self {
        Self {
            browser: Arc::new(Mutex::new(None)),
            active_page: Arc::new(Mutex::new(None)),
            handler_alive: Arc::new(AtomicBool::new(false)),
            lease_active: Arc::new(AtomicBool::new(false)), // Starts cold
        }
    }

    // [NEW] Public API to control the lease
    pub fn set_lease(&self, active: bool) {
        let prev = self.lease_active.swap(active, Ordering::SeqCst);
        if active && !prev {
            log::info!(target: "browser", "Browser lease ACQUIRED. Driver is now hot.");
        } else if !active && prev {
            log::info!(target: "browser", "Browser lease RELEASED. Driver will go cold on next error.");
        }
    }

    fn require_runtime(&self) -> std::result::Result<(), BrowserError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(BrowserError::NoTokioRuntime);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn is_executable_binary(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;

        let real_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if !real_path.is_file() {
            return false;
        }

        if let Ok(meta) = real_path.metadata() {
            if meta.permissions().mode() & 0o111 == 0 {
                return false;
            }
        } else {
            return false;
        }

        let mut f = match fs::File::open(&real_path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_err() {
            return false;
        }

        magic == [0x7f, b'E', b'L', b'F']
    }

    #[cfg(not(target_os = "linux"))]
    fn is_executable_binary(path: &Path) -> bool {
        path.exists()
    }

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

    /// Detects if an error implies the browser process or websocket is dead.
    async fn check_connection_error<T>(
        &self,
        result: Result<T, impl std::fmt::Display>,
    ) -> Result<T, BrowserError> {
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("receiver is gone")
                    || msg.contains("channel closed")
                    || msg.contains("connection reset")
                    || msg.contains("broken pipe")
                {
                    log::warn!(target: "browser", "Connection died ({}), forcing reset.", msg);
                    self.force_reset().await;
                    return Err(BrowserError::Internal(
                        "Browser connection lost. Retry the action.".into(),
                    ));
                }
                Err(BrowserError::Internal(msg))
            }
        }
    }

    async fn force_reset(&self) {
        let mut b_guard = self.browser.lock().await;
        *b_guard = None;
        let mut p_guard = self.active_page.lock().await;
        *p_guard = None;
        self.handler_alive.store(false, Ordering::SeqCst);
    }

    async fn is_healthy(&self) -> bool {
        // 1. Primary Check: Is the event loop running?
        if !self.handler_alive.load(Ordering::Relaxed) {
            return false;
        }

        // 2. Secondary Check: Can we ping the browser?
        // CLONE the arc to avoid holding the lock across the await
        let browser_arc = {
            let guard = self.browser.lock().await;
            guard.clone()
        };

        if let Some(b) = browser_arc {
            return b.version().await.is_ok();
        }
        false
    }

    pub async fn launch(&self, headless: bool) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;

        if self.is_healthy().await {
            return Ok(());
        }

        self.force_reset().await;

        let bin_path = Self::find_chrome_binary();
        if let Some(ref p) = bin_path {
            log::info!(target: "browser", "Resolved system Chrome binary: {:?}", p);
        } else {
            log::warn!(target: "browser", "No verified system binary found. Preparing to fetch...");
        }

        let mut delta_args = vec![
            "--disable-dev-shm-usage".to_string(),
            "--disable-gpu".to_string(),
            "--disable-infobars".to_string(),
            "--start-maximized".to_string(),
            "--disable-software-rasterizer".to_string(),
            "--disable-setuid-sandbox".to_string(),
            "--disable-extensions".to_string(),
        ];
        if headless {
            delta_args.push("--headless=new".to_string());
        }
        if std::env::var("CI").is_ok()
            || std::env::var("NO_SANDBOX").is_ok()
            || unsafe { libc::geteuid() == 0 }
        {
            delta_args.push("--no-sandbox".to_string());
        }

        let run_launch_attempt = |bin: Option<PathBuf>, extra_args: Vec<String>| async move {
            let args_owned = extra_args;

            log::info!(target: "browser", "Launching chromium (bin={:?}) args_count={}", bin, args_owned.len());

            let config_res = {
                let mut builder = BrowserConfig::builder();
                if let Some(ref b) = bin {
                    builder = builder.chrome_executable(b);
                }

                if !headless {
                    builder = builder.with_head();
                }

                builder.args(args_owned.clone()).build()
            };

            match config_res {
                Ok(cfg) => match Browser::launch(cfg).await {
                    Ok(tuple) => return Ok(tuple),
                    Err(e) => {
                        let msg = e.to_string();
                        if !msg.contains("unknown flag")
                            && !msg.contains("disable-background-networking")
                        {
                            return Err(msg);
                        }
                        log::warn!(target: "browser", "Wrapper rejected flags ({}). Retrying with sanitized flags...", msg);
                    }
                },
                Err(e) => return Err(format!("Config failed: {}", e)),
            }

            let mut fallback_args: Vec<String> = vec![
                "--disable-background-timer-throttling".to_string(),
                "--disable-backgrounding-occluded-windows".to_string(),
                "--disable-breakpad".to_string(),
                "--disable-client-side-phishing-detection".to_string(),
                "--disable-component-extensions-with-background-pages".to_string(),
                "--disable-default-apps".to_string(),
                "--disable-extensions".to_string(),
                "--disable-features=Translate".to_string(),
                "--disable-hang-monitor".to_string(),
                "--disable-ipc-flooding-protection".to_string(),
                "--disable-popup-blocking".to_string(),
                "--disable-prompt-on-repost".to_string(),
                "--disable-renderer-backgrounding".to_string(),
                "--disable-sync".to_string(),
                "--force-color-profile=srgb".to_string(),
                "--metrics-recording-only".to_string(),
                "--no-first-run".to_string(),
                "--enable-automation".to_string(),
                "--password-store=basic".to_string(),
                "--use-mock-keychain".to_string(),
            ];

            for arg in args_owned {
                fallback_args.push(arg);
            }

            let mut fallback_builder = BrowserConfig::builder();
            if let Some(ref b) = bin {
                fallback_builder = fallback_builder.chrome_executable(b);
            }

            if !headless {
                fallback_builder = fallback_builder.with_head();
            }

            let config_fallback = fallback_builder
                .disable_default_args()
                .args(fallback_args)
                .build()
                .map_err(|e| format!("Fallback config failed: {}", e))?;

            Browser::launch(config_fallback)
                .await
                .map_err(|e| e.to_string())
        };

        let mut launch_result = run_launch_attempt(bin_path.clone(), delta_args.clone()).await;

        if let Err(ref e) = launch_result {
            let is_early_exit = e.contains("before websocket URL could be resolved")
                || e.contains("unexpected end of stream")
                || e.contains("Input/Output error while resolving websocket URL")
                || e.contains("exited with status");

            let is_exec_missing =
                e.contains("No such file") || e.contains("not found") || e.contains("ENOENT");
            let is_glibc = e.contains("GLIBC");
            let missing = bin_path.is_none();

            if is_early_exit || is_exec_missing || is_glibc || missing {
                log::warn!(target: "browser", "System browser failed or missing (Error: {}). Fetching compatible Chromium...", e);

                let cache_path = PathBuf::from("./ioi-data/browser_cache");

                std::fs::create_dir_all(&cache_path).map_err(|e| {
                    BrowserError::Internal(format!("Failed to create cache dir: {}", e))
                })?;

                let options = BrowserFetcherOptions::builder()
                    .with_path(cache_path)
                    .build()
                    .map_err(|err| {
                        BrowserError::Internal(format!("Failed to build fetcher options: {}", err))
                    })?;

                let fetcher = BrowserFetcher::new(options);

                match fetcher.fetch().await {
                    Ok(info) => {
                        log::info!(target: "browser", "Fetched Chromium at {:?}", info.executable_path);
                        launch_result =
                            run_launch_attempt(Some(info.executable_path), delta_args).await;
                    }
                    Err(fe) => {
                        log::error!(target: "browser", "Failed to fetch Chromium: {}", fe);
                    }
                }
            }
        }

        let (browser, mut handler) = launch_result.map_err(|e| BrowserError::Internal(e))?;

        let alive_signal = self.handler_alive.clone();

        tokio::spawn(async move {
            // Set alive INSIDE the task to ensure it matches loop lifecycle
            alive_signal.store(true, Ordering::SeqCst);
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
            alive_signal.store(false, Ordering::SeqCst);
            log::warn!(target: "browser", "Chromium event loop exited.");
        });

        let mut guard = self.browser.lock().await;
        *guard = Some(Arc::new(browser));
        Ok(())
    }

    async fn ensure_page(&self) -> std::result::Result<(), BrowserError> {
        if !self.is_healthy().await {
            // [NEW] Check lease before restarting
            if !self.lease_active.load(Ordering::SeqCst) {
                return Err(BrowserError::Internal(
                    "Browser is cold (No Lease). Call set_lease(true) before use.".into(),
                ));
            }

            log::warn!(target: "browser", "Browser disconnected or dead. Restarting...");
            self.launch(false).await?;

            // Re-acquire browser handle safely
            let browser_arc = { self.browser.lock().await.clone() };

            if let Some(b) = browser_arc {
                let page = b
                    .new_page("about:blank")
                    .await
                    .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
                *self.active_page.lock().await = Some(page);
                return Ok(());
            } else {
                return Err(BrowserError::Internal(
                    "Browser init failed during recovery".into(),
                ));
            }
        }

        let has_page = self.active_page.lock().await.is_some();
        if !has_page {
            let browser_arc = { self.browser.lock().await.clone() };
            if let Some(b) = browser_arc {
                let page = b
                    .new_page("about:blank")
                    .await
                    .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
                *self.active_page.lock().await = Some(page);
            }
        }
        Ok(())
    }

    pub async fn navigate(&self, url: &str) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        if let Some(p) = page {
            p.bring_to_front()
                .await
                .map_err(|e| BrowserError::Internal(e.to_string()))?;

            // Wrap interactions in check_connection_error
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

    pub async fn synthetic_click(&self, x: f64, y: f64) -> std::result::Result<(), BrowserError> {
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
            .button(MouseButton::Left)
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_down).await.ok();

        let cmd_up = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseReleased)
            .button(MouseButton::Left)
            .x(x)
            .y(y)
            .click_count(1)
            .build()
            .map_err(|e| BrowserError::Internal(e))?;
        page.execute(cmd_up).await.ok();

        Ok(())
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

    pub async fn get_accessibility_tree(
        &self,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        let p = page.ok_or(BrowserError::NoActivePage)?;

        p.execute(accessibility::EnableParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes_vec = p
            .execute(GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        if nodes_vec.is_empty() {
            return Err(BrowserError::Internal(
                "Empty accessibility tree returned".into(),
            ));
        }

        let root_ax = &nodes_vec[0];
        Ok(self.convert_ax_node(root_ax, &nodes_vec))
    }

    pub async fn get_visual_tree(&self) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(accessibility::EnableParams::default())
            .await
            .ok();

        let snapshot = page
            .execute(accessibility::GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("GetFullAxTree failed: {}", e)))?;

        let nodes = snapshot.nodes.clone();

        if nodes.is_empty() {
            return Err(BrowserError::Internal("Empty tree".into()));
        }

        Ok(self.convert_ax_node(&nodes[0], &nodes))
    }

    fn convert_ax_node(
        &self,
        ax_node: &accessibility::AxNode,
        all_nodes: &[accessibility::AxNode],
    ) -> AccessibilityNode {
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
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = inner.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = inner.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }

        let name = extract_string(&ax_node.name);
        let mut value = extract_string(&ax_node.value);
        let role = extract_string(&ax_node.role)
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "generic".to_string());

        let is_visible = !ax_node.ignored;
        let id_string: String = ax_node.node_id.clone().into();

        let mut attributes = HashMap::new();
        if let Some(desc) = extract_string(&ax_node.description) {
            attributes.insert("description".to_string(), desc.clone());
            if value.is_none() {
                value = Some(desc);
            }
        }
        if let Some(chrome_role) = extract_string(&ax_node.chrome_role) {
            attributes.insert("chrome_role".to_string(), chrome_role);
        }

        if let Some(props) = &ax_node.properties {
            for prop in props {
                let key = prop.name.as_ref().to_ascii_lowercase();
                if key.is_empty() {
                    continue;
                }
                if let Some(raw_val) = &prop.value.value {
                    let parsed = if let Some(s) = raw_val.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = raw_val.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = raw_val.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    };

                    if let Some(parsed_val) = parsed {
                        attributes.insert(key.clone(), parsed_val.clone());
                        if value.is_none()
                            && matches!(key.as_str(), "valuetext" | "roledescription")
                        {
                            value = Some(parsed_val);
                        }
                    }
                }
            }
        }

        let rect = Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };

        AccessibilityNode {
            id: id_string,
            role,
            name,
            value,
            rect,
            children,
            is_visible,
            attributes,
            som_id: None,
        }
    }

    pub async fn click_selector(&self, selector: &str) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };

        if let Some(p) = page {
            let element = p
                .find_element(selector)
                .await
                .map_err(|e| BrowserError::Internal(format!("Element not found: {}", e)))?;

            element
                .click()
                .await
                .map_err(|e| BrowserError::Internal(format!("Click failed: {}", e)))?;

            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        } else {
            Err(BrowserError::NoActivePage)
        }
    }
}
