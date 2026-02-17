use super::*;
use ioi_crypto::algorithms::hash::sha256;
use std::io::ErrorKind;
use std::path::Path;
use uuid::Uuid;

const CHROMIUM_REVISION_ENV: &str = "IOI_CHROMIUM_REVISION";
const CHROMIUM_SHA256_ENV: &str = "IOI_CHROMIUM_SHA256";
const CHROMIUM_PIN_FILE_PREFIX: &str = "chromium-pin-";
const HANDLER_ERROR_TOLERANCE: usize = 3;

fn evaluate_health(cdp_ok: bool, _handler_alive: bool) -> bool {
    cdp_ok
}

impl BrowserDriver {
    pub fn new() -> Self {
        Self {
            browser: Arc::new(Mutex::new(None)),
            active_page: Arc::new(Mutex::new(None)),
            retrieval_page: Arc::new(Mutex::new(None)),
            profile_dir: Arc::new(Mutex::new(None)),
            handler_alive: Arc::new(AtomicBool::new(false)),
            lease_active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_lease(&self, active: bool) {
        let prev = self.lease_active.swap(active, Ordering::SeqCst);
        if active && !prev {
            log::info!(target: "browser", "Browser lease ACQUIRED. Driver is now hot.");
        } else if !active && prev {
            log::info!(target: "browser", "Browser lease RELEASED. Driver will go cold on next error.");
        }
    }

    pub(crate) fn require_runtime(&self) -> std::result::Result<(), BrowserError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(BrowserError::NoTokioRuntime);
        }
        Ok(())
    }

    pub(crate) async fn check_connection_error<T>(
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

    fn pinned_revision() -> Result<Revision, BrowserError> {
        let revision = match std::env::var(CHROMIUM_REVISION_ENV) {
            Ok(raw) if !raw.trim().is_empty() => Revision::try_from(raw.trim().to_string())
                .map_err(|e| {
                    BrowserError::Internal(format!(
                        "Invalid {} value '{}': {}",
                        CHROMIUM_REVISION_ENV,
                        raw.trim(),
                        e
                    ))
                })?,
            _ => CURRENT_REVISION.clone(),
        };
        Ok(revision)
    }

    fn normalize_sha256(raw: &str, source: &str) -> Result<String, BrowserError> {
        let value = raw.trim().to_ascii_lowercase();
        if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BrowserError::Internal(format!(
                "Invalid SHA256 in {}: expected 64 hex characters, got '{}'",
                source, value
            )));
        }
        Ok(value)
    }

    fn expected_binary_sha256() -> Result<Option<String>, BrowserError> {
        match std::env::var(CHROMIUM_SHA256_ENV) {
            Ok(raw) => Ok(Some(Self::normalize_sha256(&raw, CHROMIUM_SHA256_ENV)?)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(BrowserError::Internal(format!(
                "{} contains invalid unicode",
                CHROMIUM_SHA256_ENV
            ))),
        }
    }

    fn binary_sha256_hex(path: &PathBuf) -> Result<String, BrowserError> {
        let bytes = std::fs::read(path).map_err(|e| {
            BrowserError::Internal(format!(
                "Failed to read Chromium binary for checksum verification: {}",
                e
            ))
        })?;
        let digest = sha256(&bytes)
            .map_err(|e| BrowserError::Internal(format!("SHA256 checksum failed: {}", e)))?;
        Ok(digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>())
    }

    fn verify_binary_sha256(actual: &str, expected: &str) -> Result<(), BrowserError> {
        let expected_normalized = Self::normalize_sha256(expected, "expected checksum value")?;

        if actual != expected_normalized {
            return Err(BrowserError::Internal(format!(
                "Chromium binary checksum mismatch (expected {}, got {})",
                expected_normalized, actual
            )));
        }
        Ok(())
    }

    fn revision_pin_file(cache_path: &Path, revision: &Revision) -> PathBuf {
        cache_path.join(format!("{}{}.sha256", CHROMIUM_PIN_FILE_PREFIX, revision))
    }

    fn read_revision_pin(pin_path: &Path) -> Result<Option<String>, BrowserError> {
        let raw = match std::fs::read_to_string(pin_path) {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(BrowserError::Internal(format!(
                    "Failed to read Chromium checksum pin file {:?}: {}",
                    pin_path, e
                )))
            }
        };
        let parsed = Self::normalize_sha256(&raw, &format!("pin file {:?}", pin_path))?;
        Ok(Some(parsed))
    }

    fn write_revision_pin(pin_path: &Path, checksum: &str) -> Result<(), BrowserError> {
        std::fs::write(pin_path, format!("{}\n", checksum)).map_err(|e| {
            BrowserError::Internal(format!(
                "Failed to write Chromium checksum pin file {:?}: {}",
                pin_path, e
            ))
        })
    }

    fn create_profile_dir() -> Result<PathBuf, BrowserError> {
        let path = PathBuf::from("./ioi-data/browser_profiles").join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).map_err(|e| {
            BrowserError::Internal(format!("Failed to create browser profile dir: {}", e))
        })?;
        Ok(path)
    }

    async fn cleanup_profile_dir(&self) {
        let profile_path = { self.profile_dir.lock().await.take() };
        if let Some(path) = profile_path {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                if e.kind() != ErrorKind::NotFound {
                    log::warn!(
                        target: "browser",
                        "Failed to clean browser profile dir {:?}: {}",
                        path,
                        e
                    );
                }
            }
        }
    }

    async fn force_reset(&self) {
        {
            let mut b_guard = self.browser.lock().await;
            *b_guard = None;
        }
        {
            let mut p_guard = self.active_page.lock().await;
            *p_guard = None;
        }
        {
            let mut guard = self.retrieval_page.lock().await;
            *guard = None;
        }
        self.handler_alive.store(false, Ordering::SeqCst);
        self.cleanup_profile_dir().await;
    }

    async fn is_healthy(&self) -> bool {
        let handler_alive = self.handler_alive.load(Ordering::Relaxed);

        let browser_arc = {
            let guard = self.browser.lock().await;
            guard.clone()
        };

        if let Some(browser) = browser_arc {
            let cdp_ok = browser.version().await.is_ok();
            if cdp_ok && !handler_alive {
                log::warn!(
                    target: "browser",
                    "Browser handler marked dead, but CDP probe is healthy; preserving current session."
                );
            }
            if !cdp_ok {
                log::warn!(
                    target: "browser",
                    "Browser CDP probe failed; session will restart if lease is active."
                );
            }
            return evaluate_health(cdp_ok, handler_alive);
        }
        false
    }

    pub async fn launch(&self, headless: bool) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;

        if self.is_healthy().await {
            return Ok(());
        }

        self.force_reset().await;

        let revision = Self::pinned_revision()?;
        let expected_sha_from_env = Self::expected_binary_sha256()?;

        let cache_path = PathBuf::from("./ioi-data/browser_cache");
        std::fs::create_dir_all(&cache_path)
            .map_err(|e| BrowserError::Internal(format!("Failed to create cache dir: {}", e)))?;

        let options = BrowserFetcherOptions::builder()
            .with_path(cache_path.clone())
            .with_revision(revision.clone())
            .build()
            .map_err(|err| {
                BrowserError::Internal(format!("Failed to build fetcher options: {}", err))
            })?;

        let fetcher = BrowserFetcher::new(options);
        let info = fetcher
            .fetch()
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to fetch Chromium: {}", e)))?;

        let actual_sha = Self::binary_sha256_hex(&info.executable_path)?;
        if let Some(expected_sha) = expected_sha_from_env {
            Self::verify_binary_sha256(&actual_sha, &expected_sha)?;
            log::info!(
                target: "browser",
                "Verified Chromium checksum for revision {} via {}",
                revision,
                CHROMIUM_SHA256_ENV
            );
        } else {
            let pin_path = Self::revision_pin_file(&cache_path, &revision);
            if let Some(expected_sha) = Self::read_revision_pin(&pin_path)? {
                Self::verify_binary_sha256(&actual_sha, &expected_sha)?;
                log::info!(
                    target: "browser",
                    "Verified Chromium checksum for revision {} via local pin {:?}",
                    revision,
                    pin_path
                );
            } else {
                Self::write_revision_pin(&pin_path, &actual_sha)?;
                log::warn!(
                    target: "browser",
                    "No {} configured; seeded local checksum pin for revision {} at {:?}. Set {} for strict immutable pinning.",
                    CHROMIUM_SHA256_ENV,
                    revision,
                    pin_path,
                    CHROMIUM_SHA256_ENV
                );
            }
        }

        let profile_dir = Self::create_profile_dir()?;

        let mut delta_args = vec![
            "--disable-dev-shm-usage".to_string(),
            "--disable-gpu".to_string(),
            "--disable-infobars".to_string(),
            "--start-maximized".to_string(),
            "--disable-software-rasterizer".to_string(),
            "--disable-setuid-sandbox".to_string(),
            "--disable-extensions".to_string(),
            format!("--user-data-dir={}", profile_dir.display()),
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

        let run_launch_attempt = |bin: PathBuf, extra_args: Vec<String>| async move {
            let args_owned = extra_args;

            log::info!(
                target: "browser",
                "Launching hermetic chromium (bin={:?}) args_count={}",
                bin,
                args_owned.len()
            );

            let config_res = {
                let mut builder = BrowserConfig::builder().chrome_executable(&bin);

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

            let mut fallback_builder = BrowserConfig::builder().chrome_executable(&bin);
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

        let launch_result = run_launch_attempt(info.executable_path.clone(), delta_args).await;
        let (browser, mut handler) = match launch_result {
            Ok(tuple) => tuple,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&profile_dir);
                return Err(BrowserError::Internal(e));
            }
        };

        let alive_signal = self.handler_alive.clone();
        tokio::spawn(async move {
            alive_signal.store(true, Ordering::SeqCst);
            let mut consecutive_errors = 0usize;
            while let Some(event) = handler.next().await {
                match event {
                    Ok(_) => {
                        consecutive_errors = 0;
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        log::warn!(
                            target: "browser",
                            "Chromium handler event error (#{}/{}): {}",
                            consecutive_errors,
                            HANDLER_ERROR_TOLERANCE,
                            err
                        );
                        if consecutive_errors >= HANDLER_ERROR_TOLERANCE {
                            break;
                        }
                    }
                }
            }
            alive_signal.store(false, Ordering::SeqCst);
            log::warn!(
                target: "browser",
                "Chromium event loop exited (process exit, stream close, or repeated transport errors)."
            );
        });

        *self.profile_dir.lock().await = Some(profile_dir);
        *self.browser.lock().await = Some(Arc::new(browser));
        Ok(())
    }

    pub async fn stop(&self) {
        self.force_reset().await;
    }

    pub(crate) async fn ensure_page(&self) -> std::result::Result<(), BrowserError> {
        let has_browser = self.browser.lock().await.is_some();
        let has_page = self.active_page.lock().await.is_some();
        let handler_alive = self.handler_alive.load(Ordering::SeqCst);

        if !self.is_healthy().await {
            if !self.lease_active.load(Ordering::SeqCst) {
                log::warn!(
                    target: "browser",
                    "ensure_page blocked restart: lease inactive (has_browser={}, has_page={}, handler_alive={})",
                    has_browser,
                    has_page,
                    handler_alive
                );
                return Err(BrowserError::Internal(
                    "Browser is cold (No Lease). Call set_lease(true) before use.".into(),
                ));
            }

            log::warn!(
                target: "browser",
                "ensure_page restarting browser (has_browser={}, has_page={}, handler_alive={})",
                has_browser,
                has_page,
                handler_alive
            );
            self.launch(false).await?;

            let browser_arc = { self.browser.lock().await.clone() };
            if let Some(b) = browser_arc {
                let page = b
                    .new_page("about:blank")
                    .await
                    .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
                *self.active_page.lock().await = Some(page);
                return Ok(());
            }

            return Err(BrowserError::Internal(
                "Browser init failed during recovery".into(),
            ));
        }

        if !has_page {
            log::info!(
                target: "browser",
                "ensure_page creating a new page for active browser session."
            );
            let browser_arc = { self.browser.lock().await.clone() };
            if let Some(b) = browser_arc {
                let page = b
                    .new_page("about:blank")
                    .await
                    .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
                *self.active_page.lock().await = Some(page);
            } else {
                log::warn!(
                    target: "browser",
                    "ensure_page could not create page because browser session handle is missing."
                );
            }
        }
        Ok(())
    }

    pub(crate) async fn ensure_retrieval_page(&self) -> std::result::Result<(), BrowserError> {
        // Reuse ensure_page for browser health/restart logic.
        self.ensure_page().await?;

        let has_page = self.retrieval_page.lock().await.is_some();
        if has_page {
            return Ok(());
        }

        log::info!(
            target: "browser",
            "ensure_retrieval_page creating a new background page."
        );
        let browser_arc = { self.browser.lock().await.clone() };
        if let Some(b) = browser_arc {
            let page = b
                .new_page("about:blank")
                .await
                .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;
            *self.retrieval_page.lock().await = Some(page);
            Ok(())
        } else {
            Err(BrowserError::Internal(
                "Browser session missing while creating retrieval page".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::evaluate_health;

    #[test]
    fn cdp_health_overrides_dead_handler_flag() {
        assert!(evaluate_health(true, false));
        assert!(evaluate_health(true, true));
        assert!(!evaluate_health(false, true));
    }
}
