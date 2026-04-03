use super::*;
use ioi_crypto::algorithms::hash::sha256;
use std::fmt::Display;
use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use tokio::sync::OnceCell;
use uuid::Uuid;

const CHROMIUM_REVISION_ENV: &str = "IOI_CHROMIUM_REVISION";
const CHROMIUM_SHA256_ENV: &str = "IOI_CHROMIUM_SHA256";
const BROWSER_REQUEST_TIMEOUT_ENV: &str = "IOI_BROWSER_REQUEST_TIMEOUT_MS";
const CHROMIUM_PIN_FILE_PREFIX: &str = "chromium-pin-";
const HANDLER_ERROR_TOLERANCE: usize = 3;
const LAUNCH_RETRY_ATTEMPTS: usize = 3;
const LAUNCH_RETRY_DELAY_MS: u64 = 250;
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);
const HEALTH_PROBE_CACHE_TTL: Duration = Duration::from_millis(1_000);
const DEFAULT_BROWSER_REQUEST_TIMEOUT_MS: u64 = 2_000;
static RESOLVED_CHROMIUM_BINARY: OnceCell<PathBuf> = OnceCell::const_new();

fn evaluate_health(cdp_ok: bool, _handler_alive: bool) -> bool {
    cdp_ok
}

fn is_retryable_launch_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("before websocket url could be resolved")
        || (lower.contains("browser process exited with status") && lower.contains("websocket"))
}

fn launch_retry_backoff(attempt_index: usize) -> Duration {
    Duration::from_millis(LAUNCH_RETRY_DELAY_MS * (attempt_index as u64 + 1))
}

fn should_fallback_to_headless_launch(headless: bool, message: &str) -> bool {
    !headless && is_retryable_launch_error(message)
}

fn is_reset_worthy_browser_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("receiver is gone")
        || lower.contains("channel closed")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("request timed out")
}

fn restorable_page_url(raw: Option<&str>) -> Option<String> {
    let url = raw?.trim();
    if url.is_empty() || url.eq_ignore_ascii_case("about:blank") {
        None
    } else {
        Some(url.to_string())
    }
}

fn recent_successful_health_probe_fresh(last_ok_at: Option<Instant>, now: Instant) -> bool {
    last_ok_at
        .and_then(|timestamp| now.checked_duration_since(timestamp))
        .is_some_and(|elapsed| elapsed <= HEALTH_PROBE_CACHE_TTL)
}

fn browser_request_timeout() -> Duration {
    std::env::var(BROWSER_REQUEST_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_BROWSER_REQUEST_TIMEOUT_MS))
}

fn chromium_launch_args(headless: bool) -> Vec<String> {
    let mut args = vec![
        "--disable-background-networking".to_string(),
        "--disable-background-timer-throttling".to_string(),
        "--disable-backgrounding-occluded-windows".to_string(),
        "--disable-breakpad".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-component-extensions-with-background-pages".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-dev-shm-usage".to_string(),
        "--disable-extensions".to_string(),
        "--disable-features=Translate".to_string(),
        "--disable-gpu".to_string(),
        "--disable-hang-monitor".to_string(),
        "--disable-infobars".to_string(),
        "--disable-ipc-flooding-protection".to_string(),
        "--disable-popup-blocking".to_string(),
        "--disable-prompt-on-repost".to_string(),
        "--disable-renderer-backgrounding".to_string(),
        "--disable-setuid-sandbox".to_string(),
        "--disable-software-rasterizer".to_string(),
        "--disable-sync".to_string(),
        "--enable-automation".to_string(),
        "--force-color-profile=srgb".to_string(),
        "--force-renderer-accessibility".to_string(),
        "--metrics-recording-only".to_string(),
        "--no-first-run".to_string(),
        "--password-store=basic".to_string(),
        "--start-maximized".to_string(),
        "--use-mock-keychain".to_string(),
    ];
    if headless {
        args.push("--headless=new".to_string());
    }
    if std::env::var("CI").is_ok()
        || std::env::var("NO_SANDBOX").is_ok()
        || unsafe { libc::geteuid() == 0 }
    {
        args.push("--no-sandbox".to_string());
    }
    args
}

impl BrowserDriver {
    pub fn new() -> Self {
        Self {
            browser: Arc::new(Mutex::new(None)),
            active_page: Arc::new(Mutex::new(None)),
            active_page_url: Arc::new(Mutex::new(None)),
            retrieval_page: Arc::new(Mutex::new(None)),
            retrieval_page_url: Arc::new(Mutex::new(None)),
            profile_dir: Arc::new(Mutex::new(None)),
            handler_alive: Arc::new(AtomicBool::new(false)),
            lease_active: Arc::new(AtomicBool::new(false)),
            pointer_state: Arc::new(Mutex::new(BrowserPointerState::default())),
            last_accessibility_snapshot: Arc::new(Mutex::new(None)),
            last_prompt_observation_snapshot: Arc::new(Mutex::new(None)),
            last_browser_observation_artifacts: Arc::new(Mutex::new(None)),
            last_browser_use_interactive_backend_keys: Arc::new(Mutex::new(
                std::collections::HashSet::new(),
            )),
            recent_browser_use_events: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            browser_use_closed_popup_messages: Arc::new(Mutex::new(Vec::new())),
            browser_use_dialog_listener_targets: Arc::new(Mutex::new(
                std::collections::HashSet::new(),
            )),
            recent_successful_health_probe_at: Arc::new(Mutex::new(None)),
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

    pub async fn debugger_websocket_url(&self) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let browser = { self.browser.lock().await.clone() }.ok_or_else(|| {
            BrowserError::Internal("Browser session missing while resolving CDP endpoint".into())
        })?;

        Ok(browser.websocket_address().clone())
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
                if is_reset_worthy_browser_error(&msg) {
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

    pub(crate) async fn await_request_with_timeout<T, E, F>(
        &self,
        action: impl Into<String>,
        future: F,
    ) -> Result<T, BrowserError>
    where
        F: Future<Output = Result<T, E>>,
        E: Display,
    {
        let action = action.into();
        let timeout = browser_request_timeout();
        match tokio::time::timeout(timeout, future).await {
            Ok(result) => match self.check_connection_error(result).await {
                Ok(value) => Ok(value),
                Err(BrowserError::Internal(message)) => Err(BrowserError::Internal(format!(
                    "{action} failed: {message}"
                ))),
                Err(other) => Err(other),
            },
            Err(_) => {
                log::warn!(
                    target: "browser",
                    "{} timed out after {:?}; forcing browser session reset.",
                    action,
                    timeout
                );
                self.force_reset().await;
                Err(BrowserError::Internal(format!(
                    "{} timed out after {}ms. Browser session reset; retry the action.",
                    action,
                    timeout.as_millis()
                )))
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

    async fn resolve_chromium_binary_path() -> Result<PathBuf, BrowserError> {
        let executable = RESOLVED_CHROMIUM_BINARY
            .get_or_try_init(|| async {
                let revision = Self::pinned_revision()?;
                let expected_sha_from_env = Self::expected_binary_sha256()?;

                let cache_path = PathBuf::from("./ioi-data/browser_cache");
                std::fs::create_dir_all(&cache_path).map_err(|e| {
                    BrowserError::Internal(format!("Failed to create cache dir: {}", e))
                })?;

                let options = BrowserFetcherOptions::builder()
                    .with_path(cache_path.clone())
                    .with_revision(revision.clone())
                    .build()
                    .map_err(|err| {
                        BrowserError::Internal(format!(
                            "Failed to build fetcher options: {}",
                            err
                        ))
                    })?;

                let fetcher = BrowserFetcher::new(options);
                let info = fetcher.fetch().await.map_err(|e| {
                    BrowserError::Internal(format!("Failed to fetch Chromium: {}", e))
                })?;

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

                Ok(info.executable_path)
            })
            .await?;
        Ok(executable.clone())
    }

    fn remove_profile_dir(path: &Path) {
        if let Err(e) = std::fs::remove_dir_all(path) {
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

    fn cleanup_profile_dir_with_retries(path: PathBuf) {
        const CLEANUP_RETRY_DELAYS_MS: [u64; 4] = [0, 100, 500, 1_000];

        for delay_ms in CLEANUP_RETRY_DELAYS_MS {
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }

            match std::fs::remove_dir_all(&path) {
                Ok(()) => return,
                Err(error) if error.kind() == ErrorKind::NotFound => return,
                Err(error) => {
                    log::warn!(
                        target: "browser",
                        "Failed to clean browser profile dir {:?}: {}",
                        path,
                        error
                    );
                }
            }
        }
    }

    fn schedule_profile_dir_cleanup(path: PathBuf) {
        tokio::task::spawn_blocking(move || Self::cleanup_profile_dir_with_retries(path));
    }

    async fn cleanup_profile_dir(&self) {
        let profile_path = { self.profile_dir.lock().await.take() };
        if let Some(path) = profile_path {
            Self::schedule_profile_dir_cleanup(path);
        }
    }

    pub(crate) async fn force_reset(&self) {
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
        {
            let mut guard = self.browser_use_dialog_listener_targets.lock().await;
            guard.clear();
        }
        {
            let mut guard = self.last_browser_use_interactive_backend_keys.lock().await;
            guard.clear();
        }
        self.reset_pointer_state().await;
        self.handler_alive.store(false, Ordering::SeqCst);
        *self.recent_successful_health_probe_at.lock().await = None;
        self.cleanup_profile_dir().await;
    }

    async fn is_healthy(&self) -> bool {
        let handler_alive = self.handler_alive.load(Ordering::Relaxed);

        let browser_arc = {
            let guard = self.browser.lock().await;
            guard.clone()
        };

        if let Some(browser) = browser_arc {
            let now = Instant::now();
            let cached_healthy = {
                let guard = self.recent_successful_health_probe_at.lock().await;
                recent_successful_health_probe_fresh(*guard, now)
            };
            if cached_healthy {
                return true;
            }

            let cdp_ok = match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, browser.version()).await {
                Ok(Ok(_)) => true,
                Ok(Err(err)) => {
                    log::warn!(
                        target: "browser",
                        "Browser CDP health probe failed before timeout: {}",
                        err
                    );
                    false
                }
                Err(_) => {
                    log::warn!(
                        target: "browser",
                        "Browser CDP health probe timed out after {:?}; session will restart if lease is active.",
                        HEALTH_PROBE_TIMEOUT
                    );
                    false
                }
            };
            {
                let mut guard = self.recent_successful_health_probe_at.lock().await;
                *guard = cdp_ok.then(Instant::now);
            }
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

    async fn new_page_with_restore(
        &self,
        browser: &Arc<Browser>,
        restore_url: Option<String>,
        page_kind: &str,
    ) -> std::result::Result<Page, BrowserError> {
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to create page: {}", e)))?;

        if page_kind != "retrieval" {
            self.attach_browser_use_page_watchdogs(&page).await?;
            self.record_browser_use_event(
                "TabCreatedEvent",
                Some(page.target_id().as_ref().to_string()),
                Some("about:blank".to_string()),
                None,
            )
            .await;
        }

        if let Some(url) = restorable_page_url(restore_url.as_deref()) {
            log::warn!(
                target: "browser",
                "Rehydrating {} browser page after session reset with {}",
                page_kind,
                url
            );
            self.check_connection_error(page.goto(&url).await)
                .await?
                .wait_for_navigation()
                .await
                .map_err(|e| BrowserError::NavigateFailed {
                    url: url.clone(),
                    details: e.to_string(),
                })?;
        }

        Ok(page)
    }

    pub async fn launch(&self, headless: bool) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;

        if self.is_healthy().await {
            return Ok(());
        }

        self.force_reset().await;

        let executable_path = Self::resolve_chromium_binary_path().await?;
        let base_args = chromium_launch_args(headless);

        let run_launch_attempt = |bin: PathBuf,
                                  profile_dir: PathBuf,
                                  extra_args: Vec<String>,
                                  attempt_headless: bool| async move {
            let args_owned = extra_args;
            let request_timeout = browser_request_timeout();

            log::info!(
                target: "browser",
                "Launching hermetic chromium (bin={:?}) args_count={}",
                bin,
                args_owned.len()
            );

            let config_res = {
                let mut builder = BrowserConfig::builder()
                    .chrome_executable(&bin)
                    .request_timeout(request_timeout)
                    .user_data_dir(&profile_dir);

                if !attempt_headless {
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

            let mut fallback_builder = BrowserConfig::builder()
                .chrome_executable(&bin)
                .request_timeout(request_timeout)
                .user_data_dir(&profile_dir);
            if !attempt_headless {
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

        let launch_with_retries = |attempt_headless: bool| {
            let executable_path = executable_path.clone();
            let base_args = base_args.clone();
            async move {
                let mut last_error: Option<String> = None;
                let mut launched = None;

                for attempt_index in 0..LAUNCH_RETRY_ATTEMPTS {
                    let profile_dir = Self::create_profile_dir()?;

                    match run_launch_attempt(
                        executable_path.clone(),
                        profile_dir.clone(),
                        base_args.clone(),
                        attempt_headless,
                    )
                    .await
                    {
                        Ok((browser, handler)) => {
                            launched = Some((profile_dir, browser, handler));
                            break;
                        }
                        Err(err) => {
                            let retryable = attempt_index + 1 < LAUNCH_RETRY_ATTEMPTS
                                && is_retryable_launch_error(&err);
                            Self::remove_profile_dir(&profile_dir);
                            if retryable {
                                let delay = launch_retry_backoff(attempt_index);
                                log::warn!(
                                    target: "browser",
                                    "Chromium launch attempt {}/{} failed before websocket resolution (headless={}): {}. Retrying in {} ms.",
                                    attempt_index + 1,
                                    LAUNCH_RETRY_ATTEMPTS,
                                    attempt_headless,
                                    err,
                                    delay.as_millis()
                                );
                                last_error = Some(err);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            return Err(BrowserError::Internal(err));
                        }
                    }
                }

                launched.ok_or_else(|| {
                    BrowserError::Internal(
                        last_error
                            .unwrap_or_else(|| "Chromium launch failed without an error".into()),
                    )
                })
            }
        };

        let (profile_dir, browser, mut handler) = match launch_with_retries(headless).await {
            Ok(launched) => launched,
            Err(err) if should_fallback_to_headless_launch(headless, &err.to_string()) => {
                log::warn!(
                    target: "browser",
                    "Chromium launch failed in headed mode with a retryable startup error: {}. Retrying once in headless mode.",
                    err
                );
                launch_with_retries(true).await?
            }
            Err(err) => return Err(err),
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
        *self.recent_successful_health_probe_at.lock().await = Some(Instant::now());
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
                let restore_url = { self.active_page_url.lock().await.clone() };
                let page = self
                    .new_page_with_restore(&b, restore_url, "active")
                    .await?;
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
                let restore_url = { self.active_page_url.lock().await.clone() };
                let page = self
                    .new_page_with_restore(&b, restore_url, "active")
                    .await?;
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
            let restore_url = { self.retrieval_page_url.lock().await.clone() };
            let page = self
                .new_page_with_restore(&b, restore_url, "retrieval")
                .await?;
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
    use super::{
        chromium_launch_args, evaluate_health, is_reset_worthy_browser_error,
        is_retryable_launch_error, recent_successful_health_probe_fresh, restorable_page_url,
        should_fallback_to_headless_launch, BrowserDriver, RecentAccessibilitySnapshot,
        HEALTH_PROBE_CACHE_TTL,
    };
    use crate::gui::accessibility::{AccessibilityNode, Rect};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    fn accessibility_leaf(id: &str) -> AccessibilityNode {
        AccessibilityNode {
            id: id.to_string(),
            role: "button".to_string(),
            name: Some("Leaf".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 24,
                height: 24,
            },
            children: Vec::new(),
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        }
    }

    #[test]
    fn cdp_health_overrides_dead_handler_flag() {
        assert!(evaluate_health(true, false));
        assert!(evaluate_health(true, true));
        assert!(!evaluate_health(false, true));
    }

    #[test]
    fn websocket_resolution_exit_is_retryable() {
        assert!(is_retryable_launch_error(
            "Browser process exited with status ExitStatus(unix_wait_status(0)) before websocket URL could be resolved, stderr: BrowserStderr(\"...\")",
        ));
    }

    #[test]
    fn recent_successful_health_probe_is_fresh_within_cache_ttl() {
        let now = Instant::now();
        assert!(recent_successful_health_probe_fresh(
            Some(now - (HEALTH_PROBE_CACHE_TTL / 2)),
            now
        ));
    }

    #[test]
    fn recent_successful_health_probe_expires_after_cache_ttl() {
        let now = Instant::now();
        assert!(!recent_successful_health_probe_fresh(
            Some(now - HEALTH_PROBE_CACHE_TTL - Duration::from_millis(1)),
            now
        ));
        assert!(!recent_successful_health_probe_fresh(None, now));
    }

    #[test]
    fn retryable_headed_launch_error_falls_back_to_headless() {
        assert!(should_fallback_to_headless_launch(
            false,
            "Browser process exited with status ExitStatus(unix_wait_status(0)) before websocket URL could be resolved, stderr: BrowserStderr(\"...\")",
        ));
    }

    #[test]
    fn headless_launch_error_does_not_recurse_to_headless_fallback() {
        assert!(!should_fallback_to_headless_launch(
            true,
            "Browser process exited with status ExitStatus(unix_wait_status(0)) before websocket URL could be resolved, stderr: BrowserStderr(\"...\")",
        ));
    }

    #[test]
    fn chromium_launch_args_include_automation_and_first_run_suppression() {
        let args = chromium_launch_args(true);
        assert!(args.iter().any(|arg| arg == "--headless=new"));
        assert!(args.iter().any(|arg| arg == "--enable-automation"));
        assert!(args.iter().any(|arg| arg == "--no-first-run"));
        assert!(args
            .iter()
            .any(|arg| arg == "--disable-background-networking"));
        assert!(args
            .iter()
            .any(|arg| arg == "--force-renderer-accessibility"));
    }

    #[test]
    fn unrelated_launch_failure_is_not_retryable() {
        assert!(!is_retryable_launch_error(
            "Config failed: unsupported browser configuration",
        ));
        assert!(!should_fallback_to_headless_launch(
            false,
            "Config failed: unsupported browser configuration",
        ));
    }

    #[test]
    fn restorable_page_url_skips_blank_and_empty_values() {
        assert_eq!(restorable_page_url(None), None);
        assert_eq!(restorable_page_url(Some("")), None);
        assert_eq!(restorable_page_url(Some("   ")), None);
        assert_eq!(restorable_page_url(Some("about:blank")), None);
        assert_eq!(
            restorable_page_url(Some(" file:///tmp/example.html ")),
            Some("file:///tmp/example.html".to_string())
        );
    }

    #[test]
    fn browser_request_timeout_errors_trigger_session_reset() {
        assert!(is_reset_worthy_browser_error("Request timed out."));
        assert!(is_reset_worthy_browser_error(
            "Failed to query active URL: Request timed out."
        ));
        assert!(!is_reset_worthy_browser_error(
            "Failed to decode browser response payload"
        ));
    }

    #[tokio::test]
    async fn recent_accessibility_snapshot_returns_fresh_same_url_tree() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task.html".to_string());
        *driver.last_accessibility_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("btn_cached"),
        });

        let snapshot = driver
            .recent_accessibility_snapshot(Duration::from_secs(1))
            .await
            .expect("fresh cache");
        assert_eq!(snapshot.1.id, "btn_cached");
    }

    #[tokio::test]
    async fn recent_accessibility_snapshot_rejects_mismatched_url() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task-b.html".to_string());
        *driver.last_accessibility_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task-a.html".to_string()),
            tree: accessibility_leaf("btn_cached"),
        });

        assert!(driver
            .recent_accessibility_snapshot(Duration::from_secs(1))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn invalidate_accessibility_snapshot_clears_cached_tree() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task.html".to_string());
        *driver.last_accessibility_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("btn_cached"),
        });

        driver.invalidate_accessibility_snapshot().await;

        assert!(driver
            .recent_accessibility_snapshot(Duration::from_secs(1))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn recent_prompt_observation_snapshot_survives_general_snapshot_overwrite() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task.html".to_string());
        *driver.last_prompt_observation_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("grp_start"),
        });
        *driver.last_accessibility_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("btn_submit"),
        });

        let snapshot = driver
            .recent_prompt_observation_snapshot(Duration::from_secs(1))
            .await
            .expect("prompt cache");
        assert_eq!(snapshot.1.id, "grp_start");
    }

    #[tokio::test]
    async fn prompt_observation_cache_stays_distinct_from_general_snapshot_cache() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task.html".to_string());
        *driver.last_accessibility_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("btn_submit"),
        });

        assert!(driver
            .recent_prompt_observation_snapshot(Duration::from_secs(1))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn invalidate_accessibility_snapshot_clears_prompt_observation_cache() {
        let driver = BrowserDriver::new();
        *driver.active_page_url.lock().await = Some("file:///tmp/miniwob/task.html".to_string());
        *driver.last_prompt_observation_snapshot.lock().await = Some(RecentAccessibilitySnapshot {
            captured_at: Instant::now(),
            url: Some("file:///tmp/miniwob/task.html".to_string()),
            tree: accessibility_leaf("grp_start"),
        });

        driver.invalidate_accessibility_snapshot().await;

        assert!(driver
            .recent_prompt_observation_snapshot(Duration::from_secs(1))
            .await
            .is_none());
    }
}
