use super::{
    browser_enable_automation_flag_enabled, chromium_launch_args, evaluate_health,
    is_reset_worthy_browser_error, is_retryable_launch_error, recent_successful_health_probe_fresh,
    restorable_page_url, should_fallback_to_headless_launch, BrowserDriver,
    RecentAccessibilitySnapshot, HEALTH_PROBE_CACHE_TTL,
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
fn launch_timeout_is_retryable() {
    assert!(is_retryable_launch_error(
        "Browser launch timed out after 15000ms waiting for websocket URL resolution",
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
fn chromium_launch_args_include_hardening_and_first_run_suppression() {
    let args = chromium_launch_args(true);
    assert!(args.iter().any(|arg| arg == "--headless=new"));
    assert!(args.iter().any(|arg| arg == "--no-first-run"));
    assert!(args
        .iter()
        .any(|arg| arg == "--disable-background-networking"));
    assert!(args
        .iter()
        .any(|arg| arg == "--force-renderer-accessibility"));
    assert!(args.iter().any(|arg| arg == "--window-size=1366,768"));
    assert!(args.iter().any(|arg| arg == "--lang=en-US"));
    if browser_enable_automation_flag_enabled() {
        assert!(args.iter().any(|arg| arg == "--enable-automation"));
    } else {
        assert!(args
            .iter()
            .any(|arg| arg == "--disable-blink-features=AutomationControlled"));
        assert!(!args.iter().any(|arg| arg == "--enable-automation"));
    }
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
