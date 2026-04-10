use super::super::{ToolExecutionResult, ToolExecutor};
use super::selector_click::ensure_browser_focus_guard;
use super::tree::{
    apply_browser_auto_lens, apply_browser_auto_lens_with_som, render_browser_tree_xml,
};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration, Instant};

// Verification starts immediately after dispatch. Geometry-only targets do not have a stable
// DOM-backed identity to reconcile, so keep their tail shorter than DOM-backed targets while
// still allowing one medium recheck for slower semantic updates.
const CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY: [u64; 5] = [0, 80, 160, 320, 640];
const CLICK_DISPATCH_SETTLE_MS_DOM_BACKED: [u64; 4] = [0, 120, 240, 900];
const CLICK_DISPATCH_POST_SUCCESS_REFRESH_MS: u64 = 240;
const CLICK_DISPATCH_POST_SUCCESS_REFRESH_TIMEOUT: Duration = Duration::from_millis(400);
// Keep the outer dispatch timeout slightly above the browser driver's per-request timeout so the
// driver can surface its own reset/retry signal instead of getting pre-empted by the wrapper.
const CLICK_DISPATCH_METHOD_TIMEOUT: Duration = Duration::from_millis(2_500);
const CLICK_ELEMENT_EXECUTION_BUDGET: Duration = Duration::from_millis(8_000);
const CLICK_ELEMENT_LIVE_TREE_REFRESH_TIMEOUT: Duration = Duration::from_millis(1_500);
const LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA: usize = 4;
const NON_LINK_STABLE_TARGET_MATERIAL_TREE_CHANGE_MIN_DELTA: usize = 8;
const EXECUTION_PROMPT_OBSERVATION_CACHE_MAX_AGE: Duration = Duration::from_secs(90);
const RECENT_BROWSER_CLICK_SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(5_000);

include!("shared.rs");
include!("target_lookup.rs");
include!("dispatch.rs");
include!("attempt.rs");
