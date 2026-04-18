// Path: crates/drivers/src/browser/mod.rs

use chromiumoxide::cdp::browser_protocol::accessibility::{self, GetFullAxTreeParams};
use chromiumoxide::{Browser, BrowserConfig, Page};
use chromiumoxide_fetcher::{BrowserFetcher, BrowserFetcherOptions, Revision, CURRENT_REVISION};
use futures::StreamExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
use crate::gui::geometry::{CoordinateSpace, Point, Rect as GeoRect};
use chromiumoxide::cdp::browser_protocol::dom::{
    DescribeNodeParams, GetBoxModelParams, GetContentQuadsParams,
};
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchMouseEventParams, DispatchMouseEventType, MouseButton,
};
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, CaptureScreenshotParams, GetFrameTreeParams, GetLayoutMetricsParams,
};

pub mod context;
mod dom_ops;
mod driver_core;
mod page_ops;
use self::context::BrowserContentFrame;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorProbe {
    pub url: String,
    pub found: bool,
    pub visible: bool,
    pub inside_viewport: bool,
    pub topmost: bool,
    pub focused: bool,
    pub editable: bool,
    pub blocked_by: Option<String>,
    pub tag: String,
    pub role: String,
}

impl Default for SelectorProbe {
    fn default() -> Self {
        Self {
            url: String::new(),
            found: false,
            visible: false,
            inside_viewport: false,
            topmost: false,
            focused: false,
            editable: false,
            blocked_by: None,
            tag: String::new(),
            role: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTabInfo {
    pub tab_id: String,
    pub title: String,
    pub url: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDropdownOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDropdownSelection {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFindTextResult {
    pub found: bool,
    pub count: u32,
    pub scope: String,
    pub scrolled: bool,
    pub first_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserWaitResult {
    pub condition: String,
    pub met: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSelectionResult {
    pub found: bool,
    pub target_kind: String,
    pub selected_text: String,
    pub start_offset: u32,
    pub end_offset: u32,
    pub text_length: u32,
    pub focused: bool,
    pub collapsed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserScrollPosition {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserScrollTargetState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub focused: bool,
    pub scroll_top: f64,
    pub scroll_height: f64,
    pub client_height: f64,
    pub can_scroll_up: bool,
    pub can_scroll_down: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center_x: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center_y: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserScrollOutcome {
    pub delta_x: i32,
    pub delta_y: i32,
    pub anchor: String,
    pub anchor_x: f64,
    pub anchor_y: f64,
    pub page_before: BrowserScrollPosition,
    pub page_after: BrowserScrollPosition,
    pub page_moved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_before: Option<BrowserScrollTargetState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_after: Option<BrowserScrollTargetState>,
    pub target_moved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDomElementSummary {
    pub tag: String,
    pub text: String,
    pub visible: bool,
    pub attributes: HashMap<String, String>,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub center_x: f64,
    pub center_y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCanvasShapeSummary {
    pub found: bool,
    pub readable: bool,
    pub target_kind: String,
    pub width: u32,
    pub height: u32,
    pub dark_pixel_count: u32,
    pub component_count: u32,
    pub dominant_component_pixels: u32,
    pub dominant_component_ratio: f64,
    pub bounding_box_x: u32,
    pub bounding_box_y: u32,
    pub bounding_box_width: u32,
    pub bounding_box_height: u32,
    pub convex_hull_vertices: u32,
    pub estimated_sides: Option<u32>,
    pub analysis_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserPointerState {
    pub x: f64,
    pub y: f64,
    pub buttons: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct RecentAccessibilitySnapshot {
    pub(crate) captured_at: Instant,
    pub(crate) url: Option<String>,
    pub(crate) tree: AccessibilityNode,
}

#[derive(Debug, Clone)]
pub struct BrowserObservationArtifacts {
    pub captured_at: Instant,
    pub url: Option<String>,
    pub page_title: Option<String>,
    pub browser_use_state_text: Option<String>,
    pub browser_use_selector_map_text: Option<String>,
    pub browser_use_html_text: Option<String>,
    pub browser_use_eval_text: Option<String>,
    pub browser_use_markdown_text: Option<String>,
    pub browser_use_pagination_text: Option<String>,
    pub browser_use_tabs_text: Option<String>,
    pub browser_use_page_info_text: Option<String>,
    pub browser_use_pending_requests_text: Option<String>,
    pub browser_use_recent_events_text: Option<String>,
    pub browser_use_closed_popup_messages_text: Option<String>,
    pub browsergym_extra_properties_text: Option<String>,
    pub browsergym_focused_bid: Option<String>,
    pub browsergym_dom_text: Option<String>,
    pub browsergym_axtree_text: Option<String>,
}

pub struct BrowserDriver {
    // Hermetic Instance
    browser: Arc<Mutex<Option<Arc<Browser>>>>,
    active_page: Arc<Mutex<Option<Page>>>,
    active_page_url: Arc<Mutex<Option<String>>>,
    // Background retrieval page used by `web__*` tooling so search/read operations don't
    // steal focus or mutate the interactive browsing tab.
    retrieval_page: Arc<Mutex<Option<Page>>>,
    retrieval_page_url: Arc<Mutex<Option<String>>>,

    // Session-scoped profile directory used by the hermetic browser.
    profile_dir: Arc<Mutex<Option<PathBuf>>>,

    // Tracks if the background websocket handler loop is running
    handler_alive: Arc<AtomicBool>,

    // Lease for demand-driven activation.
    lease_active: Arc<AtomicBool>,

    // Browser-local pointer state for composed pointer primitives.
    pointer_state: Arc<Mutex<BrowserPointerState>>,
    last_accessibility_snapshot: Arc<Mutex<Option<RecentAccessibilitySnapshot>>>,
    last_prompt_observation_snapshot: Arc<Mutex<Option<RecentAccessibilitySnapshot>>>,
    last_browser_observation_artifacts: Arc<Mutex<Option<BrowserObservationArtifacts>>>,
    last_browser_use_interactive_backend_keys: Arc<Mutex<HashSet<(String, i64)>>>,
    recent_browser_use_events: Arc<Mutex<VecDeque<serde_json::Value>>>,
    browser_use_closed_popup_messages: Arc<Mutex<Vec<String>>>,
    browser_use_dialog_listener_targets: Arc<Mutex<HashSet<String>>>,
    recent_successful_health_probe_at: Arc<Mutex<Option<Instant>>>,
}

impl Drop for BrowserDriver {
    fn drop(&mut self) {
        let preserve_profile = std::env::var("IOI_BROWSER_PERSIST_PROFILE")
            .ok()
            .map(|raw| raw.trim().to_ascii_lowercase())
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on" | "enabled"));
        if preserve_profile {
            return;
        }
        if let Ok(mut guard) = self.profile_dir.try_lock() {
            if let Some(path) = guard.take() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}
