// Path: crates/drivers/src/browser/mod.rs

use chromiumoxide::cdp::browser_protocol::accessibility::{self, GetFullAxTreeParams};
use chromiumoxide::{Browser, BrowserConfig, Page};
use chromiumoxide_fetcher::{BrowserFetcher, BrowserFetcherOptions, Revision, CURRENT_REVISION};
use futures::StreamExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
use crate::gui::geometry::{CoordinateSpace, Point, Rect as GeoRect};
use chromiumoxide::cdp::browser_protocol::dom::{GetBoxModelParams, GetContentQuadsParams};
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchMouseEventParams, DispatchMouseEventType, MouseButton,
};
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, CaptureScreenshotParams, GetLayoutMetricsParams,
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

pub struct BrowserDriver {
    // Hermetic Instance
    browser: Arc<Mutex<Option<Arc<Browser>>>>,
    active_page: Arc<Mutex<Option<Page>>>,
    // Background retrieval page used by `web__*` tooling so search/read operations don't
    // steal focus or mutate the interactive browsing tab.
    retrieval_page: Arc<Mutex<Option<Page>>>,

    // Session-scoped profile directory used by the hermetic browser.
    profile_dir: Arc<Mutex<Option<PathBuf>>>,

    // Tracks if the background websocket handler loop is running
    handler_alive: Arc<AtomicBool>,

    // Lease for demand-driven activation.
    lease_active: Arc<AtomicBool>,

    // Browser-local pointer state for composed pointer primitives.
    pointer_state: Arc<Mutex<BrowserPointerState>>,
}

impl Drop for BrowserDriver {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.profile_dir.try_lock() {
            if let Some(path) = guard.take() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}
