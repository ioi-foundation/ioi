// Path: crates/drivers/src/browser/mod.rs

use chromiumoxide::cdp::browser_protocol::accessibility::{self, GetFullAxTreeParams};
use chromiumoxide::{Browser, BrowserConfig, Page};
use chromiumoxide_fetcher::{BrowserFetcher, BrowserFetcherOptions};
use futures::StreamExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
use self::context::{BrowserContentFrame, BrowserContext, LocalBrowserFacade};

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

pub struct BrowserDriver {
    // Hermetic Instance
    browser: Arc<Mutex<Option<Arc<Browser>>>>,
    active_page: Arc<Mutex<Option<Page>>>,

    // Local Instance
    local_browser: Arc<Mutex<Option<Arc<LocalBrowserFacade>>>>,

    // Tracks if the background websocket handler loop is running
    handler_alive: Arc<AtomicBool>,

    // Lease for demand-driven activation.
    lease_active: Arc<AtomicBool>,
}
