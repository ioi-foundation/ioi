use chromiumoxide::cdp::browser_protocol::page::{
    DialogType, EnableParams, EventJavascriptDialogOpening, HandleJavaScriptDialogParams,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const BROWSER_USE_RECENT_EVENTS_LIMIT: usize = 10;
const BROWSER_USE_RECENT_EVENTS_CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BrowserUsePageInfo {
    viewport_width: i64,
    viewport_height: i64,
    page_width: i64,
    page_height: i64,
    scroll_x: i64,
    scroll_y: i64,
    pixels_above: i64,
    pixels_below: i64,
    pixels_left: i64,
    pixels_right: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BrowserUsePendingRequest {
    url: String,
    #[serde(default = "browser_use_pending_request_default_method")]
    method: String,
    #[serde(default)]
    loading_duration_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BrowserUseTabInfo {
    url: String,
    title: String,
    tab_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_tab_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BrowserUseStateMetadataTexts {
    pub(crate) page_title: Option<String>,
    pub(crate) tabs_text: Option<String>,
    pub(crate) page_info_text: Option<String>,
    pub(crate) pending_requests_text: Option<String>,
    pub(crate) recent_events_text: Option<String>,
    pub(crate) closed_popup_messages_text: Option<String>,
}

fn browser_use_pending_request_default_method() -> String {
    "GET".to_string()
}

fn browser_use_short_target_id(target_id: &str) -> String {
    let trimmed = target_id.trim();
    if trimmed.chars().count() <= 4 {
        trimmed.to_string()
    } else {
        trimmed
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    }
}

fn browser_use_now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn render_browser_use_tabs_text(tabs: &[BrowserTabInfo]) -> Option<String> {
    let browser_use_tabs = tabs
        .iter()
        .map(|tab| BrowserUseTabInfo {
            url: tab.url.clone(),
            title: tab.title.clone(),
            tab_id: browser_use_short_target_id(&tab.tab_id),
            parent_tab_id: None,
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&browser_use_tabs).ok()
}

fn render_browser_use_page_info_text(info: &BrowserUsePageInfo) -> Option<String> {
    serde_json::to_string_pretty(info).ok()
}

fn render_browser_use_pending_requests_text(
    requests: &[BrowserUsePendingRequest],
) -> Option<String> {
    serde_json::to_string_pretty(requests).ok()
}

fn render_browser_use_recent_events_text(events: &[serde_json::Value]) -> Option<String> {
    serde_json::to_string(events).ok()
}

fn render_browser_use_closed_popup_messages_text(messages: &[String]) -> Option<String> {
    serde_json::to_string_pretty(messages).ok()
}

impl BrowserDriver {
    pub async fn record_browser_use_event(
        &self,
        event_type: impl Into<String>,
        target_id: Option<String>,
        url: Option<String>,
        error_message: Option<String>,
    ) {
        let mut event = serde_json::Map::new();
        event.insert(
            "event_type".to_string(),
            serde_json::Value::String(event_type.into()),
        );
        event.insert(
            "timestamp".to_string(),
            serde_json::Value::String(browser_use_now_rfc3339()),
        );
        if let Some(target_id) = target_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            event.insert("target_id".to_string(), serde_json::Value::String(target_id));
        }
        if let Some(url) = url
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            event.insert("url".to_string(), serde_json::Value::String(url));
        }
        if let Some(error_message) = error_message
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            event.insert(
                "error_message".to_string(),
                serde_json::Value::String(error_message),
            );
        }

        let mut recent_events = self.recent_browser_use_events.lock().await;
        recent_events.push_back(serde_json::Value::Object(event));
        while recent_events.len() > BROWSER_USE_RECENT_EVENTS_CAPACITY {
            recent_events.pop_front();
        }
    }

    pub(crate) async fn attach_browser_use_page_watchdogs(
        &self,
        page: &Page,
    ) -> std::result::Result<(), BrowserError> {
        let target_id = page.target_id().as_ref().to_string();
        {
            let mut registered = self.browser_use_dialog_listener_targets.lock().await;
            if !registered.insert(target_id.clone()) {
                return Ok(());
            }
        }

        self.await_request_with_timeout("Browser-use Page.enable", page.execute(EnableParams::default()))
            .await
            .map_err(|e| BrowserError::Internal(format!("Browser-use Page.enable failed: {}", e)))?;

        let mut dialog_events = page
            .event_listener::<EventJavascriptDialogOpening>()
            .await
            .map_err(|e| {
                BrowserError::Internal(format!(
                    "Browser-use dialog listener registration failed: {}",
                    e
                ))
            })?;
        let page = page.clone();
        let recent_events = self.recent_browser_use_events.clone();
        let closed_popup_messages = self.browser_use_closed_popup_messages.clone();

        tokio::spawn(async move {
            while let Some(event) = dialog_events.next().await {
                let dialog_type = event.r#type.as_ref().to_string();
                let message = event.message.trim().to_string();
                if !message.is_empty() {
                    let formatted = format!("[{dialog_type}] {message}");
                    let mut closed = closed_popup_messages.lock().await;
                    closed.push(formatted);
                }

                let should_accept = matches!(
                    event.r#type,
                    DialogType::Alert | DialogType::Confirm | DialogType::Beforeunload
                );

                if let Err(error) = page
                    .execute(HandleJavaScriptDialogParams::new(should_accept))
                    .await
                {
                    let mut record = serde_json::Map::new();
                    record.insert(
                        "event_type".to_string(),
                        serde_json::Value::String("BrowserErrorEvent".to_string()),
                    );
                    record.insert(
                        "timestamp".to_string(),
                        serde_json::Value::String(browser_use_now_rfc3339()),
                    );
                    record.insert(
                        "error_message".to_string(),
                        serde_json::Value::String(format!(
                            "Failed to auto-close JavaScript dialog: {}",
                            error
                        )),
                    );
                    let mut recent = recent_events.lock().await;
                    recent.push_back(serde_json::Value::Object(record));
                    while recent.len() > BROWSER_USE_RECENT_EVENTS_CAPACITY {
                        recent.pop_front();
                    }
                }
            }
        });

        Ok(())
    }

    pub(crate) async fn capture_browser_use_state_metadata_texts(
        &self,
    ) -> BrowserUseStateMetadataTexts {
        let (page_title_result, tabs_result, page_info_result, pending_requests_result) = tokio::join!(
            self.capture_browser_use_page_title(),
            self.capture_browser_use_tabs_text(),
            self.capture_browser_use_page_info_text(),
            self.capture_browser_use_pending_requests_text(),
        );

        let page_title = match page_title_result {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "Browser-use page-title capture failed: {}",
                    error
                );
                None
            }
        };
        let tabs_text = match tabs_result {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "Browser-use tabs capture failed: {}",
                    error
                );
                None
            }
        };
        let page_info_text = match page_info_result {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "Browser-use page-info capture failed: {}",
                    error
                );
                None
            }
        };
        let pending_requests_text = match pending_requests_result {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "Browser-use pending-request capture failed: {}",
                    error
                );
                None
            }
        };
        let recent_events_text = match self.capture_browser_use_recent_events_text().await {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    target: "browser",
                    "Browser-use recent-events capture failed: {}",
                    error
                );
                None
            }
        };
        let closed_popup_messages_text =
            match self.capture_browser_use_closed_popup_messages_text().await {
                Ok(value) => value,
                Err(error) => {
                    log::debug!(
                        target: "browser",
                        "Browser-use closed-popup capture failed: {}",
                        error
                    );
                    None
                }
            };

        BrowserUseStateMetadataTexts {
            page_title,
            tabs_text,
            page_info_text,
            pending_requests_text,
            recent_events_text,
            closed_popup_messages_text,
        }
    }

    pub(crate) async fn capture_browser_use_page_title(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        self.check_connection_error(page.get_title().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Browser-use page title failed: {}", e)))
    }

    pub(crate) async fn capture_browser_use_tabs_text(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        Ok(render_browser_use_tabs_text(&self.list_tabs().await?))
    }

    pub(crate) async fn capture_browser_use_page_info_text(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let metrics = self
            .check_connection_error(page.layout_metrics().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Browser-use page metrics failed: {}", e)))?;

        let viewport_width = metrics.css_layout_viewport.client_width.max(0);
        let viewport_height = metrics.css_layout_viewport.client_height.max(0);
        let page_width = metrics.css_content_size.width.round().max(0.0) as i64;
        let page_height = metrics.css_content_size.height.round().max(0.0) as i64;
        let scroll_x = metrics.css_visual_viewport.page_x.round().max(0.0) as i64;
        let scroll_y = metrics.css_visual_viewport.page_y.round().max(0.0) as i64;

        let page_info = BrowserUsePageInfo {
            viewport_width,
            viewport_height,
            page_width,
            page_height,
            scroll_x,
            scroll_y,
            pixels_above: scroll_y,
            pixels_below: (page_height - viewport_height - scroll_y).max(0),
            pixels_left: scroll_x,
            pixels_right: (page_width - viewport_width - scroll_x).max(0),
        };

        Ok(render_browser_use_page_info_text(&page_info))
    }

    pub(crate) async fn capture_browser_use_pending_requests_text(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        let current_url = self.known_active_url().await.unwrap_or_default();
        let current_scheme = current_url
            .split_once(':')
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(current_scheme.as_str(), "http" | "https") {
            return Ok(render_browser_use_pending_requests_text(&[]));
        }

        let script = r#"(() => {
            const now = performance.now();
            const resources = performance.getEntriesByType("resource");
            const pending = [];
            const adDomains = [
                "doubleclick.net", "googlesyndication.com", "googletagmanager.com",
                "facebook.net", "analytics", "ads", "tracking", "pixel",
                "hotjar.com", "clarity.ms", "mixpanel.com", "segment.com",
                "demdex.net", "omtrdc.net", "adobedtm.com", "ensighten.com",
                "newrelic.com", "nr-data.net", "google-analytics.com",
                "connect.facebook.net", "platform.twitter.com", "platform.linkedin.com",
                ".cloudfront.net/image/", ".akamaized.net/image/",
                "/tracker/", "/collector/", "/beacon/", "/telemetry/", "/log/",
                "/events/", "/eventBatch", "/track.", "/metrics/"
            ];

            for (const entry of resources) {
                if (entry.responseEnd !== 0) {
                    continue;
                }

                const url = entry.name || "";
                if (!url || adDomains.some((domain) => url.includes(domain))) {
                    continue;
                }
                if (url.startsWith("data:") || url.length > 500) {
                    continue;
                }

                const loadingDuration = now - entry.startTime;
                if (loadingDuration > 10000) {
                    continue;
                }

                const resourceType = entry.initiatorType || "unknown";
                const nonCriticalTypes = ["img", "image", "icon", "font"];
                if (nonCriticalTypes.includes(resourceType) && loadingDuration > 3000) {
                    continue;
                }

                const isImageUrl = /\.(jpg|jpeg|png|gif|webp|svg|ico)(\?|$)/i.test(url);
                if (isImageUrl && loadingDuration > 3000) {
                    continue;
                }

                pending.push({
                    url,
                    method: "GET",
                    loading_duration_ms: Math.round(loadingDuration),
                    resource_type: resourceType
                });
            }

            return pending.slice(0, 20);
        })()"#;

        let requests = self.evaluate_js::<Vec<BrowserUsePendingRequest>>(script).await?;
        Ok(render_browser_use_pending_requests_text(&requests))
    }

    pub(crate) async fn capture_browser_use_recent_events_text(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        let recent_events = self.recent_browser_use_events.lock().await;
        let events = recent_events
            .iter()
            .rev()
            .take(BROWSER_USE_RECENT_EVENTS_LIMIT)
            .cloned()
            .collect::<Vec<_>>();
        Ok(render_browser_use_recent_events_text(&events))
    }

    pub(crate) async fn capture_browser_use_closed_popup_messages_text(
        &self,
    ) -> std::result::Result<Option<String>, BrowserError> {
        let messages = self.browser_use_closed_popup_messages.lock().await.clone();
        Ok(render_browser_use_closed_popup_messages_text(&messages))
    }
}

#[cfg(test)]
mod browser_use_state_tests {
    use super::{
        browser_use_pending_request_default_method, browser_use_short_target_id,
        render_browser_use_page_info_text, render_browser_use_pending_requests_text,
        render_browser_use_tabs_text, BrowserUsePageInfo, BrowserUsePendingRequest,
    };
    use crate::browser::BrowserTabInfo;

    #[test]
    fn renders_tabs_page_info_and_pending_requests_as_pretty_json() {
        let tabs = vec![BrowserTabInfo {
            tab_id: "target-ab-1".to_string(),
            title: "Example".to_string(),
            url: "https://example.com".to_string(),
            active: true,
        }];
        let page_info = BrowserUsePageInfo {
            viewport_width: 1280,
            viewport_height: 720,
            page_width: 2400,
            page_height: 3600,
            scroll_x: 0,
            scroll_y: 400,
            pixels_above: 400,
            pixels_below: 2480,
            pixels_left: 0,
            pixels_right: 1120,
        };
        let requests = vec![BrowserUsePendingRequest {
            url: "https://cdn.example.com/app.js".to_string(),
            method: browser_use_pending_request_default_method(),
            loading_duration_ms: 812,
            resource_type: Some("script".to_string()),
        }];

        let tabs_text = render_browser_use_tabs_text(&tabs).expect("tabs json");
        let page_info_text = render_browser_use_page_info_text(&page_info).expect("page info json");
        let requests_text =
            render_browser_use_pending_requests_text(&requests).expect("pending requests json");

        assert!(tabs_text.contains("\"tab_id\": \"ab-1\""));
        assert!(!tabs_text.contains("\"active\": true"));
        assert!(page_info_text.contains("\"pixels_below\": 2480"));
        assert!(requests_text.contains("\"resource_type\": \"script\""));
    }

    #[test]
    fn browser_use_short_target_id_keeps_last_four_characters() {
        assert_eq!(browser_use_short_target_id("target-0001"), "0001");
        assert_eq!(browser_use_short_target_id("abc"), "abc");
    }
}
