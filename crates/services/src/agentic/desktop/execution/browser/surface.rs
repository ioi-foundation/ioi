use super::super::ToolExecutor;
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_drivers::browser::context::BrowserContentFrame;
use ioi_drivers::gui::accessibility::Rect;

#[derive(Debug, Clone, Copy)]
pub(in crate::agentic::desktop::execution) struct BrowserSurfaceRegions {
    pub viewport_rect: Rect,
}

impl BrowserSurfaceRegions {
    pub fn viewport_center(self) -> (u32, u32) {
        let cx = self.viewport_rect.x + (self.viewport_rect.width / 2);
        let cy = self.viewport_rect.y + (self.viewport_rect.height / 2);
        (cx.max(0) as u32, cy.max(0) as u32)
    }
}

pub(in crate::agentic::desktop::execution) fn is_probable_browser_window(
    title: &str,
    app_name: &str,
) -> bool {
    let title_lc = title.to_ascii_lowercase();
    let app_lc = app_name.to_ascii_lowercase();
    let browsers = [
        "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc",
    ];
    browsers
        .iter()
        .any(|name| title_lc.contains(name) || app_lc.contains(name))
}

fn to_rect_from_window(window: &WindowInfo) -> Option<Rect> {
    if window.width <= 0 || window.height <= 0 {
        return None;
    }
    Some(Rect {
        x: window.x,
        y: window.y,
        width: window.width,
        height: window.height,
    })
}

fn to_rect_from_content_frame(frame: BrowserContentFrame) -> Option<Rect> {
    let width = frame.rect.width.round() as i32;
    let height = frame.rect.height.round() as i32;
    if width <= 0 || height <= 0 {
        return None;
    }

    Some(Rect {
        x: frame.rect.x.round() as i32,
        y: frame.rect.y.round() as i32,
        width,
        height,
    })
}

fn clamp_rect_to_bounds(rect: Rect, bounds: Rect) -> Option<Rect> {
    let left = rect.x.max(bounds.x);
    let top = rect.y.max(bounds.y);
    let right = (rect.x + rect.width).min(bounds.x + bounds.width);
    let bottom = (rect.y + rect.height).min(bounds.y + bounds.height);

    let width = right - left;
    let height = bottom - top;
    if width <= 0 || height <= 0 {
        return None;
    }

    Some(Rect {
        x: left,
        y: top,
        width,
        height,
    })
}

pub(in crate::agentic::desktop::execution) fn estimate_browser_surface_regions(
    window: &WindowInfo,
    content_rect: Option<Rect>,
) -> Option<BrowserSurfaceRegions> {
    let window_rect = to_rect_from_window(window)?;
    let heur_chrome = ((window_rect.height as f32 * 0.14).round() as i32)
        .clamp(72, 180)
        .min((window_rect.height - 24).max(24));
    let heur_viewport = Rect {
        x: window_rect.x + 4,
        y: window_rect.y + heur_chrome,
        width: (window_rect.width - 8).max(16),
        height: (window_rect.height - heur_chrome - 4).max(16),
    };

    let viewport_rect = if let Some(content) = content_rect {
        if let Some(clamped) = clamp_rect_to_bounds(content, window_rect) {
            let top_gap = clamped.y - window_rect.y;
            let left_gap = (clamped.x - window_rect.x).abs();
            let width_ratio = clamped.width as f32 / window_rect.width.max(1) as f32;
            let height_ratio = clamped.height as f32 / window_rect.height.max(1) as f32;
            let frame_matches_active_window = (16..=260).contains(&top_gap)
                && left_gap <= 40
                && width_ratio >= 0.5
                && height_ratio >= 0.4;

            if clamped.height >= 64 && clamped.width >= 120 && frame_matches_active_window {
                clamped
            } else {
                heur_viewport
            }
        } else {
            heur_viewport
        }
    } else {
        heur_viewport
    };

    Some(BrowserSurfaceRegions { viewport_rect })
}

pub(in crate::agentic::desktop::execution) async fn browser_surface_regions(
    exec: &ToolExecutor,
) -> Option<BrowserSurfaceRegions> {
    let window = exec.active_window.as_ref()?;
    if !is_probable_browser_window(&window.title, &window.app_name) {
        return None;
    }

    let content_rect = exec
        .browser
        .get_content_frame()
        .await
        .ok()
        .and_then(to_rect_from_content_frame);

    estimate_browser_surface_regions(window, content_rect)
}
