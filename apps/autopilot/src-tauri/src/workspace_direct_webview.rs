use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use tauri::webview::PageLoadEvent;
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Rect, Runtime,
    State, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};
#[cfg(not(target_os = "linux"))]
use tauri::WebviewBuilder;
use url::Url;

#[derive(Default)]
pub struct WorkspaceDirectWebviewManager {
    surfaces: Mutex<HashMap<String, WorkspaceDirectWebviewRecord>>,
}

#[derive(Debug, Clone)]
struct WorkspaceDirectWebviewRecord {
    label: String,
    parent_window_label: String,
    url: String,
    bounds: WorkspaceDirectWebviewBounds,
    screen_bounds: Option<WorkspaceDirectWebviewBounds>,
    mode: WorkspaceDirectWebviewMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceDirectWebviewMode {
    Child,
    OwnedWindow,
}

impl WorkspaceDirectWebviewMode {
    fn api_name(self) -> &'static str {
        match self {
            WorkspaceDirectWebviewMode::Child => "child",
            WorkspaceDirectWebviewMode::OwnedWindow => "owned-window",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDirectWebviewBounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceDirectWebviewReadyEvent {
    surface_id: String,
    url: String,
    label: String,
    mode: String,
    parent_window_label: String,
    bounds: WorkspaceDirectWebviewBounds,
    screen_bounds: Option<WorkspaceDirectWebviewBounds>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDirectWebviewState {
    surface_id: String,
    label: String,
    parent_window_label: String,
    url: String,
    mode: String,
    bounds: WorkspaceDirectWebviewBounds,
    screen_bounds: Option<WorkspaceDirectWebviewBounds>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDirectWebviewShowResult {
    state: WorkspaceDirectWebviewState,
}

fn normalize_bounds(
    bounds: WorkspaceDirectWebviewBounds,
) -> Result<WorkspaceDirectWebviewBounds, String> {
    if !bounds.x.is_finite()
        || !bounds.y.is_finite()
        || !bounds.width.is_finite()
        || !bounds.height.is_finite()
    {
        return Err("Direct workbench bounds must be finite numbers.".to_string());
    }

    Ok(WorkspaceDirectWebviewBounds {
        x: bounds.x.max(0.0),
        y: bounds.y.max(0.0),
        width: bounds.width.max(1.0),
        height: bounds.height.max(1.0),
    })
}

fn normalize_optional_bounds(
    bounds: Option<WorkspaceDirectWebviewBounds>,
) -> Result<Option<WorkspaceDirectWebviewBounds>, String> {
    bounds.map(normalize_bounds).transpose()
}

fn label_for_surface(surface_id: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    surface_id.hash(&mut hasher);
    format!("workspace-direct-{:016x}", hasher.finish())
}

fn parse_workbench_url(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|error| {
        format!(
            "Direct OpenVSCode workbench URL '{}' is not a valid URL: {}",
            url, error
        )
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        scheme => Err(format!(
            "Direct OpenVSCode workbench URL must use http or https, got '{}'.",
            scheme
        )),
    }
}

fn rect_for_bounds(bounds: &WorkspaceDirectWebviewBounds) -> Rect {
    let x = bounds.x.round().max(0.0) as i32;
    let y = bounds.y.round().max(0.0) as i32;
    let width = bounds.width.round().max(1.0) as u32;
    let height = bounds.height.round().max(1.0) as u32;
    Rect {
        position: PhysicalPosition::new(x, y).into(),
        size: PhysicalSize::new(width, height).into(),
    }
}

fn apply_child_webview_layout<R: Runtime>(
    webview: &tauri::Webview<R>,
    label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
) -> Result<(), String> {
    let rect = rect_for_bounds(bounds);
    webview.set_bounds(rect).map_err(|error| {
        format!(
            "Failed to apply direct OpenVSCode child webview bounds '{}': {}",
            label, error
        )
    })?;
    webview
        .set_position(physical_position_for_bounds(bounds))
        .map_err(|error| {
            format!(
                "Failed to position direct OpenVSCode child webview '{}': {}",
                label, error
            )
        })?;
    webview
        .set_size(physical_size_for_bounds(bounds))
        .map_err(|error| {
            format!(
                "Failed to size direct OpenVSCode child webview '{}': {}",
                label, error
            )
        })?;
    sync_child_webview_platform(webview, label, bounds);
    Ok(())
}

fn sync_child_webview_platform<R: Runtime>(
    webview: &tauri::Webview<R>,
    label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
) {
    #[cfg(target_os = "linux")]
    {
        let label = label.to_string();
        let width = bounds.width.round().max(1.0) as i32;
        let height = bounds.height.round().max(1.0) as i32;
        let _ = webview.with_webview(move |platform_webview| {
            use gtk::prelude::WidgetExt;

            let inner = platform_webview.inner();
            inner.set_size_request(width, height);
            inner.size_allocate(&gtk::Allocation::new(0, 0, width, height));
            inner.show_all();
            inner.grab_focus();
            let _ = label;
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (webview, label);
    }
}

#[cfg(not(target_os = "linux"))]
fn sync_child_container_windows<R: Runtime>(
    parent_window: &tauri::Window<R>,
    label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
) {
    let _ = (parent_window, label, bounds);
}

fn physical_position_for_bounds(
    bounds: &WorkspaceDirectWebviewBounds,
) -> PhysicalPosition<i32> {
    PhysicalPosition::new(
        bounds.x.round().max(0.0) as i32,
        bounds.y.round().max(0.0) as i32,
    )
}

fn physical_size_for_bounds(bounds: &WorkspaceDirectWebviewBounds) -> PhysicalSize<u32> {
    PhysicalSize::new(
        bounds.width.round().max(1.0) as u32,
        bounds.height.round().max(1.0) as u32,
    )
}

fn physical_position_from_xy(x: f64, y: f64) -> PhysicalPosition<i32> {
    PhysicalPosition::new(x.round() as i32, y.round() as i32)
}

fn move_owned_window_platform<R: Runtime>(
    window: &WebviewWindow<R>,
    x: f64,
    y: f64,
) {
    #[cfg(target_os = "linux")]
    {
        use gtk::prelude::GtkWindowExt;
        if let Ok(gtk_window) = window.gtk_window() {
            gtk_window.move_(x.round() as i32, y.round() as i32);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (window, x, y);
    }
}

fn state_for_record(
    surface_id: &str,
    record: &WorkspaceDirectWebviewRecord,
) -> WorkspaceDirectWebviewState {
    WorkspaceDirectWebviewState {
        surface_id: surface_id.to_string(),
        label: record.label.clone(),
        parent_window_label: record.parent_window_label.clone(),
        url: record.url.clone(),
        mode: record.mode.api_name().to_string(),
        bounds: record.bounds.clone(),
        screen_bounds: record.screen_bounds.clone(),
    }
}

fn emit_ready<R: Runtime>(
    app: &AppHandle<R>,
    surface_id: &str,
    url: &str,
    label: &str,
    mode: WorkspaceDirectWebviewMode,
    parent_window_label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: &Option<WorkspaceDirectWebviewBounds>,
) {
    eprintln!(
        "[WorkspaceDirectWebview] ready {:?} surface={} label={} bounds=({}, {}, {}, {}) screen_bounds={:?}",
        mode,
        surface_id,
        label,
        bounds.x,
        bounds.y,
        bounds.width,
        bounds.height,
        screen_bounds
    );
    let _ = app.emit(
        "workspace-direct-webview-ready",
        WorkspaceDirectWebviewReadyEvent {
            surface_id: surface_id.to_string(),
            url: url.to_string(),
            label: label.to_string(),
            mode: mode.api_name().to_string(),
            parent_window_label: parent_window_label.to_string(),
            bounds: bounds.clone(),
            screen_bounds: screen_bounds.clone(),
        },
    );
}

#[cfg(target_os = "linux")]
fn gtk_window_xid(window: &gtk::ApplicationWindow, label: &str) -> Result<x11::xlib::Window, String> {
    use gtk::prelude::{Cast, WidgetExt};

    let gdk_window = window
        .window()
        .ok_or_else(|| format!("GTK window for '{}' does not have a GDK window.", label))?;
    let x11_window = gdk_window.downcast::<gdkx11::X11Window>().map_err(|_| {
        format!(
            "GTK window for '{}' is not backed by an X11 window; direct containment requires X11.",
            label
        )
    })?;
    Ok(x11_window.xid())
}

#[cfg(target_os = "linux")]
fn reparent_child_window<R: Runtime>(
    parent_window: &WebviewWindow<R>,
    child_window: &WebviewWindow<R>,
    label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
) -> Result<(), String> {
    let parent_gtk = parent_window.gtk_window().map_err(|error| {
        format!(
            "Failed to access parent GTK window '{}' for direct containment: {}",
            parent_window.label(),
            error
        )
    })?;
    let child_gtk = child_window.gtk_window().map_err(|error| {
        format!(
            "Failed to access child GTK window '{}' for direct containment: {}",
            label, error
        )
    })?;
    let parent_xid = gtk_window_xid(&parent_gtk, parent_window.label())?;
    let child_xid = gtk_window_xid(&child_gtk, label)?;
    let x = bounds.x.round().max(0.0) as i32;
    let y = bounds.y.round().max(0.0) as i32;
    let width = bounds.width.round().max(1.0) as u32;
    let height = bounds.height.round().max(1.0) as u32;

    unsafe {
        let display = x11::xlib::XOpenDisplay(std::ptr::null());
        if display.is_null() {
            return Err("Failed to open X11 display for direct containment.".to_string());
        }
        let mut attributes: x11::xlib::XSetWindowAttributes = std::mem::zeroed();
        attributes.override_redirect = 1;
        x11::xlib::XUnmapWindow(display, child_xid);
        x11::xlib::XChangeWindowAttributes(
            display,
            child_xid,
            x11::xlib::CWOverrideRedirect,
            &mut attributes,
        );
        x11::xlib::XReparentWindow(display, child_xid, parent_xid, x, y);
        x11::xlib::XMoveResizeWindow(display, child_xid, x, y, width, height);
        x11::xlib::XMapRaised(display, child_xid);
        x11::xlib::XFlush(display);
        x11::xlib::XCloseDisplay(display);
    }

    eprintln!(
        "[WorkspaceDirectWebview] reparented child window surface label={} parent={} xid={} child_xid={} bounds=({}, {}, {}, {})",
        label,
        parent_window.label(),
        parent_xid,
        child_xid,
        x,
        y,
        width,
        height
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn unmap_child_window(window: &gtk::ApplicationWindow, label: &str) -> Result<(), String> {
    let child_xid = gtk_window_xid(window, label)?;
    unsafe {
        let display = x11::xlib::XOpenDisplay(std::ptr::null());
        if display.is_null() {
            return Err("Failed to open X11 display for direct webview unmap.".to_string());
        }
        x11::xlib::XUnmapWindow(display, child_xid);
        x11::xlib::XFlush(display);
        x11::xlib::XCloseDisplay(display);
    }
    eprintln!(
        "[WorkspaceDirectWebview] unmapped child window label={} child_xid={}",
        label, child_xid
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn invalidate_parent_window_region(
    window: &gtk::ApplicationWindow,
    label: &str,
    bounds: &WorkspaceDirectWebviewBounds,
) -> Result<(), String> {
    use gtk::prelude::WidgetExt;

    let parent_xid = gtk_window_xid(window, label)?;
    let x = bounds.x.round().max(0.0) as i32;
    let y = bounds.y.round().max(0.0) as i32;
    let width = bounds.width.round().max(1.0) as u32;
    let height = bounds.height.round().max(1.0) as u32;

    window.queue_draw_area(x, y, width as i32, height as i32);
    window.queue_draw();

    unsafe {
        let display = x11::xlib::XOpenDisplay(std::ptr::null());
        if display.is_null() {
            return Err("Failed to open X11 display for parent redraw.".to_string());
        }
        x11::xlib::XClearArea(display, parent_xid, x, y, width, height, 1);
        x11::xlib::XFlush(display);
        x11::xlib::XCloseDisplay(display);
    }

    eprintln!(
        "[WorkspaceDirectWebview] invalidated parent window label={} xid={} bounds=({}, {}, {}, {})",
        label, parent_xid, x, y, width, height
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn invalidate_parent_for_record<R: Runtime>(
    app: &AppHandle<R>,
    record: &WorkspaceDirectWebviewRecord,
) {
    if let Some(parent_window) = app.get_webview_window(&record.parent_window_label) {
        if let Ok(parent_gtk_window) = parent_window.gtk_window() {
            if let Err(error) = invalidate_parent_window_region(
                &parent_gtk_window,
                &record.parent_window_label,
                &record.bounds,
            ) {
                eprintln!(
                    "[WorkspaceDirectWebview] failed to invalidate parent window label={} surface_label={}: {}",
                    record.parent_window_label, record.label, error
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn build_child_webview<R: Runtime>(
    app: &AppHandle<R>,
    surface_id: &str,
    parent_window_label: &str,
    label: &str,
    url: Url,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: &Option<WorkspaceDirectWebviewBounds>,
) -> Result<(), String> {
    let parent_window = app.get_webview_window(parent_window_label).ok_or_else(|| {
        format!(
            "Parent webview window '{}' was not found for direct containment.",
            parent_window_label
        )
    })?;
    let app_for_load = app.clone();
    let surface_id_for_load = surface_id.to_string();
    let label_for_load = label.to_string();
    let parent_window_label_for_load = parent_window_label.to_string();
    let bounds_for_load = bounds.clone();
    let screen_bounds_for_load = screen_bounds.clone();
    let parent_window_for_load = parent_window.clone();
    let (initial_x, initial_y) =
        fallback_window_position(&parent_window, bounds, screen_bounds.as_ref())?;
    let builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(url))
        .title("Autopilot Workspace Workbench")
        .decorations(false)
        .resizable(false)
        .skip_taskbar(true)
        .devtools(workspace_direct_devtools_enabled())
        .focused(true)
        .visible(true)
        .inner_size(bounds.width, bounds.height)
        .position(initial_x, initial_y)
        .on_page_load(move |window, payload| {
            if payload.event() == PageLoadEvent::Finished {
                if let Err(error) = reparent_child_window(
                    &parent_window_for_load,
                    &window,
                    &label_for_load,
                    &bounds_for_load,
                ) {
                    eprintln!(
                        "[WorkspaceDirectWebview] failed to reparent child window surface={} label={}: {}",
                        surface_id_for_load,
                        label_for_load,
                        error
                    );
                }
                let _ = window.show();
                if workspace_direct_devtools_enabled() {
                    open_child_window_devtools(
                        &window,
                        &surface_id_for_load,
                        &label_for_load,
                    );
                }
                emit_ready(
                    &app_for_load,
                    &surface_id_for_load,
                    payload.url().as_str(),
                    &label_for_load,
                    WorkspaceDirectWebviewMode::Child,
                    &parent_window_label_for_load,
                    &bounds_for_load,
                    &screen_bounds_for_load,
                );
            }
        });
    let window = builder.build().map_err(|error| {
        format!(
            "Failed to create direct OpenVSCode contained child window '{}': {}",
            label, error
        )
    })?;
    reparent_child_window(&parent_window, &window, label, bounds)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn build_child_webview<R: Runtime>(
    app: &AppHandle<R>,
    surface_id: &str,
    parent_window_label: &str,
    label: &str,
    url: Url,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: &Option<WorkspaceDirectWebviewBounds>,
) -> Result<(), String> {
    let parent_window = app
        .get_window(parent_window_label)
        .ok_or_else(|| format!("Parent window '{}' was not found.", parent_window_label))?;
    let app_for_load = app.clone();
    let surface_id_for_load = surface_id.to_string();
    let label_for_load = label.to_string();
    let parent_window_label_for_load = parent_window_label.to_string();
    let bounds_for_load = bounds.clone();
    let screen_bounds_for_load = screen_bounds.clone();
    let parent_window_for_load = parent_window.clone();
    let builder = WebviewBuilder::new(label, WebviewUrl::External(url))
        .devtools(workspace_direct_devtools_enabled())
        .focused(true)
        .on_page_load(move |webview, payload| {
            if payload.event() == PageLoadEvent::Finished {
                let _ = webview.show();
                let _ = apply_child_webview_layout(&webview, &label_for_load, &bounds_for_load);
                sync_child_container_windows(
                    &parent_window_for_load,
                    &label_for_load,
                    &bounds_for_load,
                );
                if workspace_direct_devtools_enabled() {
                    open_child_webview_devtools(
                        &webview,
                        &surface_id_for_load,
                        &label_for_load,
                    );
                }
                emit_ready(
                    &app_for_load,
                    &surface_id_for_load,
                    payload.url().as_str(),
                    &label_for_load,
                    WorkspaceDirectWebviewMode::Child,
                    &parent_window_label_for_load,
                    &bounds_for_load,
                    &screen_bounds_for_load,
                );
            }
        });
    let webview = parent_window
        .add_child(
            builder,
            physical_position_for_bounds(bounds),
            physical_size_for_bounds(bounds),
        )
        .map_err(|error| {
            format!(
                "Failed to attach direct OpenVSCode child webview to '{}': {}",
                parent_window_label, error
            )
        })?;
    apply_child_webview_layout(&webview, label, bounds)?;
    sync_child_container_windows(&parent_window, label, bounds);
    let _ = webview.hide();
    Ok(())
}

fn fallback_window_position<R: Runtime>(
    parent_window: &WebviewWindow<R>,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: Option<&WorkspaceDirectWebviewBounds>,
) -> Result<(f64, f64), String> {
    if let Some(screen_bounds) = screen_bounds {
        return Ok((screen_bounds.x, screen_bounds.y));
    }
    let scale_factor = parent_window.scale_factor().unwrap_or(1.0).max(0.1);
    let parent_position = parent_window.outer_position().map_err(|error| {
        format!(
            "Failed to read parent window position for direct OpenVSCode fallback: {}",
            error
        )
    })?;
    Ok((
        parent_position.x as f64 / scale_factor + bounds.x,
        parent_position.y as f64 / scale_factor + bounds.y,
    ))
}

fn set_owned_window_position<R: Runtime>(
    window: &WebviewWindow<R>,
    label: &str,
    desired_x: f64,
    desired_y: f64,
) -> Result<(), String> {
    window
        .set_position(physical_position_from_xy(desired_x, desired_y))
        .map_err(|error| {
            format!(
                "Failed to position direct OpenVSCode owned window '{}': {}",
                label, error
            )
        })?;
    move_owned_window_platform(window, desired_x, desired_y);

    if let Ok(actual_position) = window.outer_position() {
        let scale_factor = window.scale_factor().unwrap_or(1.0).max(0.1);
        let actual_x = actual_position.x as f64 / scale_factor;
        let actual_y = actual_position.y as f64 / scale_factor;
        let delta_x = desired_x - actual_x;
        let delta_y = desired_y - actual_y;
        if delta_x.abs() > 1.0 || delta_y.abs() > 1.0 {
            window
                .set_position(physical_position_from_xy(
                    desired_x + delta_x,
                    desired_y + delta_y,
                ))
                .map_err(|error| {
                    format!(
                        "Failed to compensate direct OpenVSCode owned window '{}' position: {}",
                        label, error
                    )
                })?;
            move_owned_window_platform(window, desired_x + delta_x, desired_y + delta_y);
            eprintln!(
                "[WorkspaceDirectWebview] compensated owned-window position label={} desired=({}, {}) actual=({}, {}) delta=({}, {})",
                label, desired_x, desired_y, actual_x, actual_y, delta_x, delta_y
            );
        }
    }

    Ok(())
}

fn build_owned_window<R: Runtime>(
    app: &AppHandle<R>,
    surface_id: &str,
    parent_window_label: &str,
    label: &str,
    url: Url,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: &Option<WorkspaceDirectWebviewBounds>,
) -> Result<(), String> {
    let parent_window = app.get_webview_window(parent_window_label).ok_or_else(|| {
        format!(
            "Parent webview window '{}' was not found for fallback.",
            parent_window_label
        )
    })?;
    let (x, y) = fallback_window_position(&parent_window, bounds, screen_bounds.as_ref())?;
    let app_for_load = app.clone();
    let surface_id_for_load = surface_id.to_string();
    let label_for_load = label.to_string();
    let parent_window_label_for_load = parent_window_label.to_string();
    let bounds_for_load = bounds.clone();
    let screen_bounds_for_load = screen_bounds.clone();
    let desired_x_for_load = x;
    let desired_y_for_load = y;
    let builder = WebviewWindowBuilder::new(app, label, WebviewUrl::External(url))
        .title("Autopilot Workspace Workbench")
        .decorations(false)
        .resizable(false)
        .skip_taskbar(true)
        .devtools(workspace_direct_devtools_enabled())
        .focused(true)
        .visible(false)
        .position(x, y)
        .inner_size(bounds.width, bounds.height)
        .on_page_load(move |window, payload| {
            if payload.event() == PageLoadEvent::Finished {
                let _ = window.show();
                let _ = set_owned_window_position(
                    &window,
                    &label_for_load,
                    desired_x_for_load,
                    desired_y_for_load,
                );
                if workspace_direct_devtools_enabled() {
                    open_child_window_devtools(
                        &window,
                        &surface_id_for_load,
                        &label_for_load,
                    );
                }
                emit_ready(
                    &app_for_load,
                    &surface_id_for_load,
                    payload.url().as_str(),
                    &label_for_load,
                    WorkspaceDirectWebviewMode::OwnedWindow,
                    &parent_window_label_for_load,
                    &bounds_for_load,
                    &screen_bounds_for_load,
                );
            }
        });
    #[cfg(not(target_os = "linux"))]
    let builder = builder.parent(&parent_window).map_err(|error| {
            format!(
                "Failed to parent direct OpenVSCode fallback window to '{}': {}",
                parent_window_label, error
            )
        })?;
    #[cfg(target_os = "linux")]
    let builder = builder;
    let window = builder.build().map_err(|error| {
        format!(
            "Failed to create direct OpenVSCode fallback window '{}': {}",
            label, error
        )
    })?;
    set_owned_window_position(&window, label, x, y)?;
    Ok(())
}

fn prefer_owned_window() -> bool {
    match std::env::var("AUTOPILOT_WORKSPACE_DIRECT_WEBVIEW_MODE") {
        Ok(value)
            if value.eq_ignore_ascii_case("sibling")
                || value.eq_ignore_ascii_case("owned-window") =>
        {
            true
        }
        Ok(value) if value.eq_ignore_ascii_case("child") => false,
        Ok(value) => {
            eprintln!(
                "[WorkspaceDirectWebview] Ignoring unknown AUTOPILOT_WORKSPACE_DIRECT_WEBVIEW_MODE='{}'; using child webview containment.",
                value
            );
            false
        }
        _ => false,
    }
}

fn workspace_direct_devtools_enabled() -> bool {
    crate::is_env_var_truthy("AUTOPILOT_WORKSPACE_DEVTOOLS")
        || crate::is_env_var_truthy("AUTOPILOT_OPENVSCODE_DEVTOOLS")
}

#[cfg(debug_assertions)]
fn open_child_window_devtools<R: Runtime>(
    window: &WebviewWindow<R>,
    surface_id: &str,
    label: &str,
) {
    window.open_devtools();
    eprintln!(
        "[WorkspaceDirectWebview] opened devtools for surface={} label={}",
        surface_id, label
    );
}

#[cfg(not(debug_assertions))]
fn open_child_window_devtools<R: Runtime>(
    _window: &WebviewWindow<R>,
    surface_id: &str,
    label: &str,
) {
    eprintln!(
        "[WorkspaceDirectWebview] devtools requested for surface={} label={} but this build was not compiled with devtools support",
        surface_id, label
    );
}

#[cfg(not(target_os = "linux"))]
#[cfg(debug_assertions)]
fn open_child_webview_devtools<R: Runtime>(
    webview: &tauri::Webview<R>,
    surface_id: &str,
    label: &str,
) {
    webview.open_devtools();
    eprintln!(
        "[WorkspaceDirectWebview] opened devtools for surface={} label={}",
        surface_id, label
    );
}

#[cfg(not(target_os = "linux"))]
#[cfg(not(debug_assertions))]
fn open_child_webview_devtools<R: Runtime>(
    _webview: &tauri::Webview<R>,
    surface_id: &str,
    label: &str,
) {
    eprintln!(
        "[WorkspaceDirectWebview] devtools requested for surface={} label={} but this build was not compiled with devtools support",
        surface_id, label
    );
}

#[cfg(not(debug_assertions))]
fn devtools_unavailable_error() -> String {
    "Direct OpenVSCode workbench DevTools are only available in debug desktop builds.".to_string()
}

fn read_record(
    manager: &WorkspaceDirectWebviewManager,
    surface_id: &str,
) -> Result<Option<WorkspaceDirectWebviewRecord>, String> {
    let surfaces = manager
        .surfaces
        .lock()
        .map_err(|_| "Failed to lock direct OpenVSCode webview state.".to_string())?;
    Ok(surfaces.get(surface_id).cloned())
}

fn write_record(
    manager: &WorkspaceDirectWebviewManager,
    surface_id: &str,
    record: WorkspaceDirectWebviewRecord,
) -> Result<(), String> {
    let mut surfaces = manager
        .surfaces
        .lock()
        .map_err(|_| "Failed to lock direct OpenVSCode webview state.".to_string())?;
    surfaces.insert(surface_id.to_string(), record);
    Ok(())
}

fn remove_record(
    manager: &WorkspaceDirectWebviewManager,
    surface_id: &str,
) -> Result<Option<WorkspaceDirectWebviewRecord>, String> {
    let mut surfaces = manager
        .surfaces
        .lock()
        .map_err(|_| "Failed to lock direct OpenVSCode webview state.".to_string())?;
    Ok(surfaces.remove(surface_id))
}

fn handle_exists<R: Runtime>(app: &AppHandle<R>, record: &WorkspaceDirectWebviewRecord) -> bool {
    match record.mode {
        WorkspaceDirectWebviewMode::Child => app.get_webview(&record.label).is_some(),
        WorkspaceDirectWebviewMode::OwnedWindow => app.get_webview_window(&record.label).is_some(),
    }
}

fn update_record_bounds<R: Runtime>(
    app: &AppHandle<R>,
    record: &WorkspaceDirectWebviewRecord,
    bounds: &WorkspaceDirectWebviewBounds,
    screen_bounds: Option<&WorkspaceDirectWebviewBounds>,
) -> Result<(), String> {
    match record.mode {
        WorkspaceDirectWebviewMode::Child => {
            #[cfg(target_os = "linux")]
            {
                if let (Some(window), Some(parent_window)) = (
                    app.get_webview_window(&record.label),
                    app.get_webview_window(&record.parent_window_label),
                ) {
                    reparent_child_window(&parent_window, &window, &record.label, bounds)?;
                    return Ok(());
                }
            }
            if let Some(webview) = app.get_webview(&record.label) {
                apply_child_webview_layout(&webview, &record.label, bounds)?;
            }
        }
        WorkspaceDirectWebviewMode::OwnedWindow => {
            if let Some(window) = app.get_webview_window(&record.label) {
                if let Some(parent_window) = app.get_webview_window(&record.parent_window_label) {
                    let (x, y) =
                        fallback_window_position(&parent_window, bounds, screen_bounds)?;
                    set_owned_window_position(&window, &record.label, x, y)?;
                }
                window
                    .set_size(LogicalSize::new(bounds.width, bounds.height))
                    .map_err(|error| {
                        format!(
                            "Failed to size direct OpenVSCode fallback window '{}': {}",
                            record.label, error
                        )
                    })?;
            }
        }
    }
    Ok(())
}

fn show_record<R: Runtime>(
    app: &AppHandle<R>,
    record: &WorkspaceDirectWebviewRecord,
) -> Result<(), String> {
    match record.mode {
        WorkspaceDirectWebviewMode::Child => {
            #[cfg(target_os = "linux")]
            {
                if let (Some(window), Some(parent_window)) = (
                    app.get_webview_window(&record.label),
                    app.get_webview_window(&record.parent_window_label),
                ) {
                    reparent_child_window(
                        &parent_window,
                        &window,
                        &record.label,
                        &record.bounds,
                    )?;
                    window.show().map_err(|error| {
                        format!(
                            "Failed to show direct OpenVSCode contained child window '{}': {}",
                            record.label, error
                        )
                    })?;
                    return Ok(());
                }
            }
            if let Some(webview) = app.get_webview(&record.label) {
                webview.show().map_err(|error| {
                    format!(
                        "Failed to show direct OpenVSCode child webview '{}': {}",
                        record.label, error
                    )
                })?;
                apply_child_webview_layout(&webview, &record.label, &record.bounds)?;
            }
        }
        WorkspaceDirectWebviewMode::OwnedWindow => {
            if let Some(window) = app.get_webview_window(&record.label) {
                window.show().map_err(|error| {
                    format!(
                        "Failed to show direct OpenVSCode fallback window '{}': {}",
                        record.label, error
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn close_record<R: Runtime>(
    app: &AppHandle<R>,
    record: &WorkspaceDirectWebviewRecord,
) -> Result<(), String> {
    match record.mode {
        WorkspaceDirectWebviewMode::Child => {
            #[cfg(target_os = "linux")]
            {
                if let Some(window) = app.get_webview_window(&record.label) {
                    if let Ok(gtk_window) = window.gtk_window() {
                        let _ = unmap_child_window(&gtk_window, &record.label);
                    }
                    invalidate_parent_for_record(app, record);
                    eprintln!(
                        "[WorkspaceDirectWebview] destroying Child surface label={}",
                        record.label
                    );
                    window.destroy().map_err(|error| {
                        format!(
                            "Failed to destroy direct OpenVSCode contained child window '{}': {}",
                            record.label, error
                        )
                    })?;
                    return Ok(());
                }
            }
            if let Some(webview) = app.get_webview(&record.label) {
                eprintln!(
                    "[WorkspaceDirectWebview] closing Child webview label={}",
                    record.label
                );
                webview.close().map_err(|error| {
                    format!(
                        "Failed to close direct OpenVSCode child webview '{}': {}",
                        record.label, error
                    )
                })?;
            }
        }
        WorkspaceDirectWebviewMode::OwnedWindow => {
            if let Some(window) = app.get_webview_window(&record.label) {
                eprintln!(
                    "[WorkspaceDirectWebview] destroying OwnedWindow surface label={}",
                    record.label
                );
                window.destroy().map_err(|error| {
                    format!(
                        "Failed to destroy direct OpenVSCode fallback window '{}': {}",
                        record.label, error
                    )
                })?;
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn workspace_direct_webview_get_state(
    surface_id: String,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<Option<WorkspaceDirectWebviewState>, String> {
    Ok(read_record(&manager, &surface_id)?.map(|record| state_for_record(&surface_id, &record)))
}

#[tauri::command]
pub fn workspace_direct_webview_open_devtools<R: Runtime>(
    surface_id: String,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<WorkspaceDirectWebviewState, String> {
    let record = read_record(&manager, &surface_id)?
        .ok_or_else(|| format!("Direct OpenVSCode surface '{}' was not found.", surface_id))?;

    #[cfg(debug_assertions)]
    {
        match record.mode {
            WorkspaceDirectWebviewMode::Child => {
                #[cfg(target_os = "linux")]
                {
                    let window = app.get_webview_window(&record.label).ok_or_else(|| {
                        format!(
                            "Direct OpenVSCode contained child window '{}' was not found.",
                            record.label
                        )
                    })?;
                    open_child_window_devtools(&window, &surface_id, &record.label);
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let webview = app.get_webview(&record.label).ok_or_else(|| {
                        format!(
                            "Direct OpenVSCode child webview '{}' was not found.",
                            record.label
                        )
                    })?;
                    open_child_webview_devtools(&webview, &surface_id, &record.label);
                }
            }
            WorkspaceDirectWebviewMode::OwnedWindow => {
                let window = app.get_webview_window(&record.label).ok_or_else(|| {
                    format!(
                        "Direct OpenVSCode diagnostic window '{}' was not found.",
                        record.label
                    )
                })?;
                open_child_window_devtools(&window, &surface_id, &record.label);
            }
        }
        Ok(state_for_record(&surface_id, &record))
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = app;
        Err(devtools_unavailable_error())
    }
}

#[tauri::command]
pub fn workspace_direct_webview_show<R: Runtime>(
    surface_id: String,
    parent_window_label: String,
    url: String,
    bounds: WorkspaceDirectWebviewBounds,
    screen_bounds: Option<WorkspaceDirectWebviewBounds>,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<WorkspaceDirectWebviewShowResult, String> {
    let bounds = normalize_bounds(bounds)?;
    let screen_bounds = normalize_optional_bounds(screen_bounds)?;
    eprintln!(
        "[WorkspaceDirectWebview] show requested surface={} parent={} bounds=({}, {}, {}, {}) screen_bounds={:?}",
        surface_id,
        parent_window_label,
        bounds.x,
        bounds.y,
        bounds.width,
        bounds.height,
        screen_bounds
    );
    if let Some(existing) = read_record(&manager, &surface_id)? {
        if existing.url == url
            && existing.parent_window_label == parent_window_label
            && handle_exists(&app, &existing)
        {
            let mut next = existing.clone();
            update_record_bounds(&app, &existing, &bounds, screen_bounds.as_ref())?;
            show_record(&app, &existing)?;
            next.bounds = bounds.clone();
            next.screen_bounds = screen_bounds.clone();
            write_record(&manager, &surface_id, next.clone())?;
            eprintln!(
                "[WorkspaceDirectWebview] reused {:?} surface={} label={}",
                next.mode, surface_id, next.label
            );
            return Ok(WorkspaceDirectWebviewShowResult {
                state: state_for_record(&surface_id, &next),
            });
        }
        let _ = close_record(&app, &existing);
        let _ = remove_record(&manager, &surface_id);
    }

    let parsed_url = parse_workbench_url(&url)?;
    let label = label_for_surface(&surface_id);
    let mode = if prefer_owned_window() {
        eprintln!(
            "[WorkspaceDirectWebview] using diagnostic owned-window mode for direct OpenVSCode containment."
        );
        build_owned_window(
            &app,
            &surface_id,
            &parent_window_label,
            &label,
            parsed_url,
            &bounds,
            &screen_bounds,
        )?;
        WorkspaceDirectWebviewMode::OwnedWindow
    } else {
        build_child_webview(
            &app,
            &surface_id,
            &parent_window_label,
            &label,
            parsed_url.clone(),
            &bounds,
            &screen_bounds,
        )?;
        WorkspaceDirectWebviewMode::Child
    };
    eprintln!(
        "[WorkspaceDirectWebview] created {:?} surface={} label={}",
        mode, surface_id, label
    );

    let record = WorkspaceDirectWebviewRecord {
        label,
        parent_window_label,
        url,
        bounds,
        screen_bounds,
        mode,
    };
    let state = state_for_record(&surface_id, &record);
    write_record(
        &manager,
        &surface_id,
        record,
    )?;
    Ok(WorkspaceDirectWebviewShowResult { state })
}

#[tauri::command]
pub fn workspace_direct_webview_update_bounds<R: Runtime>(
    surface_id: String,
    bounds: WorkspaceDirectWebviewBounds,
    screen_bounds: Option<WorkspaceDirectWebviewBounds>,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<(), String> {
    let bounds = normalize_bounds(bounds)?;
    let screen_bounds = normalize_optional_bounds(screen_bounds)?;
    if let Some(mut record) = read_record(&manager, &surface_id)? {
        update_record_bounds(&app, &record, &bounds, screen_bounds.as_ref())?;
        record.bounds = bounds;
        record.screen_bounds = screen_bounds;
        write_record(&manager, &surface_id, record)?;
    }
    Ok(())
}

#[tauri::command]
pub fn workspace_direct_webview_focus<R: Runtime>(
    surface_id: String,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<(), String> {
    if let Some(record) = read_record(&manager, &surface_id)? {
        match record.mode {
            WorkspaceDirectWebviewMode::Child => {
                #[cfg(target_os = "linux")]
                {
                    if let Some(window) = app.get_webview_window(&record.label) {
                        window.set_focus().map_err(|error| {
                            format!(
                                "Failed to focus direct OpenVSCode contained child window '{}': {}",
                                record.label, error
                            )
                        })?;
                        return Ok(());
                    }
                }
                if let Some(webview) = app.get_webview(&record.label) {
                    webview.set_focus().map_err(|error| {
                        format!(
                            "Failed to focus direct OpenVSCode child webview '{}': {}",
                            record.label, error
                        )
                    })?;
                }
            }
            WorkspaceDirectWebviewMode::OwnedWindow => {
                if let Some(window) = app.get_webview_window(&record.label) {
                    window.set_focus().map_err(|error| {
                        format!(
                            "Failed to focus direct OpenVSCode fallback window '{}': {}",
                            record.label, error
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn workspace_direct_webview_hide<R: Runtime>(
    surface_id: String,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<(), String> {
    if let Some(record) = read_record(&manager, &surface_id)? {
        eprintln!(
            "[WorkspaceDirectWebview] hide requested {:?} surface={} label={}",
            record.mode, surface_id, record.label
        );
        match record.mode {
            WorkspaceDirectWebviewMode::Child => {
                #[cfg(target_os = "linux")]
                {
                    if let Some(window) = app.get_webview_window(&record.label) {
                        if let Ok(gtk_window) = window.gtk_window() {
                            let _ = unmap_child_window(&gtk_window, &record.label);
                        }
                        invalidate_parent_for_record(&app, &record);
                        let _ = window.hide();
                        return Ok(());
                    }
                }
                if let Some(webview) = app.get_webview(&record.label) {
                    let _ = webview.hide();
                }
            }
            WorkspaceDirectWebviewMode::OwnedWindow => {
                if let Some(window) = app.get_webview_window(&record.label) {
                    let _ = window.hide();
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn workspace_direct_webview_destroy<R: Runtime>(
    surface_id: String,
    app: AppHandle<R>,
    manager: State<WorkspaceDirectWebviewManager>,
) -> Result<(), String> {
    if let Some(record) = remove_record(&manager, &surface_id)? {
        eprintln!(
            "[WorkspaceDirectWebview] destroy requested {:?} surface={} label={}",
            record.mode, surface_id, record.label
        );
        close_record(&app, &record)?;
    }
    Ok(())
}
