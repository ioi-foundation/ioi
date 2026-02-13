// apps/autopilot/src-tauri/src/windows.rs

#[cfg(target_os = "linux")]
use gtk::{
    gdk,
    prelude::{GtkWindowExt, WidgetExt},
};
use once_cell::sync::Lazy;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::{
    ffi::{CStr, CString},
    mem,
    path::PathBuf,
    ptr,
};
use tauri::{AppHandle, Manager, WebviewWindow};
#[cfg(target_os = "linux")]
use x11::xlib;

// ============================================
// DOCK STATE MANAGEMENT
// ============================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DockPosition {
    Right,  // Docked to right edge of screen
    Center, // Centered spotlight mode
    Float,  // Free-floating (user moved it)
}

#[derive(Debug, Clone, Copy)]
pub struct SpotlightLayout {
    pub dock_position: DockPosition,
    pub sidebar_visible: bool,
    pub artifact_panel_visible: bool,
}

impl Default for SpotlightLayout {
    fn default() -> Self {
        Self {
            dock_position: DockPosition::Right,
            sidebar_visible: false,
            artifact_panel_visible: false,
        }
    }
}

// Global layout state
static SPOTLIGHT_LAYOUT: Lazy<Mutex<SpotlightLayout>> =
    Lazy::new(|| Mutex::new(SpotlightLayout::default()));

#[cfg(target_os = "linux")]
static WAYLAND_POSITION_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static COSMIC_GEOMETRY_OVERRIDE_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
const SPOTLIGHT_WM_CLASS_INSTANCE: &str = "autopilot";
#[cfg(target_os = "linux")]
const SPOTLIGHT_WM_CLASS_NAME: &str = "Autopilot";
#[cfg(target_os = "linux")]
const SPOTLIGHT_WM_TITLE: &str = "Autopilot";

fn geometry_debug_enabled() -> bool {
    std::env::var("AUTOPILOT_GEOMETRY_DEBUG")
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_is_cosmic_session() -> bool {
    for key in [
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
    ] {
        if let Ok(value) = std::env::var(key) {
            if value
                .split(':')
                .any(|entry| entry.trim().eq_ignore_ascii_case("cosmic"))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn linux_is_cosmic_session() -> bool {
    false
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct CosmicTilingExceptionRule {
    appid: String,
    titles: Vec<String>,
}

#[cfg(target_os = "linux")]
fn cosmic_tiling_exception_custom_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))?,
    };
    Some(base.join("cosmic/com.system76.CosmicSettings.WindowRules/v1/tiling_exception_custom"))
}

#[cfg(target_os = "linux")]
fn rule_exists(rules: &[CosmicTilingExceptionRule], appid: &str) -> bool {
    rules.iter().any(|rule| {
        rule.appid == appid
            && rule
                .titles
                .iter()
                .any(|title| title == ".*" || title == "^.*$")
    })
}

#[cfg(target_os = "linux")]
fn load_cosmic_rules(path: &std::path::Path) -> Option<Vec<CosmicTilingExceptionRule>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) => {
            eprintln!(
                "[Autopilot] Could not read COSMIC tiling exceptions at '{}': {}",
                path.display(),
                err
            );
            return None;
        }
    };
    if raw.trim().is_empty() {
        return Some(Vec::new());
    }
    match ron::de::from_str::<Vec<CosmicTilingExceptionRule>>(&raw) {
        Ok(rules) => Some(rules),
        Err(err) => {
            eprintln!(
                "[Autopilot] Could not parse COSMIC tiling exceptions at '{}': {}",
                path.display(),
                err
            );
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn write_cosmic_rules(
    path: &std::path::Path,
    rules: &[CosmicTilingExceptionRule],
) -> Result<(), String> {
    let serialized = ron::ser::to_string_pretty(rules, ron::ser::PrettyConfig::default())
        .map_err(|e| format!("serialize failed: {}", e))?;
    let temp_path = path.with_extension("tmp.autopilot");
    std::fs::write(&temp_path, format!("{}\n", serialized))
        .map_err(|e| format!("write temp failed: {}", e))?;
    std::fs::rename(&temp_path, path).map_err(|e| format!("rename failed: {}", e))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn ensure_cosmic_tiling_exception_rules() {
    if !linux_is_cosmic_session() {
        return;
    }

    let Some(path) = cosmic_tiling_exception_custom_path() else {
        eprintln!("[Autopilot] Could not resolve COSMIC config directory for tiling exceptions.");
        return;
    };

    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            eprintln!(
                "[Autopilot] Failed to create COSMIC rules directory '{}': {}",
                parent.display(),
                err
            );
            return;
        }
    }

    let mut rules = if path.exists() {
        match load_cosmic_rules(&path) {
            Some(existing) => existing,
            None => return,
        }
    } else {
        Vec::new()
    };

    let required_appids = [
        "autopilot",
        "Autopilot",
        "ai.ioi.autopilot",
        "ai\\.ioi\\.autopilot",
    ];
    let mut changed = false;
    for appid in required_appids {
        if !rule_exists(&rules, appid) {
            rules.push(CosmicTilingExceptionRule {
                appid: appid.to_string(),
                titles: vec![".*".to_string()],
            });
            changed = true;
        }
    }

    if !changed {
        return;
    }

    if let Err(err) = write_cosmic_rules(&path, &rules) {
        eprintln!(
            "[Autopilot] Failed to update COSMIC tiling exceptions at '{}': {}",
            path.display(),
            err
        );
        return;
    }

    println!(
        "[Autopilot] Ensured COSMIC tiling exceptions for Spotlight docking at '{}'",
        path.display()
    );
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_cosmic_tiling_exception_rules() {}

#[cfg(target_os = "linux")]
fn linux_is_x11_backend() -> bool {
    let forced_x11 = std::env::var("WINIT_UNIX_BACKEND")
        .map(|v| v.eq_ignore_ascii_case("x11"))
        .unwrap_or(false)
        || std::env::var("GDK_BACKEND")
            .map(|v| {
                v.split(',')
                    .any(|entry| entry.trim().eq_ignore_ascii_case("x11"))
            })
            .unwrap_or(false);
    if forced_x11 {
        return true;
    }

    let xdg_x11 = std::env::var("XDG_SESSION_TYPE")
        .map(|v| v.eq_ignore_ascii_case("x11"))
        .unwrap_or(false);
    let has_wayland = std::env::var("WAYLAND_DISPLAY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let has_x_display = std::env::var("DISPLAY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    xdg_x11 || (has_x_display && !has_wayland)
}

#[cfg(not(target_os = "linux"))]
fn linux_is_x11_backend() -> bool {
    false
}

#[cfg(target_os = "linux")]
unsafe fn x11_string_and_free(raw: *mut std::os::raw::c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    let value = CStr::from_ptr(raw).to_string_lossy().trim().to_string();
    xlib::XFree(raw as *mut _);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "linux")]
unsafe fn x11_window_is_viewable(display: *mut xlib::Display, window: xlib::Window) -> bool {
    let mut attrs: xlib::XWindowAttributes = mem::zeroed();
    xlib::XGetWindowAttributes(display, window, &mut attrs) != 0
        && attrs.map_state == xlib::IsViewable
}

#[cfg(target_os = "linux")]
unsafe fn x11_window_title_matches(display: *mut xlib::Display, window: xlib::Window) -> bool {
    let mut name: *mut std::os::raw::c_char = ptr::null_mut();
    if xlib::XFetchName(display, window, &mut name) == 0 {
        return false;
    }
    x11_string_and_free(name)
        .map(|t| t.eq_ignore_ascii_case(SPOTLIGHT_WM_TITLE))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
unsafe fn x11_window_class_matches(display: *mut xlib::Display, window: xlib::Window) -> bool {
    let mut class_hint: xlib::XClassHint = mem::zeroed();
    if xlib::XGetClassHint(display, window, &mut class_hint) == 0 {
        return false;
    }

    let instance = x11_string_and_free(class_hint.res_name).unwrap_or_default();
    let class = x11_string_and_free(class_hint.res_class).unwrap_or_default();

    instance.eq_ignore_ascii_case(SPOTLIGHT_WM_CLASS_INSTANCE)
        && class.eq_ignore_ascii_case(SPOTLIGHT_WM_CLASS_NAME)
}

#[cfg(target_os = "linux")]
unsafe fn x11_find_spotlight_window(
    display: *mut xlib::Display,
    root: xlib::Window,
    depth: usize,
) -> Option<xlib::Window> {
    if depth > 7 {
        return None;
    }

    let mut root_return: xlib::Window = 0;
    let mut parent_return: xlib::Window = 0;
    let mut children: *mut xlib::Window = ptr::null_mut();
    let mut nchildren: u32 = 0;

    if xlib::XQueryTree(
        display,
        root,
        &mut root_return,
        &mut parent_return,
        &mut children,
        &mut nchildren,
    ) == 0
    {
        return None;
    }

    let mut found = None;

    if !children.is_null() && nchildren > 0 {
        let children_slice = std::slice::from_raw_parts(children, nchildren as usize);
        // Last child is typically the top-most (most recently mapped) window.
        for &child in children_slice.iter().rev() {
            if x11_window_is_viewable(display, child)
                && x11_window_class_matches(display, child)
                && x11_window_title_matches(display, child)
            {
                found = Some(child);
                break;
            }
            if let Some(child_match) = x11_find_spotlight_window(display, child, depth + 1) {
                found = Some(child_match);
                break;
            }
        }
    }

    if !children.is_null() {
        xlib::XFree(children as *mut _);
    }

    found
}

#[cfg(target_os = "linux")]
fn force_x11_spotlight_geometry(x: i32, y: i32, width: u32, height: u32) {
    if !linux_is_x11_backend() {
        return;
    }

    unsafe {
        let display = xlib::XOpenDisplay(ptr::null());
        if display.is_null() {
            return;
        }

        let root = xlib::XDefaultRootWindow(display);
        if let Some(target) = x11_find_spotlight_window(display, root, 0) {
            // Ask the WM directly via EWMH first; some compositors ignore direct
            // client-side configure calls unless this request path is used.
            if let Ok(net_moveresize_name) = CString::new("_NET_MOVERESIZE_WINDOW") {
                let net_moveresize =
                    xlib::XInternAtom(display, net_moveresize_name.as_ptr(), xlib::False);
                if net_moveresize != 0 {
                    let mut event = xlib::XClientMessageEvent {
                        type_: xlib::ClientMessage,
                        serial: 0,
                        send_event: xlib::True,
                        display,
                        window: target,
                        message_type: net_moveresize,
                        format: 32,
                        data: xlib::ClientMessageData::new(),
                    };
                    let gravity_and_flags = (xlib::NorthWestGravity as std::os::raw::c_long)
                        | ((1 << 8) | (1 << 9) | (1 << 10) | (1 << 11));
                    event.data.set_long(0, gravity_and_flags);
                    event.data.set_long(1, x as std::os::raw::c_long);
                    event.data.set_long(2, y as std::os::raw::c_long);
                    event.data.set_long(3, width as std::os::raw::c_long);
                    event.data.set_long(4, height as std::os::raw::c_long);

                    let mut xev: xlib::XEvent = mem::zeroed();
                    xev.client_message = event;
                    let _ = xlib::XSendEvent(
                        display,
                        root,
                        xlib::False,
                        xlib::SubstructureRedirectMask | xlib::SubstructureNotifyMask,
                        &mut xev,
                    );
                }
            }

            xlib::XMoveResizeWindow(display, target, x, y, width, height);
            xlib::XRaiseWindow(display, target);
            xlib::XSync(display, xlib::False);

            if geometry_debug_enabled() {
                println!(
                    "[Autopilot] X11 fallback target={}x{}@{},{} id=0x{:x}",
                    width, height, x, y, target
                );
            }
        } else if geometry_debug_enabled() {
            println!(
                "[Autopilot] X11 fallback could not find Spotlight window for WM_CLASS='{}/{}' WM_NAME='{}'",
                SPOTLIGHT_WM_CLASS_INSTANCE, SPOTLIGHT_WM_CLASS_NAME, SPOTLIGHT_WM_TITLE
            );
        }

        xlib::XCloseDisplay(display);
    }
}

#[cfg(not(target_os = "linux"))]
fn force_x11_spotlight_geometry(_x: i32, _y: i32, _width: u32, _height: u32) {}

#[cfg(target_os = "linux")]
fn apply_linux_window_hints(window: &WebviewWindow, layout: &SpotlightLayout) {
    if let Ok(gtk_window) = window.gtk_window() {
        let cosmic_x11 = linux_is_cosmic_session() && linux_is_x11_backend();

        if layout.dock_position == DockPosition::Float {
            gtk_window.set_type_hint(gdk::WindowTypeHint::Normal);
            gtk_window.set_skip_taskbar_hint(false);
            gtk_window.set_skip_pager_hint(false);
            if cosmic_x11 {
                gtk_window.realize();
                if let Some(gdk_window) = gtk_window.window() {
                    gdk_window.set_override_redirect(false);
                }
            }
        } else {
            // COSMIC tends to center normal app windows. Utility keeps overlay-like
            // behavior while allowing explicit move/resize requests.
            let hint = if linux_is_cosmic_session() {
                gdk::WindowTypeHint::Utility
            } else {
                gdk::WindowTypeHint::Dock
            };
            gtk_window.set_type_hint(hint);
            gtk_window.set_skip_taskbar_hint(true);
            gtk_window.set_skip_pager_hint(true);
            gtk_window.set_keep_above(true);
            gtk_window.set_gravity(gdk::Gravity::NorthWest);
            gtk_window.set_accept_focus(true);
            gtk_window.set_focus_on_map(true);

            // On COSMIC/X11, request override-redirect for dock mode to bypass
            // compositor-managed placement of regular toplevel windows.
            if cosmic_x11 {
                gtk_window.realize();
                if let Some(gdk_window) = gtk_window.window() {
                    gdk_window.set_override_redirect(true);
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_window_hints(_window: &WebviewWindow, _layout: &SpotlightLayout) {}

// Layout constants (logical pixels)
const BASE_WIDTH: f64 = 450.0;
const SIDEBAR_WIDTH: f64 = 260.0;
const ARTIFACT_PANEL_WIDTH: f64 = 400.0;
const SPOTLIGHT_HEIGHT: f64 = 600.0;
const VERTICAL_MARGIN: f64 = 0.0;

// Linux taskbar margin - typical panel height
#[cfg(target_os = "linux")]
const TASKBAR_MARGIN: f64 = 48.0;
#[cfg(not(target_os = "linux"))]
const TASKBAR_MARGIN: f64 = 0.0;

// ============================================
// HELPER FUNCTIONS
// ============================================

/// Get the monitor that the spotlight window is on (or should be on)
fn get_target_monitor(app: &AppHandle) -> Option<tauri::Monitor> {
    // Priority: spotlight's current monitor > studio's monitor > primary
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.current_monitor() {
            return Some(monitor);
        }
    }

    if let Some(studio) = app.get_webview_window("studio") {
        if let Ok(Some(monitor)) = studio.current_monitor() {
            return Some(monitor);
        }
    }

    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            return Some(monitor);
        }
    }

    if let Ok(monitors) = app.available_monitors() {
        if let Some(monitor) = monitors.into_iter().next() {
            return Some(monitor);
        }
    }

    None
}

/// Apply geometry changes with platform-specific ordering and safety.
/// Uses physical pixels to avoid backend-specific logical scaling ambiguity.
fn set_window_geometry(
    window: &WebviewWindow,
    x_px: f64,
    y_px: f64,
    width_px: f64,
    height_px: f64,
) {
    let width = width_px.max(1.0).round() as u32;
    let height = height_px.max(1.0).round() as u32;
    let x = x_px.round() as i32;
    let y = y_px.round() as i32;

    // 1. Set Size first
    let _ = window.set_size(tauri::Size::Physical(tauri::PhysicalSize { width, height }));

    // 2. Set Position
    // On Linux/X11, setting position immediately after size might race if the WM compensates.
    // We defer the position update slightly to ensure it overrides any auto-placement or clamping
    // based on the old geometry.
    #[cfg(target_os = "linux")]
    {
        let w_handle = window.clone();
        let debug = geometry_debug_enabled();
        let width_for_log = width;
        let height_for_log = height;
        let x_for_log = x;
        let y_for_log = y;
        tauri::async_runtime::spawn(async move {
            // COSMIC/X11 can ignore toolkit-level coordinates; this fallback uses
            // WM_CLASS/WM_NAME + Xlib to reassert target geometry.
            force_x11_spotlight_geometry(x, y, width, height);

            // Staggered retries handle WMs that asynchronously re-place windows.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let _ =
                w_handle.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
            force_x11_spotlight_geometry(x, y, width, height);

            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ =
                w_handle.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
            force_x11_spotlight_geometry(x, y, width, height);

            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            let _ =
                w_handle.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
            force_x11_spotlight_geometry(x, y, width, height);

            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let _ =
                w_handle.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
            force_x11_spotlight_geometry(x, y, width, height);

            let applied_pos_raw = w_handle.outer_position().ok();
            let applied_size_raw = w_handle.outer_size().ok();

            if linux_is_cosmic_session() {
                if let (Some(pos), Some(size)) = (&applied_pos_raw, &applied_size_raw) {
                    let pos_mismatch = (pos.x - x).abs() > 2 || (pos.y - y).abs() > 2;
                    let size_mismatch = ((size.width as i32) - (width as i32)).abs() > 2
                        || ((size.height as i32) - (height as i32)).abs() > 2;
                    if (pos_mismatch || size_mismatch)
                        && !COSMIC_GEOMETRY_OVERRIDE_WARNING_LOGGED.swap(true, Ordering::Relaxed)
                    {
                        eprintln!(
                            "[Autopilot] COSMIC compositor is overriding Spotlight geometry on X11 (target {}x{}@{},{} -> actual {}x{}@{},{}).",
                            width, height, x, y, size.width, size.height, pos.x, pos.y
                        );
                        eprintln!(
                            "[Autopilot] Verify '~/.config/cosmic/com.system76.CosmicSettings.WindowRules/v1/tiling_exception_custom' includes appids 'autopilot', 'Autopilot', and 'ai.ioi.autopilot' (or escaped regex form), then restart session."
                        );
                    }
                }
            }

            if debug {
                let applied_pos = applied_pos_raw
                    .map(|p| format!("{},{}", p.x, p.y))
                    .unwrap_or_else(|| "unknown".to_string());
                let applied_size = applied_size_raw
                    .map(|s| format!("{}x{}", s.width, s.height))
                    .unwrap_or_else(|| "unknown".to_string());
                println!(
                    "[Autopilot] Geometry apply target={}x{}@{},{} result={}@{}",
                    width_for_log, height_for_log, x_for_log, y_for_log, applied_size, applied_pos
                );
            }
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
    }
}

fn calculate_window_position(
    dock: DockPosition,
    window_width: f64,
    window_height: f64,
    screen_width: f64,
    screen_height: f64,
    monitor_x: f64,
    monitor_y: f64,
) -> (f64, f64) {
    match dock {
        DockPosition::Right => {
            // Anchor to right edge
            let x = monitor_x + screen_width - window_width;
            let y = monitor_y + VERTICAL_MARGIN;
            (x, y)
        }
        DockPosition::Center => {
            // Centered
            let x = monitor_x + (screen_width - window_width) / 2.0;
            let y = monitor_y + (screen_height - window_height) / 2.0;
            (x, y)
        }
        DockPosition::Float => {
            // For floating, this function usually isn't called directly for position
            // unless resetting.
            (monitor_x, monitor_y)
        }
    }
}

#[cfg(target_os = "linux")]
fn maybe_warn_wayland_positioning() {
    let forced_x11 = linux_is_x11_backend();

    if forced_x11 {
        return;
    }

    let xdg_session_is_wayland = std::env::var("XDG_SESSION_TYPE")
        .map(|v| v.eq_ignore_ascii_case("wayland"))
        .unwrap_or(false);
    let has_wayland_display = std::env::var("WAYLAND_DISPLAY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if (xdg_session_is_wayland || has_wayland_display)
        && !WAYLAND_POSITION_WARNING_LOGGED.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "[Autopilot] Wayland session detected. Compositor may ignore set_position, so Spotlight can appear floating instead of right-docked."
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn maybe_warn_wayland_positioning() {}

fn apply_layout(app: &AppHandle, layout: &SpotlightLayout) -> Result<(), String> {
    maybe_warn_wayland_positioning();

    let window = app
        .get_webview_window("spotlight")
        .ok_or("Spotlight window not found")?;

    apply_linux_window_hints(&window, layout);

    let monitor = get_target_monitor(app).ok_or("No monitor found")?;

    let scale = monitor.scale_factor();
    let screen_size = monitor.size();
    let screen_w = screen_size.width as f64;
    let screen_h = screen_size.height as f64;

    let monitor_pos = monitor.position();
    let monitor_x = monitor_pos.x as f64;
    let monitor_y = monitor_pos.y as f64;

    // Convert logical layout constants into physical pixels for exact positioning.
    let base_width_px = BASE_WIDTH * scale;
    let sidebar_width_px = SIDEBAR_WIDTH * scale;
    let artifact_panel_width_px = ARTIFACT_PANEL_WIDTH * scale;
    let spotlight_height_px = SPOTLIGHT_HEIGHT * scale;
    let vertical_margin_px = VERTICAL_MARGIN * scale;
    let taskbar_margin_px = TASKBAR_MARGIN * scale;

    // Calculate dimensions
    let available_height = (screen_h - taskbar_margin_px - vertical_margin_px).max(1.0);
    let mut width = base_width_px;
    if layout.sidebar_visible {
        width += sidebar_width_px;
    }
    if layout.artifact_panel_visible {
        width += artifact_panel_width_px;
    }

    let height = match layout.dock_position {
        DockPosition::Right => available_height,
        DockPosition::Center => spotlight_height_px.min(available_height),
        DockPosition::Float => {
            if let Ok(size) = window.outer_size() {
                (size.height as f64).min(available_height)
            } else {
                spotlight_height_px.min(available_height)
            }
        }
    };

    // Calculate position
    let (x, y) = if layout.dock_position == DockPosition::Float {
        if let Ok(pos) = window.outer_position() {
            let current_x = pos.x as f64;
            let current_y = pos.y as f64;

            // Adjust X to keep right edge stable if width changed
            if let Ok(current_size) = window.outer_size() {
                let current_width = current_size.width as f64;
                let width_diff = width - current_width;
                (current_x - width_diff, current_y)
            } else {
                (current_x, current_y)
            }
        } else {
            calculate_window_position(
                DockPosition::Center,
                width,
                height,
                screen_w,
                screen_h,
                monitor_x,
                monitor_y,
            )
        }
    } else {
        calculate_window_position(
            layout.dock_position,
            width,
            height,
            screen_w,
            screen_h,
            monitor_x,
            monitor_y,
        )
    };

    if geometry_debug_enabled() {
        println!(
            "[Autopilot] Layout dock={:?} scale={} screen={}x{} monitor={}x{}@{},{} target={}x{}@{},{} sidebar={} artifact={}",
            layout.dock_position,
            scale,
            screen_w.round() as i64,
            screen_h.round() as i64,
            monitor.size().width,
            monitor.size().height,
            monitor.position().x,
            monitor.position().y,
            width.round() as i64,
            height.round() as i64,
            x.round() as i64,
            y.round() as i64,
            layout.sidebar_visible,
            layout.artifact_panel_visible
        );
    }

    // Apply changes
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    }
    let is_float = layout.dock_position == DockPosition::Float;
    let _ = window.set_resizable(is_float);

    set_window_geometry(&window, x, y, width, height);

    // Visual properties
    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_decorations(is_float);
        let _ = window.set_shadow(true);
        let _ = window.set_always_on_top(!is_float);
    }

    #[cfg(target_os = "linux")]
    {
        let overlay_mode = !is_float;
        let _ = window.set_decorations(is_float);
        let _ = window.set_resizable(is_float);
        let _ = window.set_skip_taskbar(overlay_mode);
        let _ = window.set_always_on_top(overlay_mode);
    }

    Ok(())
}

// ============================================
// TAURI COMMANDS
// ============================================

#[tauri::command]
pub fn show_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        // Prepare window according to current dock mode.
        if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
            let is_float = layout.dock_position == DockPosition::Float;
            let overlay_mode = !is_float;
            let _ = window.set_decorations(is_float);
            let _ = window.set_resizable(is_float);

            #[cfg(target_os = "linux")]
            {
                let _ = window.set_skip_taskbar(overlay_mode);
                let _ = window.set_always_on_top(overlay_mode);
                apply_linux_window_hints(&window, &layout);
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = window.set_always_on_top(overlay_mode);
            }
        }

        // Apply layout before show to set initial placement hints.
        if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
            let _ = apply_layout(&app, &layout);
        }

        let _ = window.show();
        let _ = window.set_focus();

        // Re-apply after show to override compositor auto-placement.
        #[cfg(target_os = "linux")]
        if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
            let _ = apply_layout(&app, &layout);
        }
    }
}

#[tauri::command]
pub fn hide_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.hide();
    }
}

#[tauri::command]
pub fn set_spotlight_mode(app: AppHandle, mode: String) {
    let position = match mode.as_str() {
        "spotlight" | "center" => DockPosition::Center,
        "sidebar" | "right" => DockPosition::Right,
        "float" => DockPosition::Float,
        _ => DockPosition::Right,
    };

    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        layout.dock_position = position;
    }

    // Apply once before show to provide initial placement hints.
    if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
        let _ = apply_layout(&app, &layout);
    }

    // Ensure visibility.
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.show();
        let _ = window.set_focus();
    }

    // On Linux, apply layout after show for better compositor behavior.
    #[cfg(target_os = "linux")]
    if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
        let _ = apply_layout(&app, &layout);
    }
}

#[tauri::command]
pub fn toggle_spotlight_sidebar(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.sidebar_visible == visible {
            return;
        }
        layout.sidebar_visible = visible;

        // Apply changes
        // This will trigger the set_window_geometry logic which handles the X11 race condition
        let _ = apply_layout(&app, &layout);
    }
}

#[tauri::command]
pub fn toggle_spotlight_artifact_panel(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.artifact_panel_visible == visible {
            return;
        }
        layout.artifact_panel_visible = visible;
        let _ = apply_layout(&app, &layout);
    }
}

#[tauri::command]
pub fn get_spotlight_layout() -> Result<(String, bool, bool), String> {
    if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
        let s = match layout.dock_position {
            DockPosition::Right => "right",
            DockPosition::Center => "center",
            DockPosition::Float => "float",
        };
        Ok((
            s.to_string(),
            layout.sidebar_visible,
            layout.artifact_panel_visible,
        ))
    } else {
        Err("Lock failed".into())
    }
}

#[tauri::command]
pub fn resize_spotlight(app: AppHandle, width: f64, height: f64) {
    if let Some(window) = app.get_webview_window("spotlight") {
        // User manual resize implies floating mode
        if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
            layout.dock_position = DockPosition::Float;
        }
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
    }
}

#[tauri::command]
pub fn dock_spotlight_right(app: AppHandle) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        layout.dock_position = DockPosition::Right;
        let _ = apply_layout(&app, &layout);
    }
}

// ============================================
// GATE WINDOW
// ============================================

#[tauri::command]
pub fn show_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        #[cfg(not(target_os = "linux"))]
        let _ = window.set_always_on_top(true);
        let _ = window.show();
        let _ = window.set_focus();
        #[cfg(target_os = "linux")]
        if window.is_visible().unwrap_or(false) {
            let _ = window.set_always_on_top(true);
        }
    }
}

#[tauri::command]
pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

// ============================================
// STUDIO WINDOW
// ============================================

#[tauri::command]
pub fn show_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
pub fn hide_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.hide();
    }
}
