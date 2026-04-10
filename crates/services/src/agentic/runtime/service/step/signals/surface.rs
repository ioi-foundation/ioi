const BROWSER_SURFACE_MARKERS: [&str; 8] = [
    "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc", "browser",
];

const SYSTEM_SURFACE_MARKERS: [&str; 8] = [
    "finder",
    "explorer",
    "dock",
    "shell",
    "launcher",
    "desktop",
    "taskbar",
    "autopilot",
];

pub fn is_browser_surface(app_name: &str, title: &str) -> bool {
    let app_lc = app_name.to_ascii_lowercase();
    let title_lc = title.to_ascii_lowercase();

    BROWSER_SURFACE_MARKERS
        .iter()
        .any(|marker| app_lc.contains(marker) || title_lc.contains(marker))
}

pub fn is_system_surface(app_name: &str, title: &str) -> bool {
    let app_lc = app_name.to_ascii_lowercase();
    let title_lc = title.to_ascii_lowercase();

    SYSTEM_SURFACE_MARKERS
        .iter()
        .any(|marker| app_lc.contains(marker) || title_lc.contains(marker))
}
