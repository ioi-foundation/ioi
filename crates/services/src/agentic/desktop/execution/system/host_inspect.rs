use super::{ToolExecutionResult, ToolExecutor};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;

fn binary_in_path(name: &str) -> bool {
    let path_var = env::var_os("PATH");
    let Some(path_var) = path_var else {
        return false;
    };

    env::split_paths(&path_var).any(|dir| {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
        #[cfg(target_os = "windows")]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return true;
            }
        }
        false
    })
}

fn parse_os_release() -> (String, String) {
    let mut distro_id = String::new();
    let mut distro_name = String::new();
    let os_release_path = PathBuf::from("/etc/os-release");
    let Ok(raw) = std::fs::read_to_string(os_release_path) else {
        return (distro_id, distro_name);
    };

    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let cleaned = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "ID" => distro_id = cleaned,
            "PRETTY_NAME" | "NAME" if distro_name.is_empty() => distro_name = cleaned,
            _ => {}
        }
    }

    (distro_id, distro_name)
}

fn detect_desktop_environment() -> String {
    for key in ["XDG_CURRENT_DESKTOP", "DESKTOP_SESSION", "GDMSESSION"] {
        if let Ok(value) = env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    "unknown".to_string()
}

fn detect_timer_surfaces() -> Vec<String> {
    let mut surfaces = BTreeSet::<String>::new();
    if binary_in_path("gnome-clocks") {
        surfaces.insert("gnome-clocks".to_string());
    }
    if binary_in_path("kclock") {
        surfaces.insert("kclock".to_string());
    }
    if binary_in_path("chronos") {
        surfaces.insert("chronos".to_string());
    }
    if binary_in_path("notify-send") {
        surfaces.insert("notify-send".to_string());
    }
    surfaces.insert("timer__set".to_string());
    surfaces.insert("timer__cancel".to_string());
    surfaces.insert("timer__list".to_string());
    surfaces.into_iter().collect()
}

pub(super) async fn handle_system_inspect_host(_exec: &ToolExecutor) -> ToolExecutionResult {
    let os = env::consts::OS.to_string();
    let arch = env::consts::ARCH.to_string();
    let (distro_id, distro_name) = parse_os_release();
    let desktop_environment = detect_desktop_environment();
    let timer_surfaces = detect_timer_surfaces();

    let payload = json!({
        "os": os,
        "arch": arch,
        "distro_id": distro_id,
        "distro_name": distro_name,
        "desktop_environment": desktop_environment,
        "timer_surfaces": timer_surfaces,
    });
    ToolExecutionResult::success(payload.to_string())
}
