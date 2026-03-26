use anyhow::{anyhow, Result};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::computer_use_suite::types::ComputerUseMode;

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

pub(super) fn compute_session_id(seed: u64, mode: ComputerUseMode) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mode_byte = match mode {
        ComputerUseMode::Oracle => 0x11,
        ComputerUseMode::Runtime => 0x22,
        ComputerUseMode::Agent => 0x33,
    };
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add((idx as u64) * 17)
            .wrapping_add(mode_byte as u64) as u8;
    }
    out
}

pub(super) fn extract_error_class(input: &str) -> Option<String> {
    let marker = "ERROR_CLASS=";
    let start = input.find(marker)?;
    let rest = &input[start + marker.len()..];
    let class = rest
        .split_whitespace()
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(class.to_string())
}

pub(super) fn write_json_file(path: &PathBuf, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub(super) fn write_text_file(path: &PathBuf, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

pub(super) fn headless_for_run(
    config: &crate::computer_use_suite::types::SuiteConfig,
) -> Result<bool> {
    if config.require_browser_display
        && std::env::var("DISPLAY").is_err()
        && std::env::var("WAYLAND_DISPLAY").is_err()
    {
        return Err(anyhow!(
            "display session required by COMPUTER_USE_SUITE_REQUIRE_DISPLAY"
        ));
    }

    if let Ok(value) = std::env::var("COMPUTER_USE_SUITE_HEADLESS") {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized == "0" || normalized == "false" {
            return Ok(false);
        }
        if normalized == "1" || normalized == "true" {
            return Ok(true);
        }
    }

    Ok(std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err())
}
