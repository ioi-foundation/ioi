// apps/autopilot/src-tauri/src/kernel/cosmic.rs

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
const AUTOPILOT_APP_ID: &str = "ai.ioi.autopilot";

#[cfg(target_os = "linux")]
const COSMIC_RULES_RELATIVE_PATH: &str = "cosmic/com.system76.CosmicSettings.WindowRules/v1/rules";

#[cfg(target_os = "linux")]
fn is_cosmic_session() -> bool {
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

#[cfg(target_os = "linux")]
fn rules_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))?,
    };
    Some(base.join(COSMIC_RULES_RELATIVE_PATH))
}

#[cfg(target_os = "linux")]
fn autopilot_rule_entry() -> String {
    format!(
        r#"  (
    app_id: "{id}",
    condition: AppId("{id}"),
    tiling: false,
    floating: true,
    accept_focus: true,
    maximize: false,
    minimize: false
  )"#,
        id = AUTOPILOT_APP_ID
    )
}

#[cfg(target_os = "linux")]
fn has_autopilot_rule(raw: &str) -> bool {
    raw.contains(&format!("AppId(\"{}\")", AUTOPILOT_APP_ID))
        || raw.contains(&format!("app_id: \"{}\"", AUTOPILOT_APP_ID))
}

#[cfg(target_os = "linux")]
fn merge_rule(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(format!("[\n{}\n]\n", autopilot_rule_entry()));
    }

    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return None;
    }

    let mut merged = trimmed.to_string();
    merged.pop(); // trailing ']'
    if !merged.trim_end().ends_with('[') {
        if !merged.trim_end().ends_with(',') {
            merged.push(',');
        }
        merged.push('\n');
    } else {
        merged.push('\n');
    }
    merged.push_str(&autopilot_rule_entry());
    merged.push('\n');
    merged.push(']');
    merged.push('\n');
    Some(merged)
}

#[cfg(target_os = "linux")]
fn write_atomically(path: &std::path::Path, content: &str) -> Result<(), String> {
    let temp_path = path.with_extension("tmp.autopilot");
    std::fs::write(&temp_path, content).map_err(|e| format!("write temp failed: {}", e))?;
    std::fs::rename(&temp_path, path).map_err(|e| format!("rename failed: {}", e))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn ensure_cosmic_window_rules() {
    if !is_cosmic_session() {
        return;
    }

    let Some(path) = rules_path() else {
        eprintln!("[Autopilot] Could not resolve COSMIC window rules path.");
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

    let existing = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            eprintln!(
                "[Autopilot] Failed to read COSMIC rules file '{}': {}",
                path.display(),
                err
            );
            return;
        }
    };

    if has_autopilot_rule(&existing) {
        return;
    }

    let Some(merged) = merge_rule(&existing) else {
        eprintln!(
            "[Autopilot] COSMIC rules file '{}' has an unsupported format; please add a floating rule for '{}' manually.",
            path.display(),
            AUTOPILOT_APP_ID
        );
        return;
    };

    if let Err(err) = write_atomically(&path, &merged) {
        eprintln!(
            "[Autopilot] Failed to update COSMIC window rules at '{}': {}",
            path.display(),
            err
        );
        return;
    }

    println!(
        "[Autopilot] Ensured COSMIC floating window rule for '{}' at '{}'",
        AUTOPILOT_APP_ID,
        path.display()
    );
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_cosmic_window_rules() {}
