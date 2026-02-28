use super::sys_exec_command_preview;
use ioi_types::app::agentic::AgentTool;

#[derive(Debug, Clone)]
pub struct HostEnvironmentReceipt {
    pub observed_value: String,
    pub probe_source: String,
    pub timestamp_ms: u64,
    pub satisfied: bool,
    pub desktop_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignHomePathEvidence {
    pub runtime_home_directory: String,
    pub runtime_home_owner: String,
    pub payload_home_directory: String,
    pub payload_home_owner: String,
}

pub fn runtime_home_directory() -> Option<String> {
    discover_runtime_home_directory().map(|(home_dir, _)| home_dir)
}

pub fn runtime_desktop_directory() -> Option<String> {
    let home_dir = runtime_home_directory()?;
    Some(runtime_desktop_from_home(&home_dir))
}

pub fn runtime_host_environment_receipt(timestamp_ms: u64) -> HostEnvironmentReceipt {
    let fallback_probe = "process_env:HOME|USERPROFILE|HOMEDRIVE+HOMEPATH".to_string();
    match discover_runtime_home_directory() {
        Some((home_dir, probe_source)) => HostEnvironmentReceipt {
            observed_value: home_dir.clone(),
            probe_source,
            timestamp_ms,
            satisfied: true,
            desktop_directory: Some(runtime_desktop_from_home(&home_dir)),
        },
        None => HostEnvironmentReceipt {
            observed_value: "unavailable".to_string(),
            probe_source: fallback_probe,
            timestamp_ms,
            satisfied: false,
            desktop_directory: None,
        },
    }
}

pub fn sys_exec_foreign_absolute_home_path(tool: &AgentTool) -> Option<ForeignHomePathEvidence> {
    let runtime_home_dir = runtime_home_directory()?;
    detect_foreign_home_path_for_runtime_home(tool, &runtime_home_dir)
}

fn detect_foreign_home_path_for_runtime_home(
    tool: &AgentTool,
    runtime_home_dir: &str,
) -> Option<ForeignHomePathEvidence> {
    let runtime_home_owner = home_owner_from_path(runtime_home_dir)?;
    let command_preview = sys_exec_command_preview(tool)?;
    for payload_home_dir in extract_absolute_home_directories(&command_preview) {
        let Some(payload_home_owner) = home_owner_from_path(&payload_home_dir) else {
            continue;
        };
        if !payload_home_owner.eq_ignore_ascii_case(&runtime_home_owner) {
            return Some(ForeignHomePathEvidence {
                runtime_home_directory: runtime_home_dir.to_string(),
                runtime_home_owner,
                payload_home_directory: payload_home_dir,
                payload_home_owner,
            });
        }
    }
    None
}

fn discover_runtime_home_directory() -> Option<(String, String)> {
    if let Some(home) = nonempty_env_var("HOME") {
        return Some((
            normalize_path_for_receipts(&home),
            "process_env:HOME".to_string(),
        ));
    }
    if let Some(user_profile) = nonempty_env_var("USERPROFILE") {
        return Some((
            normalize_path_for_receipts(&user_profile),
            "process_env:USERPROFILE".to_string(),
        ));
    }
    let home_drive = nonempty_env_var("HOMEDRIVE");
    let home_path = nonempty_env_var("HOMEPATH");
    if let (Some(home_drive), Some(home_path)) = (home_drive, home_path) {
        let joined = format!("{}{}", home_drive.trim_end_matches(['\\', '/']), home_path);
        return Some((
            normalize_path_for_receipts(&joined),
            "process_env:HOMEDRIVE+HOMEPATH".to_string(),
        ));
    }
    None
}

fn nonempty_env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_path_for_receipts(path: &str) -> String {
    let cleaned = path.trim().trim_matches('"').trim_matches('\'');
    let normalized = cleaned.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() {
        normalized
    } else {
        trimmed.to_string()
    }
}

fn runtime_desktop_from_home(home_dir: &str) -> String {
    format!("{}/Desktop", home_dir.trim_end_matches('/'))
}

fn home_owner_from_path(path: &str) -> Option<String> {
    let normalized = normalize_path_for_receipts(path);
    let parts = normalized
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    for (idx, part) in parts.iter().enumerate() {
        if (part.eq_ignore_ascii_case("home") || part.eq_ignore_ascii_case("users"))
            && idx + 1 < parts.len()
        {
            return Some(parts[idx + 1].to_string());
        }
    }
    None
}

fn extract_absolute_home_directories(command_preview: &str) -> Vec<String> {
    let mut directories = Vec::<String>::new();
    for marker in ["/home/", "/Users/"] {
        let mut search_offset = 0usize;
        while let Some(relative_idx) = command_preview[search_offset..].find(marker) {
            let absolute_idx = search_offset + relative_idx;
            let suffix = &command_preview[absolute_idx..];
            let candidate = suffix
                .chars()
                .take_while(|ch| is_path_token_char(*ch))
                .collect::<String>();
            if candidate.len() > marker.len() {
                let normalized_candidate = normalize_path_for_receipts(&candidate);
                if home_owner_from_path(&normalized_candidate).is_some()
                    && !directories
                        .iter()
                        .any(|existing| existing.eq_ignore_ascii_case(&normalized_candidate))
                {
                    directories.push(normalized_candidate);
                }
            }
            search_offset = absolute_idx + marker.len();
        }
    }
    directories
}

fn is_path_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.' | ':')
}
