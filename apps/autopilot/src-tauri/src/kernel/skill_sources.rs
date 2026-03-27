use crate::models::{AppState, SkillSourceDiscoveredSkill, SkillSourceRecord};
use crate::orchestrator::{load_skill_sources, save_skill_sources};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const IGNORED_DIR_NAMES: &[&str] = &[".git", "node_modules", "target", "dist", "build"];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn app_memory_runtime(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Arc<ioi_memory::MemoryRuntime>, String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;
    guard
        .memory_runtime
        .clone()
        .ok_or("Memory runtime not initialized".to_string())
}

fn source_mut<'a>(
    sources: &'a mut [SkillSourceRecord],
    source_id: &str,
) -> Result<&'a mut SkillSourceRecord, String> {
    sources
        .iter_mut()
        .find(|source| source.source_id == source_id)
        .ok_or_else(|| format!("Skill source '{}' was not found.", source_id))
}

fn normalize_source_path(uri: &str) -> PathBuf {
    let trimmed = uri.trim();
    if let Some(path) = trimmed.strip_prefix("file://") {
        PathBuf::from(path)
    } else {
        PathBuf::from(trimmed)
    }
}

fn default_source_label(uri: &str) -> String {
    let path = normalize_source_path(uri);
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| uri.trim().to_string())
}

fn skill_name_from_relative_path(relative_path: &str) -> String {
    Path::new(relative_path)
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "Unnamed Skill".to_string())
}

fn parse_skill_manifest(markdown: &str, relative_path: &str) -> SkillSourceDiscoveredSkill {
    let trimmed = markdown.trim();
    let mut name = None;
    let mut description = None;

    let mut body = trimmed;
    if let Some(remainder) = trimmed.strip_prefix("---\n") {
        if let Some((frontmatter, after)) = remainder.split_once("\n---\n") {
            body = after;
            for line in frontmatter.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');
                if value.is_empty() {
                    continue;
                }
                match key {
                    "name" => name = Some(value.to_string()),
                    "description" => description = Some(value.to_string()),
                    _ => {}
                }
            }
        }
    }

    if name.is_none() {
        name = body
            .lines()
            .find_map(|line| line.trim().strip_prefix("# ").map(str::trim))
            .map(str::to_string);
    }

    if description.is_none() {
        description = body
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string);
    }

    SkillSourceDiscoveredSkill {
        name: name.unwrap_or_else(|| skill_name_from_relative_path(relative_path)),
        description,
        relative_path: relative_path.replace('\\', "/"),
    }
}

fn source_kind(root: &Path) -> String {
    if root.join(".git").exists() {
        "git_worktree".to_string()
    } else {
        "directory".to_string()
    }
}

fn walk_skill_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<SkillSourceDiscoveredSkill>,
) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("Failed to read {}: {}", current.display(), error))?;

    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;

        if file_type.is_dir() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if IGNORED_DIR_NAMES.iter().any(|ignored| ignored == &name) {
                continue;
            }
            walk_skill_files(root, &path, out)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }
        if entry.file_name().to_str() != Some("SKILL.md") {
            continue;
        }

        let markdown = fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        out.push(parse_skill_manifest(&markdown, &relative_path));
    }

    Ok(())
}

fn sync_source_record(source: &mut SkillSourceRecord) -> Result<(), String> {
    if !source.enabled {
        source.sync_status = "disabled".to_string();
        source.last_error = None;
        source.discovered_skills.clear();
        return Ok(());
    }

    let root = normalize_source_path(&source.uri);
    if !root.exists() {
        source.sync_status = "failed".to_string();
        source.last_error = Some(format!("Path '{}' does not exist.", root.display()));
        source.discovered_skills.clear();
        return Err(source.last_error.clone().unwrap_or_default());
    }

    let root_dir = if root.is_file() {
        if root.file_name().and_then(|value| value.to_str()) == Some("SKILL.md") {
            root.parent().map(Path::to_path_buf).ok_or_else(|| {
                format!("Skill file '{}' has no parent directory.", root.display())
            })?
        } else {
            return Err(format!(
                "Skill source '{}' must point to a directory or SKILL.md file.",
                root.display()
            ));
        }
    } else {
        root.clone()
    };

    if !root_dir.is_dir() {
        return Err(format!(
            "Skill source '{}' is not a directory.",
            root_dir.display()
        ));
    }

    let mut discovered = Vec::new();
    walk_skill_files(&root_dir, &root_dir, &mut discovered)?;
    discovered.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    discovered.dedup_by(|left, right| {
        left.name == right.name && left.relative_path == right.relative_path
    });

    source.kind = source_kind(&root_dir);
    source.last_synced_at_ms = Some(now_ms());
    source.last_error = None;
    source.discovered_skills = discovered;
    source.sync_status = if source.discovered_skills.is_empty() {
        "empty".to_string()
    } else {
        "ready".to_string()
    };
    Ok(())
}

#[tauri::command]
pub async fn get_skill_sources(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SkillSourceRecord>, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    Ok(load_skill_sources(&memory_runtime))
}

#[tauri::command]
pub async fn add_skill_source(
    state: State<'_, Mutex<AppState>>,
    uri: String,
    label: Option<String>,
) -> Result<SkillSourceRecord, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let trimmed_uri = uri.trim();
    if trimmed_uri.is_empty() {
        return Err("Skill source path is required.".to_string());
    }

    let mut sources = load_skill_sources(&memory_runtime);
    let mut record = SkillSourceRecord {
        source_id: format!("skill-source-{}", now_ms()),
        label: label
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default_source_label(trimmed_uri)),
        uri: trimmed_uri.to_string(),
        kind: "directory".to_string(),
        enabled: true,
        sync_status: "configured".to_string(),
        last_synced_at_ms: None,
        last_error: None,
        discovered_skills: Vec::new(),
    };
    sync_source_record(&mut record)?;
    sources.push(record.clone());
    save_skill_sources(&memory_runtime, &sources);
    Ok(record)
}

#[tauri::command]
pub async fn update_skill_source(
    state: State<'_, Mutex<AppState>>,
    source_id: String,
    uri: String,
    label: Option<String>,
) -> Result<SkillSourceRecord, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let mut sources = load_skill_sources(&memory_runtime);
    let source = source_mut(&mut sources, &source_id)?;
    let trimmed_uri = uri.trim();
    if trimmed_uri.is_empty() {
        return Err("Skill source path is required.".to_string());
    }
    source.uri = trimmed_uri.to_string();
    if let Some(label) = label {
        let trimmed = label.trim();
        if !trimmed.is_empty() {
            source.label = trimmed.to_string();
        }
    }
    sync_source_record(source)?;
    let updated = source.clone();
    save_skill_sources(&memory_runtime, &sources);
    Ok(updated)
}

#[tauri::command]
pub async fn remove_skill_source(
    state: State<'_, Mutex<AppState>>,
    source_id: String,
) -> Result<(), String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let mut sources = load_skill_sources(&memory_runtime);
    let original_len = sources.len();
    sources.retain(|source| source.source_id != source_id);
    if sources.len() == original_len {
        return Err(format!("Skill source '{}' was not found.", source_id));
    }
    save_skill_sources(&memory_runtime, &sources);
    Ok(())
}

#[tauri::command]
pub async fn set_skill_source_enabled(
    state: State<'_, Mutex<AppState>>,
    source_id: String,
    enabled: bool,
) -> Result<SkillSourceRecord, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let mut sources = load_skill_sources(&memory_runtime);
    let source = source_mut(&mut sources, &source_id)?;
    source.enabled = enabled;
    if enabled {
        sync_source_record(source)?;
    } else {
        source.sync_status = "disabled".to_string();
        source.last_error = None;
    }
    let updated = source.clone();
    save_skill_sources(&memory_runtime, &sources);
    Ok(updated)
}

#[tauri::command]
pub async fn sync_skill_source(
    state: State<'_, Mutex<AppState>>,
    source_id: String,
) -> Result<SkillSourceRecord, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let mut sources = load_skill_sources(&memory_runtime);
    let source = source_mut(&mut sources, &source_id)?;
    sync_source_record(source)?;
    let updated = source.clone();
    save_skill_sources(&memory_runtime, &sources);
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ioi-autopilot-skill-source-{}-{}", name, now_ms()));
        path
    }

    #[test]
    fn parse_skill_manifest_prefers_frontmatter_name_and_description() {
        let markdown = r#"---
name: local-research
description: "A research skill"
---

# Ignored heading

Some body text.
"#;
        let parsed = parse_skill_manifest(markdown, "skills/local-research/SKILL.md");
        assert_eq!(parsed.name, "local-research");
        assert_eq!(parsed.description.as_deref(), Some("A research skill"));
    }

    #[test]
    fn sync_source_discovers_nested_skill_docs() {
        let root = unique_temp_dir("discover");
        let nested = root.join("skills/research");
        fs::create_dir_all(&nested).expect("create nested dir");
        fs::write(
            nested.join("SKILL.md"),
            "# Research Skill\n\nInvestigate topics deeply.",
        )
        .expect("write skill file");
        fs::create_dir_all(root.join("node_modules/ignored")).expect("create ignored dir");
        fs::write(
            root.join("node_modules/ignored/SKILL.md"),
            "# Should Not Appear",
        )
        .expect("write ignored skill");

        let mut source = SkillSourceRecord {
            source_id: "source-1".to_string(),
            label: "Research".to_string(),
            uri: root.to_string_lossy().to_string(),
            kind: "directory".to_string(),
            enabled: true,
            sync_status: "configured".to_string(),
            last_synced_at_ms: None,
            last_error: None,
            discovered_skills: Vec::new(),
        };

        sync_source_record(&mut source).expect("sync source");
        assert_eq!(source.sync_status, "ready");
        assert_eq!(source.discovered_skills.len(), 1);
        assert_eq!(source.discovered_skills[0].name, "Research Skill");
        assert_eq!(
            source.discovered_skills[0].relative_path,
            "skills/research/SKILL.md"
        );

        let _ = fs::remove_dir_all(root);
    }
}
