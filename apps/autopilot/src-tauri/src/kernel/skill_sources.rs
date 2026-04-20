use crate::models::{
    AppState, ExtensionContributionRecord, ExtensionManifestRecord, SkillSourceDiscoveredSkill,
    SkillSourceRecord,
};
use crate::orchestrator::{load_skill_sources, save_skill_sources};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const IGNORED_DIR_NAMES: &[&str] = &[".git", ".tmp", "node_modules", "target", "dist", "build"];

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

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_slash_path(root: &Path, path: &Path) -> String {
    slash_path(path.strip_prefix(root).unwrap_or(path))
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

fn resolve_source_root_dir(uri: &str) -> Result<PathBuf, String> {
    let root = normalize_source_path(uri);
    if !root.exists() {
        return Err(format!("Path '{}' does not exist.", root.display()));
    }

    let root_dir = if root.is_file() {
        match root.file_name().and_then(|value| value.to_str()) {
            Some("SKILL.md") => root.parent().map(Path::to_path_buf).ok_or_else(|| {
                format!("Skill file '{}' has no parent directory.", root.display())
            })?,
            _ => {
                return Err(format!(
                    "Skill source '{}' must point to a directory or SKILL.md file.",
                    root.display()
                ));
            }
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

    Ok(root_dir)
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

fn discover_skill_files(
    root: &Path,
    current: &Path,
) -> Result<Vec<SkillSourceDiscoveredSkill>, String> {
    let mut discovered = Vec::new();
    walk_skill_files(root, current, &mut discovered)?;
    discovered.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    discovered.dedup_by(|left, right| {
        left.name == right.name && left.relative_path == right.relative_path
    });
    Ok(discovered)
}

#[derive(Clone)]
struct ManifestScanRoot {
    root_path: PathBuf,
    source_label: String,
    source_uri: String,
    source_kind: String,
    enabled: bool,
}

#[derive(Clone, Default)]
struct MarketplacePluginRecord {
    marketplace_name: Option<String>,
    marketplace_display_name: Option<String>,
    category: Option<String>,
    installation_policy: Option<String>,
    authentication_policy: Option<String>,
    products: Vec<String>,
}

fn string_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .collect()
}

fn path_from_manifest(root: &Path, raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    let relative = trimmed.strip_prefix("./").unwrap_or(trimmed);
    root.join(relative)
}

fn manifest_parent_root(manifest_path: &Path) -> Result<PathBuf, String> {
    manifest_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "Plugin manifest '{}' does not live under '.codex-plugin/'.",
                manifest_path.display()
            )
        })
}

fn walk_extension_manifests(current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
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
            walk_extension_manifests(&path, out)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }
        if entry.file_name().to_str() != Some("plugin.json") {
            continue;
        }
        if path
            .parent()
            .and_then(|value| value.file_name())
            .and_then(|value| value.to_str())
            != Some(".codex-plugin")
        {
            continue;
        }

        out.push(path);
    }

    Ok(())
}

fn load_marketplace_plugins(
    root: &Path,
) -> Result<BTreeMap<String, MarketplacePluginRecord>, String> {
    let marketplace_path = root.join(".agents/plugins/marketplace.json");
    if !marketplace_path.exists() {
        return Ok(BTreeMap::new());
    }

    let raw = fs::read_to_string(&marketplace_path)
        .map_err(|error| format!("Failed to read {}: {}", marketplace_path.display(), error))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", marketplace_path.display(), error))?;

    let marketplace_name = string_value(parsed.get("name"));
    let marketplace_display_name = parsed
        .get("interface")
        .and_then(Value::as_object)
        .and_then(|interface| string_value(interface.get("displayName")));

    let mut entries = BTreeMap::new();
    for plugin in parsed
        .get("plugins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(plugin_name) = string_value(plugin.get("name")) else {
            continue;
        };
        let record = MarketplacePluginRecord {
            marketplace_name: marketplace_name.clone(),
            marketplace_display_name: marketplace_display_name.clone(),
            category: string_value(plugin.get("category")),
            installation_policy: plugin
                .get("policy")
                .and_then(Value::as_object)
                .and_then(|policy| string_value(policy.get("installation"))),
            authentication_policy: plugin
                .get("policy")
                .and_then(Value::as_object)
                .and_then(|policy| string_value(policy.get("authentication"))),
            products: plugin
                .get("policy")
                .and_then(Value::as_object)
                .map(|policy| string_array(policy.get("products")))
                .unwrap_or_default(),
        };
        entries.insert(plugin_name, record);
    }

    Ok(entries)
}

fn source_skill_contribution(
    root_path: &Path,
    manifest_root: &Path,
    raw_path: &str,
    kind: &str,
    label: &str,
) -> ExtensionContributionRecord {
    let resolved_path = path_from_manifest(manifest_root, raw_path);
    if kind == "skills" {
        return match discover_skill_files(manifest_root, &resolved_path) {
            Ok(skills) => ExtensionContributionRecord {
                kind: kind.to_string(),
                label: label.to_string(),
                path: Some(raw_path.trim().to_string()),
                item_count: Some(skills.len() as u32),
                detail: Some(if skills.is_empty() {
                    format!(
                        "No SKILL.md files found under {}.",
                        relative_slash_path(root_path, &resolved_path)
                    )
                } else {
                    format!(
                        "{} skill{} from {}",
                        skills.len(),
                        if skills.len() == 1 { "" } else { "s" },
                        relative_slash_path(root_path, &resolved_path)
                    )
                }),
            },
            Err(error) => ExtensionContributionRecord {
                kind: kind.to_string(),
                label: label.to_string(),
                path: Some(raw_path.trim().to_string()),
                item_count: Some(0),
                detail: Some(error),
            },
        };
    }

    ExtensionContributionRecord {
        kind: kind.to_string(),
        label: label.to_string(),
        path: Some(raw_path.trim().to_string()),
        item_count: None,
        detail: Some(if resolved_path.exists() {
            format!(
                "Found at {}",
                relative_slash_path(root_path, &resolved_path)
            )
        } else {
            format!(
                "Configured path missing: {}",
                relative_slash_path(root_path, &resolved_path)
            )
        }),
    }
}

fn extension_scan_roots(sources: &[SkillSourceRecord]) -> Vec<ManifestScanRoot> {
    let mut deduped = BTreeMap::<String, ManifestScanRoot>::new();

    for source in sources {
        let Ok(root_path) = resolve_source_root_dir(&source.uri) else {
            continue;
        };
        let key = root_path
            .canonicalize()
            .unwrap_or_else(|_| root_path.clone())
            .to_string_lossy()
            .to_string();
        deduped.entry(key).or_insert_with(|| ManifestScanRoot {
            root_path,
            source_label: source.label.clone(),
            source_uri: source.uri.clone(),
            source_kind: "skill_source".to_string(),
            enabled: source.enabled,
        });
    }

    if let Ok(workspace_root) = std::env::current_dir() {
        let key = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.clone())
            .to_string_lossy()
            .to_string();
        deduped.entry(key).or_insert_with(|| ManifestScanRoot {
            root_path: workspace_root.clone(),
            source_label: "Workspace".to_string(),
            source_uri: slash_path(&workspace_root),
            source_kind: "workspace".to_string(),
            enabled: true,
        });
    }

    if let Some(home) = std::env::var_os("HOME") {
        let home_plugins = PathBuf::from(home).join("plugins");
        if home_plugins.exists() {
            let key = home_plugins
                .canonicalize()
                .unwrap_or_else(|_| home_plugins.clone())
                .to_string_lossy()
                .to_string();
            deduped.entry(key).or_insert_with(|| ManifestScanRoot {
                root_path: home_plugins.clone(),
                source_label: "Home plugins".to_string(),
                source_uri: slash_path(&home_plugins),
                source_kind: "home_plugins".to_string(),
                enabled: true,
            });
        }
    }

    deduped.into_values().collect()
}

fn load_extension_manifest(
    scan_root: &ManifestScanRoot,
    manifest_path: &Path,
    marketplace: &BTreeMap<String, MarketplacePluginRecord>,
) -> Result<ExtensionManifestRecord, String> {
    let raw = fs::read_to_string(manifest_path)
        .map_err(|error| format!("Failed to read {}: {}", manifest_path.display(), error))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", manifest_path.display(), error))?;
    let manifest_root = manifest_parent_root(manifest_path)?;

    let interface = parsed.get("interface").and_then(Value::as_object);
    let name = string_value(parsed.get("name")).unwrap_or_else(|| {
        manifest_root
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unnamed-extension")
            .to_string()
    });
    let display_name = interface.and_then(|value| string_value(value.get("displayName")));
    let description = string_value(parsed.get("description"))
        .or_else(|| interface.and_then(|value| string_value(value.get("shortDescription"))))
        .or_else(|| interface.and_then(|value| string_value(value.get("longDescription"))));
    let developer_name = interface.and_then(|value| string_value(value.get("developerName")));
    let author = parsed.get("author").and_then(Value::as_object);
    let author_name = author.and_then(|value| string_value(value.get("name")));
    let author_email = author.and_then(|value| string_value(value.get("email")));
    let author_url = author.and_then(|value| string_value(value.get("url")));
    let category = interface.and_then(|value| string_value(value.get("category")));
    let keywords = string_array(parsed.get("keywords"));
    let capabilities = interface
        .map(|value| string_array(value.get("capabilities")))
        .unwrap_or_default();
    let default_prompts = interface
        .map(|value| string_array(value.get("defaultPrompt")))
        .unwrap_or_default()
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();

    let mut contributions = Vec::new();
    let mut filesystem_skills = Vec::new();

    if let Some(skills_path) = string_value(parsed.get("skills")) {
        let resolved = path_from_manifest(&manifest_root, &skills_path);
        filesystem_skills = discover_skill_files(&manifest_root, &resolved).unwrap_or_default();
        contributions.push(source_skill_contribution(
            &scan_root.root_path,
            &manifest_root,
            &skills_path,
            "skills",
            "Skills",
        ));
    }

    if let Some(hooks_path) = string_value(parsed.get("hooks")) {
        contributions.push(source_skill_contribution(
            &scan_root.root_path,
            &manifest_root,
            &hooks_path,
            "hooks",
            "Hooks",
        ));
    }

    if let Some(mcp_servers_path) = string_value(parsed.get("mcpServers")) {
        contributions.push(source_skill_contribution(
            &scan_root.root_path,
            &manifest_root,
            &mcp_servers_path,
            "mcp_servers",
            "MCP servers",
        ));
    }

    if let Some(apps_path) = string_value(parsed.get("apps")) {
        contributions.push(source_skill_contribution(
            &scan_root.root_path,
            &manifest_root,
            &apps_path,
            "apps",
            "Apps",
        ));
    }

    let marketplace_record = marketplace.get(&name).cloned().unwrap_or_default();
    let has_hooks = contributions.iter().any(|item| item.kind == "hooks");
    let has_runtime_bridge = contributions
        .iter()
        .any(|item| matches!(item.kind.as_str(), "mcp_servers" | "apps"));
    let governed_profile = if marketplace_record.installation_policy.is_some()
        || marketplace_record.authentication_policy.is_some()
    {
        "governed_marketplace".to_string()
    } else if has_hooks {
        "automation_bridge".to_string()
    } else if has_runtime_bridge {
        "runtime_bridge".to_string()
    } else if !filesystem_skills.is_empty() {
        "local_skill_bundle".to_string()
    } else {
        "local_manifest".to_string()
    };
    let trust_posture = if marketplace_record.installation_policy.is_some()
        || marketplace_record.authentication_policy.is_some()
    {
        "policy_limited".to_string()
    } else {
        "local_only".to_string()
    };

    Ok(ExtensionManifestRecord {
        extension_id: format!("manifest:{}", slash_path(manifest_path)),
        manifest_kind: "codex_plugin".to_string(),
        manifest_path: slash_path(manifest_path),
        root_path: slash_path(&manifest_root),
        source_label: scan_root.source_label.clone(),
        source_uri: scan_root.source_uri.clone(),
        source_kind: scan_root.source_kind.clone(),
        enabled: scan_root.enabled,
        name,
        display_name,
        version: string_value(parsed.get("version")),
        description,
        developer_name,
        author_name,
        author_email,
        author_url,
        category,
        trust_posture,
        governed_profile,
        homepage: string_value(parsed.get("homepage")),
        repository: string_value(parsed.get("repository")),
        license: string_value(parsed.get("license")),
        keywords,
        capabilities,
        default_prompts,
        contributions,
        filesystem_skills,
        marketplace_name: marketplace_record.marketplace_name,
        marketplace_display_name: marketplace_record.marketplace_display_name,
        marketplace_category: marketplace_record.category,
        marketplace_installation_policy: marketplace_record.installation_policy,
        marketplace_authentication_policy: marketplace_record.authentication_policy,
        marketplace_products: marketplace_record.products,
        marketplace_available_version: None,
        marketplace_catalog_issued_at_ms: None,
        marketplace_catalog_expires_at_ms: None,
        marketplace_catalog_refreshed_at_ms: None,
        marketplace_catalog_refresh_source: None,
        marketplace_catalog_channel: None,
        marketplace_catalog_source_id: None,
        marketplace_catalog_source_label: None,
        marketplace_catalog_source_uri: None,
        marketplace_package_url: None,
        marketplace_catalog_refresh_bundle_id: None,
        marketplace_catalog_refresh_bundle_label: None,
        marketplace_catalog_refresh_bundle_issued_at_ms: None,
        marketplace_catalog_refresh_bundle_expires_at_ms: None,
        marketplace_catalog_refresh_available_version: None,
        marketplace_verification_status: None,
        marketplace_signature_algorithm: None,
        marketplace_signer_identity: None,
        marketplace_publisher_id: None,
        marketplace_signing_key_id: None,
        marketplace_publisher_label: None,
        marketplace_publisher_trust_status: None,
        marketplace_publisher_trust_source: None,
        marketplace_publisher_root_id: None,
        marketplace_publisher_root_label: None,
        marketplace_authority_bundle_id: None,
        marketplace_authority_bundle_label: None,
        marketplace_authority_bundle_issued_at_ms: None,
        marketplace_authority_trust_bundle_id: None,
        marketplace_authority_trust_bundle_label: None,
        marketplace_authority_trust_bundle_issued_at_ms: None,
        marketplace_authority_trust_bundle_expires_at_ms: None,
        marketplace_authority_trust_bundle_status: None,
        marketplace_authority_trust_issuer_id: None,
        marketplace_authority_trust_issuer_label: None,
        marketplace_authority_id: None,
        marketplace_authority_label: None,
        marketplace_publisher_statement_issued_at_ms: None,
        marketplace_publisher_trust_detail: None,
        marketplace_publisher_revoked_at_ms: None,
        marketplace_verification_error: None,
        marketplace_verified_at_ms: None,
        marketplace_verification_source: None,
        marketplace_verified_digest_sha256: None,
        marketplace_trust_score_label: None,
        marketplace_trust_score_source: None,
        marketplace_trust_recommendation: None,
    })
}

pub(crate) fn load_extension_manifests_for_sources(
    sources: &[SkillSourceRecord],
) -> Result<Vec<ExtensionManifestRecord>, String> {
    let mut manifests = Vec::new();
    for scan_root in extension_scan_roots(sources) {
        if !scan_root.root_path.exists() || !scan_root.root_path.is_dir() {
            continue;
        }

        let marketplace = load_marketplace_plugins(&scan_root.root_path)?;
        let mut manifest_paths = Vec::new();
        walk_extension_manifests(&scan_root.root_path, &mut manifest_paths)?;
        manifest_paths.sort();

        for manifest_path in manifest_paths {
            manifests.push(load_extension_manifest(
                &scan_root,
                &manifest_path,
                &marketplace,
            )?);
        }
    }

    sort_and_dedup_extension_manifests(&mut manifests);
    Ok(manifests)
}

fn extension_manifest_source_priority(source_kind: &str) -> u8 {
    match source_kind {
        "skill_source" => 0,
        "workspace" => 1,
        "home_plugins" => 2,
        _ => 3,
    }
}

fn sort_and_dedup_extension_manifests(manifests: &mut Vec<ExtensionManifestRecord>) {
    manifests.sort_by(|left, right| {
        left.display_name
            .as_deref()
            .unwrap_or(&left.name)
            .cmp(right.display_name.as_deref().unwrap_or(&right.name))
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
            .then_with(|| {
                extension_manifest_source_priority(&left.source_kind)
                    .cmp(&extension_manifest_source_priority(&right.source_kind))
            })
            .then_with(|| left.source_label.cmp(&right.source_label))
    });
    manifests.dedup_by(|left, right| left.manifest_path == right.manifest_path);
}

fn sync_source_record(source: &mut SkillSourceRecord) -> Result<(), String> {
    if !source.enabled {
        source.sync_status = "disabled".to_string();
        source.last_error = None;
        source.discovered_skills.clear();
        return Ok(());
    }

    let root_dir = match resolve_source_root_dir(&source.uri) {
        Ok(root_dir) => root_dir,
        Err(error) => {
            source.sync_status = "failed".to_string();
            source.last_error = Some(error.clone());
            source.discovered_skills.clear();
            return Err(error);
        }
    };
    let discovered = discover_skill_files(&root_dir, &root_dir)?;

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
pub async fn get_extension_manifests(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<ExtensionManifestRecord>, String> {
    let memory_runtime = app_memory_runtime(&state)?;
    let sources = load_skill_sources(&memory_runtime);
    load_extension_manifests_for_sources(&sources)
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
#[path = "skill_sources/tests.rs"]
mod tests;
