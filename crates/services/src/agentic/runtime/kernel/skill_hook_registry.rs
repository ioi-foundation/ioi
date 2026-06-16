use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const SKILL_HOOK_REGISTRY_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.skill-hook-registry-projection-request.v1";
pub const SKILL_HOOK_REGISTRY_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.skill-hook-registry-projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SkillHookRegistryProjectionRequest {
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub registry_kind: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub home_dir: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillHookRegistryProjectionError {
    code: &'static str,
    message: String,
}

impl SkillHookRegistryProjectionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct SkillHookRegistryProjectionCore;

#[derive(Debug, Clone)]
pub struct SkillHookRegistryProjectionRecord {
    pub operation_kind: String,
    pub registry_kind: String,
    pub workspace_root: String,
    pub source: String,
    pub catalog: Value,
    pub projection: Value,
    pub skills: Vec<Value>,
    pub hooks: Vec<Value>,
    pub sources: Vec<Value>,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

impl SkillHookRegistryProjectionCore {
    pub fn project(
        &self,
        request: SkillHookRegistryProjectionRequest,
    ) -> Result<SkillHookRegistryProjectionRecord, SkillHookRegistryProjectionError> {
        let registry_kind = normalized_registry_kind(&request)?;
        let workspace_root = absolute_path(
            optional_trimmed(request.workspace_root.as_deref()).unwrap_or_else(|| ".".to_string()),
        );
        let home_dir = absolute_path(
            optional_trimmed(request.home_dir.as_deref()).unwrap_or_else(|| {
                std::env::var("HOME").unwrap_or_else(|_| workspace_root.clone())
            }),
        );
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| match registry_kind.as_str() {
                "catalog" => "skill_hook.registry.catalog".to_string(),
                "skills" => "skill_hook.registry.skills".to_string(),
                "hooks" => "skill_hook.registry.hooks".to_string(),
                _ => "skill_hook.registry.unknown".to_string(),
            });
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "rust_skill_hook_registry_projection_api".to_string());
        let catalog = discover_skill_hook_catalog(&workspace_root, &home_dir);
        let skills = array_values(&catalog["skills"]);
        let hooks = array_values(&catalog["hooks"]);
        let sources = array_values(&catalog["sources"]);
        let projection = match registry_kind.as_str() {
            "catalog" => catalog.clone(),
            "skills" => skill_projection(&catalog, &skills, &sources),
            "hooks" => hook_projection(&catalog, &hooks, &sources),
            _ => {
                return Err(SkillHookRegistryProjectionError::new(
                    "skill_hook_registry_projection_kind_invalid",
                    format!("unsupported skill hook registry kind {registry_kind}"),
                ));
            }
        };
        let record_count = match registry_kind.as_str() {
            "skills" => skills.len(),
            "hooks" => hooks.len(),
            _ => skills.len() + hooks.len(),
        };

        Ok(SkillHookRegistryProjectionRecord {
            operation_kind,
            registry_kind: registry_kind.clone(),
            workspace_root,
            source,
            catalog,
            projection,
            skills,
            hooks,
            sources,
            record_count,
            evidence_refs: vec![
                "runtime_skill_hook_registry_rust_projection".to_string(),
                "agentgres_skill_hook_registry_truth_required".to_string(),
            ],
            receipt_refs: vec![format!(
                "receipt_skill_hook_registry_projection_{registry_kind}"
            )],
        })
    }
}

impl SkillHookRegistryProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": SKILL_HOOK_REGISTRY_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_skill_hook_registry_projection",
            "status": "projected",
            "operation_kind": self.operation_kind,
            "registry_kind": self.registry_kind,
            "workspace_root": self.workspace_root,
            "source": self.source,
            "catalog": self.catalog,
            "projection": self.projection,
            "skills": self.skills,
            "hooks": self.hooks,
            "sources": self.sources,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn discover_skill_hook_catalog(workspace_root: &str, home_dir: &str) -> Value {
    let sources = skill_hook_sources(workspace_root, home_dir);
    let skills: Vec<Value> = sources
        .iter()
        .flat_map(|source| discover_skills_from_source(source, workspace_root))
        .collect();
    let hooks: Vec<Value> = sources
        .iter()
        .flat_map(|source| discover_hooks_from_source(source, workspace_root))
        .collect();
    let validation_issue_count = skills
        .iter()
        .map(|skill| validation_issues(skill).len())
        .sum::<usize>()
        + hooks
            .iter()
            .map(|hook| validation_issues(hook).len())
            .sum::<usize>()
        + sources
            .iter()
            .filter(|source| source["status"] == "error")
            .count();
    let skill_status = if skills
        .iter()
        .any(|skill| skill["validation"]["status"] != "pass")
    {
        "degraded"
    } else {
        "pass"
    };
    let hook_status = if hooks
        .iter()
        .any(|hook| hook["validation"]["status"] != "pass")
    {
        "degraded"
    } else {
        "pass"
    };
    let status = if validation_issue_count > 0 || skill_status != "pass" || hook_status != "pass" {
        "degraded"
    } else {
        "pass"
    };
    let mut skill_hashes: Vec<String> = skills
        .iter()
        .filter_map(|skill| string_value(skill, "skillHash"))
        .collect();
    skill_hashes.sort();
    let mut hook_hashes: Vec<String> = hooks
        .iter()
        .filter_map(|hook| string_value(hook, "definitionHash"))
        .collect();
    hook_hashes.sort();

    json!({
        "schemaVersion": "ioi.agent-runtime.skill-hook-catalog.v1",
        "object": "ioi.agent_skill_hook_catalog",
        "generatedAt": "rust_daemon_core",
        "status": status,
        "skillStatus": skill_status,
        "hookStatus": hook_status,
        "workspace": {
            "root": workspace_root,
            "exists": Path::new(workspace_root).exists(),
        },
        "sources": sources,
        "skillCount": skills.len(),
        "hookCount": hooks.len(),
        "skills": skills,
        "hooks": hooks,
        "activeSkillSetHash": sha256_hex(&skill_hashes.join("\n")),
        "activeHookSetHash": sha256_hex(&hook_hashes.join("\n")),
        "validationIssueCount": validation_issue_count,
        "redaction": {
            "profile": "skill_hook_registry_safe",
            "hookCommandsIncluded": false,
            "hookCommandsHashed": true,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": [
            "runtime_skill_hook_discovery",
            "governed_skill_hook_catalog",
            "rust_daemon_core_skill_hook_registry_projection",
        ],
    })
}

fn skill_projection(catalog: &Value, skills: &[Value], sources: &[Value]) -> Value {
    json!({
        "schemaVersion": "ioi.agent-runtime.skills.v1",
        "object": "ioi.agent_skill_registry_projection",
        "status": catalog["status"],
        "skillCount": skills.len(),
        "skills": skills,
        "sources": sources,
        "activeSkillSetHash": catalog["activeSkillSetHash"],
        "validationIssueCount": catalog["validationIssueCount"],
        "redaction": catalog["redaction"],
        "evidenceRefs": catalog["evidenceRefs"],
    })
}

fn hook_projection(catalog: &Value, hooks: &[Value], sources: &[Value]) -> Value {
    json!({
        "schemaVersion": "ioi.agent-runtime.hooks.v1",
        "object": "ioi.agent_hook_registry_projection",
        "status": catalog["status"],
        "hookCount": hooks.len(),
        "hooks": hooks,
        "sources": sources,
        "activeHookSetHash": catalog["activeHookSetHash"],
        "validationIssueCount": catalog["validationIssueCount"],
        "redaction": catalog["redaction"],
        "evidenceRefs": catalog["evidenceRefs"],
    })
}

fn skill_hook_sources(workspace_root: &str, home_dir: &str) -> Vec<Value> {
    let mut sources = Vec::new();
    for (id, relative_path, compatibility, scope) in [
        ("workspace.ioi.skills", ".ioi/skills", "ioi", "workspace"),
        (
            "workspace.agents.skills",
            ".agents/skills",
            "agents",
            "workspace",
        ),
        (
            "workspace.cursor.skills",
            ".cursor/skills",
            "cursor",
            "workspace",
        ),
        (
            "workspace.claude.skills",
            ".claude/skills",
            "claude",
            "workspace",
        ),
        ("global.ioi.skills", ".ioi/skills", "ioi", "global"),
        ("global.agents.skills", ".agents/skills", "agents", "global"),
    ] {
        sources.push(skill_hook_source(
            id,
            relative_path,
            compatibility,
            scope,
            "skill_dir",
            if scope == "global" {
                home_dir
            } else {
                workspace_root
            },
        ));
    }
    for (id, relative_path, compatibility, scope, kind) in [
        (
            "workspace.ioi.hooks_file",
            ".ioi/hooks.json",
            "ioi",
            "workspace",
            "hook_file",
        ),
        (
            "workspace.agents.hooks_file",
            ".agents/hooks.json",
            "agents",
            "workspace",
            "hook_file",
        ),
        (
            "workspace.cursor.hooks_file",
            ".cursor/hooks.json",
            "cursor",
            "workspace",
            "hook_file",
        ),
        (
            "workspace.claude.hooks_file",
            ".claude/hooks.json",
            "claude",
            "workspace",
            "hook_file",
        ),
        (
            "workspace.ioi.hooks_dir",
            ".ioi/hooks",
            "ioi",
            "workspace",
            "hook_dir",
        ),
        (
            "workspace.agents.hooks_dir",
            ".agents/hooks",
            "agents",
            "workspace",
            "hook_dir",
        ),
        (
            "workspace.cursor.hooks_dir",
            ".cursor/hooks",
            "cursor",
            "workspace",
            "hook_dir",
        ),
        (
            "workspace.claude.hooks_dir",
            ".claude/hooks",
            "claude",
            "workspace",
            "hook_dir",
        ),
        (
            "global.ioi.hooks_file",
            ".ioi/hooks.json",
            "ioi",
            "global",
            "hook_file",
        ),
        (
            "global.agents.hooks_file",
            ".agents/hooks.json",
            "agents",
            "global",
            "hook_file",
        ),
    ] {
        sources.push(skill_hook_source(
            id,
            relative_path,
            compatibility,
            scope,
            kind,
            if scope == "global" {
                home_dir
            } else {
                workspace_root
            },
        ));
    }
    sources
}

fn skill_hook_source(
    id: &str,
    relative_path: &str,
    compatibility: &str,
    scope: &str,
    kind: &str,
    root: &str,
) -> Value {
    let source_path = Path::new(root).join(relative_path);
    let path_string = source_path.to_string_lossy().to_string();
    let exists = source_path.exists();
    json!({
        "id": id,
        "kind": kind,
        "compatibility": compatibility,
        "scope": scope,
        "trustLevel": if scope == "global" { "global_user" } else { "workspace" },
        "path": path_string,
        "pathHash": sha256_hex(&path_string),
        "exists": exists,
        "status": if exists { "available" } else { "missing" },
        "evidenceRefs": ["skill_hook_source", id],
    })
}

fn discover_skills_from_source(source: &Value, workspace_root: &str) -> Vec<Value> {
    if source["kind"] != "skill_dir" || source["exists"] != true {
        return Vec::new();
    }
    let Some(source_path) = string_value(source, "path") else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(source_path) else {
        return Vec::new();
    };
    let mut skills = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let entry_path = entry.path();
        if entry_path.is_dir() {
            skills.push(skill_record_from_path(
                source,
                entry_path,
                workspace_root,
                None,
            ));
        } else if entry_path.is_file()
            && entry_path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        {
            skills.push(skill_record_from_path(
                source,
                entry_path.clone(),
                workspace_root,
                Some(entry_path),
            ));
        }
    }
    skills
}

fn skill_record_from_path(
    source: &Value,
    skill_path: PathBuf,
    workspace_root: &str,
    markdown_file: Option<PathBuf>,
) -> Value {
    let candidate_files = if let Some(file) = markdown_file.clone() {
        vec![file]
    } else {
        ["SKILL.md", "skill.md", "README.md"]
            .iter()
            .map(|name| skill_path.join(name))
            .collect()
    };
    let skill_file = candidate_files.into_iter().find(|path| path.exists());
    let content = skill_file
        .as_ref()
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    let metadata = parse_markdown_skill_metadata(&content);
    let has_skill_md = skill_file
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("skill.md"));
    let mut issues = Vec::new();
    if skill_file.is_none() {
        issues.push("missing_skill_markdown".to_string());
    }
    if skill_file.is_some() && !has_skill_md && skill_path.is_dir() {
        issues.push("missing_canonical_SKILL_md".to_string());
    }
    if skill_file.is_some() && content.trim().is_empty() {
        issues.push("empty_skill_markdown".to_string());
    }
    let fallback_name = skill_path
        .file_stem()
        .or_else(|| skill_path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("skill")
        .to_string();
    let name = metadata
        .name
        .clone()
        .or(metadata.title.clone())
        .unwrap_or(fallback_name);
    let source_id = string_value(source, "id").unwrap_or_else(|| "source".to_string());
    let skill_file_string = skill_file
        .as_ref()
        .map(|path| path.to_string_lossy().to_string());
    let skill_path_string = skill_path.to_string_lossy().to_string();
    let skill_hash = sha256_hex(&format!(
        "{}:{}:{}",
        source_id,
        skill_file_string
            .as_deref()
            .unwrap_or(skill_path_string.as_str()),
        content
    ));
    json!({
        "schemaVersion": "ioi.agent-runtime.skill.v1",
        "id": format!("skill.{}.{}.{}", safe_id(&source_id), safe_id(&name), &skill_hash[..10]),
        "name": name,
        "description": metadata.description,
        "sourceId": source_id,
        "compatibility": source["compatibility"],
        "trustLevel": source["trustLevel"],
        "activationMode": metadata.activation_mode.unwrap_or_else(|| "discoverable".to_string()),
        "skillHash": skill_hash,
        "path": skill_path_string,
        "pathHash": sha256_hex(&skill_path.to_string_lossy()),
        "relativePath": relative_path_for_workspace(&skill_path, workspace_root),
        "skillFile": skill_file_string,
        "skillFileHash": skill_file.as_ref().map(|path| sha256_hex(&path.to_string_lossy())),
        "hasSkillMd": has_skill_md,
        "frontmatterKeys": metadata.frontmatter_keys,
        "capabilityScopes": metadata.capability_scopes,
        "validation": {
            "status": if issues.is_empty() { "pass" } else { "degraded" },
            "issues": issues,
        },
        "provenance": {
            "importedFrom": source["compatibility"],
            "governed": true,
            "readOnlyDiscovery": true,
        },
        "evidenceRefs": [
            "runtime_skill_discovery",
            source["id"].as_str().unwrap_or("source"),
            if skill_file.is_some() { "SKILL.md" } else { "missing_SKILL.md" },
        ],
    })
}

fn discover_hooks_from_source(source: &Value, workspace_root: &str) -> Vec<Value> {
    if source["exists"] != true {
        return Vec::new();
    }
    let Some(source_path) = string_value(source, "path") else {
        return Vec::new();
    };
    let path = PathBuf::from(source_path);
    match source["kind"].as_str() {
        Some("hook_file") => {
            hooks_from_definition(source, read_json_quiet(&path), path, workspace_root, None)
        }
        Some("hook_dir") => {
            let Ok(entries) = fs::read_dir(path) else {
                return Vec::new();
            };
            entries
                .flatten()
                .flat_map(|entry| {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        return Vec::new();
                    }
                    let entry_path = entry.path();
                    if entry_path.is_file()
                        && entry_path
                            .extension()
                            .and_then(|value| value.to_str())
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                    {
                        return hooks_from_definition(
                            source,
                            read_json_quiet(&entry_path),
                            entry_path,
                            workspace_root,
                            None,
                        );
                    }
                    if entry_path.is_dir() {
                        let hook_json = entry_path.join("hook.json");
                        if hook_json.exists() {
                            return hooks_from_definition(
                                source,
                                read_json_quiet(&hook_json),
                                hook_json,
                                workspace_root,
                                Some(name),
                            );
                        }
                    }
                    Vec::new()
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn hooks_from_definition(
    source: &Value,
    definition: Option<Value>,
    definition_path: PathBuf,
    workspace_root: &str,
    fallback_name: Option<String>,
) -> Vec<Value> {
    let Some(definition) = definition else {
        return vec![hook_record_from_definition(
            source,
            fallback_name.unwrap_or_else(|| path_stem(&definition_path)),
            Value::Object(Map::new()),
            definition_path,
            workspace_root,
            vec!["invalid_hook_definition".to_string()],
        )];
    };
    if let Some(items) = definition.as_array() {
        return items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                hook_record_from_definition(
                    source,
                    string_value(item, "name")
                        .or_else(|| fallback_name.clone())
                        .unwrap_or_else(|| format!("hook_{}", index + 1)),
                    item.clone(),
                    definition_path.clone(),
                    workspace_root,
                    Vec::new(),
                )
            })
            .collect();
    }
    let Some(object) = definition.as_object() else {
        return vec![hook_record_from_definition(
            source,
            fallback_name.unwrap_or_else(|| path_stem(&definition_path)),
            Value::Object(Map::new()),
            definition_path,
            workspace_root,
            vec!["invalid_hook_definition".to_string()],
        )];
    };
    if object.len() == 1 {
        if let Some(Value::Array(items)) = object.get("hooks") {
            return items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    hook_record_from_definition(
                        source,
                        string_value(item, "name")
                            .or_else(|| fallback_name.clone())
                            .unwrap_or_else(|| format!("hook_{}", index + 1)),
                        item.clone(),
                        definition_path.clone(),
                        workspace_root,
                        Vec::new(),
                    )
                })
                .collect();
        }
    }
    object
        .iter()
        .map(|(name, item)| {
            hook_record_from_definition(
                source,
                name.clone(),
                item.clone(),
                definition_path.clone(),
                workspace_root,
                Vec::new(),
            )
        })
        .collect()
}

fn hook_record_from_definition(
    source: &Value,
    name: String,
    definition: Value,
    definition_path: PathBuf,
    workspace_root: &str,
    mut issues: Vec<String>,
) -> Value {
    let record = definition.as_object().cloned().unwrap_or_default();
    let event_kinds = string_list_from_keys(
        &record,
        &["event_kinds", "events", "subscribe", "subscriptions"],
    );
    let inferred_event_kinds = if event_kinds.is_empty() {
        infer_hook_event_kinds(&name)
    } else {
        event_kinds
    };
    let authority_scopes = string_list_from_keys(&record, &["authority_scopes", "capabilities"]);
    let tool_contracts = string_list_from_keys(&record, &["tool_contracts", "tools"]);
    let command_input = string_from_keys(&record, &["command", "script", "path"])
        .or_else(|| definition.as_str().map(str::to_string));
    let failure_policy = normalize_hook_failure_policy(
        string_from_keys(&record, &["failure_policy", "on_failure", "onFailure"]).as_deref(),
    );
    let side_effect_class =
        string_from_keys(&record, &["side_effect_class"]).unwrap_or_else(|| "none".to_string());
    if command_input.is_some() && authority_scopes.is_empty() {
        issues.push("missing_authority_scope".to_string());
    }
    if side_effect_class != "none" && tool_contracts.is_empty() {
        issues.push("missing_tool_contract".to_string());
    }
    issues.sort();
    issues.dedup();
    let definition_hash =
        sha256_hex(&serde_json::to_string(&redacted_hook_definition(&record)).unwrap_or_default());
    let definition_path_string = definition_path.to_string_lossy().to_string();
    json!({
        "schemaVersion": "ioi.agent-runtime.hook.v1",
        "id": format!(
            "hook.{}.{}.{}",
            safe_id(&string_value(source, "id").unwrap_or_else(|| "source".to_string())),
            safe_id(&name),
            &definition_hash[..10],
        ),
        "name": name,
        "sourceId": source["id"],
        "compatibility": source["compatibility"],
        "trustLevel": source["trustLevel"],
        "enabled": record.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        "eventKinds": inferred_event_kinds,
        "failurePolicy": failure_policy,
        "sideEffectClass": side_effect_class,
        "authorityScopes": authority_scopes,
        "toolContracts": tool_contracts,
        "commandConfigured": command_input.is_some(),
        "commandHash": command_input.as_ref().map(|command| sha256_hex(command)),
        "commandRedacted": command_input.is_some(),
        "definitionPath": definition_path_string,
        "definitionPathHash": sha256_hex(&definition_path.to_string_lossy()),
        "relativePath": relative_path_for_workspace(&definition_path, workspace_root),
        "definitionHash": definition_hash,
        "mutationPolicy": {
            "outsideDeclaredCapabilitiesBlocked": true,
            "mutationRequiresAuthorityScope": true,
            "mutationRequiresToolContract": true,
        },
        "validation": {
            "status": if issues.is_empty() { "pass" } else { "degraded" },
            "issues": issues,
        },
        "evidenceRefs": [
            "runtime_hook_discovery",
            source["id"].as_str().unwrap_or("source"),
            "hook_failure_policy",
        ],
    })
}

fn normalized_registry_kind(
    request: &SkillHookRegistryProjectionRequest,
) -> Result<String, SkillHookRegistryProjectionError> {
    if let Some(value) = optional_trimmed_lower(request.registry_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if operation_kind.ends_with(".catalog") {
        return Ok("catalog".to_string());
    }
    if operation_kind.ends_with(".skills") {
        return Ok("skills".to_string());
    }
    if operation_kind.ends_with(".hooks") {
        return Ok("hooks".to_string());
    }
    Err(SkillHookRegistryProjectionError::new(
        "skill_hook_registry_projection_kind_required",
        "skill hook registry projection kind is required",
    ))
}

#[derive(Default)]
struct SkillMetadata {
    name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    activation_mode: Option<String>,
    capability_scopes: Vec<String>,
    frontmatter_keys: Vec<String>,
}

fn parse_markdown_skill_metadata(content: &str) -> SkillMetadata {
    let mut metadata = SkillMetadata::default();
    let mut frontmatter = Map::new();
    if content.starts_with("---") {
        if let Some(end) = content[3..].find("\n---") {
            for line in content[3..end + 3].lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    if key
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
                    {
                        frontmatter.insert(
                            key.to_string(),
                            Value::String(
                                value
                                    .trim()
                                    .trim_matches('"')
                                    .trim_matches('\'')
                                    .to_string(),
                            ),
                        );
                    }
                }
            }
        }
    }
    metadata.name = string_value_from_map(&frontmatter, "name");
    metadata.description = string_value_from_map(&frontmatter, "description");
    metadata.activation_mode = string_value_from_map(&frontmatter, "activationMode")
        .or_else(|| string_value_from_map(&frontmatter, "activation_mode"));
    metadata.capability_scopes = string_list_value(
        frontmatter
            .get("capabilityScopes")
            .or_else(|| frontmatter.get("capability_scopes")),
    );
    let mut keys: Vec<String> = frontmatter.keys().cloned().collect();
    keys.sort();
    metadata.frontmatter_keys = keys;
    metadata.title = content
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("# ").map(str::trim))
        .and_then(optional_string);
    metadata
}

fn validation_issues(value: &Value) -> Vec<String> {
    value["validation"]["issues"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn infer_hook_event_kinds(name: &str) -> Vec<String> {
    let text = name.to_ascii_lowercase();
    if text.contains("pre-model") || text.contains("pre_model") {
        return vec!["pre_model".to_string()];
    }
    if text.contains("post-model") || text.contains("post_model") {
        return vec!["post_model".to_string()];
    }
    if text.contains("pre-tool") || text.contains("pre_tool") {
        return vec!["pre_tool".to_string()];
    }
    if text.contains("post-tool") || text.contains("post_tool") {
        return vec!["post_tool".to_string()];
    }
    if text.contains("approval") {
        return vec!["approval".to_string()];
    }
    if text.contains("activation") {
        return vec!["workflow_activation".to_string()];
    }
    vec!["event_subscriber".to_string()]
}

fn normalize_hook_failure_policy(value: Option<&str>) -> String {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("block" | "warn" | "ignore" | "retry") => value.unwrap().to_ascii_lowercase(),
        _ => "warn".to_string(),
    }
}

fn redacted_hook_definition(record: &Map<String, Value>) -> Map<String, Value> {
    let mut clone = record.clone();
    for key in ["command", "script", "env", "secrets", "headers"] {
        if clone.contains_key(key) {
            clone.insert(key.to_string(), Value::String("[redacted]".to_string()));
        }
    }
    clone
}

fn string_list_from_keys(record: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| record.get(*key))
        .map(|value| string_list_value(Some(value)))
        .unwrap_or_default()
}

fn string_from_keys(record: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        record
            .get(*key)
            .and_then(Value::as_str)
            .and_then(optional_string)
    })
}

fn string_list_value(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .filter_map(optional_string)
            .collect(),
        Some(Value::String(text)) => text.split(',').filter_map(optional_string).collect(),
        _ => Vec::new(),
    }
}

fn read_json_quiet(path: &Path) -> Option<Value> {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
}

fn array_values(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(optional_string)
}

fn string_value_from_map(value: &Map<String, Value>, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(optional_string)
}

fn optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value.and_then(optional_string)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

fn absolute_path(value: String) -> String {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path.to_string_lossy().to_string()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
            .to_string_lossy()
            .to_string()
    }
}

fn relative_path_for_workspace(path: &Path, workspace_root: &str) -> Option<String> {
    let root = Path::new(workspace_root);
    path.strip_prefix(root)
        .ok()
        .map(|relative| relative.to_string_lossy().to_string())
        .filter(|value| !value.is_empty())
}

fn path_stem(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("hook")
        .to_string()
}

fn safe_id(value: &str) -> String {
    let mut result = String::new();
    let mut last_was_sep = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
            last_was_sep = false;
        } else if !last_was_sep {
            result.push('_');
            last_was_sep = true;
        }
    }
    let trimmed = result.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed
    }
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rust_projects_skill_hook_registry_catalog() {
        let (workspace, home) = fixture_roots("catalog");
        fs::create_dir_all(workspace.join(".cursor/skills/repo-cartographer")).unwrap();
        fs::write(
            workspace.join(".cursor/skills/repo-cartographer/SKILL.md"),
            "---\nname: Repo Cartographer\ndescription: Maps code\ncapability_scopes: repo.read, evidence.read\n---\n# Repo Cartographer\n",
        )
        .unwrap();
        fs::write(
            workspace.join(".cursor/hooks.json"),
            json!({
                "hooks": [
                    {
                        "name": "pre-model-redaction",
                        "event_kinds": ["pre_model"],
                        "authority_scopes": ["runtime.read"],
                        "tool_contracts": ["fs.read"],
                        "command": "redacted-command",
                        "failure_policy": "block"
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let record = SkillHookRegistryProjectionCore
            .project(SkillHookRegistryProjectionRequest {
                operation_kind: Some("skill_hook.registry.catalog".to_string()),
                registry_kind: Some("catalog".to_string()),
                workspace_root: Some(workspace.to_string_lossy().to_string()),
                home_dir: Some(home.to_string_lossy().to_string()),
                source: Some("runtime.skill_hook_surface".to_string()),
            })
            .expect("skill hook projection");

        assert_eq!(record.registry_kind, "catalog");
        assert_eq!(record.catalog["status"], "pass");
        assert_eq!(record.catalog["skillCount"], 1);
        assert_eq!(record.catalog["hookCount"], 1);
        assert_eq!(record.catalog["skills"][0]["name"], "Repo Cartographer");
        assert_eq!(
            record.catalog["skills"][0]["capabilityScopes"],
            json!(["repo.read", "evidence.read"])
        );
        assert_eq!(record.catalog["hooks"][0]["commandRedacted"], true);
        assert!(record.catalog["hooks"][0]["command"].is_null());
        assert_eq!(
            record.projection["schemaVersion"],
            "ioi.agent-runtime.skill-hook-catalog.v1"
        );
    }

    #[test]
    fn rust_projects_skill_and_hook_route_shapes() {
        let (workspace, home) = fixture_roots("routes");
        fs::create_dir_all(workspace.join(".ioi/skills/empty-skill")).unwrap();
        fs::create_dir_all(workspace.join(".ioi/hooks")).unwrap();
        fs::write(
            workspace.join(".ioi/hooks/post-tool-ledger.json"),
            json!({
                "hooks": [{
                    "name": "post-tool-ledger",
                    "events": ["post_tool"],
                    "side_effect_class": "none"
                }]
            })
            .to_string(),
        )
        .unwrap();

        let skills = SkillHookRegistryProjectionCore
            .project(SkillHookRegistryProjectionRequest {
                registry_kind: Some("skills".to_string()),
                operation_kind: Some("skill_hook.registry.skills".to_string()),
                workspace_root: Some(workspace.to_string_lossy().to_string()),
                home_dir: Some(home.to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("skills projection");
        let hooks = SkillHookRegistryProjectionCore
            .project(SkillHookRegistryProjectionRequest {
                registry_kind: Some("hooks".to_string()),
                operation_kind: Some("skill_hook.registry.hooks".to_string()),
                workspace_root: Some(workspace.to_string_lossy().to_string()),
                home_dir: Some(home.to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("hooks projection");

        assert_eq!(
            skills.projection["schemaVersion"],
            "ioi.agent-runtime.skills.v1"
        );
        assert_eq!(skills.projection["skillCount"], 1);
        assert_eq!(
            skills.projection["skills"][0]["validation"]["status"],
            "degraded"
        );
        assert_eq!(
            hooks.projection["schemaVersion"],
            "ioi.agent-runtime.hooks.v1"
        );
        assert_eq!(hooks.projection["hookCount"], 1);
        assert_eq!(
            hooks.projection["hooks"][0]["eventKinds"],
            json!(["post_tool"])
        );
    }

    #[test]
    fn rust_shapes_skill_hook_registry_direct_record() {
        let (workspace, home) = fixture_roots("command");
        let record = SkillHookRegistryProjectionCore::default()
            .project(SkillHookRegistryProjectionRequest {
                registry_kind: Some("skills".to_string()),
                operation_kind: Some("skill_hook.registry.skills".to_string()),
                workspace_root: Some(workspace.to_string_lossy().to_string()),
                home_dir: Some(home.to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("skill hook registry direct record");
        let record = record.to_value();

        assert_eq!(record["source"], "rust_skill_hook_registry_projection_api");
        assert_eq!(
            record["schema_version"],
            SKILL_HOOK_REGISTRY_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert!(record.get("operation").is_none());
        assert_eq!(record["operation_kind"], "skill_hook.registry.skills");
        assert_eq!(
            record["projection"]["schemaVersion"],
            "ioi.agent-runtime.skills.v1"
        );
    }

    fn fixture_roots(label: &str) -> (PathBuf, PathBuf) {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ioi-skill-hook-{label}-{seed}"));
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        (workspace, home)
    }
}
