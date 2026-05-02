use crate::agentic::rules::{ActionRules, Rule, RuleConditions, Verdict};
use ioi_types::app::ActionTarget;
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemScope {
    Read,
    Write,
}

impl FilesystemScope {
    fn policy_target(self) -> &'static str {
        match self {
            Self::Read => "fs::read",
            Self::Write => "fs::write",
        }
    }
}

fn filesystem_scope_for_target(target: &ActionTarget) -> Option<FilesystemScope> {
    match target {
        ActionTarget::FsRead => Some(FilesystemScope::Read),
        ActionTarget::FsWrite => Some(FilesystemScope::Write),
        ActionTarget::Custom(name) => match name.as_str() {
            "fs::read" | "file__read" | "file__view" | "file__list" | "file__search"
            | "file__info" => Some(FilesystemScope::Read),
            "fs::write" | "file__write" | "file__edit" | "file__multi_edit" | "file__delete"
            | "file__create_dir" | "file__zip" | "file__move" | "file__copy" => {
                Some(FilesystemScope::Write)
            }
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn filesystem_scope_policy_target(target: &ActionTarget) -> Option<&'static str> {
    filesystem_scope_for_target(target).map(|scope| scope.policy_target())
}

pub(super) fn required_filesystem_path_keys(
    target: &ActionTarget,
) -> Option<&'static [&'static str]> {
    match target {
        ActionTarget::FsRead | ActionTarget::FsWrite => Some(&["path"]),
        ActionTarget::Custom(name) => match name.as_str() {
            "fs::read" | "file__read" | "file__view" | "file__list" | "file__search"
            | "file__info" | "fs::write" | "file__write" | "file__edit" | "file__multi_edit"
            | "file__delete" | "file__create_dir" => Some(&["path"]),
            "file__zip" => Some(&["source_path", "destination_zip_path"]),
            "file__move" | "file__copy" => Some(&["source_path", "destination_path"]),
            _ => None,
        },
        _ => None,
    }
}

fn extract_required_paths(params: &Value, keys: &[&str]) -> Option<Vec<String>> {
    let mut paths = Vec::with_capacity(keys.len());
    for key in keys {
        let path = params.get(*key)?.as_str()?.trim();
        if path.is_empty() {
            return None;
        }
        paths.push(path.to_string());
    }
    Some(paths)
}

fn normalize_policy_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut segments: Vec<OsString> = Vec::new();

    for component in Path::new(trimmed).components() {
        match component {
            Component::Prefix(value) => {
                if prefix.replace(value.as_os_str().to_os_string()).is_some() {
                    return None;
                }
            }
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::Normal(segment) => segments.push(segment.to_os_string()),
            Component::ParentDir => {
                if segments.pop().is_none() {
                    return None;
                }
            }
        }
    }

    let mut normalized = PathBuf::new();
    if let Some(value) = prefix {
        normalized.push(value);
    }
    if has_root {
        normalized.push(std::path::MAIN_SEPARATOR.to_string());
    }
    for segment in segments {
        normalized.push(segment);
    }

    if normalized.as_os_str().is_empty() {
        if has_root {
            normalized.push(std::path::MAIN_SEPARATOR.to_string());
        } else {
            normalized.push(".");
        }
    }

    Some(normalized)
}

fn expand_tilde_path(path: &str) -> Option<PathBuf> {
    if path == "~" {
        if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(home));
        }
        if let Some(home) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(home));
        }
        return None;
    }

    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return expand_tilde_path("~").map(|home| home.join(remainder));
    }

    Some(PathBuf::from(path))
}

fn syntactic_resolve_policy_path(path: &str, working_directory: Option<&str>) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let requested = expand_tilde_path(trimmed)?;
    if requested.is_absolute() {
        return Some(requested);
    }

    let cwd = working_directory
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(".");
    let base = expand_tilde_path(cwd)?;
    let absolute_base = if base.is_absolute() {
        base
    } else {
        std::env::current_dir().ok()?.join(base)
    };

    Some(absolute_base.join(requested))
}

fn resolve_policy_path(path: &str, working_directory: Option<&str>) -> Option<PathBuf> {
    if let Some(resolved) = syntactic_resolve_policy_path(path, working_directory) {
        if let Some(normalized) = normalize_policy_path(resolved.to_string_lossy().as_ref()) {
            return Some(normalized);
        }
    }

    normalize_policy_path(path)
}

fn resolve_workspace_root(working_directory: Option<&str>) -> Option<String> {
    let normalized = working_directory
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let resolved = resolve_policy_path(".", Some(normalized))?;
    if resolved.parent().is_none() {
        return None;
    }
    Some(resolved.display().to_string())
}

pub fn augment_workspace_filesystem_policy(
    rules: &ActionRules,
    working_directory: Option<&str>,
) -> ActionRules {
    let Some(workspace_root) = resolve_workspace_root(working_directory) else {
        return rules.clone();
    };

    let mut effective = rules.clone();
    for (rule_id, target) in [
        ("allow-workspace-fs-read", "fs::read"),
        ("allow-workspace-fs-write", "fs::write"),
    ] {
        effective.rules.push(Rule {
            rule_id: Some(rule_id.to_string()),
            target: target.to_string(),
            conditions: RuleConditions {
                allow_paths: Some(vec![workspace_root.clone()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        });
    }

    effective
}

pub(super) fn validate_allow_paths_condition(
    allowed_paths: &[String],
    target: &ActionTarget,
    params: &[u8],
    working_directory: Option<&str>,
) -> bool {
    let Some(required_keys) = required_filesystem_path_keys(target) else {
        return true;
    };

    let parsed = match serde_json::from_slice::<Value>(params) {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!(
                "Policy Blocking FS Access: Failed to decode params for {:?}: {}",
                target,
                e
            );
            return false;
        }
    };

    let requested_paths = match extract_required_paths(&parsed, required_keys) {
        Some(paths) => paths,
        None => {
            tracing::warn!(
                "Policy Blocking FS Access: Missing required path fields {:?} for {:?}.",
                required_keys,
                target
            );
            return false;
        }
    };

    let normalized_allowed_paths = match allowed_paths
        .iter()
        .map(|allowed| resolve_policy_path(allowed, working_directory))
        .collect::<Option<Vec<_>>>()
    {
        Some(paths) => paths,
        None => {
            tracing::warn!(
                "Policy Blocking FS Access: allow_paths contains invalid root(s): {:?}",
                allowed_paths
            );
            return false;
        }
    };

    let denied_paths: Vec<String> = requested_paths
        .into_iter()
        .filter_map(|path| {
            let normalized_path = match resolve_policy_path(&path, working_directory) {
                Some(value) => value,
                None => return Some(format!("{path} (invalid path traversal)")),
            };

            let allowed = normalized_allowed_paths
                .iter()
                .any(|allowed| normalized_path.starts_with(allowed));

            if allowed {
                None
            } else {
                Some(format!(
                    "{} (normalized: {})",
                    path,
                    normalized_path.display()
                ))
            }
        })
        .collect();

    if !denied_paths.is_empty() {
        tracing::warn!(
            "Policy Blocking FS Access: Requested path(s) {:?} outside allowed roots {:?}",
            denied_paths,
            normalized_allowed_paths
        );
        return false;
    }

    true
}
