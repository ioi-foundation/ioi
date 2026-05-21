// apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn workflow_value_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

pub(super) fn workflow_logic_string(logic: &Value, key: &str) -> Option<String> {
    logic
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn workflow_value_bool_any(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
}

pub(super) fn workflow_value_u64_any(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(Value::as_u64).or_else(|| {
            value
                .get(*key)
                .and_then(Value::as_i64)
                .and_then(|item| (item >= 0).then_some(item as u64))
        })
    })
}

pub(super) fn workflow_value_i64_any(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(Value::as_i64).or_else(|| {
            value
                .get(*key)
                .and_then(Value::as_u64)
                .and_then(|item| i64::try_from(item).ok())
        })
    })
}

pub(super) fn workflow_string_array_any(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn workflow_project_root_for_path(workflow_path: &Path) -> String {
    workflow_path
        .parent()
        .and_then(|workflows_dir| workflows_dir.parent())
        .and_then(|agents_dir| {
            (agents_dir.file_name().and_then(|name| name.to_str()) == Some(".agents"))
                .then(|| agents_dir.parent())
                .flatten()
        })
        .or_else(|| workflow_path.parent())
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string()
}

pub(super) fn workflow_sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub(super) fn workflow_hash_value(value: &Value) -> String {
    format!("sha256:{}", workflow_hash_value_raw_hex(value))
}

pub(super) fn workflow_value_at_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.trim().is_empty()) {
        if segment == "[]" {
            current = current.as_array()?.first()?;
            continue;
        }
        current = current.get(segment)?;
    }
    Some(current.clone())
}

pub(super) fn workflow_hash_value_raw_hex(value: &Value) -> String {
    let bytes = serde_jcs::to_vec(value)
        .or_else(|_| serde_json::to_vec(value))
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
