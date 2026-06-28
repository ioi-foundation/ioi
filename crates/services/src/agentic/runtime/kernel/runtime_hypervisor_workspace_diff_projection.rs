//! Hypervisor workspace-diff projection (pure shaping).
//!
//! Rust port of `runtime-workspace-diff-projection.mjs`'s pure shaping. The
//! cockpit's Changes panel renders `changed_file_groups` from a REAL signal —
//! `git status` + `git diff --numstat` deltas for a work tree, or a real file
//! walk for a fresh scratch workspace. No fixtures: the signal is the disk.
//!
//! The daemon performs the I/O (running git, walking the filesystem) and hands
//! the raw output here; this module parses git output, derives folders, and
//! groups by folder — all pure, all unit-testable with canned input.

use serde_json::{json, Value};

pub const WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION: &str =
    "ioi.hypervisor.workspace_diff_projection.v1";

/// Projection for a session with no workspace yet (no fake work).
pub fn workspace_diff_absent() -> Value {
    json!({
        "schema_version": WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION,
        "workspace_root": Value::Null,
        "source": "absent",
        "changed_file_groups": [],
        "runtimeTruthSource": "daemon-runtime",
    })
}

/// Parse `git diff --numstat HEAD` + `git status --porcelain` into the
/// canonical projection (`source: "git"`). Pure.
pub fn workspace_diff_from_git(
    workspace_root: &str,
    numstat_stdout: &str,
    status_stdout: &str,
) -> Value {
    // numstat: `<added>\t<removed>\t<path>` (added/removed may be "-" for binary).
    let mut numstat: Vec<(String, String, String)> = Vec::new();
    for line in numstat_stdout.split('\n') {
        if let Some((added, removed, path)) = parse_numstat_line(line) {
            numstat.push((added, removed, path));
        }
    }
    let mut records: Vec<Value> = Vec::new();
    for line in status_stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        // porcelain: `XY PATH` — code = chars [0,2) trimmed, path = chars [3..) trimmed.
        let code: String = line.chars().take(2).collect::<String>().trim().to_string();
        let rel_path: String = line.chars().skip(3).collect::<String>().trim().to_string();
        let delta = numstat
            .iter()
            .find(|(_, _, path)| path == &rel_path)
            .map(|(added, removed, _)| {
                let added = if added == "-" { "0" } else { added.as_str() };
                let removed = if removed == "-" {
                    "0"
                } else {
                    removed.as_str()
                };
                format!("+{added}/-{removed}")
            })
            .unwrap_or_else(|| "+0".to_string());
        records.push(json!({ "relPath": rel_path, "delta": delta, "status": status_label(&code) }));
    }
    project_from_records(workspace_root, "git", &records)
}

/// Build the projection from daemon-walked file records (`source: "filesystem"`).
/// Each record is `{ relPath, delta, status }`. Pure.
pub fn workspace_diff_from_records(workspace_root: &str, source: &str, records: &[Value]) -> Value {
    project_from_records(workspace_root, source, records)
}

fn project_from_records(workspace_root: &str, source: &str, records: &[Value]) -> Value {
    json!({
        "schema_version": WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION,
        "workspace_root": workspace_root,
        "source": source,
        "changed_file_groups": group_by_folder(records),
        "changed_file_count": records.len(),
        "runtimeTruthSource": "daemon-runtime",
    })
}

fn parse_numstat_line(line: &str) -> Option<(String, String, String)> {
    // `^(\d+|-)\t(\d+|-)\t(.+)$`
    let mut parts = line.splitn(3, '\t');
    let added = parts.next()?;
    let removed = parts.next()?;
    let path = parts.next()?;
    if path.is_empty() || !is_count_token(added) || !is_count_token(removed) {
        return None;
    }
    Some((added.to_string(), removed.to_string(), path.to_string()))
}

fn is_count_token(token: &str) -> bool {
    token == "-" || (!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()))
}

/// Mirror JS `statusLabel`: D→deleted, A/??→added, else modified.
fn status_label(code: &str) -> &'static str {
    if code.contains('D') {
        "deleted"
    } else if code.contains('A') || code == "??" {
        "added"
    } else {
        "modified"
    }
}

/// Mirror JS `groupByFolder`: stable folder-keyed groups in first-seen order.
fn group_by_folder(records: &[Value]) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for record in records {
        let rel_path = record.get("relPath").and_then(Value::as_str).unwrap_or("");
        let delta = record.get("delta").and_then(Value::as_str).unwrap_or("+0");
        let status = record
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("modified");
        let folder = folder_for(rel_path);
        if !groups.contains_key(&folder) {
            order.push(folder.clone());
            groups.insert(folder.clone(), Vec::new());
        }
        groups.get_mut(&folder).unwrap().push(json!({
            "file_ref": format!("changed-file:{}", safe_id(rel_path)),
            "name": posix_basename(rel_path),
            "delta": delta,
            "status": status,
            "receipt_ref": format!("receipt://changes/{}", safe_id(rel_path)),
        }));
    }
    order
        .into_iter()
        .map(|folder| {
            let group_ref = format!(
                "changed-group:{}",
                safe_id(if folder.is_empty() {
                    "root"
                } else {
                    folder.as_str()
                })
            );
            let display_folder = if folder.is_empty() {
                "./".to_string()
            } else {
                folder.clone()
            };
            json!({
                "group_ref": group_ref,
                "folder": display_folder,
                "files": groups.remove(&folder).unwrap_or_default(),
            })
        })
        .collect()
}

/// `path.dirname(relPath) === "." ? "" : `${dirname}/``.
fn folder_for(rel_path: &str) -> String {
    let dir = posix_dirname(rel_path);
    if dir == "." {
        String::new()
    } else {
        format!("{dir}/")
    }
}

/// node `path.dirname` for clean relative POSIX paths.
fn posix_dirname(path: &str) -> String {
    match path.rfind('/') {
        None => ".".to_string(),
        Some(0) => "/".to_string(),
        Some(idx) => path[..idx].to_string(),
    }
}

/// node `path.basename` for clean relative POSIX paths.
fn posix_basename(path: &str) -> String {
    match path.rfind('/') {
        None => path.to_string(),
        Some(idx) => path[idx + 1..].to_string(),
    }
}

/// Mirror JS `safeId`: replace each run of `[^a-zA-Z0-9_.-]` with a single `_`.
fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_has_no_groups() {
        let projection = workspace_diff_absent();
        assert_eq!(projection["source"], "absent");
        assert_eq!(projection["workspace_root"], Value::Null);
        assert_eq!(
            projection["changed_file_groups"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn git_status_groups_by_folder_with_numstat_delta() {
        let numstat = "3\t1\tsrc/app.ts\n10\t0\tindex.html\n";
        let status = " M src/app.ts\n?? index.html\n";
        let projection = workspace_diff_from_git("/ws", numstat, status);
        assert_eq!(projection["source"], "git");
        assert_eq!(projection["workspace_root"], "/ws");
        assert_eq!(projection["changed_file_count"], 2);
        let groups = projection["changed_file_groups"].as_array().unwrap();
        // src/ folder first (first-seen order), then root.
        assert_eq!(groups[0]["folder"], "src/");
        assert_eq!(groups[0]["group_ref"], "changed-group:src_");
        assert_eq!(groups[0]["files"][0]["name"], "app.ts");
        assert_eq!(groups[0]["files"][0]["delta"], "+3/-1");
        assert_eq!(groups[0]["files"][0]["status"], "modified");
        assert_eq!(groups[0]["files"][0]["file_ref"], "changed-file:src_app.ts");
        assert_eq!(
            groups[0]["files"][0]["receipt_ref"],
            "receipt://changes/src_app.ts"
        );
        assert_eq!(groups[1]["folder"], "./");
        assert_eq!(groups[1]["group_ref"], "changed-group:root");
        assert_eq!(groups[1]["files"][0]["name"], "index.html");
        assert_eq!(groups[1]["files"][0]["status"], "added");
        assert_eq!(groups[1]["files"][0]["delta"], "+10/-0");
    }

    #[test]
    fn git_status_without_numstat_defaults_delta_and_binary_zeroes() {
        let numstat = "-\t-\tlogo.png\n";
        let status = "A  logo.png\nD  old.txt\n";
        let projection = workspace_diff_from_git("/ws", numstat, status);
        let groups = projection["changed_file_groups"].as_array().unwrap();
        let root = &groups[0];
        assert_eq!(root["files"][0]["name"], "logo.png");
        assert_eq!(root["files"][0]["delta"], "+0/-0"); // binary numstat "-" → 0
        assert_eq!(root["files"][0]["status"], "added");
        assert_eq!(root["files"][1]["name"], "old.txt");
        assert_eq!(root["files"][1]["delta"], "+0"); // no numstat entry
        assert_eq!(root["files"][1]["status"], "deleted");
    }

    #[test]
    fn filesystem_walk_records_group() {
        let records = vec![
            json!({ "relPath": "index.html", "delta": "+12", "status": "added" }),
            json!({ "relPath": "assets/styles.css", "delta": "+30", "status": "added" }),
        ];
        let projection = workspace_diff_from_records("/scratch", "filesystem", &records);
        assert_eq!(projection["source"], "filesystem");
        assert_eq!(projection["changed_file_count"], 2);
        let groups = projection["changed_file_groups"].as_array().unwrap();
        assert_eq!(groups[0]["folder"], "./");
        assert_eq!(groups[0]["files"][0]["name"], "index.html");
        assert_eq!(groups[1]["folder"], "assets/");
        assert_eq!(groups[1]["files"][0]["name"], "styles.css");
        assert_eq!(groups[1]["files"][0]["delta"], "+30");
    }

    #[test]
    fn ignores_blank_status_lines() {
        let projection = workspace_diff_from_git("/ws", "", "\n\n");
        assert_eq!(projection["changed_file_count"], 0);
        assert_eq!(
            projection["changed_file_groups"].as_array().unwrap().len(),
            0
        );
    }
}
