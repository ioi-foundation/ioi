//! Cut A — the environment-ops plane: `supervisor.v1.EnvironmentOpsService`.
//!
//! The per-environment runtime contract the native Workbench (Code / Files / Changes / Terminal /
//! Ports) consumes. Daemon-native (the daemon IS the local runner) — NOT a serve-layer shim. Reached
//! through the env gateway path `POST /supervisor/:env/supervisor.v1.EnvironmentOpsService/:method`
//! and authenticated by a real env-scoped capability lease (fail-closed on revoke/expire). Connect
//! JSON: unary methods POST JSON → JSON; bytes are base64; int64 are strings; enums are proto value
//! names. The daemon is source of truth — every read projects the real workspace.
//!
//! Contract pinned to `internal-docs/reverse-engineering/.../supervisor/v1/environmentopts.proto`.
//! This module lands the unary file + git planes (clears "Unable to load files" + the Changes panel);
//! terminal/watch/exec return Connect `unimplemented` until their streaming transport is wired.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde_json::{json, Value};

use super::authority_routes::{capability_lease_status, issue_capability_lease};
use super::DaemonState;

/// `POST /v1/hypervisor/environments/:id/ops-lease` — mint a short-lived env-scoped capability lease
/// for the environment-ops plane. `CreateEnvironmentAccessToken` (app surface) calls this; the lease
/// id is the Bearer the env gateway validates. Fail-closed: revoke/expire kills access immediately.
pub(crate) async fn handle_env_ops_lease(
    State(st): State<Arc<DaemonState>>,
    AxumPath(env_id): AxumPath<String>,
) -> Json<Value> {
    let lease = issue_capability_lease(
        &st.data_dir,
        "operator",
        "environment.ops",
        json!([format!("environment:{env_id}")]),
        3600,
    );
    let id = lease.get("grant_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    Json(json!({
        "accessToken": id,
        "lease_id": id,
        "lease_ref": lease.get("grant_ref"),
        "environment_id": env_id,
        "expires_at_unix": lease.get("expires_at_unix"),
    }))
}

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn safe(seg: &str) -> String {
    seg.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}

// ---- Connect response helpers -------------------------------------------------------------------

fn ok_json(v: Value) -> Response {
    ([(axum::http::header::CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

/// Connect error envelope: HTTP status + `{code,message}` — never HTML (which would hang the SPA).
fn connect_err(status: StatusCode, code: &str, message: &str) -> Response {
    (status, [(axum::http::header::CONTENT_TYPE, "application/json")], json!({ "code": code, "message": message }).to_string()).into_response()
}

// ---- workspace resolution + path fence ----------------------------------------------------------

fn env_workspace(data_dir: &str, env_id: &str) -> Option<String> {
    let path = Path::new(data_dir).join("environments").join(format!("{}.json", safe(env_id)));
    let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    v.get("status")
        .and_then(|s| s.get("workspace_root"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Resolve `rel` under the workspace, fenced: no `..` escape, result must stay within `ws`.
fn scoped(ws: &str, rel: &str) -> Result<PathBuf, String> {
    let rel = rel.trim_start_matches('/');
    let rel = if rel.is_empty() || rel == "." { "" } else { rel };
    if rel.split('/').any(|seg| seg == "..") {
        return Err("path escapes workspace".to_string());
    }
    let root = Path::new(ws);
    let joined = if rel.is_empty() { root.to_path_buf() } else { root.join(rel) };
    Ok(joined)
}

// ---- lease auth (env-scoped capability lease; fail-closed) --------------------------------------

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn lease_binds_env(data_dir: &str, lease_id: &str, env_id: &str) -> bool {
    let path = Path::new(data_dir).join("authority-grants").join(format!("{}.json", safe(lease_id)));
    let Ok(bytes) = std::fs::read(path) else { return false };
    let Ok(v): Result<Value, _> = serde_json::from_slice(&bytes) else { return false };
    let needle = format!("environment:{env_id}");
    v.get("resources")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().any(|x| x.as_str() == Some(needle.as_str()) || x.as_str() == Some(env_id)))
        .unwrap_or(false)
}

/// The environment a lease is bound to (from its `resources: ["environment:<env>"]`).
fn lease_env(data_dir: &str, lease_id: &str) -> Option<String> {
    let path = Path::new(data_dir).join("authority-grants").join(format!("{}.json", safe(lease_id)));
    let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    v.get("resources")?.as_array()?.iter().find_map(|x| x.as_str().and_then(|s| s.strip_prefix("environment:")).map(str::to_string))
}

/// `GET /v1/hypervisor/ops-lease/:token` — resolve a lease to its environment + live status. The
/// env-ops WebSocket transport (serve layer) calls this to authenticate the `auth` frame and learn
/// which environment the connection is bound to (the WS URL drops the env path by design).
pub(crate) async fn handle_ops_lease_resolve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(token): AxumPath<String>,
) -> Json<Value> {
    let active = capability_lease_status(&st.data_dir, &token) == "active";
    let env = lease_env(&st.data_dir, &token);
    Json(json!({ "active": active && env.is_some(), "environment_id": env }))
}

/// True iff the request carries an active capability lease bound to this environment.
fn authed(data_dir: &str, env_id: &str, headers: &HeaderMap) -> bool {
    let Some(token) = bearer(headers) else { return false };
    capability_lease_status(data_dir, &token) == "active" && lease_binds_env(data_dir, &token, env_id)
}

// ---- git helpers --------------------------------------------------------------------------------

fn git(ws: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git").arg("-C").arg(ws).args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// Run git and return stdout regardless of exit code. `git diff` exits 1 when differences exist
/// (and `--no-index` exits 1 for any diff) — that is NOT an error for our read paths.
fn git_lenient(ws: &str, args: &[&str]) -> String {
    Command::new("git")
        .arg("-C")
        .arg(ws)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Map a git porcelain XY code to the gitpod.v1.FileChange.ChangeType JSON enum name.
fn change_type(code: &str) -> &'static str {
    match code.trim() {
        "??" => "CHANGE_TYPE_ADDED",
        c if c.starts_with('A') => "CHANGE_TYPE_ADDED",
        c if c.starts_with('D') => "CHANGE_TYPE_DELETED",
        c if c.starts_with('R') => "CHANGE_TYPE_RENAMED",
        c if c.starts_with('C') => "CHANGE_TYPE_COPIED",
        c if c.contains('U') => "CHANGE_TYPE_UPDATED_BUT_UNMERGED",
        _ => "CHANGE_TYPE_MODIFIED",
    }
}

/// Changed files vs working tree (baseRef empty) or vs a ref, as gitpod.v1.FileChange[].
fn changed_files(ws: &str, base_ref: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if base_ref.is_empty() {
        // Uncommitted: porcelain captures tracked changes + untracked files. `-uall` lists each
        // untracked FILE individually (not a collapsed `dir/`), matching the reference Changes panel.
        if let Ok(stdout) = git(ws, &["status", "--porcelain", "-uall"]) {
            for line in stdout.lines() {
                if line.len() < 3 {
                    continue;
                }
                let code = &line[..2];
                let rest = line[3..].trim();
                // rename form "old -> new"
                let (path, old_path) = if let Some((o, n)) = rest.split_once(" -> ") {
                    (n.to_string(), Some(o.to_string()))
                } else {
                    (rest.to_string(), None)
                };
                let mut fc = json!({ "path": path, "changeType": change_type(code) });
                if let Some(op) = old_path {
                    fc["oldPath"] = json!(op);
                }
                out.push(fc);
            }
        }
    } else if let Ok(stdout) = git(ws, &["diff", "--name-status", base_ref]) {
        for line in stdout.lines() {
            let mut it = line.split('\t');
            let code = it.next().unwrap_or("");
            let path = it.next().unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            out.push(json!({ "path": path, "changeType": change_type(code) }));
        }
    }
    out
}

/// Parse a unified diff into supervisor.v1.GitHunk[].
fn parse_hunks(diff: &str) -> Vec<Value> {
    let mut hunks: Vec<Value> = Vec::new();
    let mut cur: Option<(i64, i64, i64, i64, String, Vec<String>)> = None;
    let flush = |cur: &mut Option<(i64, i64, i64, i64, String, Vec<String>)>, hunks: &mut Vec<Value>| {
        if let Some((os, ol, ns, nl, section, body)) = cur.take() {
            hunks.push(json!({
                "originalStartLine": os, "originalLines": ol,
                "newStartLine": ns, "newLines": nl,
                "section": section, "startPosition": 0, "body": body.join("\n"),
            }));
        }
    };
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("@@ ") {
            flush(&mut cur, &mut hunks);
            // @@ -os,ol +ns,nl @@ section
            let (ranges, section) = rest.split_once(" @@").unwrap_or((rest, ""));
            let mut parts = ranges.split_whitespace();
            let parse = |tok: Option<&str>| -> (i64, i64) {
                let t = tok.unwrap_or("").trim_start_matches(['-', '+']);
                let (a, b) = t.split_once(',').unwrap_or((t, "1"));
                (a.parse().unwrap_or(0), b.parse().unwrap_or(1))
            };
            let (os, ol) = parse(parts.next());
            let (ns, nl) = parse(parts.next());
            cur = Some((os, ol, ns, nl, section.trim().to_string(), Vec::new()));
        } else if let Some((_, _, _, _, _, body)) = cur.as_mut() {
            body.push(line.to_string());
        }
    }
    flush(&mut cur, &mut hunks);
    hunks
}

// ---- method dispatch ----------------------------------------------------------------------------

/// `POST /supervisor/:env/supervisor.v1.EnvironmentOpsService/:method` — the env-ops Connect surface.
pub(crate) async fn handle_environment_ops(
    State(st): State<Arc<DaemonState>>,
    AxumPath((env_id, method)): AxumPath<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !authed(&st.data_dir, &env_id, &headers) {
        return connect_err(StatusCode::UNAUTHORIZED, "unauthenticated", "a valid env-scoped capability lease is required");
    }
    let Some(ws) = env_workspace(&st.data_dir, &env_id) else {
        return connect_err(StatusCode::NOT_FOUND, "not_found", "environment not started (no scoped workspace)");
    };
    let req: Value = if body.is_empty() { json!({}) } else { serde_json::from_slice(&body).unwrap_or_else(|_| json!({})) };
    let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let i64s = |k: &str| req.get(k).and_then(|v| v.as_str().and_then(|x| x.parse::<i64>().ok()).or_else(|| v.as_i64())).unwrap_or(0);

    match method.as_str() {
        "ListCapabilities" => ok_json(json!({ "capabilities": [] })), // WATCH served by the WS transport (fs watcher)

        "ReadFile" => {
            let rel = s("path");
            let p = match scoped(&ws, &rel) {
                Ok(p) => p,
                Err(e) => return connect_err(StatusCode::BAD_REQUEST, "invalid_argument", &e),
            };
            if p.is_dir() {
                let mut entries = Vec::new();
                match std::fs::read_dir(&p) {
                    Ok(rd) => {
                        for e in rd.flatten() {
                            let md = match e.metadata() {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let name = e.file_name().to_string_lossy().into_owned();
                            let child = if rel.is_empty() || rel == "." { name.clone() } else { format!("{}/{}", rel.trim_end_matches('/'), name) };
                            entries.push(json!({ "path": child, "isDirectory": md.is_dir(), "size": md.len().to_string() }));
                        }
                    }
                    Err(e) => return connect_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", &e.to_string()),
                }
                entries.sort_by(|a, b| a["path"].as_str().unwrap_or("").cmp(b["path"].as_str().unwrap_or("")));
                ok_json(json!({ "directory": { "entries": entries } }))
            } else {
                match std::fs::read(&p) {
                    Ok(bytes) => {
                        let total = bytes.len() as i64;
                        let offset = i64s("offset").max(0) as usize;
                        let length = i64s("length").max(0) as usize;
                        let slice: &[u8] = if offset >= bytes.len() {
                            &[]
                        } else if length == 0 {
                            &bytes[offset..]
                        } else {
                            &bytes[offset..(offset + length).min(bytes.len())]
                        };
                        ok_json(json!({ "content": { "data": B64.encode(slice), "totalSize": total.to_string(), "contentHash": "" } }))
                    }
                    Err(e) => connect_err(StatusCode::NOT_FOUND, "not_found", &e.to_string()),
                }
            }
        }

        "WriteFile" => {
            let rel = s("path");
            let p = match scoped(&ws, &rel) {
                Ok(p) => p,
                Err(e) => return connect_err(StatusCode::BAD_REQUEST, "invalid_argument", &e),
            };
            let data = B64.decode(s("content")).unwrap_or_default();
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&p, &data) {
                Ok(_) => ok_json(json!({ "bytesWritten": (data.len() as i64).to_string() })),
                Err(e) => connect_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", &e.to_string()),
            }
        }

        "Find" => {
            let pattern = s("pattern");
            let base = s("path");
            let start = match scoped(&ws, &base) {
                Ok(p) => p,
                Err(e) => return connect_err(StatusCode::BAD_REQUEST, "invalid_argument", &e),
            };
            let mut files = Vec::new();
            let mut truncated = false;
            let mut stack = vec![start];
            while let Some(dir) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&dir) else { continue };
                for e in rd.flatten() {
                    if files.len() >= 2000 {
                        truncated = true;
                        break;
                    }
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name == ".git" {
                        continue;
                    }
                    let md = match e.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let abs = e.path();
                    let relp = abs.strip_prefix(&ws).unwrap_or(&abs).to_string_lossy().into_owned();
                    if pattern.is_empty() || name.to_lowercase().contains(&pattern.to_lowercase()) {
                        files.push(json!({ "path": relp, "isDirectory": md.is_dir(), "size": md.len().to_string() }));
                    }
                    if md.is_dir() {
                        stack.push(abs);
                    }
                }
            }
            ok_json(json!({ "files": files, "truncated": truncated }))
        }

        "GetDefaultBranch" => {
            let branch = git(&ws, &["rev-parse", "--abbrev-ref", "HEAD"]).map(|b| b.trim().to_string()).unwrap_or_else(|_| "main".into());
            ok_json(json!({ "branch": if branch.is_empty() { "main".into() } else { branch } }))
        }

        "GetGitStatus" => {
            let files = changed_files(&ws, "");
            let branch = git(&ws, &["rev-parse", "--abbrev-ref", "HEAD"]).map(|b| b.trim().to_string()).unwrap_or_default();
            ok_json(json!({ "status": {
                "branch": branch,
                "changedFiles": files.clone(),
                "totalChangedFiles": files.len() as i64,
                "unpushedCommits": [],
                "totalUnpushedCommits": 0,
            }}))
        }

        "GetGitDiffFiles" => {
            let files = changed_files(&ws, &s("baseRef"));
            ok_json(json!({ "changedFiles": files.clone(), "totalChangedFiles": files.len() as i64 }))
        }

        "GetGitDiff" => {
            let rel = s("path");
            let base = s("baseRef");
            let diff = if base.is_empty() {
                // Uncommitted: tracked diff, else treat untracked as all-added via --no-index.
                // (git diff exits 1 when differences exist — use the lenient runner.)
                let tracked = git_lenient(&ws, &["diff", "--", &rel]);
                if tracked.trim().is_empty() {
                    git_lenient(&ws, &["diff", "--no-index", "--", "/dev/null", &rel])
                } else {
                    tracked
                }
            } else {
                git_lenient(&ws, &["diff", &base, "--", &rel])
            };
            let is_binary = diff.contains("Binary files");
            ok_json(json!({
                "fileChange": { "path": rel, "changeType": "CHANGE_TYPE_MODIFIED" },
                "hunks": parse_hunks(&diff),
                "isBinary": is_binary,
            }))
        }

        "GetFileDiffContent" => {
            let rel = s("path");
            let base = s("baseRef");
            let original = if base.is_empty() {
                git(&ws, &["show", &format!("HEAD:{rel}")]).unwrap_or_default()
            } else {
                git(&ws, &["show", &format!("{base}:{rel}")]).unwrap_or_default()
            };
            let new_content = scoped(&ws, &rel).ok().and_then(|p| std::fs::read(p).ok()).unwrap_or_default();
            ok_json(json!({
                "fileChange": { "path": rel, "changeType": "CHANGE_TYPE_MODIFIED" },
                "originalContent": B64.encode(original.as_bytes()),
                "newContent": B64.encode(&new_content),
                "isBinary": false,
            }))
        }

        "ListTerminalProfiles" => {
            let bash = if Path::new("/usr/bin/bash").exists() { "/usr/bin/bash" } else { "/bin/bash" };
            ok_json(json!({ "profiles": [{ "profileName": "bash", "path": bash, "isAutoDetected": true }] }))
        }

        "Exec" => {
            let command = s("command");
            let cwd = {
                let wd = s("workingDirectory");
                if wd.is_empty() { ws.clone() } else { scoped(&ws, &wd).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| ws.clone()) }
            };
            match Command::new("bash").arg("-lc").arg(&command).current_dir(&cwd).output() {
                Ok(out) => ok_json(json!({
                    "exitCode": out.status.code().unwrap_or(-1),
                    "stdout": String::from_utf8_lossy(&out.stdout),
                    "stderr": String::from_utf8_lossy(&out.stderr),
                })),
                Err(e) => connect_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", &e.to_string()),
            }
        }

        "CancelExec" => ok_json(json!({})),

        // Terminal control + streaming (CreateTerminal/ReadTerminal/AttachTerminal/WriteTerminal/
        // ResizeTerminal/CloseTerminal/Watch) are served over the WebSocket transport (serve layer
        // bridges the daemon's real openpty terminals + an fs watcher); the SPA never calls them over
        // HTTP. StartBrowser is a declared follow-on. Honest Connect `unimplemented` over HTTP.
        "CreateTerminal" | "ReadTerminal" | "AttachTerminal" | "WriteTerminal" | "ResizeTerminal"
        | "CloseTerminal" | "ListTerminals" | "Watch" | "StartBrowser" => {
            connect_err(StatusCode::NOT_IMPLEMENTED, "unimplemented", &format!("{method} is served over the env-ops WebSocket transport"))
        }

        other => connect_err(StatusCode::NOT_IMPLEMENTED, "unimplemented", &format!("unknown method {other}")),
    }
}
