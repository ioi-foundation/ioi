//! T7 daemon spine — the operator-surface substrate the native Workbench binds to.
//!
//! Three concerns, all daemon-owned truth (the guide: "if missing, add daemon endpoints before
//! claiming Workbench completion"):
//!
//! - **T7-2 Session Execution Binding**: one ref composing session + environment + thread +
//!   work_run (+ harness/model/authority refs) so the UI/SDK consume ONE binding instead of
//!   guessing how the three relate. A projection over existing objects — NOT a new runtime owner;
//!   `/v1/threads/*` still owns conversation and `/v1/hypervisor/environments/*` still owns
//!   lifecycle.
//! - **T7-3 env-files**: list/read/write/move/delete against the scoped environment workspace,
//!   BODY-dispatched via POST /v1/hypervisor/env-files (collision-safe — a static child beside
//!   `:id/:action` makes matchit panic at startup). Path-traversal is fenced to workspace_root.
//! - **T7-E interactive terminal**: a REAL openpty(3) PTY bound to environment_ref — create /
//!   stream / input / resize / close — so the Workbench terminal is genuinely interactive (shell
//!   state persists across inputs), not request/response exec.
use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_services::agentic::runtime::kernel::emergency_containment::{
    admit_isolated_execution, DeclaredIsolation, ExecutionLocus, IsolatedSubstrate,
};
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn sstr(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

fn load_env(data_dir: &str, id: &str) -> Option<Value> {
    let path = Path::new(data_dir)
        .join("environments")
        .join(format!("{}.json", safe(id)));
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}
/// The env's scoped workspace root (None until the env is started).
fn workspace_of(data_dir: &str, env_id: &str) -> Option<String> {
    load_env(data_dir, env_id)?["status"]["workspace_root"]
        .as_str()
        .map(str::to_string)
}
/// Strip a binding/environment ref prefix ("environment:env_x" -> "env_x").
fn ref_id(r: &str) -> &str {
    r.rsplit(':').next().unwrap_or(r)
}

fn emit_receipt(data_dir: &str, kind: &str, subject: &str, event: &str) -> String {
    let id = format!("brc_{:x}", nanos());
    let receipt_ref = format!("agentgres://{kind}-receipt/{id}");
    let rec = json!({ "schema_version": "ioi.hypervisor.binding-receipt.v1", "receipt_id": id, "receipt_ref": receipt_ref, "subject": subject, "event": event, "at": iso_now() });
    // CLASSIFIED — best-effort telemetry: binding-receipts are never read back (evidence trail only)
    let _ = persist_record(data_dir, "binding-receipts", &id, &rec);
    receipt_ref
}

// ===========================================================================
// T7-2 — Session Execution Binding
// ===========================================================================

fn binding_view(data_dir: &str, mut binding: Value) -> Value {
    // Hydrate live environment truth so the binding reflects daemon state, not a stale snapshot.
    if let Some(env_ref) = sstr(&binding, "environment_ref") {
        if let Some(env) = load_env(data_dir, ref_id(&env_ref)) {
            binding["environment_status"] = json!({
                "phase": env["status"]["phase"], "readiness": env["status"]["readiness"],
                "components": env["status"]["components"], "workspace_root": env["status"]["workspace_root"]
            });
        }
    }
    binding
}

/// POST /v1/hypervisor/session-execution-bindings — compose one binding over existing refs.
pub(crate) async fn handle_binding_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let data_dir = &st.data_dir;
    let env_ref = sstr(&body, "environment_ref").unwrap_or_default();
    let env_id = ref_id(&env_ref).to_string();
    if env_id.is_empty() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "session_execution_binding_environment_required".into(),
        ));
    }
    super::environment_routes::authorize_environment_owner(data_dir, &headers, &env_id)?;
    let id = format!("bind_{:x}", nanos());
    let session_ref = sstr(&body, "session_ref").unwrap_or_else(|| format!("session:{id}"));
    let thread_ref = body.get("thread_ref").cloned().unwrap_or(Value::Null);
    let work_run_ref = body.get("work_run_ref").cloned().unwrap_or(Value::Null);
    let receipt = emit_receipt(data_dir, "binding", &id, "created");
    let record = json!({
        "schema_version": "ioi.hypervisor.session-execution-binding.v1",
        "binding_ref": format!("binding:{id}"),
        "binding_id": id,
        "session_ref": session_ref,
        "environment_ref": env_ref,
        "thread_ref": thread_ref,
        "work_run_ref": work_run_ref,
        "agent_execution_ref": body.get("agent_execution_ref").cloned().unwrap_or(Value::Null),
        "harness_binding_ref": body.get("harness_binding_ref").cloned().unwrap_or(Value::Null),
        "model_configuration_ref": sstr(&body, "model_configuration_ref").unwrap_or_else(|| "model_configuration:hypervisor:native-local".into()),
        "authority_context_ref": sstr(&body, "authority_context_ref").unwrap_or_else(|| "authority_context:local_operator".into()),
        "adapter_refs": {
            "workspace_adapter": "HypervisorWorkspaceAdapter",
            "terminal_transport": "/v1/hypervisor/terminals",
            "editor_transport": "/v1/hypervisor/env-files",
            "files_transport": "/v1/hypervisor/env-files"
        },
        "event_stream_refs": {
            "environment": if env_id.is_empty() { Value::Null } else { json!(format!("/v1/hypervisor/env-events/{env_id}")) },
            "thread": thread_ref.as_str().map(|t| format!("/v1/threads/{}/events", ref_id(t))).map(Value::String).unwrap_or(Value::Null),
            "work_run": work_run_ref.as_str().map(|w| format!("/v1/hypervisor/workruns/{}/events", ref_id(w))).map(Value::String).unwrap_or(Value::Null)
        },
        "receipt_refs": [receipt],
        "state_root_ref": format!("state_root:{id}"),
        "created_at": iso_now()
    });
    // The binding is read back by GET :id / events / input / lifecycle via load_binding; a
    // discarded write hands the caller a binding_ref no subsequent read can resolve.
    if persist_record(data_dir, "session-execution-bindings", &id, &record).is_err() {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "session_execution_binding_persistence_failed",
                "message": "the session execution binding did not commit — nothing was bound" }),
            ),
        ));
    }
    Ok((
        StatusCode::OK,
        Json(json!({ "binding": binding_view(data_dir, record) })),
    ))
}

fn load_binding(data_dir: &str, id: &str) -> Option<Value> {
    let bid = ref_id(id);
    read_record_dir(data_dir, "session-execution-bindings")
        .into_iter()
        .find(|b| b.get("binding_id").and_then(|v| v.as_str()) == Some(bid))
}

fn authorize_binding_owner(
    data_dir: &str,
    headers: &HeaderMap,
    binding: &Value,
) -> Result<(), AppError> {
    let environment_id = binding
        .get("environment_ref")
        .and_then(Value::as_str)
        .map(ref_id)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_execution_binding_environment_missing".into(),
            )
        })?;
    super::environment_routes::authorize_environment_owner(data_dir, headers, environment_id)?;
    Ok(())
}

fn load_authorized_binding(
    data_dir: &str,
    headers: &HeaderMap,
    id: &str,
) -> Result<Value, AppError> {
    let binding = load_binding(data_dir, id).ok_or_else(|| {
        AppError(
            StatusCode::NOT_FOUND,
            "session_execution_binding_not_found".into(),
        )
    })?;
    authorize_binding_owner(data_dir, headers, &binding)?;
    Ok(binding)
}

/// GET /v1/hypervisor/session-execution-bindings/:id — the binding with LIVE env truth hydrated.
pub(crate) async fn handle_binding_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let binding = load_authorized_binding(&st.data_dir, &headers, &id)?;
    Ok(Json(
        json!({ "binding": binding_view(&st.data_dir, binding) }),
    ))
}

/// GET /v1/hypervisor/session-execution-bindings/:id/events — composed event snapshot. Every event
/// carries the binding_ref so the UI hydrates one screen with NO ref drift across env/thread/run.
pub(crate) async fn handle_binding_events(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let b = load_authorized_binding(&st.data_dir, &headers, &id)?;
    let binding_ref = b
        .get("binding_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut events: Vec<Value> = Vec::new();
    let stamp = |source: &str, ev: &str, data: Value| json!({ "binding_ref": binding_ref, "source": source, "event": ev, "data": data });
    if let Some(env_ref) = b.get("environment_ref").and_then(|v| v.as_str()) {
        if let Some(env) = load_env(&st.data_dir, ref_id(env_ref)) {
            events.push(stamp("environment", "environment_status", json!({ "phase": env["status"]["phase"], "readiness": env["status"]["readiness"]["mode"] })));
            for obs in env["lifecycle_observations"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                events.push(stamp("environment", "lifecycle_observation", obs));
            }
        }
    }
    if let Some(t) = b.get("thread_ref").and_then(|v| v.as_str()) {
        events.push(stamp("thread", "thread_ref", json!(t)));
    }
    if let Some(w) = b.get("work_run_ref").and_then(|v| v.as_str()) {
        events.push(stamp("work_run", "work_run_ref", json!(w)));
    }
    Ok(Json(
        json!({ "binding_ref": binding_ref, "event_stream_refs": b.get("event_stream_refs"), "events": events, "at": iso_now() }),
    ))
}

/// POST /v1/hypervisor/session-execution-bindings/:id/input — operator input ROUTES to the bound
/// thread (conversation lives in /v1/threads/*; the binding never owns turns).
pub(crate) async fn handle_binding_input(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let b = load_authorized_binding(&st.data_dir, &headers, &id)?;
    Ok(match b.get("thread_ref").and_then(|v| v.as_str()) {
        Some(t) => Json(
            json!({ "ok": true, "routed_to": t, "route": format!("/v1/threads/{}/turns", ref_id(t)), "note": "operator input is a thread turn; the binding only resolves the owner route" }),
        ),
        None => Json(
            json!({ "ok": false, "reason": "binding has no thread_ref; bind a thread (POST /v1/threads) before sending input" }),
        ),
    })
}

fn binding_lifecycle(
    data_dir: &str,
    headers: &HeaderMap,
    id: &str,
    action: &str,
    env_route: &str,
) -> Result<Json<Value>, AppError> {
    let b = load_authorized_binding(data_dir, headers, id)?;
    let env_ref = b
        .get("environment_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // CLASSIFIED — best-effort telemetry: receipt-only delegation pointer; the environment route owns lifecycle truth
    let receipt = emit_receipt(data_dir, "binding", id, action);
    Ok(Json(
        json!({ "ok": true, "binding": id, "action": action, "environment_ref": env_ref,
        "delegated_route": format!("{}/{}", env_route, ref_id(env_ref)),
        "note": "the binding coordinates; the environment route owns lifecycle truth", "receipt_ref": receipt }),
    ))
}
pub(crate) async fn handle_binding_stop(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    binding_lifecycle(
        &st.data_dir,
        &headers,
        &id,
        "stop",
        "/v1/hypervisor/environments",
    )
}
pub(crate) async fn handle_binding_archive(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    binding_lifecycle(
        &st.data_dir,
        &headers,
        &id,
        "archive",
        "/v1/hypervisor/environments",
    )
}
pub(crate) async fn handle_binding_restore(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    binding_lifecycle(
        &st.data_dir,
        &headers,
        &id,
        "restore",
        "/v1/hypervisor/environments",
    )
}

// ===========================================================================
// T7-3 — env-files (collision-safe, scoped to workspace_root)
// ===========================================================================

/// Resolve a request path INSIDE the workspace, rejecting traversal/escape. Returns the absolute
/// path (which may not yet exist, for writes).
fn scoped_path(ws: &str, rel: &str) -> Result<PathBuf, String> {
    let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|c| c == "..") {
        return Err("path traversal ('..') is not allowed".into());
    }
    let root = Path::new(ws);
    let joined = root.join(rel);
    // The parent (for writes) or the path itself (for reads) must canonicalize within the root.
    let check = if joined.exists() {
        joined.clone()
    } else {
        joined
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf())
    };
    let canon_root = root.canonicalize().map_err(|e| e.to_string())?;
    if let Ok(canon) = check.canonicalize() {
        if !canon.starts_with(&canon_root) {
            return Err("path escapes the environment workspace".into());
        }
    }
    Ok(joined)
}

/// POST /v1/hypervisor/env-files — body `{ environment_id, op, path?, content?, to? }`.
/// op ∈ list | read | write | move | delete. Scoped to the env workspace; collision-safe.
pub(crate) async fn handle_env_files(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = sstr(&body, "environment_id")
        .or_else(|| sstr(&body, "environment_ref").map(|r| ref_id(&r).to_string()))
        .unwrap_or_default();
    super::environment_routes::authorize_environment_owner(&st.data_dir, &headers, &env_id)?;
    let op = sstr(&body, "op").unwrap_or_default();
    let Some(ws) = workspace_of(&st.data_dir, &env_id) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not started (no scoped workspace)", "environment_id": env_id }),
        ));
    };
    let rel = sstr(&body, "path").unwrap_or_default();
    let res: Result<Value, String> = (|| match op.as_str() {
        "list" => {
            let dir = scoped_path(&ws, &rel)?;
            let mut entries = Vec::new();
            for e in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
                let e = e.map_err(|e| e.to_string())?;
                let md = e.metadata().map_err(|e| e.to_string())?;
                entries.push(json!({ "name": e.file_name().to_string_lossy(), "type": if md.is_dir() { "dir" } else { "file" }, "size": md.len() }));
            }
            entries.sort_by(|a, b| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["name"].as_str().unwrap_or(""))
            });
            Ok(json!({ "path": rel, "entries": entries }))
        }
        "read" => {
            let p = scoped_path(&ws, &rel)?;
            let bytes = std::fs::read(&p).map_err(|e| e.to_string())?;
            Ok(
                json!({ "path": rel, "content": String::from_utf8_lossy(&bytes), "bytes": bytes.len() }),
            )
        }
        "write" => {
            let p = scoped_path(&ws, &rel)?;
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let content = sstr(&body, "content").unwrap_or_default();
            std::fs::write(&p, content.as_bytes()).map_err(|e| e.to_string())?;
            Ok(json!({ "path": rel, "written": true, "bytes": content.as_bytes().len() }))
        }
        "move" => {
            let from = scoped_path(&ws, &rel)?;
            let to = scoped_path(&ws, &sstr(&body, "to").ok_or("'to' required for move")?)?;
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::rename(&from, &to).map_err(|e| e.to_string())?;
            Ok(json!({ "from": rel, "to": sstr(&body, "to"), "moved": true }))
        }
        "delete" => {
            let p = scoped_path(&ws, &rel)?;
            if p.is_dir() {
                std::fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
            } else {
                std::fs::remove_file(&p).map_err(|e| e.to_string())?;
            }
            Ok(json!({ "path": rel, "deleted": true }))
        }
        other => Err(format!("unknown op '{other}'")),
    })();
    match res {
        Ok(v) => Ok(Json(
            json!({ "ok": true, "op": op, "environment_id": env_id, "scope_root": ws, "result": v }),
        )),
        Err(reason) => Ok(Json(
            json!({ "ok": false, "op": op, "environment_id": env_id, "reason": reason }),
        )),
    }
}

// ===========================================================================
// T7-E — interactive PTY terminal
// ===========================================================================

/// A live PTY: openpty master fd + the child shell + a shared output ring, bound to an env.
pub(crate) struct TerminalSession {
    pub(crate) master_fd: RawFd,
    pub(crate) child: std::process::Child,
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) environment_ref: String,
    pub(crate) log_path: String,
    pub(crate) shell: String,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
}

fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// POST /v1/hypervisor/terminals — open a REAL interactive PTY in the env workspace.
/// Body: `{ environment_ref, shell?, cols?, rows?, cwd? }`.
pub(crate) async fn handle_terminal_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_ref = sstr(&body, "environment_ref")
        .or_else(|| sstr(&body, "environment_id"))
        .unwrap_or_default();
    let env_id = ref_id(&env_ref).to_string();
    super::environment_routes::authorize_environment_owner(&st.data_dir, &headers, &env_id)?;

    // CONTAINMENT: this route spawns an interactive HOST shell (a real PTY, caller-chosen
    // binary, no guardrail deny-list) and attributes it to an environment. When that environment
    // declared a `vm_kernel` isolation floor, a host PTY cannot honour it, so it is refused by
    // name. A process-scoped environment is unaffected — there the label already matches reality.
    if let Some(env) = load_env(&st.data_dir, &env_id) {
        let live = st.live_vms.lock().unwrap().contains_key(&env_id);
        if let Err(refusal) = admit_isolated_execution(
            DeclaredIsolation::from_env_status(&env["status"]),
            IsolatedSubstrate::observed(live),
            ExecutionLocus::Host,
        ) {
            return Ok(Json(json!({
                "ok": false,
                "refused": true,
                "reason": refusal.reason,
                "detail": refusal.detail,
            })));
        }
    }

    let cwd = match workspace_of(&st.data_dir, &env_id) {
        Some(c) => c,
        None => {
            return Ok(Json(
                json!({ "ok": false, "reason": "environment not started (no scoped workspace) and no cwd given" }),
            ))
        }
    };
    let shell = sstr(&body, "shell").unwrap_or_else(|| "bash".into());
    let cols = body.get("cols").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
    let rows = body.get("rows").and_then(|v| v.as_u64()).unwrap_or(24) as u16;

    // openpty(3) — a real kernel PTY pair.
    let (mut master, mut slave): (RawFd, RawFd) = (-1, -1);
    let mut ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        )
    };
    if rc != 0 {
        return Ok(Json(
            json!({ "ok": false, "reason": format!("openpty failed: {}", std::io::Error::last_os_error()) }),
        ));
    }

    // The child shell uses the slave end as its controlling terminal.
    let slave_out = unsafe { libc::dup(slave) };
    let slave_err = unsafe { libc::dup(slave) };
    let mut cmd = std::process::Command::new(&shell);
    cmd.current_dir(&cwd)
        .env("TERM", "xterm-256color")
        .stdin(unsafe { std::process::Stdio::from_raw_fd(slave) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(slave_out) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(slave_err) });
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(master);
            }
            return Ok(Json(
                json!({ "ok": false, "reason": format!("shell spawn failed: {e}") }),
            ));
        }
    };
    // (slave fds are owned by the Stdio wrappers and closed in the parent after spawn.)

    let id = format!("term_{:x}", nanos());
    let log_dir = Path::new(&st.data_dir).join("terminals");
    // CLASSIFIED — best-effort telemetry: PTY truth is process-local (st.terminals); log/receipt are evidence trail only
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir
        .join(format!("{id}.log"))
        .to_string_lossy()
        .to_string();
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));

    // Background reader: drain the PTY master into the shared ring + the redacted log file. Reading
    // continuously also prevents the child blocking on a full kernel PTY buffer.
    {
        let buffer = buffer.clone();
        let log_path = log_path.clone();
        let fd = master;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                let chunk = &buf[..n as usize];
                if let Ok(mut b) = buffer.lock() {
                    b.extend_from_slice(chunk);
                    if b.len() > 1_048_576 {
                        let cut = b.len() - 1_048_576;
                        b.drain(0..cut);
                    }
                }
                use std::io::Write;
                // CLASSIFIED — best-effort telemetry: PTY truth is process-local (st.terminals); the log is an evidence trail only
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                {
                    let _ = f.write_all(chunk);
                }
            }
        });
    }

    // CLASSIFIED — best-effort telemetry: PTY truth is process-local (st.terminals); log/receipt are evidence trail only
    let receipt = emit_receipt(&st.data_dir, "terminal", &id, "open");
    let session = TerminalSession {
        master_fd: master,
        child,
        buffer,
        environment_ref: env_ref.clone(),
        log_path: log_path.clone(),
        shell: shell.clone(),
        cols,
        rows,
    };
    st.terminals.lock().unwrap().insert(id.clone(), session);

    Ok(Json(json!({
        "ok": true,
        "terminal_ref": format!("terminal:{id}"),
        "terminal_id": id,
        "environment_ref": env_ref,
        "interactive": true,
        "shell": shell, "cols": cols, "rows": rows,
        "stream_ref": format!("/v1/hypervisor/terminals/{id}/stream"),
        "input_ref": format!("/v1/hypervisor/terminals/{id}/input"),
        "log_ref": log_path,
        "receipt_refs": [receipt],
        "note": "real openpty PTY bound to environment_ref; shell state persists across inputs"
    })))
}

/// GET /v1/hypervisor/terminals/:id/stream?since=<n> — stream the real PTY output as SSE frames
/// (the accumulated/delta bytes from the live master). `since` returns only newer bytes.
pub(crate) async fn handle_terminal_stream(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let environment_id = {
        let terms = st.terminals.lock().unwrap();
        terms
            .get(&id)
            .map(|terminal| ref_id(&terminal.environment_ref).to_string())
    };
    if let Some(environment_id) = environment_id {
        super::environment_routes::authorize_environment_owner(
            &st.data_dir,
            &headers,
            &environment_id,
        )?;
    }
    let since: usize = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let terms = st.terminals.lock().unwrap();
    let mut sse = String::new();
    match terms.get(&id) {
        Some(t) => {
            let buf = t.buffer.lock().unwrap();
            let total = buf.len();
            let from = since.min(total);
            let out = String::from_utf8_lossy(&buf[from..]).to_string();
            let running = true;
            sse.push_str(&format!("event: output\ndata: {}\n\n", serde_json::to_string(&json!({ "terminal_id": id, "from": from, "offset": total, "output": out, "running": running })).unwrap_or_default()));
            sse.push_str(&format!(
                "event: done\ndata: {}\n\n",
                json!({ "offset": total })
            ));
        }
        None => sse.push_str(&format!(
            "event: error\ndata: {}\n\n",
            json!({ "code": "not_found", "terminal": id })
        )),
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        sse,
    ))
}

/// POST /v1/hypervisor/terminals/:id/input — write real keystrokes to the PTY master.
/// Body: `{ data: "...", "enter"?: bool }`.
pub(crate) async fn handle_terminal_input(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let mut data = sstr(&body, "data").unwrap_or_default();
    if body.get("enter").and_then(|v| v.as_bool()).unwrap_or(false) && !data.ends_with('\n') {
        data.push('\n');
    }
    let environment_id = {
        let terms = st.terminals.lock().unwrap();
        terms
            .get(&id)
            .map(|terminal| ref_id(&terminal.environment_ref).to_string())
    };
    if let Some(environment_id) = environment_id {
        super::environment_routes::authorize_environment_owner(
            &st.data_dir,
            &headers,
            &environment_id,
        )?;
    }
    let terms = st.terminals.lock().unwrap();
    let Some(t) = terms.get(&id) else {
        return Ok(Json(json!({ "ok": false, "reason": "terminal not found" })));
    };
    let bytes = data.as_bytes();
    let n = unsafe {
        libc::write(
            t.master_fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
        )
    };
    Ok(Json(
        json!({ "ok": n >= 0, "terminal_id": id, "written": n.max(0) }),
    ))
}

/// POST /v1/hypervisor/terminals/:id/resize — TIOCSWINSZ the live PTY. Body `{ cols, rows }`.
pub(crate) async fn handle_terminal_resize(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let environment_id = {
        let terms = st.terminals.lock().unwrap();
        terms
            .get(&id)
            .map(|terminal| ref_id(&terminal.environment_ref).to_string())
    };
    if let Some(environment_id) = environment_id {
        super::environment_routes::authorize_environment_owner(
            &st.data_dir,
            &headers,
            &environment_id,
        )?;
    }
    let mut terms = st.terminals.lock().unwrap();
    let Some(t) = terms.get_mut(&id) else {
        return Ok(Json(json!({ "ok": false, "reason": "terminal not found" })));
    };
    t.cols = body
        .get("cols")
        .and_then(|v| v.as_u64())
        .unwrap_or(t.cols as u64) as u16;
    t.rows = body
        .get("rows")
        .and_then(|v| v.as_u64())
        .unwrap_or(t.rows as u64) as u16;
    set_winsize(t.master_fd, t.rows, t.cols);
    Ok(Json(
        json!({ "ok": true, "terminal_id": id, "cols": t.cols, "rows": t.rows }),
    ))
}

/// POST /v1/hypervisor/terminals/:id/close — kill the shell + release the PTY (lifecycle obs).
pub(crate) async fn handle_terminal_close(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let environment_id = {
        let terms = st.terminals.lock().unwrap();
        terms
            .get(&id)
            .map(|terminal| ref_id(&terminal.environment_ref).to_string())
    };
    if let Some(environment_id) = environment_id {
        super::environment_routes::authorize_environment_owner(
            &st.data_dir,
            &headers,
            &environment_id,
        )?;
    }
    let mut terms = st.terminals.lock().unwrap();
    Ok(match terms.remove(&id) {
        Some(mut t) => {
            let _ = t.child.kill();
            let _ = t.child.wait();
            unsafe {
                libc::close(t.master_fd);
            }
            // CLASSIFIED — best-effort telemetry: PTY truth is process-local (st.terminals); log/receipt are evidence trail only
            let receipt = emit_receipt(&st.data_dir, "terminal", &id, "close");
            Json(
                json!({ "ok": true, "terminal_id": id, "closed": true, "environment_ref": t.environment_ref, "log_ref": t.log_path, "receipt_ref": receipt }),
            )
        }
        None => Json(json!({ "ok": false, "reason": "terminal not found" })),
    })
}

/// GET /v1/hypervisor/terminals — list live PTY terminals (bound env, shell, geometry).
pub(crate) async fn handle_terminals_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(super::environment_routes::environment_scope_error)?;
    let owned = super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        super::environment_routes::ENVIRONMENT_SCOPE_KIND,
    )
    .map_err(super::environment_routes::environment_scope_error)?;
    let terms = st.terminals.lock().unwrap();
    let list: Vec<Value> = terms.iter().filter(|(_, terminal)| owned.contains(ref_id(&terminal.environment_ref))).map(|(id, t)| json!({ "terminal_id": id, "terminal_ref": format!("terminal:{id}"), "environment_ref": t.environment_ref, "shell": t.shell, "cols": t.cols, "rows": t.rows, "interactive": true })).collect();
    Ok(Json(
        json!({ "schema_version": "ioi.hypervisor.terminals.v1", "terminals": list, "at": iso_now() }),
    ))
}
