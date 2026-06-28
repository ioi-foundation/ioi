//! Pre-applications WS-2 — OSS browser-IDE runtime host (openvscode-server).
//!
//! The runtime boundary the editor access service delegates to. The runtime is provisioned
//! reproducibly (pinned version/commit/sha256, fetch-once cache, checksum-verified, fail-closed)
//! by scripts/provision-hypervisor-vscode-browser-host.mjs into ~/.ioi/editor-toolchain. Until a
//! reproducible OSS runtime is installed, `oss_runtime_present()` is fail-closed so the editor
//! service start fails CLOSED with `editor_runtime_not_provisioned` (honest — never a fake ready).
//!
//! `start_oss_runtime` launches openvscode-server bound to the env workspace on a private internal
//! port (the public/proxy port is WS-4), injects the Session Execution Binding refs (WS-6a), and
//! waits for real `/version` readiness before reporting the service ready. The upstream stripped
//! reference binary is reference-only and is never vendored.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use super::DaemonState;

/// A live openvscode-server process backing one editor access service.
pub(crate) struct EditorRuntime {
    pub(crate) child: std::process::Child,
    pub(crate) internal_port: u16,
    pub(crate) log_path: String,
    pub(crate) started_at: String,
    pub(crate) workspace_root: String,
}

pub(crate) fn runtime_root() -> PathBuf {
    std::env::var("IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".ioi/editor-toolchain"))
}
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

/// The pinned openvscode-server entrypoint (installed by the WS-2 provisioner).
pub(crate) fn oss_server_bin() -> PathBuf {
    runtime_root().join("openvscode-server/bin/openvscode-server")
}

/// Is a reproducible OSS browser-IDE runtime installed + executable? Fail-closed: absent => false.
pub(crate) fn oss_runtime_present() -> bool {
    let bin = oss_server_bin();
    bin.exists()
        && std::fs::metadata(&bin)
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false)
}

/// A free localhost TCP port (bind :0, read the assigned port, drop the listener).
fn free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

/// Minimal HTTP GET /version against the internal port (no extra deps). Returns the body if 2xx.
fn http_get_version(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().ok()?,
        Duration::from_millis(400),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .write_all(
            format!("GET /version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    if !head.starts_with("HTTP/1.1 2") && !head.starts_with("HTTP/1.0 2") {
        return None;
    }
    // openvscode /version returns the 40-hex commit; the body may be chunked-encoded, so extract
    // the commit token rather than trusting raw framing.
    let body = parts.next().unwrap_or("");
    let commit = body
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|t| t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit()));
    Some(
        commit
            .map(str::to_string)
            .unwrap_or_else(|| body.trim().to_string()),
    )
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

/// The source-controlled required adapter extension (override for the negative test).
fn required_extension_source() -> PathBuf {
    std::env::var("IOI_HYPERVISOR_REQUIRED_EXTENSION_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap_or_default()
                .join("packages/hypervisor-adapter-targets/code-editors/vscode-extension")
        })
}

/// WS-6b — install the REQUIRED Hypervisor adapter into a per-service extensions dir and gate
/// readiness on it. Returns (extensions_dir, installed_ids) or Err(`editor_required_extension_missing`)
/// — a required-extension failure blocks the browser-host readiness gate (never a fake ready). The
/// install copy's engines.vscode is adapted to the runtime; the source manifest is untouched.
pub(crate) fn install_required_extensions(
    data_dir: &str,
    service_id: &str,
) -> Result<(PathBuf, Vec<String>), String> {
    let ext_dir = Path::new(data_dir)
        .join("editor-services")
        .join(service_id)
        .join("extensions");
    let _ = std::fs::create_dir_all(&ext_dir);
    let src = required_extension_source();
    let manifest_src = src.join("package.json");
    if !src.is_dir() || !manifest_src.exists() {
        return Err("editor_required_extension_missing".to_string());
    }
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_src).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("hypervisor-vscode-extension");
    let publisher = manifest
        .get("publisher")
        .and_then(|v| v.as_str())
        .unwrap_or("ioi");
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.1");
    let ext_id = format!("{publisher}.{name}");
    let install = ext_dir.join(format!("{ext_id}-{version}"));
    let _ = std::fs::remove_dir_all(&install);
    copy_dir(&src, &install).map_err(|e| format!("copy adapter extension: {e}"))?;
    // adapt engines.vscode in the INSTALL COPY so the runtime loads it (source manifest untouched).
    let copied_manifest = install.join("package.json");
    if let Ok(bytes) = std::fs::read(&copied_manifest) {
        if let Ok(mut j) = serde_json::from_slice::<Value>(&bytes) {
            j["engines"]["vscode"] = json!("^1.60.0");
            let _ = std::fs::write(
                &copied_manifest,
                serde_json::to_vec_pretty(&j).unwrap_or_default(),
            );
        }
    }
    Ok((ext_dir, vec![ext_id]))
}

fn env_workspace(data_dir: &str, env_id: &str) -> Option<String> {
    let safe: String = env_id.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    );
    let path = Path::new(data_dir)
        .join("environments")
        .join(format!("{safe}.json"));
    let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    v["status"]["workspace_root"].as_str().map(str::to_string)
}

/// Launch the OSS runtime for a service, inject binding refs (WS-6a), and wait for /version. The
/// public/proxy port is added by WS-4; here we expose only the internal port + ready phase.
pub(crate) async fn start_oss_runtime(
    st: &DaemonState,
    service_id: &str,
    svc: &Value,
) -> Result<Value, String> {
    // already running? return the live view.
    if st.editor_runtimes.lock().unwrap().contains_key(service_id) {
        let mut s = svc.clone();
        s["phase"] = json!("ready");
        return Ok(s);
    }
    let env_id = svc
        .get("environment_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let workspace_root = env_workspace(&st.data_dir, env_id).ok_or_else(|| {
        "environment not started (no scoped workspace) for the editor host".to_string()
    })?;
    // WS-6b — install the REQUIRED Hypervisor adapter FIRST; a required-extension failure blocks
    // readiness (no editor without its adapter).
    let (extensions_dir, installed_exts) = install_required_extensions(&st.data_dir, service_id)?;
    let port = free_port().ok_or("could not allocate an internal port")?;
    let log_dir = Path::new(&st.data_dir).join("editor-services");
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir
        .join(format!("{service_id}.log"))
        .to_string_lossy()
        .to_string();
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("open log: {e}"))?;
    let log_err = log_file
        .try_clone()
        .map_err(|e| format!("clone log: {e}"))?;

    // Session Execution Binding refs (WS-6a) — the extension host inherits these from the server.
    let session_ref = svc
        .get("session_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let lease_ref = svc
        .get("access_lease_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut cmd = std::process::Command::new(oss_server_bin());
    cmd.arg("--without-connection-token")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--default-folder")
        .arg(&workspace_root)
        .arg("--extensions-dir")
        .arg(&extensions_dir)
        .current_dir(&workspace_root)
        .env(
            "IOI_HYPERVISOR_ENVIRONMENT_REF",
            format!("environment:{env_id}"),
        )
        .env("IOI_HYPERVISOR_SESSION_REF", session_ref)
        .env("IOI_HYPERVISOR_ACCESS_LEASE_REF", lease_ref)
        .env(
            "IOI_HYPERVISOR_EDITOR_SERVICE_REF",
            format!("environment_service:editor_{service_id}"),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_err));
    // New process group (setsid): the launcher shell forks `node` without exec, so we must kill the
    // whole group on stop, not just the shell — otherwise the server child is orphaned + keeps the port.
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn openvscode-server: {e}"))?;

    // Wait for real /version readiness (non-blocking: async sleeps between quick probes).
    let started_at = super::iso_now();
    let mut version: Option<String> = None;
    for _ in 0..80 {
        if let Some(v) = http_get_version(port) {
            version = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let Some(version) = version else {
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("openvscode-server did not report /version on 127.0.0.1:{port} within timeout (see {log_path})"));
    };

    st.editor_runtimes.lock().unwrap().insert(
        service_id.to_string(),
        EditorRuntime {
            child,
            internal_port: port,
            log_path: log_path.clone(),
            started_at: started_at.clone(),
            workspace_root: workspace_root.clone(),
        },
    );

    let mut updated = svc.clone();
    updated["phase"] = json!("ready");
    updated["internal_port"] = json!(port);
    updated["runtime_version"] = json!(version);
    updated["installed_extensions"] = json!(installed_exts);
    updated["required_extension"] = json!("ioi.hypervisor-vscode-extension");
    updated["readiness"] = json!({ "mode": "full", "reason": "openvscode-server /version ready + required adapter installed", "internal_port": port, "installed_extensions": installed_exts });
    updated["started_at"] = json!(started_at);
    Ok(updated)
}

/// Stop the OSS runtime for a service (idempotent). Kills the whole process GROUP (the launcher
/// shell + the forked node server + workers), since the shell forks node without exec.
pub(crate) fn stop_oss_runtime(st: &DaemonState, service_id: &str) {
    if let Some(mut rt) = st.editor_runtimes.lock().unwrap().remove(service_id) {
        let pid = rt.child.id() as i32;
        // setsid made the child a group leader (pgid == pid); kill the negative pgid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = rt.child.kill();
        let _ = rt.child.wait();
    }
}

/// Read the runtime install/launch log for a service.
pub(crate) fn read_runtime_log(data_dir: &str, service_id: &str) -> Value {
    let p = Path::new(data_dir)
        .join("editor-services")
        .join(format!("{service_id}.log"));
    match std::fs::read_to_string(&p) {
        Ok(s) => json!(s
            .lines()
            .rev()
            .take(50)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")),
        Err(_) => json!(""),
    }
}

/// WS-3r — reconcile editor runtimes on daemon boot: a service persisted as `ready` whose runtime
/// did NOT survive this boot is marked `degraded` (the process died with the prior daemon). Returns
/// the count reconciled. Called once at startup.
pub(crate) fn reconcile_editor_services(data_dir: &str) -> usize {
    let dir = Path::new(data_dir).join("editor-services");
    let mut reconciled = 0;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = std::fs::read(e.path()) else {
                continue;
            };
            let Ok(mut svc) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if svc.get("phase").and_then(|v| v.as_str()) == Some("ready") {
                // No live process survives a daemon restart -> degraded, restart required.
                svc["phase"] = json!("degraded");
                svc["internal_port"] = Value::Null;
                svc["readiness"] = json!({ "mode": "blocked", "reason": "editor_runtime_lost_on_restart", "detail": "openvscode-server died with the previous daemon; restart the editor service to re-provision" });
                let _ = std::fs::write(
                    e.path(),
                    serde_json::to_vec_pretty(&svc).unwrap_or_default(),
                );
                reconciled += 1;
            }
        }
    }
    reconciled
}
