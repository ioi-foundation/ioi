//! Pre-applications WS-2 — OSS browser-IDE runtime host (openvscode-server).
//!
//! The runtime boundary the editor access service delegates to. The runtime is provisioned
//! reproducibly (pinned version/commit/sha256, fetch-once cache, checksum-verified, fail-closed)
//! by scripts/provision-hypervisor-vscode-browser-host.mjs into ~/.ioi/editor-toolchain. Until a
//! reproducible OSS runtime is installed, `oss_runtime_present()` is fail-closed so the editor
//! service start fails CLOSED with `editor_runtime_not_provisioned` (honest — never a fake ready).
//!
//! `start_oss_runtime` launches openvscode-server bound to the env workspace on a private UNIX
//! SOCKET (the public, lease-authenticated proxy is WS-4), injects the Session Execution Binding
//! refs (WS-6a), and waits for real `/version` readiness before reporting the service ready. The
//! upstream stripped reference binary is reference-only and is never vendored.
//!
//! BUILD-DELTA #31(c). The runtime listens only on `--socket-path`, a socket in a per-launch 0700
//! directory under the data dir, so no browser can reach it except through the editor proxy, which
//! requires the editor lease. It also REQUIRES a connection token (defence in depth): a random
//! secret (32 bytes, OS RNG) per launch, handed over in a per-launch file (mode 0600, created new,
//! removed once the runtime is ready or the start fails, never on the command line; a start whose
//! file cannot be removed fails and stops its runtime) and kept in the daemon's memory
//! (`EditorRuntime::connection_token`). The proxy adds it as the runtime's
//! `vscode-tkn` cookie when a request carries none; the workbench the runtime serves gives the
//! browser that cookie for its in-band WebSocket auth. The runtime's output is copied to the
//! service log with the token's exact bytes redacted. Starts of one service are serialized from
//! reading the record through persisting it. A daemon boot removes token files and sockets a
//! crashed start left behind (a service whose token file cannot be removed stays degraded and does
//! not start until it is), and redacts `tkn=` values older TCP runtimes printed into service logs.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use super::DaemonState;

/// A live openvscode-server process backing one editor access service.
pub(crate) struct EditorRuntime {
    pub(crate) child: std::process::Child,
    /// The unix socket the runtime listens on (the editor proxy's upstream).
    pub(crate) socket_path: PathBuf,
    /// The per-launch directory holding the socket, removed when the runtime stops.
    pub(crate) socket_dir: PathBuf,
    /// The runtime's connection token; the editor proxy adds it when a request carries none.
    pub(crate) connection_token: String,
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

/// The exact bytes of `secret` in `line` replaced (the runtime's output may print its token, e.g. the
/// startup line `Web UI available at http://localhost:<port>?tkn=<token>`).
pub(crate) fn redact_secret(line: &str, secret: &str) -> String {
    if secret.is_empty() {
        return line.to_string();
    }
    line.replace(secret, "[redacted]")
}

/// Every `tkn=<value>` URL parameter in `bytes` with its value replaced (a runtime that listened on
/// a TCP port printed its token that way). Works on bytes, so a log that is not UTF-8 is redacted
/// too. Returns None when nothing changed.
pub(crate) fn redact_tkn_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    const NAME: &[u8] = b"tkn=";
    const REDACTED: &[u8] = b"[redacted]";
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    let mut changed = false;
    while let Some(found) = bytes[at..].windows(NAME.len()).position(|w| w == NAME) {
        let value_start = at + found + NAME.len();
        out.extend_from_slice(&bytes[at..value_start]);
        let value_end = bytes[value_start..]
            .iter()
            .position(|b| {
                b.is_ascii_whitespace()
                    || matches!(*b, b'&' | b'#' | b'"' | b'\'' | b'<' | b'>' | b';' | b')')
            })
            .map_or(bytes.len(), |end| value_start + end);
        let value = &bytes[value_start..value_end];
        if value.is_empty() || value == REDACTED {
            out.extend_from_slice(value);
        } else {
            out.extend_from_slice(REDACTED);
            changed = true;
        }
        at = value_end;
    }
    out.extend_from_slice(&bytes[at..]);
    changed.then_some(out)
}

/// `redact_tkn_bytes` over text.
pub(crate) fn redact_tkn_values(text: &str) -> Option<String> {
    redact_tkn_bytes(text.as_bytes()).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// A SECURITY line on the daemon's own log: a secret may have been left on disk.
fn security_line(message: &str) {
    eprintln!("SECURITY editor runtime: {message}");
}

/// Remove every token handoff file a previous start of `service_id` left in `dir`. Returns the
/// ones that could not be removed.
fn remove_stale_token_files(dir: &Path, service_id: &str) -> Vec<String> {
    let prefix = format!("{service_id}.");
    let mut left = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) || !name.ends_with(".connection-token") {
            continue;
        }
        if let Err(error) = std::fs::remove_file(entry.path()) {
            if error.kind() != std::io::ErrorKind::NotFound {
                left.push(format!("{name} ({error})"));
            }
        }
    }
    left
}

/// Copy a runtime output stream into the service log line by line, with `secret` redacted.
fn copy_redacted<R: Read + Send + 'static>(source: R, log_path: String, secret: String) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(source);
        let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        else {
            return;
        };
        let mut line = Vec::new();
        while reader
            .read_until(b'\n', &mut line)
            .is_ok_and(|read| read > 0)
        {
            let text = redact_secret(&String::from_utf8_lossy(&line), &secret);
            let _ = log.write_all(text.as_bytes());
            line.clear();
        }
    });
}

/// One start at a time per editor service: the start route holds it from reading the service record
/// through persisting the result.
pub(crate) fn start_gate(service_id: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    GATES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(service_id.to_string())
        .or_default()
        .clone()
}

/// Minimal HTTP GET /version over the runtime's unix socket (no extra deps), presenting the
/// runtime's connection token. Returns the body if 2xx.
fn http_get_version(socket_path: &Path, connection_token: &str) -> Option<String> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .write_all(
            format!("GET /version HTTP/1.1\r\nHost: localhost\r\nCookie: vscode-tkn={connection_token}\r\nConnection: close\r\n\r\n")
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

/// Remove a runtime's socket directory. Returns a description of the failure, if any.
fn remove_socket_dir(socket_dir: &Path) -> Option<String> {
    std::fs::remove_dir_all(socket_dir)
        .err()
        .filter(|error| error.kind() != std::io::ErrorKind::NotFound)
        .map(|error| format!("socket directory ({error})"))
}

/// Remove a per-launch token file and socket directory (best effort; a daemon boot removes any
/// left behind). Returns a description of what could not be removed, if anything.
fn remove_launch_files(token_path: &Path, socket_dir: &Path) -> Option<String> {
    let mut left = Vec::new();
    if let Err(error) = std::fs::remove_file(token_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            left.push(format!("token file ({error})"));
        }
    }
    left.extend(remove_socket_dir(socket_dir));
    (!left.is_empty()).then(|| left.join(", "))
}

/// Launch the OSS runtime for a service on a private unix socket, inject binding refs (WS-6a), and
/// wait for /version. The public, lease-authenticated proxy is added by WS-4. The caller holds the
/// service's `start_gate` from reading `svc` through persisting the result, so a start that waited
/// reads the record the previous start committed and finds its runtime running.
pub(crate) async fn start_oss_runtime(
    st: &DaemonState,
    service_id: &str,
    svc: &Value,
) -> Result<Value, String> {
    // already running? `svc` is the record the start that launched it committed.
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
    let log_dir = Path::new(&st.data_dir).join("editor-services");
    let _ = std::fs::create_dir_all(&log_dir);
    // A token file an earlier start left behind (no runtime of it is running) must be gone before
    // this service runs again.
    let stale = remove_stale_token_files(&log_dir, service_id);
    if !stale.is_empty() {
        security_line(&format!(
            "service {service_id}: a token handoff file could not be removed: {}; the service does not start until it is",
            stale.join(", ")
        ));
        return Err("editor_runtime_token_not_removed".to_string());
    }
    let log_path = log_dir
        .join(format!("{service_id}.log"))
        .to_string_lossy()
        .to_string();

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

    // Per-launch names: the token handoff file and the socket directory are never shared with
    // another launch.
    let (connection_token, launch) = {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        (hex::encode(secret), hex::encode(nonce))
    };
    let token_path = log_dir.join(format!("{service_id}.{launch}.connection-token"));
    let socket_dir = Path::new(&st.data_dir).join("editor-sockets").join(&launch);
    let socket_path = socket_dir.join("s");
    if socket_path.as_os_str().len() > 100 {
        return Err(format!(
            "the runtime socket path is too long for a unix socket ({} bytes); use a shorter data dir",
            socket_path.as_os_str().len()
        ));
    }
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&socket_dir)
            .map_err(|e| format!("create the runtime socket directory: {e}"))?;
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)
            .and_then(|mut token_file| token_file.write_all(connection_token.as_bytes()));
        if let Err(e) = written {
            if let Some(left) = remove_launch_files(&token_path, &socket_dir) {
                security_line(&format!(
                    "service {service_id}: could not remove the {left}"
                ));
            }
            return Err(format!("write the runtime connection token: {e}"));
        }
    }
    let mut cmd = std::process::Command::new(oss_server_bin());
    cmd.arg("--connection-token-file")
        .arg(&token_path)
        .arg("--socket-path")
        .arg(&socket_path)
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
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // New process group (setsid): the launcher shell forks `node` without exec, so we must kill the
    // whole group on stop, not just the shell — otherwise the server child is orphaned.
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            if let Some(left) = remove_launch_files(&token_path, &socket_dir) {
                security_line(&format!(
                    "service {service_id}: could not remove the {left}"
                ));
            }
            return Err(format!("spawn openvscode-server: {e}"));
        }
    };
    // The runtime's output reaches the service log with the token's exact bytes redacted.
    if let Some(stdout) = child.stdout.take() {
        copy_redacted(stdout, log_path.clone(), connection_token.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        copy_redacted(stderr, log_path.clone(), connection_token.clone());
    }

    // Wait for real /version readiness (non-blocking: async sleeps between quick probes).
    let started_at = super::iso_now();
    let mut version: Option<String> = None;
    for _ in 0..80 {
        if let Some(v) = http_get_version(&socket_path, &connection_token) {
            version = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // The runtime read its token at start; the file is not kept. If it cannot be removed the start
    // FAILS: the runtime is stopped, so the secret never stays behind a success.
    let unremoved = std::fs::remove_file(&token_path)
        .err()
        .filter(|error| error.kind() != std::io::ErrorKind::NotFound);
    if let Some(error) = unremoved {
        let pid = child.id() as libc::pid_t;
        // SAFETY: a negative pid signals the process group the launcher created with setsid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
        let socket_left = remove_socket_dir(&socket_dir)
            .map(|left| format!("; could not remove the {left}"))
            .unwrap_or_default();
        security_line(&format!(
            "service {service_id}: the token handoff file could not be removed at readiness ({error}); the runtime was stopped and the start failed{socket_left}"
        ));
        return Err("editor_runtime_token_not_removed".to_string());
    }
    let Some(version) = version else {
        // CONTAINMENT (cleanup availability): the launcher shell forks the server WITHOUT exec,
        // so killing only the shell orphaned the child. On this path the runtime was never
        // registered in `st.editor_runtimes`, so `stop_oss_runtime` could not reach it either.
        // Kill the whole process GROUP here and report whether the group is provably gone.
        let pid = child.id() as libc::pid_t;
        // SAFETY: a negative pid signals the process group the launcher created with setsid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
        let group_gone = unsafe { libc::kill(-pid, 0) } != 0;
        let cleanup = if group_gone {
            "process group reaped"
        } else {
            "process group MAY still be running — cleanup unverified"
        };
        let left = remove_launch_files(&token_path, &socket_dir)
            .inspect(|left| {
                security_line(&format!(
                    "service {service_id}: could not remove the {left}"
                ))
            })
            .map(|left| format!("; could not remove the {left}"))
            .unwrap_or_default();
        return Err(format!(
            "openvscode-server did not report /version on its socket within timeout ({cleanup}{left}; see {log_path})"
        ));
    };

    st.editor_runtimes.lock().unwrap().insert(
        service_id.to_string(),
        EditorRuntime {
            child,
            socket_path,
            socket_dir,
            connection_token,
            log_path: log_path.clone(),
            started_at: started_at.clone(),
            workspace_root: workspace_root.clone(),
        },
    );

    let mut updated = svc.clone();
    updated["phase"] = json!("ready");
    updated["internal_port"] = Value::Null;
    updated["upstream"] = json!("unix_socket");
    updated["runtime_version"] = json!(version);
    updated["installed_extensions"] = json!(installed_exts);
    updated["required_extension"] = json!("ioi.hypervisor-vscode-extension");
    updated["readiness"] = json!({ "mode": "full", "reason": "openvscode-server /version ready on its unix socket + required adapter installed", "upstream": "unix_socket", "installed_extensions": installed_exts });
    updated["started_at"] = json!(started_at);
    Ok(updated)
}

/// Stop the OSS runtime for a service (idempotent). Kills the whole process GROUP (the launcher
/// shell + the forked node server + workers), since the shell forks node without exec, and removes
/// its socket directory.
pub(crate) fn stop_oss_runtime(st: &DaemonState, service_id: &str) {
    if let Some(mut rt) = st.editor_runtimes.lock().unwrap().remove(service_id) {
        let pid = rt.child.id() as i32;
        // setsid made the child a group leader (pgid == pid); kill the negative pgid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = rt.child.kill();
        let _ = rt.child.wait();
        if let Some(left) = remove_socket_dir(&rt.socket_dir) {
            security_line(&format!(
                "service {service_id}: the runtime was stopped but could not remove the {left}"
            ));
        }
    }
}

/// Read the runtime install/launch log for a service.
pub(crate) fn read_runtime_log(data_dir: &str, service_id: &str) -> Value {
    let p = Path::new(data_dir)
        .join("editor-services")
        .join(format!("{service_id}.log"));
    match std::fs::read_to_string(&p).map(|s| redact_tkn_values(&s).unwrap_or(s)) {
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

/// The fields of `/proc/<pid>/stat` after the command name: state, ppid, pgrp, session, tty_nr, ...
fn proc_stat_fields(pid: &str) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    Some(rest.split_whitespace().map(str::to_string).collect())
}

/// The four uids (real, effective, saved, filesystem) of `/proc/<pid>/status`.
fn proc_uids(pid: &str) -> Option<Vec<String>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    Some(
        line.split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect(),
    )
}

/// Does `/proc/<pid>/cmdline` carry `--extensions-dir <marker>` (the argument this daemon gave the
/// runtime it launched for that record)?
fn carries_launch_marker(pid: &str, marker: &Path) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
    args.windows(2).any(|pair| {
        pair[0] == b"--extensions-dir".as_slice()
            && Path::new(&*String::from_utf8_lossy(pair[1])) == marker
    })
}

/// Stop an editor runtime an OLDER daemon left listening on loopback TCP `port` (before runtimes
/// moved to private sockets), ONLY when this daemon launched it for that record. Every one of these
/// must hold for the process listening on exactly that port: its argv carries `--extensions-dir
/// <marker>` (the record's own extensions dir under this data dir); it runs as this daemon's uid
/// (real, effective, saved and filesystem); its process group leads its own session (the setsid the
/// daemon's launch made), has no controlling terminal, and is not the daemon's own group or
/// session; and the group's leader is alive and carries the same marker and uids (a group whose
/// leader cannot be read is never killed). Then its process group is killed. Anything else on the
/// port is left running. Returns true iff one was stopped.
fn stop_legacy_tcp_runtime(port: u16, marker: &Path) -> bool {
    let wanted = format!("{port:04X}");
    let mut inodes = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(state), Some(inode)) =
                (fields.get(1), fields.get(3), fields.get(9))
            else {
                continue;
            };
            if *state == "0A" && local.rsplit(':').next() == Some(wanted.as_str()) {
                inodes.push(format!("socket:[{inode}]"));
            }
        }
    }
    if inodes.is_empty() {
        return false;
    }
    let (Some(own_uids), Some(own_stat)) = (proc_uids("self"), proc_stat_fields("self")) else {
        return false;
    };
    let (Some(own_uid), Some(own_group), Some(own_session)) =
        (own_uids.first(), own_stat.get(2), own_stat.get(3))
    else {
        return false;
    };
    let mut stopped = false;
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|name| name.parse::<i32>().is_ok())
            .map(str::to_string)
        else {
            continue;
        };
        let owns_socket = std::fs::read_dir(entry.path().join("fd"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .any(|target| {
                inodes
                    .iter()
                    .any(|inode| target.as_os_str() == inode.as_str())
            });
        if !owns_socket || !carries_launch_marker(&pid, marker) {
            continue;
        }
        let same_uid = proc_uids(&pid)
            .is_some_and(|uids| uids.len() == 4 && uids.iter().all(|uid| uid == own_uid));
        let Some(stat) = proc_stat_fields(&pid) else {
            continue;
        };
        let (Some(group), Some(session), Some(tty)) = (stat.get(2), stat.get(3), stat.get(4))
        else {
            continue;
        };
        let Ok(group_id) = group.parse::<i32>() else {
            continue;
        };
        let own_launch_session = group == session
            && group_id > 1
            && tty == "0"
            && group != own_group
            && session != own_session;
        // The leader must be READ and VERIFIED: a group whose leader is gone or unreadable may be
        // anyone's, so it is never killed.
        let leader_carries_marker = proc_stat_fields(group).is_some()
            && carries_launch_marker(group, marker)
            && proc_uids(group)
                .is_some_and(|uids| uids.len() == 4 && uids.iter().all(|uid| uid == own_uid));
        if same_uid && own_launch_session && leader_carries_marker {
            // SAFETY: kill on a process group checked above to be the runtime's own session group,
            // never this daemon's group or session.
            unsafe {
                libc::kill(-group_id, libc::SIGKILL);
            }
            stopped = true;
        }
    }
    stopped
}

/// WS-3r — reconcile editor runtimes on daemon boot: a service persisted as `ready` whose runtime
/// did NOT survive this boot is marked `degraded` (the process died with the prior daemon). Returns
/// the count reconciled. Called once at startup.
pub(crate) fn reconcile_editor_services(data_dir: &str) -> usize {
    let dir = Path::new(data_dir).join("editor-services");
    // No runtime survives a daemon restart, so every runtime socket and token handoff file a start
    // left behind (a crash between handoff and cleanup) is stale: remove them. A token file that
    // cannot be removed keeps its service degraded (and a start refuses) until it is.
    let sockets = Path::new(data_dir).join("editor-sockets");
    if let Err(error) = std::fs::remove_dir_all(&sockets) {
        if error.kind() != std::io::ErrorKind::NotFound {
            security_line(&format!(
                "the runtime socket directory {} could not be removed ({error})",
                sockets.display()
            ));
        }
    }
    let mut unremoved_tokens = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".connection-token") {
            if let Err(error) = std::fs::remove_file(e.path()) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    let service = name.split('.').next().unwrap_or_default().to_string();
                    security_line(&format!(
                        "service {service}: the token handoff file {name} could not be removed at boot ({error}); the service stays degraded until it is"
                    ));
                    unremoved_tokens.insert(service);
                }
            }
        } else if name.ends_with(".log") {
            // A runtime that listened on a TCP port printed its token in a `tkn=` URL parameter.
            // The log is read as bytes; one that cannot be read is reported, never skipped.
            let redacted = match std::fs::read(e.path()) {
                Ok(bytes) => redact_tkn_bytes(&bytes),
                Err(error) => {
                    security_line(&format!(
                        "the editor service log {name} could not be read to redact tkn= values ({error})"
                    ));
                    None
                }
            };
            if let Some(text) = redacted {
                let staged = dir.join(format!("{name}.redacting"));
                let replaced =
                    std::fs::write(&staged, text).and_then(|_| std::fs::rename(&staged, e.path()));
                if let Err(error) = replaced {
                    let _ = std::fs::remove_file(&staged);
                    security_line(&format!(
                        "the editor service log {name} carries tkn= values that could not be redacted ({error})"
                    ));
                }
            }
        }
    }
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
            let stem = e
                .path()
                .file_stem()
                .map(|stem| stem.to_string_lossy().to_string())
                .unwrap_or_default();
            if unremoved_tokens.contains(&stem) {
                if let Some(port) = svc.get("internal_port").and_then(|v| v.as_u64()) {
                    let marker = dir.join(&stem).join("extensions");
                    let _ = u16::try_from(port)
                        .is_ok_and(|port| stop_legacy_tcp_runtime(port, &marker));
                }
                svc["phase"] = json!("degraded");
                svc["internal_port"] = Value::Null;
                svc["readiness"] = json!({ "mode": "blocked", "reason": "editor_runtime_token_not_removed", "detail": "a runtime token handoff file of this service could not be removed; the service does not start until it is" });
                let _ = std::fs::write(
                    e.path(),
                    serde_json::to_vec_pretty(&svc).unwrap_or_default(),
                );
                reconciled += 1;
                continue;
            }
            // A record naming an internal TCP port is a LEGACY runtime (an older daemon's, on
            // loopback TCP): stop it if it still listens, and mark the record unusable until the
            // service is started again, on its private socket.
            if let Some(port) = svc.get("internal_port").and_then(|v| v.as_u64()) {
                let marker = Path::new(data_dir)
                    .join("editor-services")
                    .join(e.path().file_stem().unwrap_or_default())
                    .join("extensions");
                let stopped =
                    u16::try_from(port).is_ok_and(|port| stop_legacy_tcp_runtime(port, &marker));
                svc["phase"] = json!("degraded");
                svc["internal_port"] = Value::Null;
                svc["readiness"] = json!({ "mode": "blocked", "reason": "editor_runtime_legacy_tcp", "detail": if stopped { "an editor runtime listening on a loopback TCP port was stopped; restart the editor service (its runtime now listens on a private socket)" } else { "this record named a loopback TCP runtime; restart the editor service (its runtime now listens on a private socket)" } });
                let _ = std::fs::write(
                    e.path(),
                    serde_json::to_vec_pretty(&svc).unwrap_or_default(),
                );
                reconciled += 1;
                continue;
            }
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

#[cfg(test)]
mod runtime_output_redaction_tests {
    /// The pinned server's startup line (printed on a TCP port) carries the token in its URL; the
    /// exact token bytes never reach the service log.
    #[test]
    fn the_startup_line_reaches_the_log_with_its_token_redacted() {
        let token = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let line = format!("Web UI available at http://localhost:3000?tkn={token}\n");
        let logged = super::redact_secret(&line, token);
        assert_eq!(
            logged,
            "Web UI available at http://localhost:3000?tkn=[redacted]\n"
        );
        assert!(!logged.contains(token));
    }
}
