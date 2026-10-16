//! BUILD-DELTA #21(c): a model-mount capability token's expiry is in its DURABLE issue record and is read back from
//! disk on every use; a RUN-SCOPED token (the cell's) does not outlive the daemon process its run lived in, because
//! no run is live in a process that has just started. Through the REAL daemon binary, restarted for real (SIGKILL,
//! then a new process over the same data dir), inside `unshare -rn`, every path under one temp dir.
//!
//! The run-scoped token in these tests is a durable issue record in the shape the daemon's run-scoped mint writes
//! (the daemon's own `run_scoped_model_token_issue_tests` pin that shape against the real mint): the real mint runs
//! only inside a session execute, whose authority gate needs a wallet.network chain grant.
//!
//! The startup sweep's inventory is complete or the daemon does not reach readiness: a token directory, entry or
//! record that cannot be read stops the start (only a token directory that does not exist is empty); and every field
//! of an issue record is read, so a record whose TTL or audience is missing, mistyped or inconsistent is refused.

use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RUN_TTL_SECS: i64 = 2 * 3600;
const SESSION: &str = "session:durable-issue-run";
const GRANT: &str = "receipt://hypervisor/session-execute/durable-issue-run";

fn assert_isolated_namespace() {
    let dev = std::fs::read_to_string("/proc/net/dev").expect("/proc/net/dev is readable");
    let interfaces: Vec<String> = dev
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(|name| name.trim().to_string())
        .collect();
    assert!(
        interfaces.iter().all(|name| name == "lo"),
        "refusing to start a daemon outside an isolated network namespace (interfaces: {interfaces:?}); run inside `unshare -rn`"
    );
}

struct Daemon {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Drop for Daemon {
    /// SIGKILL: the process ends the way a crash ends it, with no shutdown path run.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a namespace-local port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size, after)) = rest.split_once("\r\n") else {
            break;
        };
        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if n == 0 || after.len() < n {
            break;
        }
        out.push_str(&after[..n]);
        rest = after[n..].trim_start_matches("\r\n");
    }
    out
}

/// One HTTP/1.1 request to the daemon (Connection: close); returns (status, body).
fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        payload.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    (
        status,
        if chunked {
            dechunk(body)
        } else {
            body.to_string()
        },
    )
}

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| json!({ "raw": body }))
}

/// The daemon, ready only when ITS OWN log says it is listening and the port answers; a child that
/// failed to bind is detected and the start retried on a new port.
fn start_daemon(data_dir: &Path, home: &Path) -> Daemon {
    for _attempt in 0..5 {
        if let Some(daemon) = try_start_daemon(data_dir, home) {
            return daemon;
        }
    }
    panic!(
        "the daemon did not come up on any of five ports; last log:\n{}",
        std::fs::read_to_string(data_dir.join("daemon.log")).unwrap_or_default()
    );
}

/// The daemon process over `data_dir` on a fresh namespace-local port, its output in `data_dir/daemon.log`.
fn spawn_daemon(data_dir: &Path, home: &Path) -> Daemon {
    let port = free_port();
    let log = data_dir.join("daemon.log");
    let log_file = std::fs::File::create(&log).unwrap();
    let tmp = data_dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let child = Command::new(env!("CARGO_BIN_EXE_hypervisor-daemon"))
        .current_dir(workspace_root)
        .env("IOI_HYPERVISOR_DAEMON_ADDR", format!("127.0.0.1:{port}"))
        .env("IOI_HYPERVISOR_DATA_DIR", data_dir)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "IOI_HYPERVISOR_SESSIONS_ROOT",
            data_dir.join("sessions-root"),
        )
        .env("TMPDIR", &tmp)
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn hypervisor-daemon");
    Daemon { child, port, log }
}

fn try_start_daemon(data_dir: &Path, home: &Path) -> Option<Daemon> {
    let mut daemon = spawn_daemon(data_dir, home);
    let port = daemon.port;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if daemon.child.try_wait().ok().flatten().is_some() {
            return None; // it exited (e.g. the port was taken): retry on another port
        }
        let listening = std::fs::read_to_string(&daemon.log)
            .unwrap_or_default()
            .contains("hypervisor-daemon listening");
        if listening && TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let (status, _) = http(
                port,
                "GET",
                "/v1/hypervisor/auth/bootstrap-status",
                None,
                None,
            );
            if status == 200 {
                return Some(daemon);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the daemon did not come up; log:\n{}",
            std::fs::read_to_string(&daemon.log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A daemon start that must stop before readiness: the process exits without ever listening, and its log says the
/// startup sweep blocked readiness. Returns the log.
fn start_expecting_blocked_readiness(data_dir: &Path, home: &Path, case: &str) -> String {
    let mut daemon = spawn_daemon(data_dir, home);
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let exited = daemon.child.try_wait().ok().flatten().is_some();
        let log = std::fs::read_to_string(&daemon.log).unwrap_or_default();
        assert!(
            !log.contains("hypervisor-daemon listening"),
            "{case}: readiness was not blocked: the daemon is listening; log:\n{log}"
        );
        if exited {
            assert!(
                log.contains("run-scoped model token revocation blocks readiness"),
                "{case}: the startup sweep is what stopped the daemon; log:\n{log}"
            );
            return log;
        }
        assert!(
            Instant::now() < deadline,
            "{case}: the daemon neither exited nor listened; log:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(data.join("tmp")).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    (dir, data, home)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn rfc3339(unix_secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Sleep until the wall clock is strictly past `unix_secs`.
fn wait_past(unix_secs: i64) {
    while now_secs() <= unix_secs {
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// A token minted through the owner route, with an optional requested expiry; returns (token, token_id).
fn create_route_token(daemon: &Daemon, expires_at: Option<i64>) -> (String, String) {
    let mut body = json!({
        "audience": "hypervisor-session",
        "grant_id": "grant://wallet/capability",
        "allowed_scopes": ["server.logs:read"],
        "denied_scopes": [],
    });
    if let Some(expires_at) = expires_at {
        body["expiresAt"] = json!(rfc3339(expires_at));
    }
    let (status, text) = http(
        daemon.port,
        "POST",
        "/v1/model-mount/tokens",
        None,
        Some(&body),
    );
    assert_eq!(status, 200, "token create: {text}");
    let made = json_of(&text);
    (
        made["token"].as_str().expect("a token").to_string(),
        made["token_id"].as_str().expect("a token id").to_string(),
    )
}

/// A route token's use (scope server.logs:read): the status.
fn logs_status(daemon: &Daemon, token: &str) -> u16 {
    http(
        daemon.port,
        "GET",
        "/v1/model-mount/server/logs",
        Some(token),
        None,
    )
    .0
}

/// A run-scoped token's use (scope model.chat:*, the harness's call): (status, body).
fn chat(daemon: &Daemon, token: &str) -> (u16, String) {
    http(
        daemon.port,
        "POST",
        "/v1/chat/completions",
        Some(token),
        Some(&json!({ "messages": [{ "role": "user", "content": "ping" }] })),
    )
}

fn authorized(status: u16) -> bool {
    status != 401 && status != 403 && status != 0
}

/// A capability-token create record as the daemon's kernel writes it (random token, stored as a hash).
fn token_record(
    token_id: &str,
    token: &str,
    authority: Value,
    issue_record: Option<Value>,
) -> Value {
    let record_id = format!(
        "capability_token_control:{token_id}:{}",
        &sha256_hex(token_id)[..16]
    );
    let mut record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": "ioi.model_mount.capability_token_control.v1",
        "object": "ioi.model_mount_capability_token_control",
        "status": "planned",
        "operation_kind": "model_mount.capability_token.create",
        "source": "runtime-daemon.model_mounting.capability_token_control",
        "token_id": token_id,
        "token_hash": sha256_hex(token),
        "rust_core_boundary": "model_mount.capability_token",
        "capability_token_authority": authority,
        "token_entropy": "os_rng_256_v1",
        "planned_at": "rust_model_mount_core",
    });
    if let Some(issue_record) = issue_record {
        record["issue_record"] = issue_record;
    }
    record
}

fn write_record(data: &Path, name: &str, record: &Value) {
    let dir = data.join("capability-tokens");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(record).unwrap(),
    )
    .unwrap();
}

fn fresh_token() -> (String, String) {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    (
        format!("ioi_mnt_{}", hex(&secret)),
        format!("capability_token:{}", hex(&id)),
    )
}

/// The durable record a run-scoped mint leaves for its run (issued at `issued_at`, two-hour TTL).
fn seed_run_scoped_token(data: &Path, name: &str, issued_at: i64) -> (String, String) {
    let (token, token_id) = fresh_token();
    let record = token_record(
        &token_id,
        &token,
        json!({
            "grant_id": GRANT,
            "audience": SESSION,
            "required_scope": null,
            "allowed_scopes": ["model.chat:*"],
            "denied_scopes": [],
            "authority_grant_refs": ["wallet-network://capability-grant/model-mount"],
            "authority_receipt_refs": [],
        }),
        Some(json!({
            "schema_version": "ioi.model_mount.capability_token_issue.v1",
            "issued_at_unix_secs": issued_at,
            "expires_at_unix_secs": issued_at + RUN_TTL_SECS,
            "ttl_secs": RUN_TTL_SECS,
            "audience": SESSION,
            "run_session_ref": SESSION,
        })),
    );
    write_record(data, name, &record);
    (token, token_id)
}

fn records(data: &Path) -> Vec<Value> {
    std::fs::read_dir(data.join("capability-tokens"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                .filter_map(|text| serde_json::from_str(&text).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// THE RESTART TEST (the IOI Director's condition (ii)). A route token with a requested expiry, a route token
/// with none, and a run's run-scoped token are valid in daemon A; A is killed (no shutdown path runs, the lane
/// never returns); daemon B starts over the same data dir. B refuses the run-scoped token at once (its run ended
/// with A), keeps the route token without an expiry, and refuses the other route token once its expiry passes,
/// reading that expiry from disk: no process memory carries it across.
#[test]
fn a_minted_token_is_refused_after_a_real_restart() {
    let (_dir, data, home) = fixture();
    let first = start_daemon(&data, &home);
    let route_expiry = now_secs() + 6;
    let (expiring, _) = create_route_token(&first, Some(route_expiry));
    let (lasting, _) = create_route_token(&first, None);
    let (run_token, _) = seed_run_scoped_token(&data, "run-scoped-a", now_secs());
    assert_eq!(
        logs_status(&first, &expiring),
        200,
        "valid before its expiry"
    );
    assert_eq!(logs_status(&first, &lasting), 200);
    let (status, body) = chat(&first, &run_token);
    assert!(
        authorized(status),
        "the run-scoped token is valid while its run's process lives: {status} {body}"
    );
    let first_pid = first.child.id();
    drop(first);

    let second = start_daemon(&data, &home);
    assert_ne!(second.child.id(), first_pid, "a new daemon process");
    let (status, body) = chat(&second, &run_token);
    assert_eq!(
        status, 403,
        "the run-scoped token of a run that ended with its process is refused after a real restart: {body}"
    );
    assert_eq!(
        logs_status(&second, &lasting),
        200,
        "a route token with no requested expiry is not a run's: the restart keeps it"
    );
    wait_past(route_expiry + 1);
    assert_eq!(
        logs_status(&second, &expiring),
        403,
        "the requested expiry survived the restart: the token is refused after it, read from its durable record"
    );
}

/// Without a restart: a run-scoped token is refused once its TTL has passed (its issue record says it was issued a
/// TTL ago less five seconds), by the same process that served it before.
#[test]
fn a_run_scoped_token_past_its_ttl_is_refused_without_a_restart() {
    let (_dir, data, home) = fixture();
    let mut daemon = start_daemon(&data, &home);
    let issued_at = now_secs() - RUN_TTL_SECS + 5;
    let (token, _) = seed_run_scoped_token(&data, "run-scoped-ttl", issued_at);
    let (status, body) = chat(&daemon, &token);
    assert!(
        authorized(status),
        "valid before its expiry: {status} {body}"
    );
    wait_past(issued_at + RUN_TTL_SECS + 1);
    let (status, body) = chat(&daemon, &token);
    assert_eq!(status, 403, "refused past its TTL with no restart: {body}");
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "the same daemon process throughout"
    );
}

/// A daemon that starts over the record of a run-scoped token whose run is not live refuses it, revokes it durably
/// and no longer lists it.
#[test]
fn a_dead_sessions_run_scoped_token_is_refused_at_startup() {
    let (_dir, data, home) = fixture();
    let (token, token_id) = seed_run_scoped_token(&data, "run-scoped-dead", now_secs());
    let daemon = start_daemon(&data, &home);
    let (status, body) = chat(&daemon, &token);
    assert_eq!(
        status, 403,
        "a run-scoped token whose run is not live is refused from the first request: {body}"
    );
    assert!(
        records(&data).iter().any(|record| {
            record["operation_kind"] == "model_mount.capability_token.revoke"
                && record["token_id"] == token_id.as_str()
        }),
        "the startup revocation is durable"
    );
    let (status, listing) = http(daemon.port, "GET", "/v1/model-mount/tokens", None, None);
    assert_eq!(status, 200);
    assert!(
        !listing.contains(&token_id),
        "a revoked token is not listed: {listing}"
    );
}

/// Pre-Alpha starts fresh: a token record that cannot show its expiry from disk (the shape a create wrote before
/// issue records) is refused, never treated as non-expiring.
#[test]
fn a_token_record_without_a_durable_expiry_is_refused() {
    let (_dir, data, home) = fixture();
    let (token, token_id) = fresh_token();
    let record = token_record(
        &token_id,
        &token,
        json!({
            "grant_id": "grant://wallet/capability",
            "audience": "hypervisor-session",
            "allowed_scopes": ["server.logs:read"],
            "denied_scopes": [],
        }),
        None,
    );
    write_record(&data, "no-issue-record", &record);
    let daemon = start_daemon(&data, &home);
    assert_eq!(
        logs_status(&daemon, &token),
        403,
        "a token without a durable expiry is refused"
    );
}

/// A requested expiry is honoured or the create is refused: one that cannot be read, or is not in the future, never
/// becomes "no expiry".
#[test]
fn a_requested_expiry_that_is_unreadable_or_past_is_refused_at_create() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    for expires_at in ["not-a-time".to_string(), rfc3339(now_secs() - 60)] {
        let (status, text) = http(
            daemon.port,
            "POST",
            "/v1/model-mount/tokens",
            None,
            Some(&json!({
                "audience": "hypervisor-session",
                "grant_id": "grant://wallet/capability",
                "allowed_scopes": ["server.logs:read"],
                "expiresAt": expires_at,
            })),
        );
        assert_eq!(status, 400, "expiresAt {expires_at:?} is refused: {text}");
        assert!(
            !text.contains("ioi_mnt_"),
            "no token is returned for a refused create"
        );
    }
}

// Codex #36d r1: the startup sweep's inventory of capability-tokens/ must be complete. A token directory that does
// not exist is an empty inventory; a directory, an entry or a record that cannot be read keeps the daemon from
// readiness (it exits before it listens), so a run's token whose record could not be read at startup is never
// honoured once reading recovers. Permission bits do not make a file unreadable to the namespace root these tests run
// as, so the failures are made by what the entries are.

#[cfg(unix)]
#[test]
fn startup_readiness_stays_blocked_while_the_token_directory_cannot_be_read() {
    let (_dir, data, home) = fixture();
    let tokens = data.join("capability-tokens");
    std::fs::write(&tokens, b"not a directory").unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "a file where the directory belongs");
    assert!(log.contains("stage: \"directory\""), "{log}");
    std::fs::rename(&tokens, data.join("capability-tokens.aside-file")).unwrap();
    std::os::unix::fs::symlink(data.join("no-such-dir"), &tokens).unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "a symlink to nothing in its place");
    assert!(log.contains("stage: \"directory\""), "{log}");
    // Reading recovers: the real directory, holding a run's token, is read and the sweep revokes the token.
    std::fs::rename(&tokens, data.join("capability-tokens.aside-link")).unwrap();
    let (token, _) = seed_run_scoped_token(&data, "run-scoped-after-directory", now_secs());
    let daemon = start_daemon(&data, &home);
    let (status, body) = chat(&daemon, &token);
    assert_eq!(
        status, 403,
        "the run's token is revoked by the sweep: {body}"
    );
}

#[cfg(unix)]
#[test]
fn startup_readiness_stays_blocked_while_a_token_directory_entry_cannot_be_read() {
    let (_dir, data, home) = fixture();
    let (token, _) = seed_run_scoped_token(&data, "run-scoped-entry", now_secs());
    let tokens = data.join("capability-tokens");
    let entry = tokens.join("pending.json");
    std::os::unix::fs::symlink(data.join("no-such-record.json"), &entry).unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "an entry that resolves to nothing");
    assert!(log.contains("stage: \"entry\""), "{log}");
    std::fs::rename(&entry, tokens.join("pending.aside-link")).unwrap();
    std::fs::create_dir(&entry).unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "a directory with a record's name");
    assert!(log.contains("stage: \"entry\""), "{log}");
    // Reading recovers: the entry is moved aside and the sweep revokes the run's token.
    std::fs::rename(&entry, tokens.join("pending.aside-dir")).unwrap();
    let daemon = start_daemon(&data, &home);
    let (status, body) = chat(&daemon, &token);
    assert_eq!(
        status, 403,
        "the run's token is revoked by the sweep: {body}"
    );
}

/// Codex's case: the run's OWN record cannot be read while the daemon starts. Without a strict inventory the sweep
/// passes it over, startup succeeds, and once the record reads again the token authorizes although its run ended
/// with the earlier process.
#[cfg(unix)]
#[test]
fn startup_readiness_stays_blocked_while_a_token_record_cannot_be_read() {
    let (_dir, data, home) = fixture();
    let (token, _) = seed_run_scoped_token(&data, "run-scoped-record", now_secs());
    let tokens = data.join("capability-tokens");
    let record = tokens.join("run-scoped-record.json");
    let held = tokens.join("run-scoped-record.held");
    std::fs::rename(&record, &held).unwrap();
    // A regular file whose read fails (EIO: the reading process's own memory at offset 0).
    std::os::unix::fs::symlink("/proc/self/mem", &record).unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "the run's record cannot be read");
    assert!(log.contains("stage: \"record\""), "{log}");
    std::fs::rename(&record, tokens.join("run-scoped-record.aside-link")).unwrap();
    let bytes = std::fs::read(&held).unwrap();
    std::fs::write(&record, &bytes[..bytes.len() / 2]).unwrap();
    let log = start_expecting_blocked_readiness(&data, &home, "the run's record is torn");
    assert!(log.contains("stage: \"record\""), "{log}");
    // Reading recovers: the whole record is back, and the sweep revokes the token before the listener opens.
    std::fs::rename(&held, &record).unwrap();
    let daemon = start_daemon(&data, &home);
    let (status, body) = chat(&daemon, &token);
    assert_eq!(
        status, 403,
        "a run's token whose record could not be read at an earlier start is never honoured: {body}"
    );
}

#[test]
fn an_absent_token_directory_is_an_empty_inventory_at_startup() {
    let (_dir, data, home) = fixture();
    assert!(std::fs::symlink_metadata(data.join("capability-tokens")).is_err());
    let daemon = start_daemon(&data, &home);
    let (token, _) = create_route_token(&daemon, None);
    assert_eq!(logs_status(&daemon, &token), 200, "the daemon serves");
}

/// Codex #36d r1 (MINOR): every field of the issue record is read. The TTL must be the expiry less the issue instant
/// (null with no expiry) and the audience null or a name; a record that says otherwise is refused, while the
/// well-formed controls authorize.
#[test]
fn a_token_record_with_a_malformed_issue_record_is_refused() {
    let (_dir, data, home) = fixture();
    let issued = now_secs();
    let authority = json!({
        "grant_id": "grant://wallet/capability",
        "audience": "hypervisor-session",
        "allowed_scopes": ["server.logs:read"],
        "denied_scopes": [],
    });
    let expiring = json!({
        "schema_version": "ioi.model_mount.capability_token_issue.v1",
        "issued_at_unix_secs": issued,
        "expires_at_unix_secs": issued + 3600,
        "ttl_secs": 3600,
        "audience": "hypervisor-session",
        "run_session_ref": null,
    });
    let mut lasting = expiring.clone();
    lasting["expires_at_unix_secs"] = json!(null);
    lasting["ttl_secs"] = json!(null);
    let with = |base: &Value, field: &str, value: Value| {
        let mut issue = base.clone();
        issue[field] = value;
        issue
    };
    let without = |base: &Value, field: &str| {
        let mut issue = base.clone();
        issue.as_object_mut().unwrap().remove(field);
        issue
    };
    let mut seeded = Vec::new();
    for (label, issue) in [
        ("well formed, with an expiry", expiring.clone()),
        ("well formed, no expiry", lasting.clone()),
        (
            "a TTL that is not the expiry less the issue instant",
            with(&expiring, "ttl_secs", json!(60)),
        ),
        ("no TTL", without(&expiring, "ttl_secs")),
        (
            "a TTL that is not an integer",
            with(&expiring, "ttl_secs", json!("3600")),
        ),
        (
            "a TTL with no expiry",
            with(&lasting, "ttl_secs", json!(3600)),
        ),
        ("no audience", without(&expiring, "audience")),
        (
            "an audience that is not a string",
            with(&expiring, "audience", json!(7)),
        ),
    ] {
        let (token, token_id) = fresh_token();
        write_record(
            &data,
            &format!("issue-{}", seeded.len()),
            &token_record(&token_id, &token, authority.clone(), Some(issue)),
        );
        seeded.push((label, token));
    }
    let daemon = start_daemon(&data, &home);
    for (label, token) in &seeded {
        let want = if label.starts_with("well formed") {
            200
        } else {
            403
        };
        assert_eq!(
            logs_status(&daemon, token),
            want,
            "{label}: {}",
            if want == 200 {
                "the control authorizes"
            } else {
                "a malformed issue record is refused"
            }
        );
    }
}
