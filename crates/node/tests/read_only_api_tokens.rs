//! A read-only API token is enforced as read-only by DEFAULT DENY: it is admitted only on an explicit list of
//! routes verified write-free (any method), and every other request it carries is refused with
//! `hypervisor.auth_token_read_only` before any handler runs, on gate-exempt routes too and whether the
//! token arrives as the bearer or as the session cookie. The listed routes answer it exactly as they
//! answer a full token, and a NO-WRITE harness shows a read-only call on each leaves the data directory
//! byte-identical. A full token still writes. Through the REAL daemon, inside `unshare -rn`, every path
//! under one temp dir.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
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

/// One HTTP/1.1 request to the daemon (Connection: close) with extra headers; returns (status, body).
fn http_with(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
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
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
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

/// The same request with an optional `Authorization: Bearer` token.
fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, String) {
    let bearer = token.map(|token| format!("Bearer {token}"));
    let headers: Vec<(&str, &str)> = bearer
        .as_deref()
        .map(|value| vec![("Authorization", value)])
        .unwrap_or_default();
    http_with(port, method, path, &headers, body)
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
    panic!("the daemon did not come up on any of five ports");
}

fn try_start_daemon(data_dir: &Path, home: &Path) -> Option<Daemon> {
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
    let mut daemon = Daemon { child, port, log };
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

const OWNER: (&str, &str) = ("owner@example.test", "read-only-owner-password-1");

fn login(daemon: &Daemon, (email, password): (&str, &str)) -> String {
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/auth/login",
        None,
        Some(&json!({ "email": email, "password": password })),
    );
    assert_eq!(status, 200, "test-setup login {email}: {body}");
    let answer = json_of(&body);
    answer
        .get("session_token")
        .or_else(|| answer.get("session").and_then(|s| s.get("session_token")))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| panic!("a session token in the login answer: {body}"))
}

/// The first operator (the deployment owner), set from the bootstrap token in the daemon's own log.
fn owner_session(daemon: &Daemon) -> String {
    let log = std::fs::read_to_string(&daemon.log).unwrap_or_default();
    let at = log
        .find("ioi_bootstrap_")
        .expect("a bootstrap token in the daemon log");
    let token: String = log[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/auth/bootstrap",
        None,
        Some(&json!({ "token": token, "password": OWNER.1, "email": OWNER.0 })),
    );
    assert_eq!(status, 200, "test-setup bootstrap: {body}");
    login(daemon, OWNER)
}

struct Fixture {
    _dir: tempfile::TempDir,
    daemon: Daemon,
    owner: String,
}

fn fixture() -> Fixture {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let daemon = start_daemon(&data, &home);
    let owner = owner_session(&daemon);
    Fixture {
        _dir: dir,
        daemon,
        owner,
    }
}

impl Fixture {
    /// Mint an API token as the owner; (value, token id).
    fn mint(&self, read_only: bool) -> (String, String) {
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/api-tokens",
            Some(&self.owner),
            Some(
                &json!({ "description": format!("read_only={read_only}"), "read_only": read_only }),
            ),
        );
        let answer = json_of(&body);
        assert_eq!(status, 200, "test-setup token mint: {body}");
        (
            answer["token"]["value"]
                .as_str()
                .unwrap_or_else(|| panic!("a token value: {body}"))
                .to_string(),
            answer["token"]["token_id"]
                .as_str()
                .unwrap_or_else(|| panic!("a token id: {body}"))
                .to_string(),
        )
    }

    /// The owner's view of the API token ids.
    fn token_ids(&self) -> Vec<String> {
        let (status, body) = http(
            self.daemon.port,
            "GET",
            "/v1/hypervisor/api-tokens",
            Some(&self.owner),
            None,
        );
        assert_eq!(status, 200, "test-setup token list: {body}");
        let answer = json_of(&body);
        answer["tokens"]
            .as_array()
            .or_else(|| answer["api_tokens"].as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t["token_id"].as_str().map(str::to_string))
            .collect()
    }
}

fn is_read_only_refusal(status: u16, body: &str) -> bool {
    let answer = json_of(body);
    status == 403
        && (answer["code"] == json!("hypervisor.auth_token_read_only")
            || answer["error"]["code"] == json!("hypervisor.auth_token_read_only"))
}

/// The allowlisted POST-shaped reads (BUILD-DELTA #13's class); product-surface-projections is not proven write-free and is not here.
const POST_SHAPED_READS: &[&str] = &[
    "/v1/hypervisor/collections/query",
    "/v1/hypervisor/odk/object-instance-search",
    "/v1/hypervisor/authority/evaluate",
    "/v1/hypervisor/provider-ladder/resolve",
    "/v1/mcp/gateway-requirements/resolve",
];

/// A read-only token is refused, by name, on every state-changing request, before any handler
/// runs: it mints no token (no escalation), revokes none, creates nothing, and is refused on a
/// gate-exempt route that resolves its caller, as the bearer or as the session cookie.
#[test]
fn a_read_only_token_is_refused_on_every_state_change() {
    let f = fixture();
    let (read_only, read_only_id) = f.mint(true);
    let before = f.token_ids();
    let cases: Vec<(&str, String, Value)> = vec![
        (
            "POST",
            "/v1/hypervisor/api-tokens".to_string(),
            json!({ "description": "escalate" }),
        ),
        (
            "DELETE",
            format!("/v1/hypervisor/api-tokens/{read_only_id}"),
            json!({}),
        ),
        ("POST", "/v1/threads".to_string(), json!({})),
        (
            "PATCH",
            "/v1/hypervisor/automations/automation-x".to_string(),
            json!({ "enabled": false }),
        ),
        (
            "PUT",
            "/v1/hypervisor/preferences/preference-x".to_string(),
            json!({}),
        ),
        (
            "POST",
            "/v1/hypervisor/org-invite/accept".to_string(),
            json!({ "invite_id": "invite-x", "email": OWNER.0 }),
        ),
    ];
    let mut admitted = Vec::new();
    for (method, path, body) in &cases {
        let (status, answer) = http(f.daemon.port, method, path, Some(&read_only), Some(body));
        if !is_read_only_refusal(status, &answer) {
            admitted.push(format!("{method} {path} -> {status} {answer}"));
        }
    }
    let cookie = format!("ioi_session={read_only}");
    let (status, answer) = http_with(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/org-invite/accept",
        &[("Cookie", cookie.as_str())],
        Some(&json!({ "invite_id": "invite-x", "email": OWNER.0 })),
    );
    if !is_read_only_refusal(status, &answer) {
        admitted.push(format!(
            "POST /v1/hypervisor/org-invite/accept (token as the session cookie) -> {status} {answer}"
        ));
    }
    assert!(
        admitted.is_empty(),
        "a read-only token is refused by name on every state change:\n{}",
        admitted.join("\n")
    );
    assert_eq!(
        f.token_ids(),
        before,
        "no token was minted or revoked by the read-only token"
    );
}

/// A read-only token reads on the listed routes. Its identity route is not listed (the identity bootstrap
/// can write), so it is refused by name there, and a full token's answer is unchanged.
#[test]
fn a_read_only_token_reads_on_the_listed_routes_only() {
    let f = fixture();
    let (read_only, read_only_id) = f.mint(true);
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/api-tokens",
        Some(&read_only),
        None,
    );
    assert_eq!(status, 200, "a listed read: {body}");
    assert!(body.contains(&read_only_id), "the listing answers: {body}");
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/auth/whoami",
        Some(&read_only),
        None,
    );
    assert!(
        is_read_only_refusal(status, &body),
        "an unlisted read is refused by name: {status} {body}"
    );
    let (full, _) = f.mint(false);
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/auth/whoami",
        Some(&full),
        None,
    );
    assert_eq!(status, 200, "a full token reads whoami: {body}");
    assert_ne!(
        json_of(&body)["principal"]["api_token_read_only"],
        json!(true)
    );
}

/// On each reviewed POST-shaped read, a read-only token gets exactly the status a full token gets,
/// and never the read-only refusal.
#[test]
fn a_read_only_token_gets_a_full_tokens_answer_on_each_post_shaped_read() {
    let f = fixture();
    let (read_only, _) = f.mint(true);
    let (full, _) = f.mint(false);
    for path in POST_SHAPED_READS {
        let (full_status, full_body) =
            http(f.daemon.port, "POST", path, Some(&full), Some(&json!({})));
        let (status, body) = http(
            f.daemon.port,
            "POST",
            path,
            Some(&read_only),
            Some(&json!({})),
        );
        assert!(
            !is_read_only_refusal(status, &body),
            "{path}: the read-only token is admitted: {status} {body}"
        );
        assert_eq!(
            status, full_status,
            "{path}: the same status as a full token ({full_body}) : {body}"
        );
    }
}

/// A full token still mints and revokes.
#[test]
fn a_full_token_still_writes() {
    let f = fixture();
    let (full, _) = f.mint(false);
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/api-tokens",
        Some(&full),
        Some(&json!({ "description": "minted by a full token" })),
    );
    assert_eq!(status, 200, "a full token mints: {body}");
    let minted = json_of(&body)["token"]["token_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let (status, body) = http(
        f.daemon.port,
        "DELETE",
        &format!("/v1/hypervisor/api-tokens/{minted}"),
        Some(&full),
        None,
    );
    assert!(
        (200..300).contains(&status),
        "a full token revokes: {status} {body}"
    );
}

/// Every route a read-only token may call, any method: each verified write-free (handler and helpers read no
/// writer) and each proved by the no-write harness below. A route joins this list only with that proof.
const READ_ONLY_ALLOWLIST: &[(&str, &str)] = &[
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/v1/hypervisor/api-tokens"),
    ("POST", "/v1/hypervisor/collections/query"),
    ("POST", "/v1/hypervisor/odk/object-instance-search"),
    ("POST", "/v1/hypervisor/authority/evaluate"),
    ("POST", "/v1/hypervisor/provider-ladder/resolve"),
    ("POST", "/v1/mcp/gateway-requirements/resolve"),
];

/// Reads and read-shaped requests that WRITE (BUILD-DELTA #38's class) or are not proven write-free: a
/// read-only token is refused on every one, as it is on a route that does not exist.
const READS_THAT_WRITE_OR_ARE_UNPROVEN: &[(&str, &str)] = &[
    ("GET", "/v1/hypervisor/org-invite"),
    ("GET", "/v1/hypervisor/auth/whoami"),
    ("GET", "/v1/hypervisor/principals"),
    ("GET", "/v1/hypervisor/organization"),
    ("GET", "/v1/hypervisor/environment-classes"),
    ("GET", "/v1/hypervisor/model-routes"),
    ("GET", "/v1/hypervisor/harness-profiles"),
    ("GET", "/v1/hypervisor/sessions"),
    ("GET", "/v1/hypervisor/notifications"),
    ("GET", "/v1/hypervisor/work-projection"),
    ("GET", "/v1/hypervisor/download-intents/intent-x/content"),
    ("GET", "/v1/hypervisor/backup-exports/token-x"),
    (
        "GET",
        "/v1/hypervisor/auth/device-held-principals/principal-x/binding-state",
    ),
    ("POST", "/v1/hypervisor/product-surface-projections"),
    ("GET", "/v1/hypervisor/no-such-route-at-all"),
];

const ALL_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

/// The exact metadata keys the token listing returns for each token: an explicit projection, never the stored record.
const LISTED_TOKEN_KEYS: &[&str] = &[
    "created_at",
    "description",
    "expires_at",
    "last_used_at",
    "read_only",
    "token_id",
];

fn call(f: &Fixture, token: &str, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
    http(f.daemon.port, method, path, Some(token), body)
}

/// Default deny, method AND path exact: across every method on every listed path and every unlisted candidate, the
/// requests a read-only token is admitted on are exactly the listed (method, path) pairs. HEAD and OPTIONS on a
/// listed GET path are refused: nothing is normalised to another method.
#[test]
fn a_read_only_token_is_admitted_on_exactly_the_allowlist() {
    let f = fixture();
    let (read_only, _) = f.mint(true);
    let (full, _) = f.mint(false);
    let mut paths: Vec<&str> = READ_ONLY_ALLOWLIST.iter().map(|(_, path)| *path).collect();
    paths.extend(
        READS_THAT_WRITE_OR_ARE_UNPROVEN
            .iter()
            .map(|(_, path)| *path),
    );
    paths.sort_unstable();
    paths.dedup();
    let mut admitted: Vec<(String, String)> = Vec::new();
    let mut vacuous: Vec<String> = Vec::new();
    for path in &paths {
        for method in ALL_METHODS {
            let body =
                (*method != "GET" && *method != "HEAD" && *method != "OPTIONS").then(|| json!({}));
            let (status, answer) = call(&f, &read_only, method, path, body.as_ref());
            // A HEAD or OPTIONS answer has no body to carry the refusal code, so it is read from the status:
            // the read-only token's 403 where a full token's answer is not a 403.
            let refused = if *method == "HEAD" || *method == "OPTIONS" {
                let (full_status, _) = call(&f, &full, method, path, body.as_ref());
                if full_status == 403 {
                    // The full token is refused here too, so this case cannot show the guard acted: named, not silent.
                    vacuous.push(format!("{method} {path} (a full token also gets 403)"));
                    continue;
                }
                status == 403
            } else {
                is_read_only_refusal(status, &answer)
            };
            if !refused {
                admitted.push((method.to_string(), path.to_string()));
            }
        }
    }
    let mut expected: Vec<(String, String)> = READ_ONLY_ALLOWLIST
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    admitted.sort();
    expected.sort();
    for case in &vacuous {
        println!("  EXCLUDED-VACUOUS {case}");
    }
    for (method, path) in READ_ONLY_ALLOWLIST {
        assert!(
            !vacuous
                .iter()
                .any(|v| v.starts_with(&format!("{method} {path} "))),
            "a listed route's control answer must not be vacuous: {method} {path}"
        );
    }
    assert_eq!(
        admitted, expected,
        "the admitted (method, path) set is exactly the allowlist"
    );
}

/// The token listing is an explicit metadata projection: exactly these keys per token, nothing else.
#[test]
fn the_token_listing_returns_exactly_the_named_metadata_keys() {
    let f = fixture();
    let (read_only, read_only_id) = f.mint(true);
    let (_, full_id) = f.mint(false);
    let (status, body) = call(&f, &read_only, "GET", "/v1/hypervisor/api-tokens", None);
    assert_eq!(status, 200, "{body}");
    let tokens = json_of(&body)["tokens"]
        .as_array()
        .cloned()
        .expect("a tokens array");
    assert!(tokens.len() >= 2, "{body}");
    for token in &tokens {
        let mut keys: Vec<&str> = token
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, LISTED_TOKEN_KEYS, "the exact key set: {token}");
    }
    let ids: Vec<&str> = tokens
        .iter()
        .filter_map(|t| t["token_id"].as_str())
        .collect();
    assert!(ids.contains(&read_only_id.as_str()) && ids.contains(&full_id.as_str()));
}

/// Everything under the data directory, path -> bytes, directories as their own entries. Any enumeration or read
/// error is fatal: evidence that cannot be read is not evidence.
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    files: std::collections::BTreeMap<String, Vec<u8>>,
    dirs: std::collections::BTreeSet<String>,
}

fn snapshot(data: &Path) -> Snapshot {
    fn walk(root: &Path, dir: &Path, out: &mut Snapshot) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot enumerate {}: {e}", dir.display()));
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|e| panic!("cannot read an entry of {}: {e}", dir.display()));
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let kind = entry
                .file_type()
                .unwrap_or_else(|e| panic!("cannot stat {rel}: {e}"));
            if kind.is_dir() {
                out.dirs.insert(rel);
                walk(root, &path, out);
            } else {
                let bytes =
                    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"));
                out.files.insert(rel, bytes);
            }
        }
    }
    let mut out = Snapshot {
        files: Default::default(),
        dirs: Default::default(),
    };
    walk(data, data, &mut out);
    out
}

/// The ONLY paths the no-write comparison does not hold fixed, each with the reason. Anything else that changes,
/// during a call or while the daemon idles, fails the test. tmp/ is NOT excluded: it is the daemon's TMPDIR and
/// could hold persistent scratch or lock state, so a write there must be seen.
const EXCLUDED: &[(&str, &str)] = &[
    (
        "daemon.log",
        "the daemon's own log: it may only be appended to, and its new lines are printed",
    ),
    (
        "scheduler-heartbeats",
        "the directory the automation scheduler's timer creates, present only after its first tick, independent of any request (the daemon has no switch that disables its scheduler: it is spawned unconditionally)",
    ),
    (
        "scheduler-heartbeats/automation-scheduler.json",
        "the automation scheduler's heartbeat, rewritten by the daemon's own timer (measured changing while idle; no switch disables the scheduler, so it is excluded by name rather than by configuration)",
    ),
];

/// Paths whose bytes or presence differ between two snapshots, outside EXCLUDED.
fn differences(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let excluded = |path: &str| EXCLUDED.iter().any(|(p, _)| *p == path);
    let mut out = Vec::new();
    for path in before.files.keys().chain(after.files.keys()) {
        if !excluded(path) && before.files.get(path) != after.files.get(path) {
            out.push(format!("file {path}"));
        }
    }
    for path in before.dirs.symmetric_difference(&after.dirs) {
        if excluded(path) {
            continue;
        }
        out.push(format!("directory {path}"));
    }
    out.sort();
    out.dedup();
    out
}

/// The log may only grow. Returns the new lines.
fn appended_log_lines(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let old = before.files.get("daemon.log").cloned().unwrap_or_default();
    let new = after.files.get("daemon.log").cloned().unwrap_or_default();
    assert!(
        new.starts_with(&old),
        "daemon.log was rewritten, not appended to"
    );
    String::from_utf8_lossy(&new[old.len()..])
        .lines()
        .map(str::to_string)
        .collect()
}

struct Case {
    label: &'static str,
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    /// The expected SUCCESS-path result: a fixed, asserted answer, so the call provably reached its read.
    check: Box<dyn Fn(u16, &str) -> Result<String, String>>,
}

fn must(condition: bool, what: &str, body: &str) -> Result<String, String> {
    if condition {
        Ok(what.to_string())
    } else {
        Err(format!("{what}: {body}"))
    }
}

/// Seeds records the listed routes read, so each call reaches its success path (and its conditional branches).
fn seed(data: &Path) -> (String, String) {
    let write = |rel: &str, value: Value| {
        let path = data.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    };
    write(
        "projects/proj_fix3.json",
        json!({ "id": "proj_fix3", "name": "Fixture project", "org_ref": "org://local" }),
    );
    write(
        "odk-materialized-object-sets/set_fix3.json",
        json!({
            "ref": "odk-materialized-set://fix3", "ontology_ref": "ontology://fix3", "object_type_id": "Aircraft",
            "materializing_run_ref": "run://fix3", "objects": [{ "tail": "N123FIX3" }, { "tail": "N999OTHER" }]
        }),
    );
    write(
        "odk-domain-ontologies/ont_fix3.json",
        json!({ "id": "ont_fix3", "ref": "ontology://fix3" }),
    );
    write(
        "justification-checkpoints/jc_fix3.json",
        json!({
            "checkpoint_id": "justification-checkpoint://jc_fix3", "enablement": "enabled", "scope_ref": "org://local",
            "interaction_kinds": ["automation.run_now"], "conditions": { "item_refs": [], "exempt_principal_refs": [] }
        }),
    );
    write(
        "recipes/rcp_fix3.json",
        json!({ "id": "rcp_fix3", "name": "Fixture recipe" }),
    );
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/architecture/_meta/schemas/fixtures/mcp-gateway-requirement-envelope-v1/positive-released-read-only-requirement.json"),
        )
        .expect("the released read-only requirement fixture"),
    )
    .unwrap();
    let revision = fixture["revision_ref"].as_str().unwrap().to_string();
    write("mcp-gateway-requirements/req_fix3.json", fixture);
    ("rcp_fix3".to_string(), revision)
}

fn cases(f: &Fixture, read_only_id: String, revision: String) -> Vec<Case> {
    let _ = f;
    let scope = "scope:project.read";
    let tool = "tool://project.inspect/revision/1.0.0";
    vec![
        Case {
            label: "health probe",
            method: "GET",
            path: "/healthz",
            body: None,
            check: Box::new(|s, b| must(s == 200 && b.trim() == "OK", "healthz answers OK", b)),
        },
        Case {
            label: "readiness probe",
            method: "GET",
            path: "/readyz",
            body: None,
            check: Box::new(|s, b| must(s == 200 && b.trim() == "OK", "readyz answers OK", b)),
        },
        Case {
            label: "token listing",
            method: "GET",
            path: "/v1/hypervisor/api-tokens",
            body: None,
            check: Box::new(move |s, b| {
                must(
                    s == 200 && b.contains(&read_only_id),
                    "the listing names the read-only token",
                    b,
                )
            }),
        },
        Case {
            label: "collection query reaches a seeded project",
            method: "POST",
            path: "/v1/hypervisor/collections/query",
            body: Some(json!({ "collection": "projects" })),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["items"]
                            .as_array()
                            .is_some_and(|i| i.iter().any(|x| x["id"] == "proj_fix3")),
                    "the seeded project is returned",
                    b,
                )
            }),
        },
        Case {
            label: "object search over the seeded corpus",
            method: "POST",
            path: "/v1/hypervisor/odk/object-instance-search",
            body: Some(json!({ "q": "N123FIX3" })),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["total_matched"] == 1
                        && json_of(b)["results"][0]["object"]["tail"] == "N123FIX3",
                    "one seeded object matches",
                    b,
                )
            }),
        },
        Case {
            label: "object search resolving a seeded ontology",
            method: "POST",
            path: "/v1/hypervisor/odk/object-instance-search",
            body: Some(
                json!({ "ontology_ref": "ontology://fix3", "object_type_id": "Aircraft", "q": "n123" }),
            ),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["corpus"]["object_instances_in_scope"] == 2
                        && json_of(b)["total_matched"] == 1,
                    "the ontology filter resolves and scopes the corpus",
                    b,
                )
            }),
        },
        Case {
            label: "authority evaluation reading a seeded checkpoint",
            method: "POST",
            path: "/v1/hypervisor/authority/evaluate",
            body: Some(json!({ "effect": "automation.run_now" })),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["obligations"][0]["checkpoint_refs"][0]
                            == "justification-checkpoint://jc_fix3",
                    "the checkpoint becomes an obligation",
                    b,
                )
            }),
        },
        Case {
            label: "authority evaluation of a local effect",
            method: "POST",
            path: "/v1/hypervisor/authority/evaluate",
            body: Some(json!({ "effect": "local_file_read" })),
            check: Box::new(|s, b| {
                must(
                    s == 200 && json_of(b)["decision"] == "allowed_local",
                    "a local effect is allowed locally",
                    b,
                )
            }),
        },
        Case {
            label: "provider ladder with a seeded recipe",
            method: "POST",
            path: "/v1/hypervisor/provider-ladder/resolve",
            body: Some(json!({ "recipe_ref": "rcp_fix3" })),
            check: Box::new(|s, b| {
                must(
                    s == 200 && json_of(b)["resolution"]["recipe_ref"] == "rcp_fix3",
                    "the recipe loads and is bound",
                    b,
                )
            }),
        },
        Case {
            label: "provider ladder with a missing recipe",
            method: "POST",
            path: "/v1/hypervisor/provider-ladder/resolve",
            body: Some(json!({ "recipe_ref": "rcp_missing" })),
            check: Box::new(|s, b| {
                must(
                    s == 200 && json_of(b)["ok"] == false && b.contains("not found"),
                    "a missing recipe is named",
                    b,
                )
            }),
        },
        Case {
            label: "gateway requirement within its ceiling",
            method: "POST",
            path: "/v1/mcp/gateway-requirements/resolve",
            body: Some(
                json!({ "requirement_revision_ref": revision.clone(), "proposed_authority_scope_refs": [scope], "proposed_runtime_tool_contract_refs": [tool], "proposed_maximum_risk_class": "read" }),
            ),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["resolvable"] == true
                        && json_of(b)["authority_granted"] == false,
                    "a use inside the ceiling resolves",
                    b,
                )
            }),
        },
        Case {
            label: "gateway requirement beyond its ceiling",
            method: "POST",
            path: "/v1/mcp/gateway-requirements/resolve",
            body: Some(
                json!({ "requirement_revision_ref": revision, "proposed_authority_scope_refs": [scope, "scope:project.write"], "proposed_maximum_risk_class": "read" }),
            ),
            check: Box::new(|s, b| {
                must(
                    s == 200
                        && json_of(b)["resolvable"] == false
                        && b.contains("scope:project.write"),
                    "a use beyond the ceiling names the excess",
                    b,
                )
            }),
        },
    ]
}

/// The NO-WRITE harness. Records the routes read are seeded so every listed route reaches its success path; each
/// case's answer is asserted; the data directory (files, bytes, directory entries, tmp/ included) is compared before
/// and after each call and across an idle period. Only EXCLUDED is exempt, and it is printed. Outbound calls are not
/// observable here (the namespace has no route out); the listed handlers were read for them and issue none.
#[test]
fn a_read_only_call_on_an_allowlisted_route_changes_nothing() {
    let f = fixture();
    let (read_only, read_only_id) = f.mint(true);
    let data = f._dir.path().join("data");
    let (_recipe, revision) = seed(&data);
    println!("NO-WRITE harness exclusions (everything else must stay identical):");
    for (path, why) in EXCLUDED {
        println!("  {path}: {why}");
    }
    let idle_a = snapshot(&data);
    std::thread::sleep(Duration::from_millis(800));
    let idle_b = snapshot(&data);
    let idle = differences(&idle_a, &idle_b);
    assert!(idle.is_empty(), "the data directory changed while the daemon idled (name it in EXCLUDED with its reason): {idle:?}");
    let mut failures = Vec::new();
    let mut covered = std::collections::BTreeSet::new();
    for case in cases(&f, read_only_id, revision) {
        let before = snapshot(&data);
        let (status, body) = call(&f, &read_only, case.method, case.path, case.body.as_ref());
        let after = snapshot(&data);
        if is_read_only_refusal(status, &body) {
            failures.push(format!(
                "{}: refused as read-only ({status}) {body}",
                case.label
            ));
            continue;
        }
        match (case.check)(status, &body) {
            Ok(asserted) => println!(
                "  REACHED {} ({} {}) -> {status}: {asserted}",
                case.label, case.method, case.path
            ),
            Err(why) => failures.push(format!("{}: {why}", case.label)),
        }
        let changed = differences(&before, &after);
        if !changed.is_empty() {
            failures.push(format!(
                "{} ({} {}): wrote {changed:?}",
                case.label, case.method, case.path
            ));
        }
        for line in appended_log_lines(&before, &after) {
            println!("  daemon.log + [{}] {line}", case.label);
        }
        covered.insert((case.method, case.path));
    }
    for (method, path) in READ_ONLY_ALLOWLIST {
        assert!(
            covered.contains(&(*method, *path)),
            "no harness case reaches {method} {path}"
        );
    }
    assert!(
        failures.is_empty(),
        "the no-write harness failed:\n{}",
        failures.join("\n")
    );
}

/// BUILD-DELTA #36d: the registered API-token mint (handle_api_token_create) called 256 times through its real route:
/// every token value distinct, prefixed and the right length, and every id distinct.
#[test]
fn two_hundred_fifty_six_api_tokens_minted_through_the_route_are_distinct_and_the_right_length() {
    let f = fixture();
    let mut values = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..256 {
        let (value, id) = f.mint(false);
        assert_eq!(
            value.len(),
            "ioi_pat_".len() + 64,
            "expected length: {value}"
        );
        assert!(value.starts_with("ioi_pat_"), "prefix: {value}");
        assert!(values.insert(value), "a repeated token value");
        assert!(ids.insert(id), "a repeated token id");
    }
}
