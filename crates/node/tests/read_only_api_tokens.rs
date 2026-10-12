//! A read-only API token is enforced as read-only: the identity it resolves carries the flag, and
//! every state-changing request it carries (any method but GET, HEAD and OPTIONS) is refused with
//! `hypervisor.auth_token_read_only` before any handler runs, on gate-exempt routes too and
//! whether the token arrives as the bearer or as the session cookie, except the reviewed POST-shaped
//! reads, which answer it exactly as they answer a full token. A full token still writes. Through
//! the REAL daemon, inside `unshare -rn`, every path under one temp dir.

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

/// The reviewed POST-shaped reads a read-only token may call (BUILD-DELTA #13's class).
const POST_SHAPED_READS: &[&str] = &[
    "/v1/hypervisor/product-surface-projections",
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

/// A read-only token still reads, and the identity it resolves says it is read-only.
#[test]
fn a_read_only_token_reads_and_its_identity_carries_the_flag() {
    let f = fixture();
    let (read_only, read_only_id) = f.mint(true);
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/api-tokens",
        Some(&read_only),
        None,
    );
    assert_eq!(status, 200, "a read: {body}");
    assert!(body.contains(&read_only_id), "the listing answers: {body}");
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/auth/whoami",
        Some(&read_only),
        None,
    );
    let answer = json_of(&body);
    assert_eq!(status, 200, "whoami: {body}");
    assert_eq!(
        answer["authenticated"],
        json!(true),
        "the token resolves: {body}"
    );
    assert_eq!(
        answer["principal"]["api_token_read_only"],
        json!(true),
        "the resolved identity carries the read-only flag: {body}"
    );
    let (full, _) = f.mint(false);
    let (_, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/auth/whoami",
        Some(&full),
        None,
    );
    assert_ne!(
        json_of(&body)["principal"]["api_token_read_only"],
        json!(true),
        "a full token's identity is not read-only: {body}"
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
