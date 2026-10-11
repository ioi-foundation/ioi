//! BUILD-DELTA #24: an existing principal is never signed in by the organization invite; it joins by an
//! authenticated accept, as itself. A new email is still provisioned and signed in. Through the REAL daemon,
//! inside `unshare -rn`, every path under one temp dir.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

#[allow(dead_code)]
struct Daemon {
    child: Child,
    port: u16,
    log: std::path::PathBuf,
    /// The daemon's own TMPDIR, under the test's temp dir.
    tmp: std::path::PathBuf,
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

fn start_daemon(data_dir: &Path, home: &Path) -> Daemon {
    start_daemon_env(data_dir, home, &[])
}

/// The daemon with extra environment. Ready only when ITS OWN log says it is listening and the port answers:
/// a port another test's daemon took first is never mistaken for ours; a child that failed to bind is detected
/// and the start retried on a new port.
fn start_daemon_env(data_dir: &Path, home: &Path, extra: &[(&str, &str)]) -> Daemon {
    for _attempt in 0..5 {
        if let Some(daemon) = try_start_daemon(data_dir, home, extra) {
            return daemon;
        }
    }
    panic!("the daemon did not come up on any of five ports");
}

fn try_start_daemon(data_dir: &Path, home: &Path, extra: &[(&str, &str)]) -> Option<Daemon> {
    let port = free_port();
    let log = data_dir.join("daemon.log");
    let log_file = std::fs::File::create(&log).unwrap();
    let tmp = data_dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hypervisor-daemon"));
    command
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
        .stderr(Stdio::from(log_file));
    for (name, value) in extra {
        command.env(name, value);
    }
    let child = command.spawn().expect("spawn hypervisor-daemon");
    let mut daemon = Daemon {
        child,
        port,
        log,
        tmp,
    };
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

const OWNER: (&str, &str) = ("owner@example.test", "d24-owner-password-1");
const ADMIN: (&str, &str) = ("admin@example.test", "d24-admin-password-1");
const MEMBER: (&str, &str) = ("member@example.test", "d24-member-password-1");

fn session_token_of(body: &str) -> Option<String> {
    let answer = json_of(body);
    answer
        .get("session_token")
        .or_else(|| answer.get("session").and_then(|s| s.get("session_token")))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn login(daemon: &Daemon, (email, password): (&str, &str)) -> String {
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/auth/login",
        None,
        Some(&json!({ "email": email, "password": password })),
    );
    assert_eq!(status, 200, "test-setup login {email}: {body}");
    session_token_of(&body).unwrap_or_else(|| panic!("a session token in the login answer: {body}"))
}

/// The first operator (the deployment owner), set from the bootstrap token the daemon printed to its own log.
fn owner_token(daemon: &Daemon) -> String {
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

fn create_principal(daemon: &Daemon, owner: &str, (email, password): (&str, &str), role: &str) {
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/principals",
        Some(owner),
        Some(&json!({ "email": email, "password": password, "role": role })),
    );
    assert!(
        status == 200 || status == 201,
        "test-setup principal {email}: {status} {body}"
    );
}

fn invite_id(daemon: &Daemon, owner: &str) -> String {
    let (status, body) = http(
        daemon.port,
        "GET",
        "/v1/hypervisor/org-invite",
        Some(owner),
        None,
    );
    assert_eq!(status, 200, "test-setup invite: {body}");
    json_of(&body)["invite"]["invite_id"]
        .as_str()
        .unwrap_or_else(|| panic!("an invite id: {body}"))
        .to_string()
}

/// How many sign-in sessions the daemon has stored (records carrying a token hash).
fn stored_sessions(data_dir: &Path) -> usize {
    std::fs::read_dir(data_dir.join("sessions"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.path().extension().is_some_and(|e| e == "json")
                        && std::fs::read_to_string(entry.path())
                            .map(|text| text.contains("\"token_hash\""))
                            .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn accept(daemon: &Daemon, token: Option<&str>, body: &Value) -> (u16, String) {
    http(
        daemon.port,
        "POST",
        "/v1/hypervisor/org-invite/accept",
        token,
        Some(body),
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    data: std::path::PathBuf,
    daemon: Daemon,
    invite: String,
}

fn fixture() -> Fixture {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let daemon = start_daemon(&data, &home);
    let owner = owner_token(&daemon);
    create_principal(&daemon, &owner, ADMIN, "admin");
    create_principal(&daemon, &owner, MEMBER, "member");
    let invite = invite_id(&daemon, &owner);
    Fixture {
        _dir: dir,
        data,
        daemon,
        invite,
    }
}

/// The owner's, an admin's and a member's email each get a typed refusal from an unauthenticated accept, with
/// their real password, a wrong one or none, and no session is issued.
#[test]
fn d24_an_existing_principal_is_never_signed_in_by_the_invite() {
    let f = fixture();
    let before = stored_sessions(&f.data);
    for (email, password) in [OWNER, ADMIN, MEMBER] {
        for supplied in [Some(password), Some("some-other-password"), None] {
            let mut body = json!({ "invite_id": f.invite, "email": email, "name": "Someone" });
            if let Some(supplied) = supplied {
                body["password"] = json!(supplied);
            }
            let (status, answer) = accept(&f.daemon, None, &body);
            assert_eq!(status, 401, "{email} (password {supplied:?}): {answer}");
            assert_eq!(
                json_of(&answer)["code"],
                json!("hypervisor.org_invite_existing_principal_sign_in_required"),
                "{email}: {answer}"
            );
            assert!(
                session_token_of(&answer).is_none(),
                "{email}: no session: {answer}"
            );
        }
    }
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// A new email is still provisioned as a member and signed in (and the session counter sees it).
#[test]
fn d24_a_new_email_is_still_provisioned_and_signed_in() {
    let f = fixture();
    let before = stored_sessions(&f.data);
    let (status, answer) = accept(
        &f.daemon,
        None,
        &json!({ "invite_id": f.invite, "email": "new@example.test", "name": "New", "password": "d24-new-password-1" }),
    );
    assert_eq!(status, 200, "{answer}");
    let token = session_token_of(&answer)
        .unwrap_or_else(|| panic!("a session for the new member: {answer}"));
    assert!(!token.is_empty());
    assert_eq!(
        stored_sessions(&f.data),
        before + 1,
        "the new member's session is stored"
    );
}

/// An existing principal signed in as itself accepts the invite: it joins, and no new session is issued.
#[test]
fn d24_an_existing_principal_joins_by_an_authenticated_accept_as_itself() {
    let f = fixture();
    let member = login(&f.daemon, MEMBER);
    let before = stored_sessions(&f.data);
    let (status, answer) = accept(
        &f.daemon,
        Some(&member),
        &json!({ "invite_id": f.invite, "email": MEMBER.0 }),
    );
    assert_eq!(status, 200, "{answer}");
    let joined = json_of(&answer);
    assert_eq!(joined["ok"], json!(true), "{answer}");
    assert!(
        joined
            .get("membership_receipt")
            .is_some_and(|r| !r.is_null()),
        "the join is receipted: {answer}"
    );
    assert!(
        session_token_of(&answer).is_none(),
        "no new session: {answer}"
    );
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// An accept authenticated as one principal for another principal's email is refused, typed, with no session.
#[test]
fn d24_an_authenticated_accept_for_another_principal_is_refused() {
    let f = fixture();
    let member = login(&f.daemon, MEMBER);
    let before = stored_sessions(&f.data);
    for email in [ADMIN.0, OWNER.0] {
        let (status, answer) = accept(
            &f.daemon,
            Some(&member),
            &json!({ "invite_id": f.invite, "email": email }),
        );
        assert_eq!(status, 403, "{email}: {answer}");
        assert_eq!(
            json_of(&answer)["code"],
            json!("hypervisor.org_invite_principal_mismatch"),
            "{email}: {answer}"
        );
        assert!(
            session_token_of(&answer).is_none(),
            "{email}: no session: {answer}"
        );
    }
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}
