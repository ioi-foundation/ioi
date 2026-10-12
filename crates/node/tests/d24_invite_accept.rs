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
    let auth: Vec<String> = token
        .map(|token| format!("Authorization: Bearer {token}"))
        .into_iter()
        .collect();
    http_with(port, method, path, &auth, body)
}

/// The same request with the caller's own header lines (e.g. Cookie, Authorization).
fn http_with(
    port: u16,
    method: &str,
    path: &str,
    header_lines: &[String],
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
    for line in header_lines {
        request.push_str(&format!("{line}\r\n"));
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

/// Opens and reads of the daemon's principals directory and its records, counted by inotify: every principal
/// lookup reads that directory, then each record in it.
struct PrincipalReads(i32);

impl PrincipalReads {
    fn watch(dir: &Path) -> Self {
        use std::os::unix::ffi::OsStrExt;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0, "inotify_init1");
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        let watch =
            unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS) };
        assert!(watch >= 0, "inotify_add_watch {}", dir.display());
        Self(fd)
    }

    /// Events since the last call (the queue is drained).
    fn take(&self) -> usize {
        let mut events = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return events;
            }
            let mut at = 0usize;
            while at < n as usize {
                let event: libc::inotify_event = unsafe {
                    std::ptr::read_unaligned(buf.as_ptr().add(at).cast::<libc::inotify_event>())
                };
                events += 1;
                at += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
            }
        }
    }
}

impl Drop for PrincipalReads {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// How many accounts the daemon has stored.
fn stored_principals(data_dir: &Path) -> usize {
    std::fs::read_dir(data_dir.join("principals"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|e| e == "json"))
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
    owner: String,
}

fn fixture() -> Fixture {
    fixture_env(&[])
}

fn fixture_env(extra: &[(&str, &str)]) -> Fixture {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let daemon = start_daemon_env(&data, &home, extra);
    let owner = owner_token(&daemon);
    create_principal(&daemon, &owner, ADMIN, "admin");
    create_principal(&daemon, &owner, MEMBER, "member");
    let invite = invite_id(&daemon, &owner);
    Fixture {
        _dir: dir,
        data,
        daemon,
        invite,
        owner,
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
    let member = whoami(&f.daemon, &token);
    assert_eq!(member["role"], json!("member"), "{member}");
    assert!(
        member["tenant_refs"]
            .as_array()
            .is_some_and(|refs| refs.contains(&json!("org://local"))),
        "the new member's organization membership exists: {member}"
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

/// The daemon's portal session exchange, configured for the impersonation test (an HS256 test secret).
const PORTAL_SECRET: &str = "d24-portal-exchange-test-secret-000000000000000000";
const PORTAL_ISSUER: &str = "surface://portal.test/d24";
const PORTAL_AUDIENCE: &str = "daemon://hypervisor/d24";
const PORTAL_ENV: [(&str, &str); 4] = [
    ("IOI_PORTAL_DAEMON_EXCHANGE_SECRET", PORTAL_SECRET),
    ("IOI_PORTAL_DAEMON_EXCHANGE_ISSUER", PORTAL_ISSUER),
    ("IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE", PORTAL_AUDIENCE),
    ("IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF", "org://local"),
];

fn whoami(daemon: &Daemon, token: &str) -> Value {
    let (status, body) = http(
        daemon.port,
        "GET",
        "/v1/hypervisor/auth/whoami",
        Some(token),
        None,
    );
    assert_eq!(status, 200, "whoami: {body}");
    json_of(&body)["principal"].clone()
}

/// A portal-exchanged session for `subject`, impersonated by `actor` when one is given.
fn portal_session(daemon: &Daemon, subject: &str, actor: Option<&str>) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut claims = json!({
        "iss": PORTAL_ISSUER,
        "aud": PORTAL_AUDIENCE,
        "sub": subject,
        "tenant_ref": "org://local",
        "source_identity_hash": format!("sha256:{}", "a".repeat(64)),
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "jti": format!("d24_portal_{}", "1".repeat(32)),
    });
    if let Some(actor) = actor {
        claims["act"] = json!(actor);
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some("ioi-portal-daemon-exchange+jwt".to_string());
    let assertion = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(PORTAL_SECRET.as_bytes()),
    )
    .unwrap();
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/auth/portal-session-exchange",
        None,
        Some(&json!({ "assertion": assertion })),
    );
    assert_eq!(status, 200, "test-setup portal exchange: {body}");
    session_token_of(&body).unwrap_or_else(|| panic!("an exchanged session: {body}"))
}

/// An accept by an impersonated session for its subject's email is refused, typed, with no session: the
/// subject is not the one acting.
#[test]
fn d24_an_impersonated_session_does_not_accept_for_its_subject() {
    let f = fixture_env(&PORTAL_ENV);
    let owner = whoami(&f.daemon, &f.owner);
    let owner_id = owner["principal_id"].as_str().unwrap();
    let admin = login(&f.daemon, ADMIN);
    let admin_id = whoami(&f.daemon, &admin)["principal_id"]
        .as_str()
        .unwrap()
        .to_string();
    let session = portal_session(&f.daemon, owner_id, Some(&admin_id));
    let resolved = whoami(&f.daemon, &session);
    assert_eq!(
        resolved["principal_id"],
        json!(owner_id),
        "the session's subject is the owner: {resolved}"
    );
    assert_eq!(resolved["is_impersonated"], json!(true), "{resolved}");
    let before = stored_sessions(&f.data);
    let (status, answer) = accept(
        &f.daemon,
        Some(&session),
        &json!({ "invite_id": f.invite, "email": OWNER.0 }),
    );
    assert_eq!(status, 403, "{answer}");
    assert_eq!(
        json_of(&answer)["code"],
        json!("hypervisor.org_invite_impersonated_session_refused"),
        "{answer}"
    );
    assert!(session_token_of(&answer).is_none(), "no session: {answer}");
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// A route-scoped session (the portal exchange's, not impersonated) for the owner never accepts the owner's
/// invite, whatever its scope lists: refused, typed, with no session, before and after its stored scope is
/// widened to name the accept route.
#[test]
fn d24_a_route_scoped_session_is_refused_whatever_its_scope() {
    let f = fixture_env(&PORTAL_ENV);
    let owner = whoami(&f.daemon, &f.owner);
    let owner_id = owner["principal_id"].as_str().unwrap();
    let session = portal_session(&f.daemon, owner_id, None);
    let resolved = whoami(&f.daemon, &session);
    assert_eq!(resolved["principal_id"], json!(owner_id), "{resolved}");
    assert!(resolved.get("is_impersonated").is_none(), "{resolved}");
    let before = stored_sessions(&f.data);
    for widened in [false, true] {
        if widened {
            widen_portal_session_scope(&f.data);
        }
        let (status, answer) = accept(
            &f.daemon,
            Some(&session),
            &json!({ "invite_id": f.invite, "email": OWNER.0 }),
        );
        assert_eq!(status, 403, "widened {widened}: {answer}");
        assert_eq!(
            json_of(&answer)["code"],
            json!("hypervisor.org_invite_scoped_session_refused"),
            "widened {widened}: {answer}"
        );
        assert!(
            session_token_of(&answer).is_none(),
            "widened {widened}: no session: {answer}"
        );
    }
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// Rewrite the stored portal-exchange session so its scope names the accept route (exactly and by prefix).
fn widen_portal_session_scope(data_dir: &Path) {
    let mut widened = 0;
    for entry in std::fs::read_dir(data_dir.join("sessions")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let mut session: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if session["source"] != json!("portal_exchange") {
            continue;
        }
        session["allowed_exact_routes"]
            .as_array_mut()
            .expect("a scoped session lists exact routes")
            .push(json!("/v1/hypervisor/org-invite/accept"));
        session["allowed_route_prefixes"] = json!(["/v1/hypervisor/"]);
        std::fs::write(&path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();
        widened += 1;
    }
    assert_eq!(
        widened, 1,
        "exactly one portal-exchange session was widened"
    );
}

/// A request presenting more than one credential is refused, typed (400), with no session and no join: two
/// session cookies in either order (in one Cookie header or two), or a cookie and a different bearer. A cookie
/// and the SAME bearer is one credential: it joins.
#[test]
fn d24_an_ambiguous_credential_is_refused() {
    let f = fixture_env(&PORTAL_ENV);
    let owner_id = whoami(&f.daemon, &f.owner)["principal_id"]
        .as_str()
        .unwrap()
        .to_string();
    let scoped = portal_session(&f.daemon, &owner_id, None);
    let member = login(&f.daemon, MEMBER);
    let before = stored_sessions(&f.data);
    let ambiguous: Vec<(&str, Vec<String>)> = vec![
        (
            "member then scoped",
            vec![format!(
                "Cookie: ioi_session={member}; ioi_session={scoped}"
            )],
        ),
        (
            "scoped then member",
            vec![format!(
                "Cookie: ioi_session={scoped}; ioi_session={member}"
            )],
        ),
        (
            "two Cookie headers",
            vec![
                format!("Cookie: ioi_session={member}"),
                format!("Cookie: ioi_session={scoped}"),
            ],
        ),
        (
            "cookie and a different bearer",
            vec![
                format!("Cookie: ioi_session={member}"),
                format!("Authorization: Bearer {scoped}"),
            ],
        ),
        (
            "two bearers",
            vec![
                format!("Authorization: Bearer {member}"),
                format!("Authorization: Bearer {scoped}"),
            ],
        ),
    ];
    for (case, lines) in &ambiguous {
        for email in [OWNER.0, MEMBER.0] {
            let (status, answer) = http_with(
                f.daemon.port,
                "POST",
                "/v1/hypervisor/org-invite/accept",
                lines,
                Some(&json!({ "invite_id": f.invite, "email": email })),
            );
            assert_eq!(status, 400, "{case} {email}: {answer}");
            assert_eq!(
                json_of(&answer)["code"],
                json!("hypervisor.ambiguous_request_identity"),
                "{case} {email}: {answer}"
            );
            assert!(
                session_token_of(&answer).is_none(),
                "{case} {email}: no session: {answer}"
            );
        }
    }
    let (status, answer) = http_with(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/org-invite/accept",
        &[
            format!("Cookie: ioi_session={member}"),
            format!("Authorization: Bearer {member}"),
        ],
        Some(&json!({ "invite_id": f.invite, "email": MEMBER.0 })),
    );
    assert_eq!(status, 200, "the same token as cookie and bearer: {answer}");
    assert_eq!(json_of(&answer)["joined"], json!(true), "{answer}");
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// An agent-held capability token is not a principal: its accept for an existing account is refused, typed,
/// with no session. The principal's own API token is that principal authenticating: it joins, with no session.
#[test]
fn d24_a_capability_token_is_refused_and_the_principals_own_api_token_joins() {
    let f = fixture();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/model-mount/tokens",
        Some(&f.owner),
        Some(&json!({ "audience": "d24-run", "allowed": ["*"] })),
    );
    assert_eq!(status, 200, "test-setup capability token: {body}");
    let capability = json_of(&body)["token"]
        .as_str()
        .unwrap_or_else(|| panic!("a capability token: {body}"))
        .to_string();
    let member = login(&f.daemon, MEMBER);
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/api-tokens",
        Some(&member),
        Some(&json!({ "description": "d24 member token" })),
    );
    assert_eq!(status, 200, "test-setup api token: {body}");
    let api_token = json_of(&body)["token"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("an api token: {body}"))
        .to_string();
    let before = stored_sessions(&f.data);
    for email in [OWNER.0, MEMBER.0] {
        let (status, answer) = accept(
            &f.daemon,
            Some(&capability),
            &json!({ "invite_id": f.invite, "email": email }),
        );
        assert_eq!(status, 401, "{email}: {answer}");
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
    let (status, answer) = accept(
        &f.daemon,
        Some(&api_token),
        &json!({ "invite_id": f.invite, "email": MEMBER.0 }),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(json_of(&answer)["joined"], json!(true), "{answer}");
    assert!(
        session_token_of(&answer).is_none(),
        "no new session: {answer}"
    );
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// The password rule applies only to a new account: a short password never blocks an existing account's join,
/// and a new email with one is refused before any account exists.
#[test]
fn d24_a_short_password_never_blocks_an_existing_accounts_join() {
    let f = fixture();
    let member = login(&f.daemon, MEMBER);
    let (status, answer) = accept(
        &f.daemon,
        Some(&member),
        &json!({ "invite_id": f.invite, "email": MEMBER.0, "password": "short" }),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(json_of(&answer)["joined"], json!(true), "{answer}");
    let principals = stored_principals(&f.data);
    let (status, answer) = accept(
        &f.daemon,
        None,
        &json!({ "invite_id": f.invite, "email": "short@example.test", "password": "short" }),
    );
    assert_eq!(status, 400, "{answer}");
    assert_eq!(
        json_of(&answer)["reason"],
        json!("password_too_short"),
        "{answer}"
    );
    assert_eq!(
        stored_principals(&f.data),
        principals,
        "no account was made"
    );
}

/// An inactive account's email is refused, typed, with no session.
#[test]
fn d24_an_inactive_account_is_refused() {
    let f = fixture();
    let member = login(&f.daemon, MEMBER);
    let member_id = whoami(&f.daemon, &member)["principal_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = http(
        f.daemon.port,
        "DELETE",
        &format!("/v1/hypervisor/principals/{member_id}"),
        Some(&f.owner),
        None,
    );
    assert_eq!(status, 200, "test-setup deactivate: {body}");
    let before = stored_sessions(&f.data);
    let (status, answer) = accept(
        &f.daemon,
        None,
        &json!({ "invite_id": f.invite, "email": MEMBER.0, "password": MEMBER.1 }),
    );
    assert_eq!(status, 409, "{answer}");
    assert_eq!(
        json_of(&answer)["code"],
        json!("hypervisor.org_invite_principal_inactive"),
        "{answer}"
    );
    assert!(session_token_of(&answer).is_none(), "no session: {answer}");
    assert_eq!(stored_sessions(&f.data), before, "no session was stored");
}

/// A rotated or unknown invite is refused before any account lookup: an existing email gets the invite
/// refusal (not the account's), and a new email makes no account. No session either way.
#[test]
fn d24_a_rotated_or_invalid_invite_is_refused_before_any_lookup() {
    // The background completer pass is slowed so that the principal-read counter below sees only this test's
    // requests.
    let f = fixture_env(&[("IOI_HYPERVISOR_GOVERNED_REPLAY_INTERVAL_MS", "300000")]);
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/org-invite",
        Some(&f.owner),
        Some(&json!({})),
    );
    assert_eq!(status, 200, "test-setup rotate: {body}");
    assert_ne!(
        json_of(&body)["invite"]["invite_id"],
        json!(f.invite),
        "{body}"
    );
    let sessions = stored_sessions(&f.data);
    let principals = stored_principals(&f.data);
    assert!(
        principals >= 3,
        "the counter sees the stored accounts ({principals})"
    );
    let reads = PrincipalReads::watch(&f.data.join("principals"));
    reads.take();
    for invite in [f.invite.as_str(), "inv_not_an_invite"] {
        for email in [OWNER.0, "rotated@example.test"] {
            let (status, answer) = accept(
                &f.daemon,
                None,
                &json!({ "invite_id": invite, "email": email, "password": "d24-new-password-1" }),
            );
            assert_eq!(status, 403, "{invite} {email}: {answer}");
            assert_eq!(
                json_of(&answer)["reason"],
                json!("invalid_or_expired_invite"),
                "{invite} {email}: {answer}"
            );
            assert_eq!(
                reads.take(),
                0,
                "{invite} {email}: no account was read before the invite was refused"
            );
        }
    }
    // The counter's own control: with the CURRENT invite, the same existing email is looked up (then refused).
    let current = json_of(&body)["invite"]["invite_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, answer) = accept(
        &f.daemon,
        None,
        &json!({ "invite_id": current, "email": OWNER.0 }),
    );
    assert_eq!(status, 401, "{answer}");
    assert!(
        reads.take() > 0,
        "the counter sees a principal lookup: {answer}"
    );
    assert_eq!(stored_sessions(&f.data), sessions, "no session was stored");
    assert_eq!(
        stored_principals(&f.data),
        principals,
        "no account was made"
    );
}
