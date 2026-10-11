//! The env-ops access token is a random secret, returned once by the ops-lease mint, stored only as
//! a hash, and distinct from the lease's grant id, which receipts and the audit trail cite. The
//! env-ops seam accepts the token and never the grant id; the lease resolve route takes the token
//! only in a header. Through the REAL daemon, inside `unshare -rn`, every path under one temp dir.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

const OWNER: (&str, &str) = ("owner@example.test", "env-ops-owner-password-1");
const MEMBER: (&str, &str) = ("member@example.test", "env-ops-member-password-1");

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

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Every regular file under `root` whose bytes contain `needle`.
fn files_containing(root: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file()
                && std::fs::read(&path)
                    .map(|bytes| {
                        bytes
                            .windows(needle.len())
                            .any(|window| window == needle.as_bytes())
                    })
                    .unwrap_or(false)
            {
                found.push(path);
            }
        }
    }
    found
}

struct Lease {
    token: String,
    lease_id: String,
    lease_ref: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    data: PathBuf,
    daemon: Daemon,
    owner: String,
    env: String,
    workspace: PathBuf,
}

impl Fixture {
    fn mint(&self) -> Lease {
        let (status, body) = http(
            self.daemon.port,
            "POST",
            &format!("/v1/hypervisor/environments/{}/ops-lease", self.env),
            Some(&self.owner),
            Some(&json!({})),
        );
        assert_eq!(status, 200, "ops-lease mint: {body}");
        let answer = json_of(&body);
        let field = |name: &str| {
            answer[name]
                .as_str()
                .unwrap_or_else(|| panic!("`{name}` in the mint answer: {body}"))
                .to_string()
        };
        Lease {
            token: field("accessToken"),
            lease_id: field("lease_id"),
            lease_ref: field("lease_ref"),
        }
    }

    fn ops(&self, method: &str, bearer: &str, body: &Value) -> (u16, String) {
        http(
            self.daemon.port,
            "POST",
            &format!(
                "/supervisor/{}/supervisor.v1.EnvironmentOpsService/{method}",
                self.env
            ),
            Some(bearer),
            Some(body),
        )
    }

    /// WriteFile `name` with `bearer`; returns the status and whether the file now exists.
    fn write_file(&self, bearer: &str, name: &str) -> (u16, bool) {
        let (status, _) = self.ops(
            "WriteFile",
            bearer,
            &json!({ "path": name, "content": "eA==" }),
        );
        (status, self.workspace.join(name).exists())
    }
}

/// A daemon with a bootstrapped owner, a second member, and one STARTED environment the owner owns.
fn fixture() -> Fixture {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let daemon = start_daemon(&data, &home);
    let owner = owner_session(&daemon);
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/principals",
        Some(&owner),
        Some(&json!({ "email": MEMBER.0, "password": MEMBER.1, "role": "member" })),
    );
    assert!(
        status == 200 || status == 201,
        "test-setup member: {status} {body}"
    );
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/environments",
        Some(&owner),
        Some(&json!({ "spec": {} })),
    );
    assert_eq!(status, 200, "test-setup environment: {body}");
    let env = json_of(&body)["environment"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("an environment id: {body}"))
        .to_string();
    let (status, body) = http(
        daemon.port,
        "POST",
        &format!("/v1/hypervisor/environments/{env}/start"),
        Some(&owner),
        Some(&json!({})),
    );
    assert_eq!(status, 200, "test-setup start: {body}");
    let record: Value = serde_json::from_slice(
        &std::fs::read(data.join("environments").join(format!("{env}.json")))
            .expect("the environment record"),
    )
    .expect("the environment record is JSON");
    let workspace = PathBuf::from(
        record["status"]["workspace_root"]
            .as_str()
            .unwrap_or_else(|| panic!("a workspace root: {record}")),
    );
    assert!(workspace.is_dir(), "the workspace exists: {workspace:?}");
    Fixture {
        _dir: dir,
        data,
        daemon,
        owner,
        env,
        workspace,
    }
}

/// The mint returns an access token that is not the grant id, does not contain it, carries at least
/// 128 bits (32 hex digits), differs per lease, and is stored only as its SHA-256.
#[test]
fn env_ops_access_token_is_a_random_secret_distinct_from_the_grant_id() {
    let f = fixture();
    let first = f.mint();
    let second = f.mint();
    for lease in [&first, &second] {
        assert_ne!(
            lease.token, lease.lease_id,
            "the access token is not the grant id"
        );
        let grant_digits = lease.lease_id.trim_start_matches("agr_");
        assert!(
            !lease.token.contains(grant_digits) && !lease.token.contains(&lease.lease_id),
            "the access token does not contain the grant id ({}): {}",
            lease.lease_id,
            lease.token
        );
        assert!(
            !lease.lease_ref.contains(&lease.token),
            "the lease ref does not carry the access token"
        );
        assert!(
            lease.token.chars().filter(char::is_ascii_hexdigit).count() >= 32,
            "the access token carries at least 128 bits: {}",
            lease.token
        );
        let grant_record = std::fs::read_to_string(
            f.data
                .join("authority-grants")
                .join(format!("{}.json", lease.lease_id)),
        )
        .expect("the lease's grant record");
        assert!(
            !grant_record.contains(&lease.token),
            "the grant record never holds the plaintext token"
        );
        assert!(
            grant_record.contains(&sha256_hex(&lease.token)),
            "the grant record holds the token's SHA-256"
        );
    }
    assert_ne!(first.token, second.token, "each lease has its own token");
}

/// No receipt, audit-trail row, grant listing or stored file carries the access token.
#[test]
fn env_ops_access_token_never_appears_in_receipts_the_trail_or_any_stored_file() {
    let f = fixture();
    let lease = f.mint();
    let member = login(&f.daemon, MEMBER);
    for (who, session) in [("member", &member), ("owner", &f.owner)] {
        let (status, trail) = http(
            f.daemon.port,
            "GET",
            "/v1/hypervisor/audit/trail?limit=500",
            Some(session),
            None,
        );
        assert_eq!(status, 200, "{who} reads the trail: {trail}");
        assert!(
            trail.contains(&lease.lease_id),
            "the trail cites the lease's grant id (so this check reads the right rows)"
        );
        assert!(
            !trail.contains(&lease.token),
            "{who}: the trail never carries the access token"
        );
    }
    let (status, grants) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/authority/grants",
        Some(&member),
        None,
    );
    assert_eq!(status, 200, "the grant listing: {grants}");
    assert!(
        !grants.contains(&lease.token),
        "the grant listing never carries the access token"
    );
    assert_eq!(
        files_containing(&f.data, &lease.token),
        Vec::<PathBuf>::new(),
        "no stored file (receipts, grants, logs) carries the access token"
    );
}

/// The env-ops seam admits the access token and refuses the grant id, the grant ref, the stored
/// hash, and a revoked lease's token, each proven by the absence of the file it would have written.
#[test]
fn env_ops_seam_accepts_the_access_token_and_never_the_grant_id() {
    let f = fixture();
    let lease = f.mint();
    let digest = sha256_hex(&lease.token);
    for (label, bearer) in [
        ("grant id", lease.lease_id.as_str()),
        ("grant ref", lease.lease_ref.as_str()),
        ("token hash", digest.as_str()),
    ] {
        let name = format!("refused-{}.txt", label.replace(' ', "-"));
        let (status, wrote) = f.write_file(bearer, &name);
        assert_eq!(status, 401, "the {label} is not an env-ops credential");
        assert!(!wrote, "the {label} wrote no file");
    }
    let (status, wrote) = f.write_file(&lease.token, "admitted.txt");
    assert_eq!(status, 200, "the access token is the env-ops credential");
    assert!(wrote, "the access token wrote its file");

    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/authority/revoke",
        Some(&f.owner),
        Some(&json!({ "grant_id": lease.lease_id })),
    );
    assert_eq!(status, 200, "revoke: {body}");
    let (status, wrote) = f.write_file(&lease.token, "after-revoke.txt");
    assert_eq!(status, 401, "a revoked lease's token is refused");
    assert!(!wrote, "a revoked lease's token wrote no file");
}

/// The resolve route answers only for the token presented in a header: a lease id or a token in the
/// URL path gets no lease answer, and a missing or wrong header gets 401 with no environment.
#[test]
fn ops_lease_resolve_takes_the_token_only_in_a_header() {
    let f = fixture();
    let lease = f.mint();
    for (label, segment) in [
        ("grant id", lease.lease_id.as_str()),
        ("access token", lease.token.as_str()),
    ] {
        let (status, body) = http(
            f.daemon.port,
            "GET",
            &format!("/v1/hypervisor/ops-lease/{segment}"),
            None,
            None,
        );
        let answer = json_of(&body);
        assert!(
            answer["active"] != json!(true) && !body.contains(&f.env),
            "a {label} in the URL path gets no lease answer: {status} {body}"
        );
    }
    let resolve = |headers: &[(&str, &str)]| {
        let (status, body) = http_with(
            f.daemon.port,
            "GET",
            "/v1/hypervisor/ops-lease",
            headers,
            None,
        );
        (status, json_of(&body), body)
    };
    let (status, answer, body) = resolve(&[("x-ioi-env-ops-token", lease.token.as_str())]);
    assert_eq!(status, 200, "the token in the header resolves: {body}");
    assert_eq!(answer["active"], json!(true), "{body}");
    assert_eq!(answer["environment_id"], json!(f.env), "{body}");
    let grant_bearer = format!("Bearer {}", lease.lease_id);
    for (label, headers) in [
        ("no header", vec![]),
        (
            "the grant id",
            vec![("x-ioi-env-ops-token", lease.lease_id.as_str())],
        ),
        (
            "the grant id as a bearer",
            vec![("Authorization", grant_bearer.as_str())],
        ),
    ] {
        let (status, answer, body) = resolve(&headers);
        assert_eq!(status, 401, "{label}: {body}");
        assert_ne!(answer["active"], json!(true), "{label}: {body}");
        assert!(
            !body.contains(&f.env),
            "{label} learns no environment: {body}"
        );
    }
}
