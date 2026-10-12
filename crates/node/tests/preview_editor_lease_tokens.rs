//! Port-preview and editor leases carry their own access token: returned once by the minter,
//! stored only as a hash, and distinct from the lease's grant id. The preview and editor proxies
//! take it only from the `x-ioi-lease` header or from the cookie their own exchange sets, never from
//! a URL. No URL, environment status or proxy event carries it, and the grant listing needs an
//! authenticated principal. The proxies forward no daemon session or lease credential upstream, on
//! any request; they serve only their own host name, a different site from the owner's UI; and the
//! daemon refuses a cross-origin state change. Through the REAL daemon, inside `unshare -rn`.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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

/// One raw HTTP/1.1 exchange; returns (status, head, body).
fn raw(port: u16, request: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_string()
    };
    (status, head.to_string(), body)
}

/// A request with extra headers (Connection: close); returns (status, head, body).
fn http_with(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (u16, String, String) {
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
    raw(port, &request)
}

/// A daemon request with an optional `Authorization: Bearer` session; returns (status, body).
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
    let (status, _, body) = http_with(port, method, path, &headers, body);
    (status, body)
}

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| json!({ "raw": body }))
}

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
            return None;
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

const OWNER: (&str, &str) = ("owner@example.test", "preview-owner-password-1");
const MEMBER: (&str, &str) = ("member@example.test", "preview-member-password-1");
const MARKER: &str = "preview-upstream-marker";

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

/// A loopback HTTP service standing in for the environment's preview target and for the editor
/// runtime: answers every request with MARKER and records each request head it received (and its
/// body, in `bodies`). It answers `Expect: 100-continue` with an interim 100 before reading the body,
/// reads a chunked body to its last chunk, and keeps a connection open for further requests unless a
/// request asks for `Connection: close`.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let record_bodies = bodies.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let record = record.clone();
            let record_bodies = record_bodies.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut pending: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let head_end = loop {
                        if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(at + 4);
                        }
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => pending.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let Some(head_end) = head_end else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&pending[..head_end]).to_string();
                    pending.drain(..head_end);
                    let lower = head.to_ascii_lowercase();
                    let path = lower
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    if lower.contains("\r\nupgrade: websocket") && path.starts_with("/ws-") {
                        // A WebSocket service for /ws-* paths: it switches with the RFC 6455
                        // example accept (/ws-bad-accept: a wrong one; /ws-early-hints: a 103
                        // first), then records every byte the client sends until it closes.
                        record.lock().unwrap().push(head);
                        if path.starts_with("/ws-early-hints") {
                            let _ = stream.write_all(
                                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
                            );
                        }
                        let accept = if path.starts_with("/ws-bad-accept") {
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAA="
                        } else {
                            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
                        };
                        let _ = stream.write_all(
                            format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes(),
                        );
                        let mut after = std::mem::take(&mut pending);
                        loop {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => after.extend_from_slice(&chunk[..n]),
                            }
                        }
                        record_bodies.lock().unwrap().push(after);
                        return;
                    }
                    if lower.contains("\r\nexpect: 100-continue") {
                        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    let body_len = if lower.contains("\r\ntransfer-encoding: chunked") {
                        // Through the last chunk ("0\r\n") and its trailer section's empty line.
                        loop {
                            let last = pending
                                .windows(4)
                                .position(|w| w == b"\n0\r\n")
                                .map(|at| at + 4)
                                .or_else(|| pending.starts_with(b"0\r\n").then_some(3));
                            if let Some(after) = last {
                                if pending[after..].starts_with(b"\r\n") {
                                    break after + 2;
                                }
                                if let Some(end) =
                                    pending[after..].windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    break after + end + 4;
                                }
                            }
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => pending.extend_from_slice(&chunk[..n]),
                            }
                        }
                    } else {
                        lower
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0)
                    };
                    while pending.len() < body_len {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body: Vec<u8> = pending.drain(..body_len).collect();
                    record.lock().unwrap().push(head);
                    record_bodies.lock().unwrap().push(body);
                    let close = lower.contains("\r\nconnection: close");
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{MARKER}",
                            MARKER.len(),
                            if close { "close" } else { "keep-alive" }
                        )
                        .as_bytes(),
                    );
                    if close {
                        return;
                    }
                }
            });
        }
    });
    Upstream { port, seen, bodies }
}

struct Fixture {
    _dir: tempfile::TempDir,
    data: PathBuf,
    home: PathBuf,
    daemon: Daemon,
    owner: String,
    member: String,
    env: String,
    upstream: Upstream,
}

/// A port preview: the minted token, its grant id (read from the environment record), and the
/// proxy's public port and URL.
struct Preview {
    token: String,
    grant_id: String,
    public_port: u16,
    url: String,
}

/// An exposed editor service: the lease's token (None when the minter returned none), its grant
/// id and ref, and the proxy's public port and open URL.
struct Editor {
    service_id: String,
    token: Option<String>,
    lease_id: String,
    lease_ref: String,
    public_port: u16,
    open_url: String,
    /// The stand-in runtime behind the editor (stopped when the test ends).
    _runtime: FakeRuntime,
}

/// A proxy's address: its TCP port and the host name its URL names (sent as `Host`).
struct ProxyAddr {
    port: u16,
    host: String,
}

impl ProxyAddr {
    fn from_url(url: &str, port: u16) -> ProxyAddr {
        let authority = url
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority);
        ProxyAddr {
            port,
            host: if host.is_empty() { "127.0.0.1" } else { host }.to_string(),
        }
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Preview {
    fn addr(&self) -> ProxyAddr {
        ProxyAddr::from_url(&self.url, self.public_port)
    }
}

impl Editor {
    fn addr(&self) -> ProxyAddr {
        ProxyAddr::from_url(&self.open_url, self.public_port)
    }
}

/// A daemon with a bootstrapped owner, an authenticated member, and one started environment the
/// owner owns, declaring the upstream's port.
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
    let member = login(&daemon, MEMBER);
    let upstream = upstream();
    let declared =
        json!([{ "port": upstream.port, "protocol": "tcp", "access_policy": "session_lease" }]);
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/environments",
        Some(&owner),
        Some(&json!({ "spec": { "declared_ports": declared } })),
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
    Fixture {
        _dir: dir,
        data,
        home,
        daemon,
        owner,
        member,
        env,
        upstream,
    }
}

impl Fixture {
    fn environment_record(&self) -> Value {
        serde_json::from_slice(
            &std::fs::read(
                self.data
                    .join("environments")
                    .join(format!("{}.json", self.env)),
            )
            .expect("the environment record"),
        )
        .expect("the environment record is JSON")
    }

    fn expose(&self) -> Preview {
        let (status, body) = http(
            self.daemon.port,
            "POST",
            &format!(
                "/v1/hypervisor/environments/{}/ports/{}/expose",
                self.env, self.upstream.port
            ),
            Some(&self.owner),
            Some(&json!({})),
        );
        let answer = json_of(&body);
        assert!(
            status == 200 && answer["ok"] == json!(true),
            "port expose: {status} {body}"
        );
        let row = self.environment_record()["status"]["ports"]
            .as_array()
            .and_then(|ports| {
                ports
                    .iter()
                    .find(|p| p["port"].as_u64() == Some(u64::from(self.upstream.port)))
                    .cloned()
            })
            .unwrap_or_else(|| panic!("the exposed port's status row"));
        Preview {
            token: answer["accessToken"]
                .as_str()
                .unwrap_or_else(|| panic!("an accessToken: {body}"))
                .to_string(),
            grant_id: row["capability_lease_ref"]
                .as_str()
                .unwrap_or_else(|| panic!("the row's lease: {row}"))
                .to_string(),
            public_port: answer["public_proxy_port"]
                .as_u64()
                .unwrap_or_else(|| panic!("a public proxy port: {body}"))
                as u16,
            url: answer["url"].as_str().unwrap_or_default().to_string(),
        }
    }

    /// Create an editor service, start its runtime (the stand-in for openvscode-server, on its
    /// unix socket), mint an editor lease and expose the service.
    fn editor(&self) -> Editor {
        let runtime = FakeRuntime(install_fake_editor_runtime(&self.home));
        let service_id = self.editor_service();
        let (status, body) = http(
            self.daemon.port,
            "POST",
            &format!("/v1/hypervisor/editor-services/{service_id}/start"),
            Some(&self.owner),
            Some(&json!({})),
        );
        assert!(
            status == 200 && json_of(&body)["ok"] == json!(true),
            "the editor runtime starts: {status} {body}"
        );
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/editor-access-leases",
            Some(&self.owner),
            Some(&json!({ "environment_id": self.env, "service_id": service_id })),
        );
        assert_eq!(status, 200, "editor lease: {body}");
        let lease = json_of(&body);
        let lease_id = lease["lease_id"].as_str().unwrap_or_default().to_string();
        let lease_ref = lease["lease_ref"].as_str().unwrap_or_default().to_string();
        let token = lease["access_token"].as_str().map(str::to_string);
        let (status, body) = http(
            self.daemon.port,
            "POST",
            &format!("/v1/hypervisor/editor-services/{service_id}/expose"),
            Some(&self.owner),
            Some(&json!({ "lease_id": lease_id })),
        );
        let exposed = json_of(&body);
        assert!(
            status == 200 && exposed["ok"] == json!(true),
            "editor expose: {status} {body}"
        );
        Editor {
            service_id,
            token,
            lease_id,
            lease_ref,
            public_port: exposed["public_proxy_port"]
                .as_u64()
                .unwrap_or_else(|| panic!("a public proxy port: {body}"))
                as u16,
            open_url: exposed["open_url"].as_str().unwrap_or_default().to_string(),
            _runtime: runtime,
        }
    }
}

/// GET `path` on a proxy's port, naming `host` (a test may name another host than the proxy's own).
fn proxy_get_as(port: u16, host: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let (status, _, body) = raw(port, &request);
    (status, body)
}

/// GET `path` on a proxy with `headers`; (status, body).
fn proxy_get(addr: &ProxyAddr, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    proxy_get_as(addr.port, &addr.authority(), path, headers)
}

/// POST the browser exchange form (`token=…`) to a proxy's port, naming `host`; (status, head).
fn exchange_as(port: u16, host: &str, token: &str) -> (u16, String) {
    let form = format!("token={token}");
    let (status, head, _) = raw(
        port,
        &format!(
            "POST /__ioi/lease HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
            form.len()
        ),
    );
    (status, head)
}

/// POST the browser exchange form (`token=…`) to a proxy; (status, head).
fn exchange(addr: &ProxyAddr, token: &str) -> (u16, String) {
    exchange_as(addr.port, &addr.authority(), token)
}

/// Assert a proxy refuses each (label, path, headers) case with 403 and never reaches the upstream.
fn assert_proxy_refuses(addr: &ProxyAddr, cases: &[(&str, String, Vec<(&str, String)>)]) {
    for (label, path, headers) in cases {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let (status, body) = proxy_get(addr, path, &headers);
        assert_eq!(status, 403, "{label} is refused at the proxy: {body}");
        assert!(!body.contains(MARKER), "{label} never reaches the upstream");
    }
}

/// The port-expose mint returns an access token that is not the lease's grant id and does not
/// contain it, has at least 32 hex digits, and is stored only as its SHA-256.
#[test]
fn port_preview_access_token_is_distinct_from_its_grant_id_and_stored_only_as_its_hash() {
    let f = fixture();
    let preview = f.expose();
    assert_ne!(
        preview.token, preview.grant_id,
        "the preview token is not the grant id"
    );
    assert!(
        !preview
            .token
            .contains(preview.grant_id.trim_start_matches("agr_")),
        "the preview token does not contain the grant id"
    );
    assert!(
        preview
            .token
            .chars()
            .filter(char::is_ascii_hexdigit)
            .count()
            >= 32,
        "the preview token has at least 32 hex digits: {}",
        preview.token
    );
    let grant = std::fs::read_to_string(
        f.data
            .join("authority-grants")
            .join(format!("{}.json", preview.grant_id)),
    )
    .expect("the preview lease's grant record");
    assert!(
        !grant.contains(&preview.token),
        "the grant record never holds the plaintext token"
    );
    assert!(
        grant.contains(&sha256_hex(&preview.token)),
        "the grant record holds the token's SHA-256"
    );
}

/// The preview proxy admits the token in the `x-ioi-lease` header and refuses no credential, the
/// grant id, the grant ref, the stored hash, and any token in a query string.
#[test]
fn port_preview_proxy_takes_the_token_only_in_the_lease_header() {
    let f = fixture();
    let preview = f.expose();
    let grant_ref = format!("enterprise.authority://grant/{}", preview.grant_id);
    let (status, body) = proxy_get(
        &preview.addr(),
        "/",
        &[("x-ioi-lease", preview.token.as_str())],
    );
    assert_eq!(status, 200, "the token in the header is admitted: {body}");
    assert_eq!(body, MARKER, "the upstream answered");
    assert_eq!(
        f.upstream.seen.lock().unwrap().len(),
        1,
        "one admitted request reached the upstream"
    );
    assert_proxy_refuses(
        &preview.addr(),
        &[
            ("no credential", "/".into(), vec![]),
            (
                "the grant id in the header",
                "/".into(),
                vec![("x-ioi-lease", preview.grant_id.clone())],
            ),
            (
                "the grant ref in the header",
                "/".into(),
                vec![("x-ioi-lease", grant_ref)],
            ),
            (
                "the token hash in the header",
                "/".into(),
                vec![("x-ioi-lease", sha256_hex(&preview.token))],
            ),
            (
                "the token in the query",
                format!("/?lease={}", preview.token),
                vec![],
            ),
            (
                "the grant id in the query",
                format!("/?lease={}", preview.grant_id),
                vec![],
            ),
        ],
    );
    assert_eq!(
        f.upstream.seen.lock().unwrap().len(),
        1,
        "no refused request reached the upstream"
    );
}

/// The browser exchange: POST /__ioi/lease with the token as a form field answers 303 to `/` and
/// sets an HttpOnly, SameSite=Lax cookie for this proxy, which then admits the browser. A wrong
/// token or the grant id sets nothing, and the grant id as the cookie is refused.
#[test]
fn port_preview_exchange_sets_an_httponly_lease_cookie() {
    let f = fixture();
    let preview = f.expose();
    let (status, head) = exchange(&preview.addr(), &preview.token);
    assert_eq!(status, 303, "the exchange answers 303: {head}");
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("\r\nlocation: /\r\n"),
        "it redirects to /: {head}"
    );
    let cookie_name = format!("ioi_lease_{}", preview.public_port);
    let set_cookie = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap_or_else(|| panic!("a Set-Cookie: {head}"))
        .to_string();
    assert!(
        set_cookie.contains(&format!("{cookie_name}={}", preview.token)),
        "the cookie carries the token for this proxy: {set_cookie}"
    );
    for attribute in ["httponly", "samesite=lax", "path=/"] {
        assert!(
            set_cookie.to_ascii_lowercase().contains(attribute),
            "the cookie is {attribute}: {set_cookie}"
        );
    }
    let cookie = format!("{cookie_name}={}", preview.token);
    let (status, body) = proxy_get(&preview.addr(), "/", &[("Cookie", cookie.as_str())]);
    assert_eq!(status, 200, "the exchanged cookie is admitted: {body}");
    assert_eq!(body, MARKER);
    for (label, wrong) in [
        ("a wrong token", "ioi_lease_0000"),
        ("the grant id", preview.grant_id.as_str()),
    ] {
        let (status, head) = exchange(&preview.addr(), wrong);
        assert_eq!(status, 403, "{label} is refused at the exchange: {head}");
        assert!(
            !head.to_ascii_lowercase().contains("set-cookie"),
            "{label} sets no cookie: {head}"
        );
    }
    let grant_cookie = format!("{cookie_name}={}", preview.grant_id);
    assert_proxy_refuses(
        &preview.addr(),
        &[(
            "the grant id as the cookie",
            "/".into(),
            vec![("Cookie", grant_cookie)],
        )],
    );
}

/// The editor lease's minter returns an access token distinct from the lease id, stored only as its
/// hash. The editor proxy admits it by header or by its exchanged cookie, and refuses the lease id
/// and any token in a query string.
#[test]
fn editor_lease_access_token_is_distinct_and_taken_only_by_header_or_exchanged_cookie() {
    let f = fixture();
    let editor = f.editor();
    let token = editor
        .token
        .clone()
        .unwrap_or_else(|| panic!("the editor lease returns an access_token"));
    assert_ne!(
        token, editor.lease_id,
        "the editor token is not the lease id"
    );
    let grant = std::fs::read_to_string(
        f.data
            .join("authority-grants")
            .join(format!("{}.json", editor.lease_id)),
    )
    .expect("the editor lease's grant record");
    assert!(
        !grant.contains(&token),
        "the grant record never holds the plaintext token"
    );
    assert!(
        grant.contains(&sha256_hex(&token)),
        "the grant record holds the token's SHA-256"
    );
    let (status, body) = proxy_get(&editor.addr(), "/", &[("x-ioi-lease", token.as_str())]);
    assert_eq!(status, 200, "the token in the header is admitted: {body}");
    let (status, head) = exchange(&editor.addr(), &token);
    assert_eq!(status, 303, "the exchange answers 303: {head}");
    let cookie = format!("ioi_lease_{}={token}", editor.public_port);
    let (status, _) = proxy_get(&editor.addr(), "/", &[("Cookie", cookie.as_str())]);
    assert_eq!(status, 200, "the exchanged cookie is admitted");
    assert_proxy_refuses(
        &editor.addr(),
        &[
            (
                "the lease id in the header",
                "/".into(),
                vec![("x-ioi-lease", editor.lease_id.clone())],
            ),
            (
                "the lease ref in the header",
                "/".into(),
                vec![("x-ioi-lease", editor.lease_ref.clone())],
            ),
            (
                "the lease id in the query",
                format!("/?lease={}", editor.lease_id),
                vec![],
            ),
            ("the token in the query", format!("/?lease={token}"), vec![]),
        ],
    );
}

/// No URL the daemon answers, no environment status and no stored record (proxy events included)
/// carries a preview or editor token, or a lease in a query string.
#[test]
fn no_url_status_or_record_carries_a_preview_or_editor_token() {
    let f = fixture();
    let preview = f.expose();
    let editor = f.editor();
    let (status, _) = proxy_get(
        &preview.addr(),
        "/",
        &[("x-ioi-lease", preview.token.as_str())],
    );
    assert_eq!(status, 200, "the preview was used once");
    assert!(
        !preview.url.contains("lease="),
        "the preview URL carries no lease: {}",
        preview.url
    );
    let row = f.environment_record()["status"]["ports"].to_string();
    assert!(
        !row.contains("lease="),
        "the environment status carries no lease URL: {row}"
    );
    assert!(
        !editor.open_url.contains("lease="),
        "the editor URL carries no lease: {}",
        editor.open_url
    );
    let (status, body) = http(
        f.daemon.port,
        "GET",
        &format!(
            "/v1/hypervisor/editor-services/{}/open-url?lease_ref={}",
            editor.service_id, editor.lease_ref
        ),
        Some(&f.owner),
        None,
    );
    assert_eq!(status, 200, "open-url: {body}");
    assert!(
        !body.contains("lease="),
        "open-url carries no lease URL: {body}"
    );
    let mut tokens = vec![preview.token.clone()];
    tokens.extend(editor.token.clone());
    for token in &tokens {
        assert_eq!(
            files_containing(&f.data, token),
            Vec::<PathBuf>::new(),
            "no stored file carries a preview or editor token"
        );
    }
    for grant_id in [&preview.grant_id, &editor.lease_id] {
        assert_eq!(
            files_containing(&f.data, &format!("lease={grant_id}")),
            Vec::<PathBuf>::new(),
            "no stored file carries a lease URL"
        );
    }
}

/// GET /authority/grants needs an authenticated principal: an anonymous loopback read is refused.
#[test]
fn grant_listing_requires_an_authenticated_principal() {
    let f = fixture();
    let _preview = f.expose();
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/authority/grants",
        None,
        None,
    );
    assert_eq!(status, 401, "an anonymous listing is refused: {body}");
    assert!(
        !body.contains("agr_"),
        "an anonymous caller learns no grant: {body}"
    );
    for (who, session) in [("owner", &f.owner), ("member", &f.member)] {
        let (status, body) = http(
            f.daemon.port,
            "GET",
            "/v1/hypervisor/authority/grants",
            Some(session),
            None,
        );
        assert_eq!(status, 200, "{who} lists grants: {body}");
    }
}

/// A grant-listing reader cannot use any listed grant id, grant ref or stored hash at the preview
/// or editor proxy, by header, cookie or query.
#[test]
fn a_grant_listing_reader_cannot_use_any_listed_grant_at_a_proxy() {
    let f = fixture();
    let preview = f.expose();
    let editor = f.editor();
    let (status, body) = http(
        f.daemon.port,
        "GET",
        "/v1/hypervisor/authority/grants",
        Some(&f.member),
        None,
    );
    assert_eq!(status, 200, "the member lists grants: {body}");
    let mut candidates = Vec::new();
    for grant in json_of(&body)["grants"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        for member in ["grant_id", "grant_ref", "bearer_sha256"] {
            if let Some(value) = grant[member].as_str() {
                candidates.push(value.to_string());
            }
        }
    }
    assert!(
        candidates.contains(&preview.grant_id) && candidates.contains(&editor.lease_id),
        "the listing names both leases (so this check reads the right rows)"
    );
    for (port, addr) in [
        (preview.public_port, preview.addr()),
        (editor.public_port, editor.addr()),
    ] {
        let cases: Vec<(&str, String, Vec<(&str, String)>)> = candidates
            .iter()
            .flat_map(|value| {
                vec![
                    (
                        "a listed value in the header",
                        "/".to_string(),
                        vec![("x-ioi-lease", value.clone())],
                    ),
                    (
                        "a listed value as the cookie",
                        "/".to_string(),
                        vec![("Cookie", format!("ioi_lease_{port}={value}"))],
                    ),
                    (
                        "a listed value in the query",
                        format!("/?lease={value}"),
                        vec![],
                    ),
                ]
            })
            .collect();
        assert_proxy_refuses(&addr, &cases);
    }
}

/// Two requests on ONE client connection to a proxy (the first keep-alive); returns both raw answers.
fn two_requests_on_one_connection(addr: &ProxyAddr, first: &str, second: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream.write_all(first.as_bytes()).unwrap();
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    let first_answer = loop {
        let text = String::from_utf8_lossy(&answer).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let length = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if body.len() >= length {
                break text;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break String::from_utf8_lossy(&answer).to_string(),
            Ok(n) => answer.extend_from_slice(&chunk[..n]),
        }
    };
    let _ = stream.write_all(second.as_bytes());
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    (first_answer, String::from_utf8_lossy(&rest).to_string())
}

/// The preview proxy forwards no lease credential to the environment's service: not on the opening
/// request, and not on a second request on the same keep-alive connection. The application's own
/// cookie and query survive.
#[test]
fn the_upstream_never_sees_a_lease_credential_on_any_request() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let cookie = format!(
        "ioi_lease_{}={}; app=keep",
        preview.public_port, preview.token
    );
    let request = |path: &str, connection: &str| {
        format!(
            "GET {path}?lease={}&keep=1 HTTP/1.1\r\nHost: {}\r\nConnection: {connection}\r\nx-ioi-lease: {}\r\nCookie: {cookie}\r\n\r\n",
            preview.grant_id,
            addr.authority(),
            preview.token
        )
    };
    let (first_answer, _) = two_requests_on_one_connection(
        &addr,
        &request("/", "keep-alive"),
        &request("/second", "close"),
    );
    assert!(
        first_answer.starts_with("HTTP/1.1 200") && first_answer.contains(MARKER),
        "the first request is admitted and answered: {first_answer}"
    );
    let seen = f.upstream.seen.lock().unwrap().clone();
    assert!(!seen.is_empty(), "the upstream saw the admitted request");
    for head in &seen {
        let lower = head.to_ascii_lowercase();
        assert!(
            !head.contains(&preview.token),
            "the upstream never sees the lease token: {head}"
        );
        assert!(
            !lower.contains("ioi_lease_"),
            "no lease cookie upstream: {head}"
        );
        assert!(
            !lower.contains("x-ioi-lease"),
            "no lease header upstream: {head}"
        );
        let request_line = head.lines().next().unwrap_or_default();
        assert!(
            !request_line.contains("lease="),
            "no lease in the forwarded URL: {request_line}"
        );
        assert!(
            head.contains("app=keep"),
            "the application's own cookie survives: {head}"
        );
        assert!(
            request_line.contains("keep=1"),
            "the application's own query survives: {request_line}"
        );
    }
}

/// The proxy refuses any request that carries the owner's daemon session cookie, even with the
/// right lease token: on the opening request, and on a later request on an admitted keep-alive
/// connection. The upstream never sees it.
#[test]
fn the_proxy_refuses_any_request_carrying_the_owner_session() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let session_cookie = format!("ioi_session={}; app=keep", f.owner);
    let before = f.upstream.seen.lock().unwrap().len();
    let (status, body) = proxy_get(
        &addr,
        "/",
        &[("x-ioi-lease", token), ("Cookie", session_cookie.as_str())],
    );
    assert_eq!(
        status, 403,
        "an opening request carrying ioi_session is refused: {body}"
    );
    assert!(!body.contains(MARKER), "it never reaches the upstream");
    assert_eq!(
        f.upstream.seen.lock().unwrap().len(),
        before,
        "the upstream saw nothing"
    );
    let first = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nx-ioi-lease: {token}\r\n\r\n",
        addr.authority()
    );
    let second = format!(
        "GET /second HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nx-ioi-lease: {token}\r\nCookie: {session_cookie}\r\n\r\n",
        addr.authority()
    );
    let (first_answer, second_answer) = two_requests_on_one_connection(&addr, &first, &second);
    assert!(
        first_answer.starts_with("HTTP/1.1 200") && first_answer.contains(MARKER),
        "the first request (no session cookie) is admitted: {first_answer}"
    );
    assert!(
        !second_answer.contains(MARKER),
        "the later request carrying ioi_session is not answered by the upstream: {second_answer}"
    );
    let seen = f.upstream.seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        before + 1,
        "only the first request reached the upstream"
    );
    for head in &seen {
        assert!(
            !head.contains(&f.owner),
            "the upstream never sees the owner's session: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("ioi_session"),
            "no ioi_session cookie upstream: {head}"
        );
    }
}

/// Previews and editors are served on their own `*.localhost` host, a different site from the
/// owner's UI (127.0.0.1) and from each other; a request naming another host (the UI's site) is
/// refused even with the right token.
#[test]
fn preview_and_editor_hosts_are_separate_sites_and_serve_only_their_own_name() {
    let f = fixture();
    let preview = f.expose();
    let editor = f.editor();
    let (preview_host, editor_host) = (preview.addr().host, editor.addr().host);
    for (label, host) in [("preview", &preview_host), ("editor", &editor_host)] {
        assert!(
            host.ends_with(".localhost") && host.len() > ".localhost".len(),
            "the {label} is served on its own *.localhost name: {host}"
        );
    }
    assert_ne!(preview_host, editor_host, "each proxy has its own site");
    let before = f.upstream.seen.lock().unwrap().len();
    for host in [
        format!("127.0.0.1:{}", preview.public_port),
        format!("localhost:{}", preview.public_port),
        format!("{editor_host}:{}", preview.public_port),
    ] {
        let (status, body) = proxy_get_as(
            preview.public_port,
            &host,
            "/",
            &[("x-ioi-lease", preview.token.as_str())],
        );
        assert_ne!(status, 200, "Host {host} is refused: {body}");
        assert!(
            !body.contains(MARKER),
            "Host {host} never reaches the upstream"
        );
    }
    assert_eq!(
        f.upstream.seen.lock().unwrap().len(),
        before,
        "no request naming another host reached the upstream"
    );
    let (status, body) = proxy_get(
        &preview.addr(),
        "/",
        &[("x-ioi-lease", preview.token.as_str())],
    );
    assert_eq!(status, 200, "the proxy's own name is served: {body}");
}

/// The exchange sets its cookie only on the preview host (a host-only cookie, no Domain), and
/// refuses an exchange naming any other host.
#[test]
fn the_lease_exchange_sets_its_cookie_only_on_the_preview_host() {
    let f = fixture();
    let preview = f.expose();
    let (status, head) = exchange_as(
        preview.public_port,
        &format!("127.0.0.1:{}", preview.public_port),
        &preview.token,
    );
    assert_ne!(
        status, 303,
        "an exchange naming the UI's host is refused: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("set-cookie"),
        "it sets no cookie: {head}"
    );
    let (status, head) = exchange(&preview.addr(), &preview.token);
    assert_eq!(
        status, 303,
        "the exchange on the preview host answers 303: {head}"
    );
    let set_cookie = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        !set_cookie.is_empty(),
        "a cookie is set on the preview host: {head}"
    );
    assert!(
        !set_cookie.contains("domain="),
        "the cookie is host-only: {set_cookie}"
    );
}

/// A state-changing daemon request carrying the owner's session from another origin (a preview
/// site, or another loopback port) is refused and changes nothing; the same request from the
/// daemon's own origin, or from a client that sends no browser origin headers, is admitted.
#[test]
fn a_cross_origin_state_change_with_the_owner_session_is_refused() {
    let f = fixture();
    let preview = f.expose();
    let session_cookie = format!("ioi_session={}", f.owner);
    let preview_origin = format!("http://{}", preview.addr().authority());
    let other_port_origin = format!("http://127.0.0.1:{}", preview.public_port);
    let own_origin = format!("http://127.0.0.1:{}", f.daemon.port);
    let environments = || {
        std::fs::read_dir(f.data.join("environments"))
            .map(|entries| entries.count())
            .unwrap_or(0)
    };
    for (label, origin, fetch_site) in [
        ("a preview origin", preview_origin.as_str(), "cross-site"),
        (
            "another loopback port",
            other_port_origin.as_str(),
            "same-site",
        ),
    ] {
        let before = environments();
        let (status, _, body) = http_with(
            f.daemon.port,
            "POST",
            "/v1/hypervisor/environments",
            &[
                ("Cookie", session_cookie.as_str()),
                ("Origin", origin),
                ("Sec-Fetch-Site", fetch_site),
            ],
            Some(&json!({ "spec": {} })),
        );
        assert_eq!(
            status, 403,
            "{label}: a cross-origin state change is refused: {body}"
        );
        assert_eq!(environments(), before, "{label}: nothing was created");
    }
    for (label, headers) in [
        (
            "the daemon's own origin",
            vec![
                ("Cookie", session_cookie.as_str()),
                ("Origin", own_origin.as_str()),
                ("Sec-Fetch-Site", "same-origin"),
            ],
        ),
        (
            "a client with no browser origin headers",
            vec![("Cookie", session_cookie.as_str())],
        ),
    ] {
        let (status, _, body) = http_with(
            f.daemon.port,
            "POST",
            "/v1/hypervisor/environments",
            &headers,
            Some(&json!({ "spec": {} })),
        );
        assert_eq!(status, 200, "{label} is admitted: {body}");
    }
}

/// No request head the upstream recorded carries the lease token, a lease cookie, the lease header
/// or a lease query parameter.
fn assert_upstream_saw_no_lease_credential(f: &Fixture, preview: &Preview, label: &str) {
    for head in f.upstream.seen.lock().unwrap().iter() {
        let lower = head.to_ascii_lowercase();
        let request_line = lower.lines().next().unwrap_or_default().to_string();
        assert!(
            !head.contains(&preview.token),
            "{label}: the upstream never sees the lease token: {head}"
        );
        assert!(
            !lower.contains("ioi_lease_"),
            "{label}: no lease cookie upstream: {head}"
        );
        assert!(
            !lower.contains("x-ioi-lease"),
            "{label}: no lease header upstream: {head}"
        );
        assert!(
            !request_line.contains("lease="),
            "{label}: no lease query upstream: {request_line}"
        );
    }
}

/// Write `request` on a new connection to the proxy and read until the proxy closes it.
fn send_and_drain(addr: &ProxyAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).to_string()
}

/// An `Upgrade: websocket` request the upstream does not switch keeps HTTP framing: with no valid
/// WebSocket handshake, or with a handshake the upstream answers with anything but 101, a later
/// request on the same client connection never reaches the upstream unfiltered; neither do bytes
/// sent along with a handshake.
#[test]
fn an_unswitched_upgrade_keeps_http_framing_and_filtering() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let credentialed = |path: &str| {
        format!(
            "GET {path}?lease={token} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nx-ioi-lease: {token}\r\nCookie: ioi_lease_{}={token}\r\n\r\n",
            addr.authority(),
            preview.public_port
        )
    };
    let upgrade = |connection: &str, handshake: bool| {
        let mut request = format!(
            "GET /ws HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: {connection}\r\nx-ioi-lease: {token}\r\n",
            addr.authority()
        );
        if handshake {
            request.push_str(
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
            );
        }
        request.push_str("\r\n");
        request
    };
    let (first, _) = two_requests_on_one_connection(
        &addr,
        &upgrade("keep-alive", false),
        &credentialed("/after-an-upgrade-header"),
    );
    assert!(
        first.starts_with("HTTP/1.1 200") && first.contains(MARKER),
        "a request with an Upgrade header and no handshake is answered as plain HTTP: {first}"
    );
    assert_upstream_saw_no_lease_credential(&f, &preview, "after an Upgrade header");
    let (first, _) = two_requests_on_one_connection(
        &addr,
        &upgrade("Upgrade", true),
        &credentialed("/after-a-refused-upgrade"),
    );
    assert!(
        first.starts_with("HTTP/1.1 200"),
        "the upstream's answer other than 101 is relayed: {first}"
    );
    assert_upstream_saw_no_lease_credential(&f, &preview, "after a refused upgrade");
    let _ = send_and_drain(
        &addr,
        &format!(
            "{}{}",
            upgrade("Upgrade", true),
            credentialed("/pipelined-with-a-handshake")
        ),
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_upstream_saw_no_lease_credential(&f, &preview, "bytes sent with a handshake");
}

/// The proxy removes a `lease` query parameter whose name is percent-encoded, as a URL decoder reads
/// it; the application's own parameters survive.
#[test]
fn a_percent_encoded_lease_parameter_is_removed() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let before = f.upstream.seen.lock().unwrap().len();
    let (status, body) = proxy_get(
        &addr,
        &format!("/?%6cease={token}&%6C%65%61%73%65={token}&keep=1"),
        &[("x-ioi-lease", token)],
    );
    assert_eq!(status, 200, "the request is admitted: {body}");
    let seen = f.upstream.seen.lock().unwrap()[before..].to_vec();
    assert_eq!(seen.len(), 1, "one request reached the upstream: {seen:?}");
    let request_line = seen[0].lines().next().unwrap_or_default();
    assert!(
        !seen[0].contains(token),
        "an encoded lease parameter never reaches the upstream: {request_line}"
    );
    assert!(
        request_line.contains("keep=1"),
        "the application's own query survives: {request_line}"
    );
}

/// The lease exchange refuses a request carrying the owner's session cookie, as every other request
/// on the proxy is refused, and sets no cookie.
#[test]
fn the_lease_exchange_refuses_a_request_carrying_the_owner_session() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let form = format!("token={}", preview.token);
    let (status, head, _) = raw(
        addr.port,
        &format!(
            "POST /__ioi/lease HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: ioi_session={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
            addr.authority(),
            f.owner,
            form.len()
        ),
    );
    assert_eq!(
        status, 403,
        "an exchange carrying ioi_session is refused: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("set-cookie"),
        "it sets no cookie: {head}"
    );
}

/// A chunked request body is forwarded once, intact, and nothing the client sends after it reaches
/// the upstream on that connection.
#[test]
fn a_chunked_request_body_is_forwarded_and_nothing_after_it() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let before = f.upstream.seen.lock().unwrap().len();
    let chunked_body = "4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
    let answer = send_and_drain(
        &addr,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\nx-ioi-lease: {token}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n{chunked_body}GET /after-the-body?lease={token} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nx-ioi-lease: {token}\r\n\r\n",
            authority = addr.authority()
        ),
    );
    assert!(
        answer.starts_with("HTTP/1.1 200") && answer.contains(MARKER),
        "the chunked request is forwarded and answered: {answer}"
    );
    std::thread::sleep(Duration::from_millis(500));
    let seen = f.upstream.seen.lock().unwrap()[before..].to_vec();
    let bodies = f.upstream.bodies.lock().unwrap()[before..].to_vec();
    assert_eq!(
        seen.len(),
        1,
        "only the chunked request reached the upstream: {seen:?}"
    );
    assert!(
        seen[0].starts_with("POST /upload "),
        "the chunked request: {}",
        seen[0]
    );
    assert_eq!(
        bodies[0],
        chunked_body.as_bytes(),
        "its chunked body arrived intact"
    );
    assert_upstream_saw_no_lease_credential(&f, &preview, "after a chunked body");
}

/// A client that waits for `100 Continue` before sending its body receives the upstream's interim
/// answer, then sends the body and receives the final answer.
#[test]
fn an_expect_100_continue_request_gets_the_interim_answer_before_its_body() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nx-ioi-lease: {token}\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
                addr.authority()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut interim = Vec::new();
    let mut chunk = [0u8; 1024];
    while !interim.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => interim.extend_from_slice(&chunk[..n]),
        }
    }
    let interim = String::from_utf8_lossy(&interim).to_string();
    assert!(
        interim.starts_with("HTTP/1.1 100"),
        "the interim 100 reaches the client before it sends the body: {interim:?}"
    );
    stream.write_all(b"hello").unwrap();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    let rest = String::from_utf8_lossy(&rest).to_string();
    assert!(
        format!("{interim}{rest}").contains("HTTP/1.1 200") && rest.contains(MARKER),
        "the final answer follows the body: {rest}"
    );
    assert_eq!(
        f.upstream
            .bodies
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default(),
        b"hello".to_vec(),
        "the body reached the upstream"
    );
}

/// The proxy forwards neither `Referer` nor `Origin`, on a plain request or a WebSocket handshake:
/// the site the owner followed a link from never reaches the environment's service.
#[test]
fn the_upstream_never_sees_the_referer_or_origin() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let ui_site = "h-0123456789abcdef.localhost";
    let before = f.upstream.seen.lock().unwrap().len();
    let (status, body) = proxy_get(
        &addr,
        "/page",
        &[
            ("x-ioi-lease", token),
            ("Referer", &format!("http://{ui_site}:4173/work/sessions")),
            ("Origin", &format!("http://{ui_site}:4173")),
        ],
    );
    assert_eq!(status, 200, "the request is admitted: {body}");
    let _ = send_and_drain(
        &addr,
        &format!(
            "GET /ws HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nx-ioi-lease: {token}\r\nOrigin: http://{ui_site}:4173\r\nReferer: http://{ui_site}:4173/\r\n\r\n",
            addr.authority()
        ),
    );
    std::thread::sleep(Duration::from_millis(500));
    let seen = f.upstream.seen.lock().unwrap()[before..].to_vec();
    assert_eq!(
        seen.len(),
        2,
        "both requests reached the upstream: {seen:?}"
    );
    for head in &seen {
        let lower = head.to_ascii_lowercase();
        assert!(
            !lower.contains("\r\nreferer:") && !lower.contains("\r\norigin:"),
            "no Referer or Origin upstream: {head}"
        );
        assert!(
            !head.contains(ui_site),
            "the UI's site never reaches the upstream: {head}"
        );
    }
}

/// The RFC 6455 example key; the stand-in upstream answers its accept value.
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// A WebSocket handshake to `path` on a proxy, with `extra` header lines, padded with an `X-Pad`
/// header to exactly `pad_to` bytes when given.
fn ws_handshake(
    addr: &ProxyAddr,
    path: &str,
    token: &str,
    extra: &str,
    pad_to: Option<usize>,
) -> String {
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\n{extra}Sec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\nx-ioi-lease: {token}\r\n",
        addr.authority()
    );
    match pad_to {
        Some(total) => {
            let fixed = head.len() + "X-Pad: \r\n\r\n".len();
            assert!(total > fixed, "room for the pad");
            format!("{head}X-Pad: {}\r\n\r\n", "a".repeat(total - fixed))
        }
        None => format!("{head}\r\n"),
    }
}

/// Read from `stream` until `done` holds for what was read, or 10 seconds pass.
fn read_until(stream: &mut TcpStream, done: impl Fn(&str) -> bool) -> String {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline && !done(&String::from_utf8_lossy(&got)) {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(_) => continue,
        }
    }
    String::from_utf8_lossy(&got).to_string()
}

/// The bytes the stand-in recorded after switching for the handshake whose path is `path`, once
/// the connection closed (waits up to 15 seconds).
fn bytes_after_switch(f: &Fixture, path: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let seen = f.upstream.seen.lock().unwrap().clone();
        let bodies = f.upstream.bodies.lock().unwrap().clone();
        if let Some(index) = seen
            .iter()
            .position(|head| head.starts_with(&format!("GET {path} ")))
        {
            if let Some(body) = bodies.get(index) {
                return body.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "the upstream recorded the switched connection for {path}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// After the upstream's 101, only valid client WebSocket frames reach it: a request appended to a
/// handshake padded to exactly 1,024 bytes (a read boundary) never does, and the connection closes;
/// a valid masked frame passes intact.
#[test]
fn a_switched_websocket_forwards_only_valid_client_frames() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    let appended = format!(
        "GET /after-the-handshake?lease={token} HTTP/1.1\r\nHost: {}\r\nx-ioi-lease: {token}\r\nConnection: close\r\n\r\n",
        addr.authority()
    );
    let handshake = ws_handshake(
        &addr,
        "/ws-switch-padded",
        token,
        "Connection: Upgrade\r\n",
        Some(1024),
    );
    assert_eq!(
        handshake.len(),
        1024,
        "the handshake is exactly 1,024 bytes"
    );
    stream
        .write_all(format!("{handshake}{appended}").as_bytes())
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("\r\n\r\n"));
    assert!(
        answer.starts_with("HTTP/1.1 101"),
        "the upstream switched: {answer}"
    );
    let _ = read_until(&mut stream, |_| false);
    drop(stream);
    let after = String::from_utf8_lossy(&bytes_after_switch(&f, "/ws-switch-padded")).to_string();
    assert!(
        !after.contains("after-the-handshake") && !after.contains(token),
        "a request after the handshake never reaches the upstream: {after:?}"
    );

    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .write_all(
            ws_handshake(
                &addr,
                "/ws-switch-frame",
                token,
                "Connection: Upgrade\r\n",
                None,
            )
            .as_bytes(),
        )
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("\r\n\r\n"));
    assert!(answer.starts_with("HTTP/1.1 101"), "switched: {answer}");
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x81u8, 0x80 | 5];
    frame.extend_from_slice(&mask);
    frame.extend(b"hello".iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    stream.write_all(&frame).unwrap();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = read_until(&mut stream, |_| false);
    assert_eq!(
        bytes_after_switch(&f, "/ws-switch-frame"),
        frame,
        "a valid masked client frame reaches the upstream intact"
    );
}

/// A 101 without the Sec-WebSocket-Accept the key requires does not switch the connection.
#[test]
fn a_101_without_the_matching_accept_is_refused() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .write_all(
            ws_handshake(
                &addr,
                "/ws-bad-accept",
                &preview.token,
                "Connection: Upgrade\r\n",
                None,
            )
            .as_bytes(),
        )
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("\r\n\r\n"));
    assert!(
        !answer.starts_with("HTTP/1.1 101"),
        "a 101 with the wrong accept is not relayed as a switch: {answer}"
    );
}

/// `Connection: keep-alive` followed by a second `Connection: Upgrade` is one combined list that
/// includes upgrade: the handshake still switches.
#[test]
fn a_combined_connection_list_still_upgrades() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .write_all(
            ws_handshake(
                &addr,
                "/ws-switch-combined",
                &preview.token,
                "Connection: keep-alive\r\nConnection: Upgrade\r\n",
                None,
            )
            .as_bytes(),
        )
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("\r\n\r\n"));
    assert!(
        answer.starts_with("HTTP/1.1 101"),
        "the combined list upgrades: {answer}"
    );
}

/// An informational answer (103 Early Hints) before the upstream's 101 does not end the upgrade.
#[test]
fn an_early_hints_answer_does_not_end_the_upgrade() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .write_all(
            ws_handshake(
                &addr,
                "/ws-early-hints",
                &preview.token,
                "Connection: Upgrade\r\n",
                None,
            )
            .as_bytes(),
        )
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("HTTP/1.1 101"));
    assert!(
        answer.contains("HTTP/1.1 101"),
        "the 101 follows the 103: {answer}"
    );
}

/// The trailer section of a chunked body carries no lease credential, daemon cookie, Referer or
/// Origin upstream.
#[test]
fn chunked_trailers_carry_no_credential_upstream() {
    let f = fixture();
    let preview = f.expose();
    let addr = preview.addr();
    let token = preview.token.as_str();
    let before = f.upstream.bodies.lock().unwrap().len();
    let answer = send_and_drain(
        &addr,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nx-ioi-lease: {token}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\nx-ioi-lease: {token}\r\nCookie: ioi_session={owner}\r\nReferer: http://h-0123456789abcdef.localhost:4173/\r\nOrigin: http://h-0123456789abcdef.localhost:4173\r\n\r\n",
            authority = addr.authority(),
            owner = f.owner
        ),
    );
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the request is answered: {answer}"
    );
    let bodies = f.upstream.bodies.lock().unwrap()[before..].to_vec();
    assert_eq!(bodies.len(), 1, "one body reached the upstream");
    let body = String::from_utf8_lossy(&bodies[0]).to_string();
    assert!(body.contains("wiki"), "the body arrived: {body:?}");
    for leaked in [token, f.owner.as_str(), "h-0123456789abcdef"] {
        assert!(
            !body.contains(leaked),
            "no credential or site name in the trailers upstream: {body:?}"
        );
    }
}

/// A stand-in for openvscode-server at the daemon's toolchain path, modelling the pinned server's
/// observable contract: it listens on `--socket-path` (a unix socket) or `--host`/`--port`; reads
/// its token from `--connection-token-file`; prints the real startup line
/// (`Web UI available at http://localhost:<port>?tkn=<TOKEN>`; the real server prints it only on a
/// TCP port, the stand-in also on a socket so the log redaction is exercised end to end); answers
/// /version without a token; redirects `?tkn=<token>` with 302 and `Set-Cookie: vscode-tkn=...`;
/// answers a request with the `vscode-tkn` cookie 200 with `Set-Cookie: vscode-tkn=<TOKEN>;
/// Max-Age=604800; SameSite=Lax` (not HttpOnly), else 403; and on a WebSocket requires the FIRST
/// message to be `{"type":"auth","auth":"<TOKEN>"}`, answering `{"type":"sign",...}` or the real
/// refusal texts. It records its arguments, token, pid and each request in a JSON-lines file.
fn install_fake_editor_runtime(home: &Path) -> PathBuf {
    let bin = home.join(".ioi/editor-toolchain/openvscode-server/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let record = bin.join("runtime-record.jsonl");
    let script = r#"#!/usr/bin/python3 -I
import base64, hashlib, http.server, json, os, socketserver, sys, urllib.parse
args = sys.argv[1:]
record = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runtime-record.jsonl")
def arg(name):
    return args[args.index(name) + 1] if name in args else None
token = None
if arg("--connection-token-file"):
    with open(arg("--connection-token-file")) as source:
        token = source.read().strip()
    if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "hold-token-file")):
        os.remove(arg("--connection-token-file"))
        os.mkdir(arg("--connection-token-file"))
        open(os.path.join(arg("--connection-token-file"), "held"), "w").close()
def note(entry):
    with open(record, "a") as out:
        out.write(json.dumps(entry) + "\n")
note({"pid": os.getpid(), "args": args, "token": token})
port = int(arg("--port")) if arg("--port") else 3000
print(f"Web UI available at http://localhost:{port}" + (f"?tkn={token}" if token else ""), flush=True)
def frame(text):
    data = text.encode()
    return bytes([0x81, len(data)]) + data
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *rest):
        pass
    def answer(self, status, body, extra=()):
        data = body.encode()
        self.send_response(status)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        cookies = dict(c.strip().split("=", 1) for c in cookie.split(";") if "=" in c)
        target = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(target.query)
        note({"path": self.path, "cookie": cookie})
        if target.path.startswith("/version"):
            socket_dir = os.path.dirname(arg("--socket-path") or "")
            swap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "swap-socket-dir")
            if socket_dir and os.path.exists(swap) and os.path.isdir(socket_dir):
                os.rename(socket_dir, socket_dir + ".moved")
                open(socket_dir, "w").close()
            return self.answer(200, "0123456789abcdef0123456789abcdef01234567")
        if "tkn" in query:
            if query["tkn"][0] != token:
                return self.answer(403, "Forbidden")
            rest = urllib.parse.urlencode([(k, v) for k, vs in query.items() if k != "tkn" for v in vs])
            return self.answer(302, "", [("Set-Cookie", f"vscode-tkn={query['tkn'][0]}; Max-Age=604800; SameSite=Lax"), ("Location", target.path + ("?" + rest if rest else ""))])
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key") or ""
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.wfile.write(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode())
            self.wfile.flush()
            head = self.rfile.read(2)
            length = head[1] & 0x7F
            if length == 126:
                length = int.from_bytes(self.rfile.read(2), "big")
            mask = self.rfile.read(4)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self.rfile.read(length)))
            try:
                first = json.loads(payload)
            except Exception:
                reply = "Malformed first message"
            else:
                if first.get("type") != "auth":
                    reply = "Invalid first message"
                elif token is not None and first.get("auth") != token:
                    reply = "Unauthorized client refused: auth mismatch"
                else:
                    reply = json.dumps({"type": "sign", "data": "challenge", "signedData": "signed"})
            note({"ws_first_message": payload.decode(errors="replace"), "reply": reply})
            self.wfile.write(frame(reply))
            self.wfile.flush()
            self.close_connection = True
            return
        if token is not None and cookies.get("vscode-tkn") == token:
            return self.answer(200, "<!doctype html><title>workbench</title>", [("Set-Cookie", f"vscode-tkn={token}; Max-Age=604800; SameSite=Lax")])
        return self.answer(403, "Forbidden")
class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
class TcpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
if arg("--socket-path"):
    UnixServer(arg("--socket-path"), Handler).serve_forever()
else:
    TcpServer((arg("--host") or "127.0.0.1", port), Handler).serve_forever()
"#;
    let path = bin.join("openvscode-server");
    std::fs::write(&path, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    record
}

/// Stops the stand-in runtime (its own process group) when the test ends.
struct FakeRuntime(PathBuf);

impl FakeRuntime {
    fn entries(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.0)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn starts(&self) -> Vec<Value> {
        self.entries()
            .into_iter()
            .filter(|entry| entry["args"].is_array())
            .collect()
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        for entry in self.entries() {
            if let Some(pid) = entry["pid"].as_i64() {
                let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
            }
        }
    }
}

impl Fixture {
    /// Create an editor service for the fixture's environment; its id.
    fn editor_service(&self) -> String {
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/editor-services",
            Some(&self.owner),
            Some(&json!({ "environment_id": self.env })),
        );
        assert_eq!(status, 200, "editor service create: {body}");
        json_of(&body)["editorService"]["service_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a service id: {body}"))
            .to_string()
    }

    /// Stop the daemon and start a new one on the same data.
    fn restart(&mut self) {
        let _ = self.daemon.child.kill();
        let _ = self.daemon.child.wait();
        self.daemon = start_daemon(&self.data, &self.home);
    }
}

/// A masked client text frame.
fn masked_text_frame(text: &str) -> Vec<u8> {
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    let payload = text.as_bytes();
    let mut frame = vec![0x81u8];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// The editor runtime listens only on a unix socket and requires its connection token: it is
/// started with --socket-path (no TCP port) and a token file (never without a token); the token is
/// redacted from the runtime's log and kept in no file; through the lease-authenticated proxy the
/// workbench answers and hands the browser its token cookie (as the real server does), and the
/// WebSocket's in-band auth with that token is answered with the server's sign message.
#[test]
fn the_editor_runtime_listens_only_on_a_unix_socket_and_requires_its_token() {
    let f = fixture();
    let runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let service_id = f.editor_service();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/start"),
        Some(&f.owner),
        Some(&json!({})),
    );
    assert!(
        status == 200 && json_of(&body)["ok"] == json!(true),
        "the editor runtime starts: {status} {body}"
    );
    let started = runtime
        .starts()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the runtime recorded its start"));
    let args: Vec<String> = started["args"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|arg| arg.as_str().map(str::to_string))
        .collect();
    for absent in ["--without-connection-token", "--port", "--host"] {
        assert!(
            !args.iter().any(|arg| arg == absent),
            "the runtime is not started with {absent}: {args:?}"
        );
    }
    for present in ["--socket-path", "--connection-token-file"] {
        assert!(
            args.iter().any(|arg| arg == present),
            "the runtime is started with {present}: {args:?}"
        );
    }
    let token = started["token"].as_str().unwrap_or_default().to_string();
    assert!(token.len() >= 32, "a long random token: {token:?}");
    let (_, logs) = http(
        f.daemon.port,
        "GET",
        &format!("/v1/hypervisor/editor-services/{service_id}/logs"),
        Some(&f.owner),
        None,
    );
    assert!(
        logs.contains("Web UI available at") && !logs.contains(&token),
        "the runtime's startup line reaches the log with its token redacted: {logs}"
    );
    assert!(
        files_containing(&f.data, &token).is_empty(),
        "no file under the daemon's data dir keeps the token"
    );

    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/editor-access-leases",
        Some(&f.owner),
        Some(&json!({ "environment_id": f.env, "service_id": service_id })),
    );
    assert_eq!(status, 200, "editor lease: {body}");
    let lease = json_of(&body);
    let access = lease["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let lease_id = lease["lease_id"].as_str().unwrap_or_default().to_string();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/expose"),
        Some(&f.owner),
        Some(&json!({ "lease_id": lease_id })),
    );
    let exposed = json_of(&body);
    assert!(
        status == 200 && exposed["ok"] == json!(true),
        "editor expose: {status} {body}"
    );
    let addr = ProxyAddr::from_url(
        exposed["open_url"].as_str().unwrap_or_default(),
        exposed["public_proxy_port"].as_u64().unwrap_or_default() as u16,
    );
    let (status, head, body) = raw(
        addr.port,
        &format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nx-ioi-lease: {access}\r\n\r\n",
            addr.authority()
        ),
    );
    assert_eq!(
        status, 200,
        "the workbench answers through the proxy: {head}"
    );
    assert!(body.contains("workbench"), "the workbench page: {body}");
    let cookie = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .starts_with("set-cookie: vscode-tkn=")
                .then(|| {
                    line["set-cookie: ".len()..]
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                })
        })
        .unwrap_or_else(|| panic!("the workbench hands the browser its token cookie: {head}"));

    let mut stream = TcpStream::connect(("127.0.0.1", addr.port)).expect("connect to the proxy");
    stream
        .write_all(
            ws_handshake(
                &addr,
                "/",
                &access,
                &format!("Connection: Upgrade\r\nCookie: {cookie}\r\n"),
                None,
            )
            .as_bytes(),
        )
        .unwrap();
    let answer = read_until(&mut stream, |got| got.contains("\r\n\r\n"));
    assert!(
        answer.starts_with("HTTP/1.1 101"),
        "the WebSocket switches: {answer}"
    );
    stream
        .write_all(&masked_text_frame(
            &json!({ "type": "auth", "auth": token }).to_string(),
        ))
        .unwrap();
    let reply = read_until(&mut stream, |got| {
        got.contains("sign") || got.contains("refused")
    });
    assert!(
        reply.contains("\"type\": \"sign\""),
        "the in-band auth with the browser's token is answered with the sign message: {reply:?}"
    );
}

/// Concurrent starts of one editor service launch ONE runtime. Every answer, and the record on disk
/// after all of them, is the started runtime's own view: ready on its socket, with its version and
/// its one start time, never a snapshot read before an earlier start committed.
#[test]
fn concurrent_starts_of_one_editor_service_launch_one_runtime() {
    let f = fixture();
    let runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let service_id = f.editor_service();
    let port = f.daemon.port;
    let owner = f.owner.clone();
    let handles: Vec<_> = (0..3)
        .map(|_| {
            let (owner, service_id) = (owner.clone(), service_id.clone());
            std::thread::spawn(move || {
                http(
                    port,
                    "POST",
                    &format!("/v1/hypervisor/editor-services/{service_id}/start"),
                    Some(&owner),
                    Some(&json!({})),
                )
            })
        })
        .collect();
    let answers: Vec<(u16, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (status, body) in &answers {
        assert!(
            *status == 200 && json_of(body)["ok"] == json!(true),
            "each start answers ready: {status} {body}"
        );
    }
    assert_eq!(
        runtime.starts().len(),
        1,
        "one runtime was launched: {:?}",
        runtime.starts()
    );
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(
            f.data
                .join("editor-services")
                .join(format!("{service_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let started_at = persisted["started_at"].clone();
    assert!(
        persisted["phase"] == json!("ready")
            && persisted["upstream"] == json!("unix_socket")
            && persisted["runtime_version"].is_string()
            && started_at.is_string()
            && persisted["readiness"]["mode"] == json!("full"),
        "the record on disk is the started runtime's view: {persisted}"
    );
    for (_, body) in &answers {
        let service = &json_of(body)["editorService"];
        assert!(
            service["upstream"] == json!("unix_socket")
                && service["runtime_version"] == persisted["runtime_version"]
                && service["started_at"] == started_at
                && service["readiness"]["mode"] == json!("full"),
            "each answer is the started runtime's view: {service}"
        );
    }
}

/// A daemon boot removes token handoff files and runtime sockets a crashed start left behind.
#[test]
fn boot_reconciliation_removes_stale_token_files_and_sockets() {
    let mut f = fixture();
    let services = f.data.join("editor-services");
    std::fs::create_dir_all(&services).unwrap();
    let stale_token = services.join("edsvc_stale.0123456789abcdef.connection-token");
    std::fs::write(&stale_token, "stale-token").unwrap();
    let stale_socket_dir = f.data.join("editor-sockets").join("0123456789abcdef");
    std::fs::create_dir_all(&stale_socket_dir).unwrap();
    std::fs::write(stale_socket_dir.join("s"), "").unwrap();
    f.restart();
    assert!(!stale_token.exists(), "the stale token file is removed");
    assert!(
        !stale_socket_dir.exists(),
        "the stale runtime socket is removed"
    );
}

/// A legacy editor-service record that names an internal TCP port but has no live runtime of this
/// daemon is never proxied over TCP: its expose is refused by name and binds no proxy, and a boot
/// marks the record unusable until the service is started again (on its socket).
#[test]
fn a_legacy_editor_record_is_never_proxied_over_tcp() {
    let mut f = fixture();
    let service_id = f.editor_service();
    let path = f
        .data
        .join("editor-services")
        .join(format!("{service_id}.json"));
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the editor service record"))
            .expect("the record is JSON");
    record["phase"] = json!("ready");
    record["internal_port"] = json!(f.upstream.port);
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/editor-access-leases",
        Some(&f.owner),
        Some(&json!({ "environment_id": f.env, "service_id": service_id })),
    );
    assert_eq!(status, 200, "editor lease: {body}");
    let lease_id = json_of(&body)["lease_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let before = f.upstream.seen.lock().unwrap().len();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/expose"),
        Some(&f.owner),
        Some(&json!({ "lease_id": lease_id })),
    );
    let answer = json_of(&body);
    assert!(
        answer["ok"] != json!(true) && answer["public_proxy_port"].is_null(),
        "a legacy record is not exposed: {status} {body}"
    );
    assert_eq!(
        answer["code"],
        json!("hypervisor.editor_runtime_not_live"),
        "refused by name: {body}"
    );
    assert_eq!(
        f.upstream.seen.lock().unwrap().len(),
        before,
        "nothing reached the TCP port"
    );
    f.restart();
    let record: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the editor service record"))
            .expect("the record is JSON");
    assert!(
        record["internal_port"].is_null() && record["phase"] != json!("ready"),
        "a boot marks the legacy record unusable: {record}"
    );
}

/// Stops a test-spawned stand-in runtime when the test ends.
struct Spawned(Child);

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How a stand-in runtime is grouped: in a new session (as the daemon's launcher did with setsid),
/// or as a job in the caller's session (its own process group, as a terminal starts a command).
#[derive(Clone, Copy, PartialEq)]
enum Grouping {
    NewSession,
    JobInCallersSession,
}

/// Start the stand-in openvscode-server on a loopback TCP port, as an older daemon (or the owner,
/// by hand) would have.
fn spawn_tcp_runtime(home: &Path, port: u16, extra: &[&str], grouping: Grouping) -> Spawned {
    let bin = home.join(".ioi/editor-toolchain/openvscode-server/bin/openvscode-server");
    let mut command = Command::new(bin);
    command
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    use std::os::unix::process::CommandExt;
    if grouping == Grouping::NewSession {
        // SAFETY: setsid in the forked child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        command.process_group(0);
    }
    let child = Spawned(command.spawn().expect("spawn the stand-in runtime"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the stand-in listens on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
    child
}

/// Write an editor-service record as a LEGACY one: ready on an internal TCP port.
fn make_legacy_record(f: &Fixture, service_id: &str, port: u16) {
    let path = f
        .data
        .join("editor-services")
        .join(format!("{service_id}.json"));
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the editor service record"))
            .expect("the record is JSON");
    record["phase"] = json!("ready");
    record["internal_port"] = json!(port);
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
}

/// A boot stops a legacy TCP editor runtime ONLY when this daemon launched it for that record: its
/// argv carries the record's extensions dir under this data dir, it runs as this uid, in its own
/// session (never a job in the owner's terminal session), on the port the record names. The same
/// binary run by hand without the marker, or with the marker as a job in the caller's session, is
/// not killed. Every legacy record is made unusable either way.
#[test]
fn boot_stops_only_a_legacy_editor_runtime_this_daemon_launched() {
    let mut f = fixture();
    let _runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let launched = f.editor_service();
    let unmarked = f.editor_service();
    let terminal = f.editor_service();
    let marker = |service: &str| {
        f.data
            .join("editor-services")
            .join(service)
            .join("extensions")
            .to_string_lossy()
            .to_string()
    };
    let launched_marker = marker(&launched);
    let terminal_marker = marker(&terminal);
    // Each port is taken by its stand-in before the next is chosen, so the three differ.
    let launched_port = free_port();
    let mut daemon_launched = spawn_tcp_runtime(
        &f.home,
        launched_port,
        &["--extensions-dir", &launched_marker],
        Grouping::NewSession,
    );
    let unmarked_port = free_port();
    let mut by_hand = spawn_tcp_runtime(&f.home, unmarked_port, &[], Grouping::NewSession);
    let terminal_port = free_port();
    let mut in_terminal_group = spawn_tcp_runtime(
        &f.home,
        terminal_port,
        &["--extensions-dir", &terminal_marker],
        Grouping::JobInCallersSession,
    );
    make_legacy_record(&f, &launched, launched_port);
    make_legacy_record(&f, &unmarked, unmarked_port);
    make_legacy_record(&f, &terminal, terminal_port);
    f.restart();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon_launched.0.try_wait().ok().flatten().is_none() {
        assert!(
            Instant::now() < deadline,
            "the legacy runtime this daemon launched is stopped"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        by_hand.0.try_wait().ok().flatten().is_none(),
        "the same binary run without the daemon's marker is not killed"
    );
    assert!(
        in_terminal_group.0.try_wait().ok().flatten().is_none(),
        "a runtime run as a job in the caller's session is not killed"
    );
    for service in [&launched, &unmarked, &terminal] {
        let record: Value = serde_json::from_slice(
            &std::fs::read(
                f.data
                    .join("editor-services")
                    .join(format!("{service}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            record["internal_port"].is_null() && record["phase"] != json!("ready"),
            "every legacy record is unusable: {record}"
        );
    }
}

/// Stops processes a test started outside its own children when the test ends.
struct KillPids(Vec<i32>);

impl Drop for KillPids {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        }
    }
}

/// Is `pid` a live (not zombie) process?
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rfind(')')
                .map(|end| stat[end + 1..].trim_start().starts_with(['Z', 'X']))
        })
        .is_some_and(|dead| !dead)
}

/// A boot never stops a process group whose leader it cannot read and verify. Here a terminal-free
/// setsid wrapper that is not this daemon's launch started a runtime carrying the record's marker on
/// the record's port, plus an unrelated sibling, and exited. Nothing in that group is killed; the
/// legacy record is still made unusable.
#[test]
fn boot_never_stops_a_group_whose_leader_is_gone() {
    let mut f = fixture();
    let _runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let service = f.editor_service();
    let marker = f
        .data
        .join("editor-services")
        .join(&service)
        .join("extensions");
    let port = free_port();
    let bin = f
        .home
        .join(".ioi/editor-toolchain/openvscode-server/bin/openvscode-server");
    let script = format!(
        "'{}' --host 127.0.0.1 --port {port} --extensions-dir '{}' </dev/null >/dev/null 2>&1 & echo $!; sleep 600 </dev/null >/dev/null 2>&1 & echo $!",
        bin.display(),
        marker.display()
    );
    let mut wrapper = Command::new("sh");
    wrapper
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid in the forked child before exec.
        unsafe {
            wrapper.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let out = wrapper.output().expect("the wrapper runs and exits");
    let pids: Vec<i32> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    let _group = KillPids(pids.clone());
    assert_eq!(pids.len(), 2, "the runtime and its sibling: {pids:?}");
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the runtime listens on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
    make_legacy_record(&f, &service, port);
    f.restart();
    for pid in &pids {
        assert!(
            alive(*pid),
            "{pid}, in a group whose leader is gone, is not killed"
        );
    }
    let record: Value = serde_json::from_slice(
        &std::fs::read(
            f.data
                .join("editor-services")
                .join(format!("{service}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        record["internal_port"].is_null() && record["phase"] != json!("ready"),
        "the legacy record is unusable: {record}"
    );
}

/// When the runtime's token handoff file cannot be removed at readiness, the start FAILS: the
/// runtime is stopped, the answer names the reason, nothing can be exposed, and the daemon logs a
/// SECURITY line. The secret never stays behind a success.
#[test]
fn a_token_file_that_cannot_be_removed_at_readiness_fails_the_start() {
    let f = fixture();
    let runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    std::fs::write(
        f.home
            .join(".ioi/editor-toolchain/openvscode-server/bin/hold-token-file"),
        "",
    )
    .unwrap();
    let service_id = f.editor_service();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/start"),
        Some(&f.owner),
        Some(&json!({})),
    );
    let answer = json_of(&body);
    assert!(
        answer["ok"] != json!(true)
            && answer["reason"] == json!("editor_runtime_token_not_removed"),
        "the start fails by name: {status} {body}"
    );
    for start in runtime.starts() {
        let pid = start["pid"].as_i64().unwrap_or_default() as i32;
        let deadline = Instant::now() + Duration::from_secs(10);
        while alive(pid) {
            assert!(Instant::now() < deadline, "the runtime {pid} is stopped");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/editor-access-leases",
        Some(&f.owner),
        Some(&json!({ "environment_id": f.env, "service_id": service_id })),
    );
    assert_eq!(status, 200, "editor lease: {body}");
    let lease_id = json_of(&body)["lease_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/expose"),
        Some(&f.owner),
        Some(&json!({ "lease_id": lease_id })),
    );
    let exposed = json_of(&body);
    assert!(
        exposed["ok"] == json!(false)
            && exposed["phase"] == json!("failed")
            && exposed["public_proxy_port"].is_null()
            && exposed["open_url"].is_null(),
        "nothing is exposed, by an explicit refusal: {status} {body}"
    );
    let log = std::fs::read_to_string(&f.daemon.log).unwrap_or_default();
    assert!(
        log.lines()
            .any(|line| line.starts_with("SECURITY") && line.contains(&service_id)),
        "the daemon logs a SECURITY line naming the service"
    );
}

/// A boot that cannot remove a token handoff file logs a SECURITY line and leaves that service
/// degraded; the service does not start while the file remains, and starts once it is gone.
#[test]
fn a_token_file_a_boot_cannot_remove_keeps_its_service_degraded() {
    let mut f = fixture();
    let _runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let service_id = f.editor_service();
    let held = f
        .data
        .join("editor-services")
        .join(format!("{service_id}.0123456789abcdef.connection-token"));
    std::fs::create_dir_all(&held).unwrap();
    std::fs::write(held.join("held"), "").unwrap();
    f.restart();
    let record: Value = serde_json::from_slice(
        &std::fs::read(
            f.data
                .join("editor-services")
                .join(format!("{service_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        record["phase"] == json!("degraded")
            && record["readiness"]["reason"] == json!("editor_runtime_token_not_removed"),
        "the service is degraded by name: {record}"
    );
    let log = std::fs::read_to_string(&f.daemon.log).unwrap_or_default();
    assert!(
        log.lines()
            .any(|line| line.starts_with("SECURITY") && line.contains(&service_id)),
        "the boot logs a SECURITY line naming the service"
    );
    let start = |f: &Fixture| {
        http(
            f.daemon.port,
            "POST",
            &format!("/v1/hypervisor/editor-services/{service_id}/start"),
            Some(&f.owner),
            Some(&json!({})),
        )
    };
    let (status, body) = start(&f);
    assert!(
        json_of(&body)["ok"] != json!(true)
            && json_of(&body)["reason"] == json!("editor_runtime_token_not_removed"),
        "no start while the token file remains: {status} {body}"
    );
    std::fs::remove_dir_all(&held).unwrap();
    let (status, body) = start(&f);
    assert!(
        status == 200 && json_of(&body)["ok"] == json!(true),
        "the service starts once the file is gone: {status} {body}"
    );
}

/// Editor service logs written before runtimes moved to private sockets can carry the runtime's
/// token in a `tkn=` URL parameter. A boot redacts every such value in the log files, and the logs
/// endpoint serves none of them.
#[test]
fn boot_redacts_connection_tokens_in_existing_editor_logs() {
    let mut f = fixture();
    let service_id = f.editor_service();
    let first = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let second = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let log_path = f
        .data
        .join("editor-services")
        .join(format!("{service_id}.log"));
    std::fs::write(
        &log_path,
        format!(
            "Web UI available at http://localhost:3000?tkn={first}\nExtension host agent started.\nopen http://127.0.0.1:3000/?folder=/w&tkn={second}&x=1\n"
        ),
    )
    .unwrap();
    f.restart();
    let on_disk = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !on_disk.contains(first) && !on_disk.contains(second),
        "no token value is left in the log file: {on_disk}"
    );
    assert_eq!(
        on_disk.matches("tkn=[redacted]").count(),
        2,
        "each value is redacted in place: {on_disk}"
    );
    assert!(
        on_disk.contains("Extension host agent started.") && on_disk.contains("&x=1"),
        "the rest of the log is kept: {on_disk}"
    );
    let (status, body) = http(
        f.daemon.port,
        "GET",
        &format!("/v1/hypervisor/editor-services/{service_id}/logs"),
        Some(&f.owner),
        None,
    );
    assert!(
        status == 200 && !body.contains(first) && !body.contains(second),
        "the logs endpoint serves no token value: {status} {body}"
    );
}

/// A boot redacts the `tkn=` values of an editor service log whose bytes are not all UTF-8; the
/// rest of the file, the non-UTF-8 byte included, is kept.
#[test]
fn boot_redacts_connection_tokens_in_a_log_that_is_not_utf8() {
    let mut f = fixture();
    let service_id = f.editor_service();
    let token = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let log_path = f
        .data
        .join("editor-services")
        .join(format!("{service_id}.log"));
    let mut bytes = format!("Web UI available at http://localhost:3000?tkn={token}\n").into_bytes();
    bytes.extend_from_slice(b"raw \xff byte\n");
    std::fs::write(&log_path, &bytes).unwrap();
    f.restart();
    let on_disk = std::fs::read(&log_path).unwrap();
    let find = |needle: &[u8]| on_disk.windows(needle.len()).any(|w| w == needle);
    assert!(
        !find(token.as_bytes()),
        "no token value is left in the log file: {}",
        String::from_utf8_lossy(&on_disk)
    );
    assert!(
        find(&b"tkn=[redacted]"[..]) && find(&b"raw \xff byte\n"[..]),
        "the value is redacted in place and the rest is kept: {}",
        String::from_utf8_lossy(&on_disk)
    );
}

/// The daemon log's SECURITY line names its service and what could not be removed.
fn security_line_naming(f: &Fixture, service_id: &str, what: &str) -> bool {
    std::fs::read_to_string(&f.daemon.log)
        .unwrap_or_default()
        .lines()
        .any(|line| {
            line.starts_with("SECURITY") && line.contains(service_id) && line.contains(what)
        })
}

/// When a failed start (its token file cannot be removed) also cannot remove the runtime's socket
/// directory, the SECURITY line reports that too.
#[test]
fn a_failed_start_reports_a_socket_directory_it_cannot_remove() {
    let f = fixture();
    let _runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    let bin = f.home.join(".ioi/editor-toolchain/openvscode-server/bin");
    std::fs::write(bin.join("hold-token-file"), "").unwrap();
    std::fs::write(bin.join("swap-socket-dir"), "").unwrap();
    let service_id = f.editor_service();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/start"),
        Some(&f.owner),
        Some(&json!({})),
    );
    assert_eq!(
        json_of(&body)["reason"],
        json!("editor_runtime_token_not_removed"),
        "the start fails by name: {status} {body}"
    );
    assert!(
        security_line_naming(&f, &service_id, "socket directory"),
        "the SECURITY line reports the socket directory"
    );
}

/// When stopping a runtime cannot remove its socket directory, the daemon logs a SECURITY line
/// naming the service.
#[test]
fn a_stop_reports_a_socket_directory_it_cannot_remove() {
    let f = fixture();
    let _runtime = FakeRuntime(install_fake_editor_runtime(&f.home));
    std::fs::write(
        f.home
            .join(".ioi/editor-toolchain/openvscode-server/bin/swap-socket-dir"),
        "",
    )
    .unwrap();
    let service_id = f.editor_service();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/start"),
        Some(&f.owner),
        Some(&json!({})),
    );
    assert!(
        status == 200 && json_of(&body)["ok"] == json!(true),
        "the runtime starts: {status} {body}"
    );
    let (status, body) = http(
        f.daemon.port,
        "POST",
        &format!("/v1/hypervisor/editor-services/{service_id}/stop"),
        Some(&f.owner),
        Some(&json!({})),
    );
    assert_eq!(status, 200, "the stop is answered: {body}");
    assert!(
        security_line_naming(&f, &service_id, "socket directory"),
        "the SECURITY line reports the socket directory"
    );
}
