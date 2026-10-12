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
                    if lower.contains("\r\nexpect: 100-continue") {
                        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    let body_len = if lower.contains("\r\ntransfer-encoding: chunked") {
                        loop {
                            if let Some(at) = pending.windows(5).position(|w| w == b"0\r\n\r\n") {
                                break at + 5;
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

    /// Create an editor service, advance its record to `ready` on the upstream's port (the one
    /// transition runtime provisioning makes), mint an editor lease and expose the service.
    fn editor(&self) -> Editor {
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/editor-services",
            Some(&self.owner),
            Some(&json!({ "environment_id": self.env })),
        );
        assert_eq!(status, 200, "editor service create: {body}");
        let service_id = json_of(&body)["editorService"]["service_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a service id: {body}"))
            .to_string();
        let path = self
            .data
            .join("editor-services")
            .join(format!("{service_id}.json"));
        let mut record: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the editor service record"))
                .expect("the record is JSON");
        record["phase"] = json!("ready");
        record["internal_port"] = json!(self.upstream.port);
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
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
