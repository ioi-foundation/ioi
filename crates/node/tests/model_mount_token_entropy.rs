//! BUILD-DELTA #36: the model-mount capability token is 256 random bits from the OS RNG, returned once and stored
//! only as a hash; its public token_id is independent of it; a token minted by the old derivation (a hash of
//! non-secret inputs) no longer authorizes; the expiry of a token is looked up by its token_id, never by a
//! presented value. Through the REAL daemon, inside `unshare -rn`, every path under one temp dir.

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

fn create_token(daemon: &Daemon, body: &Value) -> Value {
    let (status, text) = http(
        daemon.port,
        "POST",
        "/v1/model-mount/tokens",
        None,
        Some(body),
    );
    assert_eq!(status, 200, "token create: {text}");
    json_of(&text)
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn token_body() -> Value {
    json!({
        "audience": "hypervisor-session",
        "grant_id": "grant://wallet/capability",
        "allowed_scopes": ["server.logs:read"],
        "denied_scopes": [],
    })
}

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

#[test]
fn a_revoked_token_is_absent_from_the_listing_and_no_longer_authorizes() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let first = create_token(&daemon, &token_body());
    let second = create_token(&daemon, &token_body());
    let token = first["token"].as_str().unwrap().to_string();
    assert_eq!(logs_status(&daemon, &token), 200);
    let id = first["token_id"].as_str().unwrap();
    let (status, text) = http(
        daemon.port,
        "DELETE",
        &format!("/v1/model-mount/tokens/{id}"),
        None,
        None,
    );
    assert_eq!(status, 200, "{text}");
    let (_, listing) = http(daemon.port, "GET", "/v1/model-mount/tokens", None, None);
    let ids: Vec<String> = json_of(&listing)
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["token_id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        ids,
        vec![second["token_id"].as_str().unwrap().to_string()],
        "only the live token is listed: {listing}"
    );
    assert_eq!(
        logs_status(&daemon, &token),
        403,
        "a revoked token authorizes nothing"
    );
}

const LISTED_KEYS: &[&str] = &[
    "allowed_scopes",
    "audience",
    "created_at",
    "denied_scopes",
    "grant_id",
    "id",
    "object",
    "status",
    "token_id",
];

#[test]
fn the_token_listing_is_an_explicit_metadata_projection_without_the_hash() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let first = create_token(&daemon, &token_body());
    let second = create_token(&daemon, &token_body());
    let (status, text) = http(daemon.port, "GET", "/v1/model-mount/tokens", None, None);
    assert_eq!(status, 200, "{text}");
    let listing = json_of(&text);
    let items = listing.as_array().expect("the listing is an array");
    assert_eq!(items.len(), 2, "one entry per active token: {text}");
    for item in items {
        let mut keys: Vec<&str> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, LISTED_KEYS, "the exact metadata key set: {item}");
    }
    for made in [&first, &second] {
        assert!(
            !text.contains(made["token_hash"].as_str().unwrap()),
            "no token hash in the listing"
        );
        assert!(
            !text.contains(&made["token"].as_str().unwrap()[8..24]),
            "no part of a token in the listing"
        );
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

#[test]
fn two_creates_with_identical_inputs_give_different_tokens_and_ids() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let first = create_token(&daemon, &token_body());
    let second = create_token(&daemon, &token_body());
    let (t1, t2) = (
        first["token"].as_str().unwrap(),
        second["token"].as_str().unwrap(),
    );
    assert_ne!(t1, t2, "identical inputs must not give the same token");
    assert_ne!(first["token_id"], second["token_id"]);
    for token in [t1, t2] {
        let hex = token.strip_prefix("ioi_mnt_").expect("ioi_mnt_ prefix");
        assert_eq!(hex.len(), 64, "256 bits");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn the_public_token_id_shares_nothing_with_the_token() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let made = create_token(&daemon, &token_body());
    let token_hex = made["token"]
        .as_str()
        .unwrap()
        .strip_prefix("ioi_mnt_")
        .unwrap()
        .to_string();
    let id_hex = made["token_id"]
        .as_str()
        .unwrap()
        .strip_prefix("capability_token:")
        .unwrap()
        .to_string();
    assert!(!id_hex.is_empty());
    assert!(
        !token_hex.starts_with(&id_hex),
        "the id is not a prefix of the token"
    );
    assert!(
        !token_hex.contains(&id_hex[..id_hex.len().min(16)]),
        "no 16-hex run of the id appears in the token"
    );
    // The listing is public; it must not carry the token or a prefix of it.
    let (status, listing) = http(daemon.port, "GET", "/v1/model-mount/tokens", None, None);
    assert_eq!(status, 200);
    assert!(
        !listing.contains(&token_hex[..16]),
        "no part of the token is in the listing"
    );
}

#[test]
fn only_the_exact_token_authorizes_and_it_is_stored_only_as_a_hash() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let made = create_token(&daemon, &token_body());
    let token = made["token"].as_str().unwrap().to_string();
    assert_eq!(logs_status(&daemon, &token), 200);
    let mut wrong = token.clone();
    let last = wrong.pop().unwrap();
    wrong.push(if last == '0' { '1' } else { '0' });
    assert_eq!(logs_status(&daemon, &wrong), 403);
    assert_eq!(
        logs_status(&daemon, made["token_id"].as_str().unwrap()),
        403,
        "the public id is not a credential"
    );
    for entry in std::fs::read_dir(data.join("capability-tokens")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(
            !text.contains(&token),
            "the plaintext token is never stored"
        );
    }
}

#[test]
fn a_token_minted_by_the_old_derivation_no_longer_authorizes() {
    let (_dir, data, home) = fixture();
    let dir = data.join("capability-tokens");
    std::fs::create_dir_all(&dir).unwrap();
    // The shape the old derivation stored: a hash of a token that was itself a hash of non-secret inputs.
    let legacy_token = "ioi_mnt_00112233445566778899aabbccddeeff";
    let record = json!({
        "id": "capability_token_control:capability_token:legacy:0000000000000000",
        "record_id": "capability_token_control:capability_token:legacy:0000000000000000",
        "schema_version": "ioi.model_mount.capability_token_control.v1",
        "object": "ioi.model_mount_capability_token_control",
        "status": "planned",
        "operation_kind": "model_mount.capability_token.create",
        "token_id": "capability_token:0011223344556677",
        "token_hash": sha256_hex(legacy_token),
        "rust_core_boundary": "model_mount.capability_token",
        "capability_token_authority": {
            "audience": "hypervisor-session", "grant_id": "grant://legacy",
            "allowed_scopes": ["server.logs:read"], "denied_scopes": []
        },
        "planned_at": "2026-06-13T12:00:00.000Z",
    });
    std::fs::write(dir.join("legacy.json"), record.to_string()).unwrap();
    let daemon = start_daemon(&data, &home);
    assert_eq!(
        logs_status(&daemon, legacy_token),
        403,
        "an upgrade invalidates derived tokens"
    );
}

#[test]
fn a_token_is_refused_after_its_expiry() {
    let (_dir, data, home) = fixture();
    let daemon = start_daemon(&data, &home);
    let soon = {
        let at = std::time::SystemTime::now() + Duration::from_secs(4);
        let secs = at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        // RFC 3339 UTC from epoch seconds, without a date library.
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (mut y, mut d) = (1970u64, days);
        loop {
            let len = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                366
            } else {
                365
            };
            if d < len {
                break;
            }
            d -= len;
            y += 1;
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let months = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut m = 0;
        while d >= months[m] {
            d -= months[m];
            m += 1;
        }
        format!(
            "{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            m + 1,
            d + 1,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    };
    let mut body = token_body();
    body["expiresAt"] = json!(soon);
    let made = create_token(&daemon, &body);
    let token = made["token"].as_str().unwrap().to_string();
    assert_eq!(logs_status(&daemon, &token), 200, "valid before its expiry");
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(
        logs_status(&daemon, &token),
        403,
        "refused after its expiry"
    );
}
