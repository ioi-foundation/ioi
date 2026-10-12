//! SSO sign-in identifies a principal by its verified IdP subject, never by an email claim alone.
//! The callback requires a signed id_token (no userinfo-only sign-in) whose email is verified; an
//! EXISTING principal is signed in only through an (issuer, subject) link it created while signed
//! in; a new principal is provisioned from a verified email and bound to its subject; and the
//! pending sign-in state expires. Through the REAL daemon and a loopback test IdP, inside
//! `unshare -rn`, every path under one temp dir.

use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        // The sign-in start seals its PKCE verifier; a non-test daemon build seals only with an
        // explicit custody passphrase.
        .env("IOI_WALLET_SECRET_PASS", "ioi-oidc-identity-binding-test")
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

const OWNER: (&str, &str) = ("owner@example.test", "oidc-owner-password-1");
const CLIENT_ID: &str = "s1-oidc-test-client";

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

/// What the test IdP's token endpoint answers for one authorization code.
#[derive(Clone)]
enum TokenAnswer {
    /// A signed id_token carrying these claims (iss, aud, exp and iat are added).
    IdToken(Value),
    /// No id_token; the userinfo endpoint answers these claims for the access token.
    UserinfoOnly(Value),
}

/// A loopback OpenID provider: discovery, JWKS, token and userinfo endpoints, signing RS256 with a
/// key generated for this test by the openssl CLI.
struct Idp {
    issuer: String,
    answers: Arc<Mutex<HashMap<String, TokenAnswer>>>,
}

fn rsa_key(dir: &Path) -> (Vec<u8>, String) {
    let key = dir.join("idp-key.pem");
    let status = Command::new("openssl")
        .args(["genrsa", "-traditional", "-out"])
        .arg(&key)
        .arg("2048")
        .stderr(Stdio::null())
        .status()
        .expect("run openssl genrsa");
    assert!(status.success(), "openssl genrsa");
    let out = Command::new("openssl")
        .args(["rsa", "-noout", "-modulus", "-in"])
        .arg(&key)
        .output()
        .expect("run openssl rsa -modulus");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let modulus = text.trim().trim_start_matches("Modulus=");
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(hex::decode(modulus).expect("a hex modulus"));
    (std::fs::read(&key).unwrap(), n)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn respond(stream: &mut TcpStream, body: &Value) {
    let text = body.to_string();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        )
        .as_bytes(),
    );
}

fn idp(dir: &Path) -> Idp {
    let (pem, n) = rsa_key(dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the IdP");
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let answers: Arc<Mutex<HashMap<String, TokenAnswer>>> = Arc::default();
    let userinfo: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
    let (iss, table) = (issuer.clone(), answers.clone());
    std::thread::spawn(move || {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&pem).expect("the IdP signing key");
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break bytes.len(),
                    Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&bytes[..head_end]).to_string();
            let length = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while bytes.len() < head_end + length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                }
            }
            let body = String::from_utf8_lossy(&bytes[head_end..]).to_string();
            let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            let path = target.split('?').next().unwrap_or("/");
            match path {
                "/.well-known/openid-configuration" => respond(
                    &mut stream,
                    &json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/authorize"),
                        "token_endpoint": format!("{iss}/token"),
                        "userinfo_endpoint": format!("{iss}/userinfo"),
                        "jwks_uri": format!("{iss}/jwks"),
                    }),
                ),
                "/jwks" => respond(
                    &mut stream,
                    &json!({ "keys": [{ "kty": "RSA", "kid": "s1-test-key", "use": "sig", "alg": "RS256", "n": n, "e": "AQAB" }] }),
                ),
                "/token" => {
                    let code = body
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("code="))
                        .unwrap_or_default()
                        .to_string();
                    let access = format!("at-{code}");
                    match table.lock().unwrap().get(&code).cloned() {
                        Some(TokenAnswer::IdToken(mut claims)) => {
                            claims["iss"] = json!(iss);
                            claims["aud"] = json!(CLIENT_ID);
                            claims["iat"] = json!(now_secs());
                            claims["exp"] = json!(now_secs() + 600);
                            let mut header =
                                jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                            header.kid = Some("s1-test-key".into());
                            let id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
                            respond(
                                &mut stream,
                                &json!({ "access_token": access, "token_type": "Bearer", "id_token": id_token }),
                            );
                        }
                        Some(TokenAnswer::UserinfoOnly(info)) => {
                            userinfo.lock().unwrap().insert(access.clone(), info);
                            respond(
                                &mut stream,
                                &json!({ "access_token": access, "token_type": "Bearer" }),
                            );
                        }
                        None => respond(&mut stream, &json!({ "error": "invalid_grant" })),
                    }
                }
                "/userinfo" => {
                    let access = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.trim()
                                .eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().trim_start_matches("Bearer ").to_string())
                        })
                        .unwrap_or_default();
                    let info = userinfo
                        .lock()
                        .unwrap()
                        .get(&access)
                        .cloned()
                        .unwrap_or(json!({}));
                    respond(&mut stream, &info);
                }
                _ => respond(&mut stream, &json!({ "error": "not_found" })),
            }
        }
    });
    Idp { issuer, answers }
}

struct Fixture {
    _dir: tempfile::TempDir,
    data: PathBuf,
    daemon: Daemon,
    owner: String,
    idp: Idp,
    sso_id: String,
}

/// A daemon with a bootstrapped owner and one active SSO configuration for the test IdP.
fn fixture() -> Fixture {
    assert_isolated_namespace();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(home.join(".config")).unwrap();
    let idp = idp(dir.path());
    let daemon = start_daemon(&data, &home);
    let owner = owner_session(&daemon);
    let (status, body) = http(
        daemon.port,
        "POST",
        "/v1/hypervisor/sso-configurations",
        Some(&owner),
        Some(&json!({ "issuer_url": idp.issuer, "client_id": CLIENT_ID })),
    );
    assert_eq!(status, 200, "test-setup SSO configuration: {body}");
    let sso_id = json_of(&body)["sso_configuration"]["sso_id"]
        .as_str()
        .unwrap_or_else(|| panic!("an sso id: {body}"))
        .to_string();
    Fixture {
        _dir: dir,
        data,
        daemon,
        owner,
        idp,
        sso_id,
    }
}

/// A started sign-in (or link): its state and the nonce the IdP must echo.
struct Started {
    state: String,
    nonce: String,
}

impl Fixture {
    /// POST /auth/oidc/start; `link` asks for a link of the session's principal.
    fn start(&self, session: Option<&str>, link: bool) -> (u16, Option<Started>, String) {
        let mut request = json!({ "config_id": self.sso_id });
        if link {
            request["link"] = json!(true);
        }
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/auth/oidc/start",
            session,
            Some(&request),
        );
        let answer = json_of(&body);
        let started = answer["authorize_url"].as_str().map(|url| Started {
            state: answer["state"].as_str().unwrap_or_default().to_string(),
            nonce: url
                .split(['?', '&'])
                .find_map(|pair| pair.strip_prefix("nonce="))
                .unwrap_or_default()
                .to_string(),
        });
        (status, started, body)
    }

    /// Answer `code` at the IdP with `answer`, then POST the callback for `started`.
    fn callback(&self, started: &Started, code: &str, answer: TokenAnswer) -> (u16, Value, String) {
        let answer = match answer {
            TokenAnswer::IdToken(mut claims) => {
                claims["nonce"] = json!(started.nonce);
                TokenAnswer::IdToken(claims)
            }
            other => other,
        };
        self.idp
            .answers
            .lock()
            .unwrap()
            .insert(code.to_string(), answer);
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/auth/oidc/callback",
            None,
            Some(&json!({ "state": started.state, "code": code })),
        );
        (status, json_of(&body), body)
    }

    /// A full sign-in: start, then the callback answered with `answer`.
    fn sign_in(&self, code: &str, answer: TokenAnswer) -> (u16, Value, String) {
        let (status, started, body) = self.start(None, false);
        let started = started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"));
        self.callback(&started, code, answer)
    }

    fn principals(&self) -> Vec<Value> {
        std::fs::read_dir(self.data.join("principals"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| std::fs::read(entry.path()).ok())
                    .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The principal id a session token resolves to (GET /auth/whoami).
    fn whoami(&self, session: &str) -> String {
        let (status, body) = http(
            self.daemon.port,
            "GET",
            "/v1/hypervisor/auth/whoami",
            Some(session),
            None,
        );
        let answer = json_of(&body);
        assert!(
            status == 200 && answer["authenticated"] == json!(true),
            "whoami resolves the session: {status} {body}"
        );
        answer["principal"]["principal_id"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn owner_id(&self) -> String {
        self.whoami(&self.owner)
    }
}

fn verified(sub: &str, email: &str) -> TokenAnswer {
    TokenAnswer::IdToken(
        json!({ "sub": sub, "email": email, "email_verified": true, "name": "Test User" }),
    )
}

fn session_of(answer: &Value) -> Option<String> {
    answer["session_token"]
        .as_str()
        .or_else(|| answer["session"]["session_token"].as_str())
        .map(str::to_string)
}

/// An id_token whose email is not verified signs no one in and provisions no one.
#[test]
fn oidc_refuses_an_unverified_email() {
    let f = fixture();
    let before = f.principals().len();
    for (code, claims) in [
        (
            "unverified-false",
            json!({ "sub": "sub-u1", "email": "new1@example.test", "email_verified": false }),
        ),
        (
            "unverified-absent",
            json!({ "sub": "sub-u2", "email": "new2@example.test" }),
        ),
    ] {
        let (status, answer, body) = f.sign_in(code, TokenAnswer::IdToken(claims));
        assert_ne!(status, 200, "{code}: refused: {body}");
        assert!(session_of(&answer).is_none(), "{code}: no session: {body}");
    }
    assert_eq!(f.principals().len(), before, "no principal was provisioned");
}

/// Without a signed id_token, the userinfo answer signs no one in, even a verified email.
#[test]
fn oidc_refuses_the_userinfo_only_path() {
    let f = fixture();
    let before = f.principals().len();
    let (status, answer, body) = f.sign_in(
        "userinfo-only",
        TokenAnswer::UserinfoOnly(
            json!({ "sub": "sub-i1", "email": "info@example.test", "email_verified": true }),
        ),
    );
    assert_ne!(status, 200, "refused: {body}");
    assert!(session_of(&answer).is_none(), "no session: {body}");
    assert_eq!(f.principals().len(), before, "no principal was provisioned");
}

/// A verified email claim naming an EXISTING principal (the owner) signs no one in without that
/// principal's link to the IdP subject.
#[test]
fn oidc_never_signs_in_an_existing_principal_by_email() {
    let f = fixture();
    let (status, answer, body) = f.sign_in("owner-by-email", verified("someone-else", OWNER.0));
    assert_eq!(status, 403, "an existing principal needs its link: {body}");
    assert!(session_of(&answer).is_none(), "no session: {body}");
}

/// The owner links its IdP subject while signed in; then that subject signs the owner in. A link
/// needs a session, and another subject carrying the owner's email still signs no one in.
#[test]
fn oidc_signs_in_an_existing_principal_through_its_authenticated_link() {
    let f = fixture();
    let (status, _, body) = f.start(None, true);
    assert_eq!(
        status, 401,
        "a link needs an authenticated principal: {body}"
    );
    let (status, started, body) = f.start(Some(&f.owner), true);
    let started = started.unwrap_or_else(|| panic!("a started link: {status} {body}"));
    let (status, answer, body) = f.callback(&started, "link-owner", verified("owner-sub", OWNER.0));
    assert_eq!(status, 200, "the link is stored: {body}");
    assert_eq!(
        answer["linked"],
        json!(true),
        "the callback reports the link: {body}"
    );
    assert!(
        session_of(&answer).is_none(),
        "a link issues no new session: {body}"
    );

    let (status, answer, body) = f.sign_in("owner-linked", verified("owner-sub", OWNER.0));
    assert_eq!(status, 200, "the linked subject signs in: {body}");
    let session = session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"));
    assert_eq!(f.whoami(&session), f.owner_id(), "as the owner");

    let (status, answer, body) = f.sign_in("owner-other-sub", verified("other-sub", OWNER.0));
    assert_eq!(
        status, 403,
        "another subject with the owner's email is refused: {body}"
    );
    assert!(session_of(&answer).is_none(), "no session: {body}");
}

/// A new verified email is provisioned as a member and bound to its subject: the same subject
/// signs the same principal in again, and another subject with that email is refused.
#[test]
fn oidc_provisions_a_new_principal_by_verified_email_and_binds_its_subject() {
    let f = fixture();
    let (status, answer, body) = f.sign_in("new-first", verified("new-sub", "new@example.test"));
    assert_eq!(status, 200, "a new verified email is provisioned: {body}");
    let first = f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}")));
    assert!(
        !first.is_empty() && first != f.owner_id(),
        "a new principal: {first}"
    );
    let (status, answer, body) = f.sign_in("new-again", verified("new-sub", "new@example.test"));
    assert_eq!(status, 200, "the bound subject signs in again: {body}");
    assert_eq!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        first,
        "as the same principal"
    );
    let (status, answer, body) =
        f.sign_in("new-other-sub", verified("other-sub", "new@example.test"));
    assert_eq!(
        status, 403,
        "another subject with that email is refused: {body}"
    );
    assert!(session_of(&answer).is_none(), "no session: {body}");
}

/// A pending sign-in older than its time-to-live is refused and consumed.
#[test]
fn oidc_pending_state_expires() {
    let f = fixture();
    let (status, started, body) = f.start(None, false);
    let started = started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"));
    let pending_dir = f.data.join("oauth-pending");
    let path = std::fs::read_dir(&pending_dir)
        .expect("the pending sign-in records")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            std::fs::read_to_string(path)
                .map(|text| text.contains(&started.state))
                .unwrap_or(false)
        })
        .expect("the pending record of this sign-in");
    let mut pending: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    pending["created_at"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
    let (status, answer, body) = f.callback(
        &started,
        "expired",
        verified("late-sub", "late@example.test"),
    );
    assert_ne!(status, 200, "an expired sign-in is refused: {body}");
    assert!(session_of(&answer).is_none(), "no session: {body}");
    assert!(!path.exists(), "the expired state is consumed");
}
