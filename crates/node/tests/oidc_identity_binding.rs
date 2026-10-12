//! SSO sign-in identifies a principal by its verified IdP subject, never by an email claim alone.
//! The callback requires a signed id_token (no userinfo-only sign-in) whose email is verified (the
//! JSON boolean true only); an EXISTING principal is signed in only through an (issuer, subject)
//! link it created while signed in; a new principal is provisioned from a verified email and bound
//! to its subject, compared exactly at its issuer; the pending state expires and is spent once,
//! before any identity changes; concurrent callbacks take effect once; a provisioning that fails at
//! a write is completed by the same subject's next sign-in, and its email is reserved meanwhile.
//! Through the REAL daemon and a loopback test IdP, inside `unshare -rn`, every path under one temp
//! dir.

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

fn start_daemon(data_dir: &Path, home: &Path, extra_env: &[(&str, &str)]) -> Daemon {
    for _attempt in 0..5 {
        if let Some(daemon) = try_start_daemon(data_dir, home, extra_env) {
            return daemon;
        }
    }
    panic!("the daemon did not come up on any of five ports");
}

fn try_start_daemon(data_dir: &Path, home: &Path, extra_env: &[(&str, &str)]) -> Option<Daemon> {
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
        .envs(extra_env.iter().copied())
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
    home: PathBuf,
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
    let daemon = start_daemon(&data, &home, &[]);
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
        home,
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
        self.start_for(&self.sso_id, session, link)
    }

    /// POST /auth/oidc/start for the SSO configuration `sso_id`.
    fn start_for(
        &self,
        sso_id: &str,
        session: Option<&str>,
        link: bool,
    ) -> (u16, Option<Started>, String) {
        let mut request = json!({ "config_id": sso_id });
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
        self.callback_as(started, code, answer, &self.idp, None)
    }

    /// The callback answered by `idp`, posted with an optional session of its own.
    fn callback_as(
        &self,
        started: &Started,
        code: &str,
        answer: TokenAnswer,
        idp: &Idp,
        session: Option<&str>,
    ) -> (u16, Value, String) {
        let answer = match answer {
            TokenAnswer::IdToken(mut claims) => {
                claims["nonce"] = json!(started.nonce);
                TokenAnswer::IdToken(claims)
            }
            other => other,
        };
        idp.answers.lock().unwrap().insert(code.to_string(), answer);
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/auth/oidc/callback",
            session,
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

    /// A full sign-in through the SSO configuration `sso_id`, whose IdP is `idp`.
    fn sign_in_for(
        &self,
        sso_id: &str,
        idp: &Idp,
        code: &str,
        answer: TokenAnswer,
    ) -> (u16, Value, String) {
        let (status, started, body) = self.start_for(sso_id, None, false);
        let started = started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"));
        self.callback_as(&started, code, answer, idp, None)
    }

    /// Another active SSO configuration (an optional email domain) for `issuer`.
    fn add_config(&self, issuer: &str, email_domain: Option<&str>) -> String {
        let mut request = json!({ "issuer_url": issuer, "client_id": CLIENT_ID });
        if let Some(domain) = email_domain {
            request["email_domain"] = json!(domain);
        }
        let (status, body) = http(
            self.daemon.port,
            "POST",
            "/v1/hypervisor/sso-configurations",
            Some(&self.owner),
            Some(&request),
        );
        assert_eq!(status, 200, "test-setup SSO configuration: {body}");
        json_of(&body)["sso_configuration"]["sso_id"]
            .as_str()
            .unwrap_or_else(|| panic!("an sso id: {body}"))
            .to_string()
    }

    /// Stop the daemon and start a new one on the same data, with `extra_env`.
    fn restart(&mut self, extra_env: &[(&str, &str)]) {
        let _ = self.daemon.child.kill();
        let _ = self.daemon.child.wait();
        self.daemon = start_daemon(&self.data, &self.home, extra_env);
    }

    /// The records of one family under the data dir.
    fn records(&self, family: &str) -> Vec<Value> {
        std::fs::read_dir(self.data.join(family))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                    .filter_map(|entry| std::fs::read(entry.path()).ok())
                    .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
                    .collect()
            })
            .unwrap_or_default()
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

/// The key of an (issuer, subject) pair: SHA-256 of the JCS form of `[issuer, subject]`.
fn subject_key(issuer: &str, subject: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(
        serde_jcs::to_vec(&[issuer, subject]).expect("JCS of two strings"),
    ))
}

/// The principal id an SSO provisioning of `key` creates.
fn provisioned_principal_id(key: &str) -> String {
    use sha2::Digest as _;
    let digest = hex::encode(sha2::Sha256::digest(format!("sso-principal\n{key}")));
    format!("usr_{}", &digest[..32])
}

fn emails_of(principals: &[Value], email: &str) -> usize {
    principals
        .iter()
        .filter(|p| p["email"].as_str() == Some(email))
        .count()
}

/// The subject is compared exactly (a subject padded with spaces is another subject) and only at
/// the issuer that bound it; the stored pair is the exact pair.
#[test]
fn oidc_compares_the_exact_subject_at_its_issuer() {
    let f = fixture();
    let (status, answer, body) = f.sign_in("exact", verified("exact-sub", "exact@example.test"));
    assert_eq!(status, 200, "provisioned: {body}");
    let first = f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}")));
    let (status, answer, body) = f.sign_in("padded", verified(" exact-sub ", "exact@example.test"));
    assert_eq!(
        status, 403,
        "a padded subject is another subject, and the email is taken: {body}"
    );
    assert!(session_of(&answer).is_none(), "no session: {body}");
    let bindings = f.records("sso-subject-links");
    assert!(
        bindings
            .iter()
            .any(|b| b["subject"] == json!("exact-sub") && b["issuer"] == json!(f.idp.issuer)),
        "the binding stores the exact pair: {bindings:?}"
    );
    std::fs::create_dir_all(f.data.join("idp2")).unwrap();
    let other = idp(&f.data.join("idp2"));
    let other_sso = f.add_config(&other.issuer, None);
    let (status, answer, body) = f.sign_in_for(
        &other_sso,
        &other,
        "other-issuer",
        verified("exact-sub", "exact@example.test"),
    );
    assert_eq!(
        status, 403,
        "the same subject at another issuer is not the bound identity: {body}"
    );
    assert!(session_of(&answer).is_none(), "no session: {body}");
    let (status, answer, body) = f.sign_in_for(
        &other_sso,
        &other,
        "other-issuer-new",
        verified("exact-sub", "exact2@example.test"),
    );
    assert_eq!(status, 200, "a new email there is provisioned: {body}");
    assert_ne!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        first,
        "as a different principal"
    );
}

/// Only the JSON boolean `true` verifies an email: the string "true", 1 and null do not.
#[test]
fn oidc_requires_email_verified_to_be_boolean_true() {
    let f = fixture();
    let before = f.principals().len();
    for (code, verified_claim) in [
        ("verified-string", json!("true")),
        ("verified-one", json!(1)),
        ("verified-null", Value::Null),
    ] {
        let (status, answer, body) = f.sign_in(
            code,
            TokenAnswer::IdToken(
                json!({ "sub": format!("sub-{code}"), "email": format!("{code}@example.test"), "email_verified": verified_claim }),
            ),
        );
        assert_ne!(status, 200, "{code}: refused: {body}");
        assert!(session_of(&answer).is_none(), "{code}: no session: {body}");
    }
    assert_eq!(f.principals().len(), before, "no principal was provisioned");
}

/// A configuration with an email domain provisions only emails in that domain.
#[test]
fn oidc_provisions_only_inside_a_nonempty_domain() {
    let f = fixture();
    std::fs::create_dir_all(f.data.join("idp-corp")).unwrap();
    let corp_idp = idp(&f.data.join("idp-corp"));
    let corp = f.add_config(&corp_idp.issuer, Some("corp.test"));
    let (status, answer, body) = f.sign_in_for(
        &corp,
        &corp_idp,
        "outside",
        verified("outside-sub", "x@other.test"),
    );
    assert_eq!(status, 403, "outside the domain: {body}");
    assert!(session_of(&answer).is_none(), "no session: {body}");
    let (status, answer, body) = f.sign_in_for(
        &corp,
        &corp_idp,
        "inside",
        verified("inside-sub", "y@corp.test"),
    );
    assert_eq!(status, 200, "inside the domain: {body}");
    assert!(session_of(&answer).is_some(), "a session: {body}");
}

/// A link binds the principal that STARTED it, whoever posts the callback (another principal's
/// session included).
#[test]
fn oidc_link_binds_the_principal_that_started_it() {
    let f = fixture();
    let (status, body) = http(
        f.daemon.port,
        "POST",
        "/v1/hypervisor/principals",
        Some(&f.owner),
        Some(
            &json!({ "email": "member@example.test", "password": "member-password-1", "name": "Member" }),
        ),
    );
    assert!(
        status == 200 || status == 201,
        "test-setup member: {status} {body}"
    );
    let member = login(&f.daemon, ("member@example.test", "member-password-1"));
    let (status, started, body) = f.start(Some(&f.owner), true);
    let started = started.unwrap_or_else(|| panic!("a started link: {status} {body}"));
    let (status, answer, body) = f.callback_as(
        &started,
        "swapped",
        verified("swapped-sub", OWNER.0),
        &f.idp,
        Some(&member),
    );
    assert_eq!(status, 200, "the link is stored: {body}");
    assert_eq!(
        answer["principal_id"].as_str(),
        Some(f.owner_id().as_str()),
        "for the principal that started it: {body}"
    );
    let (status, answer, body) = f.sign_in("swapped-in", verified("swapped-sub", OWNER.0));
    assert_eq!(status, 200, "the linked subject signs in: {body}");
    assert_eq!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        f.owner_id(),
        "as the owner, never the member"
    );
}

/// An expired link binds nothing.
#[test]
fn oidc_expired_link_binds_nothing() {
    let f = fixture();
    let (status, started, body) = f.start(Some(&f.owner), true);
    let started = started.unwrap_or_else(|| panic!("a started link: {status} {body}"));
    for entry in std::fs::read_dir(f.data.join("oauth-pending")).unwrap() {
        let path = entry.unwrap().path();
        let mut pending: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if pending["state"] == json!(started.state) {
            pending["created_at"] = json!("2020-01-01T00:00:00Z");
            std::fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
        }
    }
    let (status, _, body) = f.callback(&started, "late-link", verified("late-link-sub", OWNER.0));
    assert_ne!(status, 200, "an expired link is refused: {body}");
    assert!(
        f.records("sso-subject-links").is_empty(),
        "no binding was stored"
    );
    let (status, _, body) = f.sign_in("late-link-in", verified("late-link-sub", OWNER.0));
    assert_eq!(status, 403, "the subject is not linked: {body}");
}

/// A state that completed a sign-in is spent: replaying it with another code changes nothing.
#[test]
fn oidc_used_state_changes_nothing() {
    let f = fixture();
    let (status, started, body) = f.start(None, false);
    let started = started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"));
    let (status, _, body) = f.callback(
        &started,
        "first-use",
        verified("used-sub", "used@example.test"),
    );
    assert_eq!(status, 200, "the first use signs in: {body}");
    let (principals, bindings) = (f.principals().len(), f.records("sso-subject-links").len());
    let (status, answer, body) = f.callback(
        &started,
        "replayed",
        verified("replay-sub", "replay@example.test"),
    );
    assert_ne!(status, 200, "a replayed state is refused: {body}");
    assert!(session_of(&answer).is_none(), "no session: {body}");
    assert_eq!(f.principals().len(), principals, "no principal was added");
    assert_eq!(
        f.records("sso-subject-links").len(),
        bindings,
        "no binding was added"
    );
}

/// Callbacks for ONE state fired together take effect once. (At the pre-fix code this is a race,
/// so its RED is probabilistic; the replay test above is the deterministic one.)
#[test]
fn oidc_concurrent_callbacks_on_one_state_take_effect_once() {
    let f = fixture();
    let (status, started, body) = f.start(None, false);
    let started = started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"));
    let before = f.principals().len();
    for index in 0..6 {
        let mut claims = json!({ "sub": format!("burst-sub-{index}"), "email": format!("burst{index}@example.test"), "email_verified": true, "nonce": started.nonce });
        claims["name"] = json!("Burst");
        f.idp
            .answers
            .lock()
            .unwrap()
            .insert(format!("burst-{index}"), TokenAnswer::IdToken(claims));
    }
    let port = f.daemon.port;
    let state = started.state.clone();
    let handles: Vec<_> = (0..6)
        .map(|index| {
            let state = state.clone();
            std::thread::spawn(move || {
                http(
                    port,
                    "POST",
                    "/v1/hypervisor/auth/oidc/callback",
                    None,
                    Some(&json!({ "state": state, "code": format!("burst-{index}") })),
                )
            })
        })
        .collect();
    let answers: Vec<(u16, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let admitted = answers.iter().filter(|(status, _)| *status == 200).count();
    assert_eq!(admitted, 1, "exactly one callback is admitted: {answers:?}");
    assert_eq!(
        f.principals().len(),
        before + 1,
        "exactly one principal was provisioned"
    );
    assert_eq!(
        f.records("sso-subject-links").len(),
        1,
        "exactly one binding"
    );
}

/// Two subjects carrying one email, provisioned together, yield one principal and one binding.
/// (Probabilistic at the pre-fix code; the pre-seeded intent test is the deterministic RED.)
#[test]
fn oidc_two_subjects_with_one_email_are_provisioned_once() {
    let f = fixture();
    let starts: Vec<Started> = (0..2)
        .map(|_| {
            let (status, started, body) = f.start(None, false);
            started.unwrap_or_else(|| panic!("a started sign-in: {status} {body}"))
        })
        .collect();
    for (index, started) in starts.iter().enumerate() {
        f.idp.answers.lock().unwrap().insert(
            format!("twin-{index}"),
            TokenAnswer::IdToken(
                json!({ "sub": format!("twin-sub-{index}"), "email": "twin@example.test", "email_verified": true, "nonce": started.nonce }),
            ),
        );
    }
    let port = f.daemon.port;
    let handles: Vec<_> = starts
        .iter()
        .enumerate()
        .map(|(index, started)| {
            let state = started.state.clone();
            std::thread::spawn(move || {
                http(
                    port,
                    "POST",
                    "/v1/hypervisor/auth/oidc/callback",
                    None,
                    Some(&json!({ "state": state, "code": format!("twin-{index}") })),
                )
            })
        })
        .collect();
    let answers: Vec<(u16, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        answers.iter().filter(|(status, _)| *status == 200).count(),
        1,
        "one subject is provisioned, the other refused: {answers:?}"
    );
    assert_eq!(
        emails_of(&f.principals(), "twin@example.test"),
        1,
        "one principal carries the email"
    );
    assert_eq!(f.records("sso-subject-links").len(), 1, "one binding");
}

/// An unfinished provisioning (an intent whose identity has no binding yet) reserves its email:
/// another subject with that email is refused, and the intent's own subject completes it, as the
/// principal the intent names, whatever email its new token carries. An intent whose identity is
/// already bound reserves nothing.
#[test]
fn oidc_unfinished_provisioning_reserves_its_email_and_resumes_by_its_subject() {
    let f = fixture();
    let key = subject_key(&f.idp.issuer, "seeded-sub");
    let principal_id = provisioned_principal_id(&key);
    let intents = f.data.join("sso-provisioning-intents");
    std::fs::create_dir_all(&intents).unwrap();
    std::fs::write(
        intents.join(format!("spi_{key}.json")),
        serde_json::to_vec(&json!({
            "schema_version": "ioi.hypervisor.sso-provisioning-intent.v1", "key": key,
            "issuer": f.idp.issuer, "subject": "seeded-sub", "sso_id": f.sso_id,
            "principal_id": principal_id, "email": "seeded@example.test", "name": "Seeded",
            "created_at": "2026-10-12T00:00:00Z",
        }))
        .unwrap(),
    )
    .unwrap();
    let (status, answer, body) =
        f.sign_in("seeded-other", verified("other-sub", "seeded@example.test"));
    assert_eq!(
        status, 403,
        "another subject cannot take a reserved email: {body}"
    );
    assert!(session_of(&answer).is_none(), "no session: {body}");
    assert_eq!(
        emails_of(&f.principals(), "seeded@example.test"),
        0,
        "nothing was provisioned for it"
    );
    let (status, answer, body) =
        f.sign_in("seeded-own", verified("seeded-sub", "changed@example.test"));
    assert_eq!(status, 200, "the intent's own subject completes it: {body}");
    assert_eq!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        principal_id,
        "as the principal the intent names"
    );
    assert_eq!(
        emails_of(&f.principals(), "seeded@example.test"),
        1,
        "with the intent's email"
    );
    assert!(
        !intents.join(format!("spi_{key}.json")).exists(),
        "the completed intent is removed"
    );

    // A leftover intent whose identity is bound reserves nothing.
    let bound_key = subject_key(&f.idp.issuer, "seeded-sub");
    std::fs::write(
        intents.join(format!("spi_{bound_key}.json")),
        serde_json::to_vec(&json!({
            "schema_version": "ioi.hypervisor.sso-provisioning-intent.v1", "key": bound_key,
            "issuer": f.idp.issuer, "subject": "seeded-sub", "sso_id": f.sso_id,
            "principal_id": principal_id, "email": "free@example.test", "name": "Seeded",
            "created_at": "2026-10-12T00:00:00Z",
        }))
        .unwrap(),
    )
    .unwrap();
    let (status, _, body) = f.sign_in("free-email", verified("free-sub", "free@example.test"));
    assert_eq!(
        status, 200,
        "an intent whose identity is bound reserves nothing: {body}"
    );
}

/// A provisioning that fails at a write spends its state and answers so; the same subject's next
/// sign-in (after a restart) completes it, and another subject cannot take its email. The test
/// fault point is inert when unset, and a daemon started with it says so in its log.
#[test]
fn oidc_failed_provisioning_spends_its_state_and_completes_on_the_next_sign_in() {
    let mut f = fixture();
    let normal_log = std::fs::read_to_string(&f.daemon.log).unwrap_or_default();
    assert!(
        !normal_log.contains("IOI_TEST_"),
        "a daemon without a test fault variable logs no fault warning"
    );
    for (step, subject, email) in [
        (
            "principal",
            "fail-principal-sub",
            "fail-principal@example.test",
        ),
        ("binding", "fail-binding-sub", "fail-binding@example.test"),
    ] {
        f.restart(&[("IOI_TEST_SSO_FAIL_AT", step)]);
        let (status, started, body) = f.start(None, false);
        let started =
            started.unwrap_or_else(|| panic!("{step}: a started sign-in: {status} {body}"));
        let (status, answer, body) =
            f.callback(&started, &format!("fail-{step}"), verified(subject, email));
        assert_eq!(status, 503, "{step}: the provisioning fails: {body}");
        let log = std::fs::read_to_string(&f.daemon.log).unwrap_or_default();
        assert!(
            log.contains("IOI_TEST_SSO_FAIL_AT"),
            "{step}: the daemon warns that a test fault variable is set"
        );
        assert!(session_of(&answer).is_none(), "{step}: no session: {body}");
        assert!(
            answer["message"]
                .as_str()
                .is_some_and(|m| m.contains("start again")),
            "{step}: the answer says to start again: {body}"
        );
        let (status, _, body) = f.callback(
            &started,
            &format!("fail-{step}-replay"),
            verified(subject, email),
        );
        assert_ne!(status, 200, "{step}: the spent state is refused: {body}");
        f.restart(&[]);
        let (status, _, body) = f.sign_in(
            &format!("fail-{step}-other"),
            verified(&format!("{subject}-other"), email),
        );
        assert_eq!(
            status, 403,
            "{step}: another subject cannot take the email: {body}"
        );
        let (status, answer, body) =
            f.sign_in(&format!("fail-{step}-again"), verified(subject, email));
        assert_eq!(status, 200, "{step}: the same subject completes it: {body}");
        assert_eq!(
            f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
            provisioned_principal_id(&subject_key(&f.idp.issuer, subject)),
            "{step}: as the principal derived from its identity"
        );
        assert_eq!(
            emails_of(&f.principals(), email),
            1,
            "{step}: one principal"
        );
    }
}

/// A provisioned subject and a linked subject still sign in to the same principals after a daemon
/// restart.
#[test]
fn oidc_bindings_survive_a_restart() {
    let mut f = fixture();
    let (status, answer, body) =
        f.sign_in("durable", verified("durable-sub", "durable@example.test"));
    assert_eq!(status, 200, "provisioned: {body}");
    let provisioned = f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}")));
    let (status, started, body) = f.start(Some(&f.owner), true);
    let started = started.unwrap_or_else(|| panic!("a started link: {status} {body}"));
    let (status, _, body) =
        f.callback(&started, "durable-link", verified("owner-durable", OWNER.0));
    assert_eq!(status, 200, "linked: {body}");
    f.restart(&[]);
    let (status, answer, body) = f.sign_in(
        "durable-again",
        verified("durable-sub", "durable@example.test"),
    );
    assert_eq!(status, 200, "the provisioned subject signs in: {body}");
    assert_eq!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        provisioned
    );
    let (status, answer, body) = f.sign_in("durable-owner", verified("owner-durable", OWNER.0));
    assert_eq!(status, 200, "the linked subject signs in: {body}");
    assert_eq!(
        f.whoami(&session_of(&answer).unwrap_or_else(|| panic!("a session: {body}"))),
        f.owner_id()
    );
}

/// The refusal for an unlinked subject whose email names an existing principal says how to
/// recover: sign in another way (or have an administrator set a password), then link.
#[test]
fn oidc_link_required_answer_names_the_recovery() {
    let f = fixture();
    let (status, answer, body) = f.sign_in("recovery", verified("recovery-sub", OWNER.0));
    assert_eq!(status, 403, "refused: {body}");
    assert_eq!(
        answer["code"],
        json!("hypervisor.sso_link_required"),
        "by name: {body}"
    );
    let message = answer["message"].as_str().unwrap_or_default();
    for needed in ["password", "administrator", "link"] {
        assert!(
            message.contains(needed),
            "the message names the recovery ({needed}): {message}"
        );
    }
}
