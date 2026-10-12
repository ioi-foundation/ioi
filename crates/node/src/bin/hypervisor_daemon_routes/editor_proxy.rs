//! Pre-applications WS-4 — lease-authenticated WebSocket/HTTP proxy for the browser-IDE.
//!
//! Security infrastructure, not UI plumbing (Locked Decision 5). The OSS runtime listens on a
//! PRIVATE internal port; the daemon never hands out that raw port. This proxy binds a public port
//! per editor service, authenticates the OPENING request against the capability lease, and only
//! then forwards the raw connection (HTTP + the WS upgrade) to the internal target. Expiry/revoke
//! fail CLOSED on new connections (existing ones get reconnect grace). The proxy is bound to one
//! lease (its grant id) and admits only that lease's access token, presented in the `x-ioi-lease`
//! header or in the cookie this proxy's own browser handoff (`POST /__ioi/lease`) sets; never from
//! a URL. The handoff is not single-use: it answers any POST carrying the live lease's token. The
//! token is checked by its hash in constant time (`authority_routes::bearer_admits_lease`).
//!
//! SITE SEPARATION. Each proxy is served on its own host name, `p<16 hex>.localhost`, a different
//! site from the owner's UI (127.0.0.1) and from every other proxy, so the browser never sends the
//! owner's cookies there and proxied content cannot make same-site requests to the UI. A request
//! naming any other host is refused (421), so content is never served on the UI's site.
//!
//! FORWARDING. The upstream (agent-run code for a port preview) never sees a daemon session or a
//! lease credential: a request carrying the daemon session cookie (`ioi_session`) is refused and
//! never forwarded, and every forwarded request has lease cookies, `x-ioi-lease` and a `lease`
//! query parameter removed. Plain HTTP is ONE request per upstream connection
//! (`Connection: close` is sent upstream and nothing more is read from the client), so a later
//! keep-alive request cannot pass unfiltered; it arrives on a new connection and is authenticated
//! and filtered again. A WebSocket upgrade forwards its filtered handshake, then the frames.
use std::collections::HashMap;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::authority_routes::bearer_admits_lease;
use super::{iso_now, persist_record};

/// A live lease-authenticated proxy in front of one editor service's internal runtime port.
pub(crate) struct EditorProxy {
    pub(crate) public_port: u16,
    /// The proxy's own host name (`p<16 hex>.localhost`); its URLs are `http://<host>:<port>/`.
    pub(crate) host: String,
    pub(crate) internal_port: u16,
    pub(crate) lease_id: String,
    pub(crate) service_id: String,
    pub(crate) shutdown: tokio::sync::oneshot::Sender<()>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

fn proxy_event(data_dir: &str, service_id: &str, event: &str, lease_id: &str) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = format!("epx_{nanos:x}");
    let _ = persist_record(
        data_dir,
        "editor-proxy-events",
        &id,
        &json!({
            "schema_version": "ioi.hypervisor.editor-proxy-event.v1",
            "event_id": id, "service_id": service_id, "lease_id": lease_id, "event": event, "at": iso_now()
        }),
    );
}

/// A request's header value (first occurrence, case-insensitive name).
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

/// A credential the daemon issues to browsers, which no upstream may receive.
fn is_daemon_cookie(name: &str) -> bool {
    name == "ioi_session" || name.starts_with("ioi_lease_")
}

/// True iff any `Cookie` header of the request carries the daemon session cookie.
fn carries_session_cookie(head: &str) -> bool {
    head.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.trim().eq_ignore_ascii_case("cookie")
                && value
                    .split(';')
                    .any(|pair| pair.split('=').next().unwrap_or_default().trim() == "ioi_session")
        })
    })
}

/// The opening request as forwarded upstream: daemon cookies, `x-ioi-lease` and `lease` query
/// parameters removed; for plain HTTP, `Connection: close`. Returns the head, whether it is a
/// WebSocket upgrade, and its body length; Err for a request whose body length is not a single
/// Content-Length (chunked or conflicting), which the proxy refuses rather than forwards.
fn forwarded_request_head(head: &str) -> Result<(String, bool, usize), &'static str> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let target = match target.split_once('?') {
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|pair| pair.split('=').next() != Some("lease"))
                .collect();
            if kept.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{}", kept.join("&"))
            }
        }
        None => target.to_string(),
    };
    let upgrade =
        header_value(head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if header_value(head, "transfer-encoding").is_some() {
        return Err("a request body must carry a single Content-Length through this proxy");
    }
    let lengths: Vec<&str> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim())
        .collect();
    let body_len = match lengths.as_slice() {
        [] => 0,
        [one] => one
            .parse::<usize>()
            .map_err(|_| "an invalid Content-Length")?,
        _ => return Err("conflicting Content-Length headers"),
    };
    let mut out = format!("{method} {target} {version}\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        match key_lower.as_str() {
            "x-ioi-lease" => continue,
            "connection" | "keep-alive" | "proxy-connection" if !upgrade => continue,
            "cookie" => {
                let kept: Vec<&str> = value
                    .split(';')
                    .map(str::trim)
                    .filter(|pair| !pair.is_empty())
                    .filter(|pair| {
                        !is_daemon_cookie(pair.split('=').next().unwrap_or_default().trim())
                    })
                    .collect();
                if !kept.is_empty() {
                    out.push_str(&format!("{}: {}\r\n", key.trim(), kept.join("; ")));
                }
                continue;
            }
            _ => {}
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    Ok((out, upgrade, body_len))
}

fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// The cookie this proxy's exchange sets. Cookies are not port-scoped, so the name carries the
/// proxy's public port.
pub(crate) fn lease_cookie_name(public_port: u16) -> String {
    format!("ioi_lease_{public_port}")
}

/// The lease access token an opening request presents: the `x-ioi-lease` header, else this
/// proxy's lease cookie. A token in the request-target (query string) is not a credential.
fn presented_lease_token(head: &str, public_port: u16) -> Option<String> {
    let cookie_prefix = format!("{}=", lease_cookie_name(public_port));
    let mut from_cookie = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "x-ioi-lease" {
            return Some(value.trim().to_string());
        }
        if name == "cookie" && from_cookie.is_none() {
            from_cookie = value
                .split(';')
                .find_map(|part| part.trim().strip_prefix(cookie_prefix.as_str()))
                .map(str::to_string);
        }
    }
    from_cookie
}

/// Decode one `application/x-www-form-urlencoded` field value.
pub(crate) fn form_field(body: &str, field: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == field).then(|| {
            let bytes = value.replace('+', " ").into_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                let hex = (bytes[index] == b'%')
                    .then(|| bytes.get(index + 1..index + 3))
                    .flatten()
                    .and_then(|pair| std::str::from_utf8(pair).ok())
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            String::from_utf8_lossy(&out).into_owned()
        })
    })
}

/// The browser exchange's answer: 303 to `/` with this proxy's HttpOnly, SameSite=Lax lease cookie.
pub(crate) fn lease_exchange_response(public_port: u16, token: &str) -> String {
    format!(
        "HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: {}={token}; HttpOnly; SameSite=Lax; Path=/\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        lease_cookie_name(public_port)
    )
}

/// `POST /__ioi/lease` with the token as the `token` form field: a valid token for the bound lease
/// is answered with the lease cookie; anything else with 403 and no cookie. Nothing is forwarded.
async fn answer_lease_exchange(
    inbound: &mut TcpStream,
    mut buf: Vec<u8>,
    head_len: usize,
    public_port: u16,
    bound_lease: &str,
    service_id: &str,
    data_dir: &str,
) {
    let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
    let content_length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(4096);
    let mut tmp = [0u8; 1024];
    while buf.len() < head_len + content_length {
        match inbound.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let end = buf.len().min(head_len + content_length);
    let body = String::from_utf8_lossy(&buf[head_len..end]).to_string();
    let token = form_field(&body, "token").unwrap_or_default();
    if bearer_admits_lease(data_dir, bound_lease, &token) {
        proxy_event(data_dir, service_id, "lease_cookie_issued", bound_lease);
        let _ = inbound
            .write_all(lease_exchange_response(public_port, &token).as_bytes())
            .await;
    } else {
        proxy_event(data_dir, service_id, "authentication_denied", bound_lease);
        let _ = inbound
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
    }
}

async fn handle_conn(
    mut inbound: TcpStream,
    internal_port: u16,
    public_port: u16,
    host: &str,
    bound_lease: &str,
    service_id: &str,
    data_dir: &str,
) {
    // Read the opening request up to the end of headers (or a cap).
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        match inbound.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if headers_end(&buf).is_some() || buf.len() > 16384 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    proxy_event(data_dir, service_id, "websocket_intercepted", bound_lease);
    let head_len = headers_end(&buf).unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
    // Site separation: only this proxy's own name is served (never the UI's 127.0.0.1 site).
    let own_authority = format!("{host}:{public_port}");
    if !header_value(&head, "host").is_some_and(|value| value.eq_ignore_ascii_case(&own_authority))
    {
        proxy_event(data_dir, service_id, "host_refused", bound_lease);
        let _ = inbound
            .write_all(b"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }
    if head.starts_with("POST /__ioi/lease ") {
        answer_lease_exchange(
            &mut inbound,
            buf,
            head_len,
            public_port,
            bound_lease,
            service_id,
            data_dir,
        )
        .await;
        return;
    }
    // The daemon session cookie is host-only on the UI's host, so a browser never sends it here; a
    // request that carries it anyway is refused and never forwarded.
    if carries_session_cookie(&head) {
        proxy_event(data_dir, service_id, "session_cookie_refused", bound_lease);
        let body = "Hypervisor preview/editor proxy: a request carrying the daemon session cookie is refused.";
        let resp = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = inbound.write_all(resp.as_bytes()).await;
        return;
    }
    // Auth model for this loopback, per-service public port: every opening request carries the
    // bound lease's access token (header or exchanged cookie), and the lease must be active
    // (fail-closed on revoke/expire). Knowledge of the port, a grant id or a URL admits nothing.
    let authed = presented_lease_token(&head, public_port)
        .is_some_and(|token| bearer_admits_lease(data_dir, bound_lease, &token));
    if !authed {
        proxy_event(data_dir, service_id, "authentication_denied", bound_lease);
        let body = "Hypervisor editor access denied: a valid, unexpired, non-revoked editor capability lease is required. Open through Sessions/Environments, not the raw endpoint.";
        let resp = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = inbound.write_all(resp.as_bytes()).await;
        return;
    }
    proxy_event(
        data_dir,
        service_id,
        "authentication_succeeded",
        bound_lease,
    );
    let (forwarded_head, upgrade, body_len) = match forwarded_request_head(&head) {
        Ok(shape) => shape,
        Err(reason) => {
            let resp = format!("HTTP/1.1 411 Length Required\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}", reason.len());
            let _ = inbound.write_all(resp.as_bytes()).await;
            return;
        }
    };
    let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", internal_port)).await else {
        proxy_event(
            data_dir,
            service_id,
            "target_version_unreachable",
            bound_lease,
        );
        let _ = inbound
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            .await;
        return;
    };
    if outbound.write_all(forwarded_head.as_bytes()).await.is_err() {
        return;
    }
    proxy_event(
        data_dir,
        service_id,
        "raw_connection_established",
        bound_lease,
    );
    let read_ahead = &buf[head_len..];
    if upgrade {
        // The WebSocket handshake is filtered above; frames carry no headers.
        if outbound.write_all(read_ahead).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    } else {
        // One request per upstream connection: forward exactly this request's body, then relay
        // the answer. Nothing further from the client reaches this upstream connection.
        let in_hand = read_ahead.len().min(body_len);
        if outbound.write_all(&read_ahead[..in_hand]).await.is_err() {
            return;
        }
        let remaining = (body_len - in_hand) as u64;
        if remaining > 0 {
            let mut body = (&mut inbound).take(remaining);
            if tokio::io::copy(&mut body, &mut outbound).await.is_err() {
                return;
            }
        }
        let _ = tokio::io::copy(&mut outbound, &mut inbound).await;
        let _ = inbound.shutdown().await;
    }
    proxy_event(data_dir, service_id, "client_disconnected", bound_lease);
}

/// Bind a lease-authenticated proxy in front of `internal_port`. Returns the public port + handle.
pub(crate) async fn bind_editor_proxy(
    data_dir: &str,
    service_id: &str,
    internal_port: u16,
    lease_id: &str,
) -> Result<(u16, EditorProxy), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    let public_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let host = format!("p{}.localhost", hex::encode(rand::random::<[u8; 8]>()));
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    proxy_event(data_dir, service_id, "proxy_started", lease_id);
    let dd = data_dir.to_string();
    let lease = lease_id.to_string();
    let sid = service_id.to_string();
    let proxy_host = host.clone();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => { proxy_event(&dd, &sid, "proxy_stopped", &lease); break; }
                accept = listener.accept() => {
                    let Ok((inbound, _peer)) = accept else { continue; };
                    let (dd2, lease2, sid2, host2) = (dd.clone(), lease.clone(), sid.clone(), proxy_host.clone());
                    tokio::spawn(async move { handle_conn(inbound, internal_port, public_port, &host2, &lease2, &sid2, &dd2).await; });
                }
            }
        }
    });
    Ok((
        public_port,
        EditorProxy {
            public_port,
            host,
            internal_port,
            lease_id: lease_id.to_string(),
            service_id: service_id.to_string(),
            shutdown: tx,
            join,
        },
    ))
}

/// Tear down a service's proxy if present (deterministic socket close).
pub(crate) fn stop_editor_proxy(proxies: &mut HashMap<String, EditorProxy>, service_id: &str) {
    if let Some(p) = proxies.remove(service_id) {
        let _ = p.shutdown.send(());
    }
}
