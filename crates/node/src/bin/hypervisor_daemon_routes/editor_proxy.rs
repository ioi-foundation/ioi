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
//! FORWARDING. The upstream (agent-run code for a port preview) never sees a daemon session, a
//! lease credential or the site the browser came from: a request carrying the daemon session cookie
//! (`ioi_session`) is refused and never forwarded, and every forwarded request has lease cookies,
//! `x-ioi-lease`, a `lease` query parameter (its name compared after percent-decoding), `Referer`
//! and `Origin` removed. Plain HTTP is ONE request per upstream connection (`Connection: close` is
//! sent upstream; the request's own body, by `Content-Length` or chunked, is forwarded while the
//! answer is relayed, and nothing after it is read from the client), so a later keep-alive request
//! cannot pass unfiltered; it arrives on a new connection and is authenticated and filtered again.
//! Only a valid WebSocket handshake that the upstream answers with 101 switches to raw frames; any
//! other answer is relayed as plain HTTP and the connection closes. Bytes a client sends with a
//! handshake, before the upstream's answer, are refused.
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

/// How a forwarded request's body is delimited.
enum BodyFraming {
    /// Exactly this many bytes (`Content-Length`, or none).
    Length(usize),
    /// `Transfer-Encoding: chunked`: chunk by chunk, through the last chunk and the trailer.
    Chunked,
}

/// The opening request as the proxy forwards it upstream.
struct Forward {
    head: String,
    /// A valid WebSocket opening handshake: switched to raw frames only on the upstream's 101.
    websocket: bool,
    body: BodyFraming,
}

/// Decode `application/x-www-form-urlencoded` text: `+` is a space and `%XX` a byte.
fn percent_decoded(text: &str) -> String {
    let bytes = text.replace('+', " ").into_bytes();
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
}

/// The request target without any query parameter NAMED `lease`, the name compared after
/// percent-decoding (so `%6cease` is `lease` too).
fn without_lease_query(target: &str) -> String {
    match target.split_once('?') {
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|pair| {
                    percent_decoded(pair.split('=').next().unwrap_or_default()) != "lease"
                })
                .collect();
            if kept.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{}", kept.join("&"))
            }
        }
        None => target.to_string(),
    }
}

/// Every value of a request header (case-insensitive name), in order.
fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

/// A WebSocket opening handshake (RFC 6455 section 4.1): GET with `Upgrade: websocket`, an `upgrade`
/// token in `Connection`, a `Sec-WebSocket-Key` and a `Sec-WebSocket-Version`, and no body.
fn is_websocket_handshake(head: &str, body: &BodyFraming) -> bool {
    head.starts_with("GET ")
        && matches!(body, BodyFraming::Length(0))
        && header_value(head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && header_value(head, "connection").is_some_and(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && header_value(head, "sec-websocket-key").is_some_and(|v| !v.is_empty())
        && header_value(head, "sec-websocket-version").is_some()
}

/// The opening request as forwarded upstream: daemon cookies, `x-ioi-lease`, `lease` query
/// parameters, `Referer` and `Origin` removed; for anything but a WebSocket handshake, the
/// connection headers replaced by `Connection: close`. Err (a status line and a reason) for a body
/// whose framing the proxy does not forward: conflicting lengths, a transfer coding other than
/// chunked, or both `Transfer-Encoding` and `Content-Length`.
fn forwarded_request_head(head: &str) -> Result<Forward, (&'static str, &'static str)> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let target = without_lease_query(target);
    let codings = header_values(head, "transfer-encoding");
    let lengths = header_values(head, "content-length");
    let body = match (codings.as_slice(), lengths.as_slice()) {
        ([], []) => BodyFraming::Length(0),
        ([], [one]) => BodyFraming::Length(
            one.parse::<usize>()
                .map_err(|_| ("400 Bad Request", "an invalid Content-Length"))?,
        ),
        ([], _) => return Err(("400 Bad Request", "conflicting Content-Length headers")),
        ([coding], []) if coding.eq_ignore_ascii_case("chunked") => BodyFraming::Chunked,
        ([_], []) => {
            return Err((
                "501 Not Implemented",
                "a transfer coding other than chunked",
            ))
        }
        _ => {
            return Err((
                "400 Bad Request",
                "a body framed by several transfer codings, or by both Transfer-Encoding and Content-Length",
            ))
        }
    };
    let websocket = is_websocket_handshake(head, &body);
    let mut out = format!("{method} {target} {version}\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        match key_lower.as_str() {
            "x-ioi-lease" | "referer" | "origin" => continue,
            "connection" | "keep-alive" | "proxy-connection" | "upgrade" if !websocket => continue,
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
    if !websocket {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    Ok(Forward {
        head: out,
        websocket,
        body,
    })
}

/// Read more of `client` into `pending`; the client closing first is an error.
async fn fill<R>(client: &mut R, pending: &mut Vec<u8>, chunk: &mut [u8]) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let read = client.read(chunk).await?;
    if read == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    pending.extend_from_slice(&chunk[..read]);
    Ok(())
}

/// The index of the CRLF ending the first line in `pending`, reading more as needed; a line longer
/// than 4 KiB is refused.
async fn line_end<R>(
    client: &mut R,
    pending: &mut Vec<u8>,
    chunk: &mut [u8],
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(at) = pending.windows(2).position(|w| w == b"\r\n") {
            return Ok(at);
        }
        if pending.len() > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a chunked-body line longer than 4 KiB",
            ));
        }
        fill(client, pending, chunk).await?;
    }
}

/// Forward a chunked body as received, chunk by chunk, through its last chunk and trailer, and
/// nothing after it. A malformed chunk ends the forwarding with an error.
async fn forward_chunked<R, W>(
    client: &mut R,
    upstream: &mut W,
    mut pending: Vec<u8>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let invalid =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let mut chunk = [0u8; 8192];
    loop {
        let end = line_end(client, &mut pending, &mut chunk).await?;
        let size_text = std::str::from_utf8(&pending[..end])
            .map_err(|_| invalid("a chunk size that is not text"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid("a chunk size that is not hexadecimal"));
        }
        let size = usize::from_str_radix(&size_text, 16).map_err(|_| invalid("a chunk size"))?;
        upstream.write_all(&pending[..end + 2]).await?;
        pending.drain(..end + 2);
        if size == 0 {
            // The trailer section, through its empty line.
            loop {
                let end = line_end(client, &mut pending, &mut chunk).await?;
                upstream.write_all(&pending[..end + 2]).await?;
                pending.drain(..end + 2);
                if end == 0 {
                    return Ok(());
                }
            }
        }
        let mut left = size;
        while left > 0 {
            if pending.is_empty() {
                fill(client, &mut pending, &mut chunk).await?;
            }
            let now = left.min(pending.len());
            upstream.write_all(&pending[..now]).await?;
            pending.drain(..now);
            left -= now;
        }
        while pending.len() < 2 {
            fill(client, &mut pending, &mut chunk).await?;
        }
        if &pending[..2] != b"\r\n" {
            return Err(invalid("a chunk not ended by CRLF"));
        }
        upstream.write_all(b"\r\n").await?;
        pending.drain(..2);
    }
}

/// Forward exactly this request's body (`in_hand` is what was read past its head) and nothing more:
/// bytes the client sends after the body never reach the upstream.
async fn forward_body<R, W>(
    client: &mut R,
    upstream: &mut W,
    in_hand: &[u8],
    body: &BodyFraming,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    match body {
        BodyFraming::Length(length) => {
            let now = in_hand.len().min(*length);
            upstream.write_all(&in_hand[..now]).await?;
            let remaining = (*length - now) as u64;
            if remaining > 0 {
                let copied = tokio::io::copy(&mut (&mut *client).take(remaining), upstream).await?;
                if copied < remaining {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
            }
            Ok(())
        }
        BodyFraming::Chunked => forward_chunked(client, upstream, in_hand.to_vec()).await,
    }
}

/// The upstream's answer head (and whatever arrived with it): (bytes, head length), or None.
async fn read_answer_head(outbound: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
    let mut answer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = headers_end(&answer) {
            return Some((answer, end));
        }
        if answer.len() > 16384 {
            return None;
        }
        match outbound.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => answer.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Relay an upstream's answer to a handshake it did not switch (anything but 101) as plain HTTP:
/// its connection headers replaced by `Connection: close`, its body by `Content-Length` (else until
/// the upstream closes, at most 30 seconds), then the client connection closes. Nothing more is read
/// from the client.
async fn relay_unswitched_answer(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
    answer: &[u8],
    head_len: usize,
) {
    let head = String::from_utf8_lossy(&answer[..head_len]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    let mut length = matches!(status, Some(100..=199) | Some(204) | Some(304)).then_some(0u64);
    let mut out = format!("{status_line}\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let key = line
            .split_once(':')
            .map(|(key, _)| key.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(key.as_str(), "connection" | "keep-alive" | "upgrade") {
            continue;
        }
        if key == "content-length" {
            length = length.or_else(|| {
                line.split_once(':')
                    .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            });
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    if inbound.write_all(out.as_bytes()).await.is_err() {
        return;
    }
    let early = &answer[head_len..];
    match length {
        Some(length) => {
            let now = (early.len() as u64).min(length) as usize;
            if inbound.write_all(&early[..now]).await.is_err() {
                return;
            }
            let remaining = length - now as u64;
            if remaining > 0 {
                let _ = tokio::io::copy(&mut (&mut *outbound).take(remaining), inbound).await;
            }
        }
        None => {
            if inbound.write_all(early).await.is_err() {
                return;
            }
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::io::copy(outbound, inbound),
            )
            .await;
        }
    }
    let _ = inbound.shutdown().await;
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
        (name == field).then(|| percent_decoded(value))
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
    // The daemon session cookie is host-only on the UI's host, so a browser never sends it here; a
    // request that carries it anyway (the lease exchange included) is refused and never forwarded.
    if carries_session_cookie(&head) {
        proxy_event(data_dir, service_id, "session_cookie_refused", bound_lease);
        let body = "Hypervisor preview/editor proxy: a request carrying the daemon session cookie is refused.";
        let resp = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = inbound.write_all(resp.as_bytes()).await;
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
    let forward = match forwarded_request_head(&head) {
        Ok(forward) => forward,
        Err((status, reason)) => {
            let resp = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}", reason.len());
            let _ = inbound.write_all(resp.as_bytes()).await;
            return;
        }
    };
    let read_ahead = &buf[head_len..];
    if forward.websocket && !read_ahead.is_empty() {
        // A client sends frames only after the upstream's 101; bytes sent with the handshake are
        // never forwarded.
        let reason = "bytes sent with a WebSocket handshake are refused";
        let resp = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}", reason.len());
        let _ = inbound.write_all(resp.as_bytes()).await;
        return;
    }
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
    if outbound.write_all(forward.head.as_bytes()).await.is_err() {
        return;
    }
    proxy_event(
        data_dir,
        service_id,
        "raw_connection_established",
        bound_lease,
    );
    if forward.websocket {
        // Raw frames only once the upstream switches protocols (101); any other answer is relayed
        // as plain HTTP and the connection closes, so no later request passes unfiltered.
        let Some((answer, answer_head_len)) = read_answer_head(&mut outbound).await else {
            let _ = inbound.shutdown().await;
            return;
        };
        let switched = String::from_utf8_lossy(&answer[..answer_head_len])
            .split_whitespace()
            .nth(1)
            == Some("101");
        if switched {
            if inbound.write_all(&answer).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        } else {
            relay_unswitched_answer(&mut inbound, &mut outbound, &answer, answer_head_len).await;
        }
    } else {
        // One request per upstream connection: exactly this request's body is forwarded while the
        // answer is relayed (an interim `100 Continue` reaches a client waiting for it); nothing
        // after the body reaches this upstream connection.
        let (mut client_read, mut client_write) = inbound.split();
        {
            let (mut upstream_read, mut upstream_write) = outbound.split();
            let body = forward_body(
                &mut client_read,
                &mut upstream_write,
                read_ahead,
                &forward.body,
            );
            let answer = tokio::io::copy(&mut upstream_read, &mut client_write);
            tokio::pin!(body, answer);
            let mut forwarding = true;
            loop {
                tokio::select! {
                    sent = &mut body, if forwarding => {
                        forwarding = false;
                        if sent.is_err() {
                            break;
                        }
                    }
                    _ = &mut answer => break,
                }
            }
        }
        let _ = client_write.shutdown().await;
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
