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
//! Only a valid WebSocket handshake (HTTP/1.1 GET, Upgrade: websocket, an upgrade token in the
//! combined Connection list, one 16-byte base64 Sec-WebSocket-Key, version 13) that the upstream
//! answers with a 101 completing it (Upgrade, Connection and the matching Sec-WebSocket-Accept)
//! switches the connection; informational answers before it (e.g. 103) are relayed. After the
//! switch, the client's bytes reach the upstream only as valid CLIENT frames (masked, defined
//! opcodes, RSV bits clear unless permessage-deflate was agreed); anything else, an HTTP request
//! line included, closes the connection. Any other final answer is relayed as plain HTTP and the
//! connection closes. Bytes a client sends with a handshake, before the upstream's answer, are
//! refused. A chunked body's trailer section loses the same fields as the headers.
//!
//! UPSTREAM CONNECTION TOKEN (BUILD-DELTA #31(c)). An editor proxy holds its runtime's connection
//! token and adds it, as the `vscode-tkn` cookie, to every request it forwards (the WebSocket
//! handshake included); a `vscode-tkn` cookie or `tkn` query parameter the browser sends is
//! removed first, so the runtime only ever sees the proxy's.
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
    /// For a valid WebSocket opening handshake, the Sec-WebSocket-Accept its 101 must carry; the
    /// connection switches only on such a 101.
    websocket_accept: Option<String>,
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

/// The editor runtime's connection-token cookie, which only the proxy presents.
const UPSTREAM_TOKEN_COOKIE: &str = "vscode-tkn";

/// The request target without any query parameter named in `names`, each name compared after
/// percent-decoding (so `%6cease` is `lease` too).
fn without_query_names(target: &str, names: &[&str]) -> String {
    match target.split_once('?') {
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|pair| {
                    let name = percent_decoded(pair.split('=').next().unwrap_or_default());
                    !names.contains(&name.as_str())
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

/// True iff the combined list of every `name` header holds `token` (case-insensitive).
fn header_list_has(head: &str, name: &str, token: &str) -> bool {
    header_values(head, name)
        .iter()
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

/// SHA-1 (RFC 3174), for the WebSocket accept value only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    for block in message.chunks(64) {
        let mut words = [0u32; 80];
        for (index, word) in block.chunks(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (value, add) in state.iter_mut().zip([a, b, c, d, e]) {
            *value = value.wrapping_add(add);
        }
    }
    let mut digest = [0u8; 20];
    for (out, value) in digest.chunks_mut(4).zip(state) {
        out.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

/// The Sec-WebSocket-Accept a 101 must carry for `key` (RFC 6455 section 4.2.2).
fn websocket_accept(key: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(sha1(
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    ))
}

/// For a valid WebSocket opening handshake (RFC 6455 section 4.1: an HTTP/1.1 GET with no body,
/// `Upgrade: websocket`, an `upgrade` token in the combined `Connection` list, exactly one
/// `Sec-WebSocket-Key` decoding to 16 bytes, and version 13), the accept value its 101 must carry.
fn websocket_accept_for(head: &str, body: &BodyFraming) -> Option<String> {
    use base64::Engine as _;
    let mut request_line = head.split("\r\n").next()?.split(' ');
    let (method, _target, version) = (
        request_line.next()?,
        request_line.next()?,
        request_line.next()?,
    );
    if method != "GET" || version != "HTTP/1.1" || request_line.next().is_some() {
        return None;
    }
    let keys = header_values(head, "sec-websocket-key");
    let valid = matches!(body, BodyFraming::Length(0))
        && header_list_has(head, "upgrade", "websocket")
        && header_list_has(head, "connection", "upgrade")
        && keys.len() == 1
        && header_values(head, "sec-websocket-version") == ["13"]
        && base64::engine::general_purpose::STANDARD
            .decode(keys[0])
            .is_ok_and(|key| key.len() == 16);
    valid.then(|| websocket_accept(keys[0]))
}

/// For an upstream 101, whether it completes the handshake whose accept value is `accept`
/// (`Upgrade: websocket`, an `upgrade` token in `Connection`, exactly that Sec-WebSocket-Accept):
/// Some(permessage-deflate agreed), or None.
fn completed_switch(answer_head: &str, accept: &str) -> Option<bool> {
    let completes = answer_head.split_whitespace().nth(1) == Some("101")
        && header_list_has(answer_head, "upgrade", "websocket")
        && header_list_has(answer_head, "connection", "upgrade")
        && header_values(answer_head, "sec-websocket-accept") == [accept];
    completes.then(|| {
        header_values(answer_head, "sec-websocket-extensions")
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("permessage-deflate"))
    })
}

/// The opening request as forwarded upstream: daemon cookies, `x-ioi-lease`, `lease` query
/// parameters, `Referer` and `Origin` removed; for anything but a WebSocket handshake, the
/// connection headers replaced by `Connection: close`. Err (a status line and a reason) for a body
/// whose framing the proxy does not forward: conflicting lengths, a transfer coding other than
/// chunked, or both `Transfer-Encoding` and `Content-Length`.
fn forwarded_request_head(
    head: &str,
    upstream_token: Option<&str>,
) -> Result<Forward, (&'static str, &'static str)> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let target = without_query_names(target, &["lease"]);
    let target = if upstream_token.is_some() {
        without_query_names(&target, &["tkn"])
    } else {
        target
    };
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
    let websocket_accept = websocket_accept_for(head, &body);
    let websocket = websocket_accept.is_some();
    let mut out = format!("{method} {target} {version}\r\n");
    // Every Cookie line's kept pairs are forwarded as ONE Cookie header.
    let mut cookies: Vec<String> = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        match key_lower.as_str() {
            "x-ioi-lease" | "referer" | "origin" => continue,
            "connection" | "keep-alive" | "proxy-connection" | "upgrade" if !websocket => continue,
            "cookie" => {
                cookies.extend(
                    value
                        .split(';')
                        .map(str::trim)
                        .filter(|pair| !pair.is_empty())
                        .filter(|pair| {
                            let name = pair.split('=').next().unwrap_or_default().trim();
                            !is_daemon_cookie(name)
                                && !(upstream_token.is_some() && name == UPSTREAM_TOKEN_COOKIE)
                        })
                        .map(str::to_string),
                );
                continue;
            }
            _ => {}
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if let Some(token) = upstream_token {
        cookies.push(format!("{UPSTREAM_TOKEN_COOKIE}={token}"));
    }
    if !cookies.is_empty() {
        out.push_str(&format!("Cookie: {}\r\n", cookies.join("; ")));
    }
    if !websocket {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    Ok(Forward {
        head: out,
        websocket_accept,
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
            // The trailer section, through its empty line; it loses the fields the headers lose.
            loop {
                let end = line_end(client, &mut pending, &mut chunk).await?;
                let name = String::from_utf8_lossy(&pending[..end])
                    .split_once(':')
                    .map(|(name, _)| name.trim().to_ascii_lowercase())
                    .unwrap_or_default();
                let dropped = matches!(
                    name.as_str(),
                    "x-ioi-lease" | "cookie" | "referer" | "origin"
                );
                if end == 0 || !dropped {
                    upstream.write_all(&pending[..end + 2]).await?;
                }
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

/// Forward the client's WebSocket frames to the upstream, each checked as a valid CLIENT frame
/// (RFC 6455 section 5.2): RSV bits clear (RSV1 only on a message's first frame, and only when
/// permessage-deflate was agreed), a defined opcode, the MASK bit set, a control frame final and at
/// most 125 bytes. Anything else, an HTTP request line included, ends the stream with an error.
/// Frame bytes are forwarded unchanged; the client closing between frames ends it cleanly.
async fn forward_client_frames<R, W>(
    client: &mut R,
    upstream: &mut W,
    rsv1_allowed: bool,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let invalid =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        while pending.len() < 2 {
            let read = client.read(&mut chunk).await?;
            if read == 0 {
                return if pending.is_empty() {
                    Ok(())
                } else {
                    Err(invalid("a truncated frame"))
                };
            }
            pending.extend_from_slice(&chunk[..read]);
        }
        let (first, second) = (pending[0], pending[1]);
        let (fin, rsv, opcode) = (first & 0x80 != 0, first & 0x70, first & 0x0f);
        let length_code = u64::from(second & 0x7f);
        if second & 0x80 == 0 {
            return Err(invalid("an unmasked client frame"));
        }
        if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
            return Err(invalid("an undefined opcode"));
        }
        if rsv != 0 && !(rsv1_allowed && rsv == 0x40 && matches!(opcode, 0x1 | 0x2)) {
            return Err(invalid("RSV bits set without an agreed extension"));
        }
        if opcode >= 0x8 && (!fin || length_code > 125) {
            return Err(invalid("a fragmented or oversized control frame"));
        }
        let extended = match length_code {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let header_length = 2 + extended + 4;
        while pending.len() < header_length {
            fill(client, &mut pending, &mut chunk).await?;
        }
        let length = match extended {
            0 => length_code,
            2 => u64::from(u16::from_be_bytes([pending[2], pending[3]])),
            _ => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&pending[2..10]);
                u64::from_be_bytes(bytes)
            }
        };
        if length >> 63 != 0 {
            return Err(invalid("a 64-bit length with its top bit set"));
        }
        upstream.write_all(&pending[..header_length]).await?;
        pending.drain(..header_length);
        let mut left = length;
        while left > 0 {
            if pending.is_empty() {
                fill(client, &mut pending, &mut chunk).await?;
            }
            let now = left.min(pending.len() as u64) as usize;
            upstream.write_all(&pending[..now]).await?;
            pending.drain(..now);
            left -= now as u64;
        }
    }
}

/// The upstream's FINAL answer head to a handshake (and whatever arrived with it): (bytes, head
/// length), or None. An informational answer before it (1xx other than 101, e.g. 103 Early Hints)
/// is relayed to the client and does not end the exchange.
async fn read_final_answer(
    outbound: &mut TcpStream,
    inbound: &mut TcpStream,
) -> Option<(Vec<u8>, usize)> {
    let mut answer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = headers_end(&answer) {
            let status = String::from_utf8_lossy(&answer[..end])
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok());
            if status.is_some_and(|code| (100..200).contains(&code) && code != 101) {
                inbound.write_all(&answer[..end]).await.ok()?;
                answer.drain(..end);
                continue;
            }
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

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    mut inbound: TcpStream,
    internal_port: u16,
    public_port: u16,
    host: &str,
    bound_lease: &str,
    service_id: &str,
    data_dir: &str,
    upstream_token: Option<&str>,
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
    let forward = match forwarded_request_head(&head, upstream_token) {
        Ok(forward) => forward,
        Err((status, reason)) => {
            let resp = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}", reason.len());
            let _ = inbound.write_all(resp.as_bytes()).await;
            return;
        }
    };
    let read_ahead = &buf[head_len..];
    if forward.websocket_accept.is_some() && !read_ahead.is_empty() {
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
    if let Some(accept) = forward.websocket_accept.as_deref() {
        // The connection switches only on a 101 that completes this handshake; then the client's
        // bytes pass only as valid client frames. Any other final answer is relayed as plain HTTP
        // and the connection closes, so no later request passes unfiltered.
        let Some((answer, answer_head_len)) = read_final_answer(&mut outbound, &mut inbound).await
        else {
            let _ = inbound.shutdown().await;
            return;
        };
        let answer_head = String::from_utf8_lossy(&answer[..answer_head_len]).to_string();
        if answer_head.split_whitespace().nth(1) == Some("101") {
            let Some(rsv1_allowed) = completed_switch(&answer_head, accept) else {
                let reason = "the upstream's 101 does not complete this WebSocket handshake";
                let resp = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}", reason.len());
                let _ = inbound.write_all(resp.as_bytes()).await;
                let _ = inbound.shutdown().await;
                return;
            };
            if inbound.write_all(&answer).await.is_err() {
                return;
            }
            let (mut client_read, mut client_write) = inbound.split();
            let (mut upstream_read, mut upstream_write) = outbound.split();
            {
                let frames =
                    forward_client_frames(&mut client_read, &mut upstream_write, rsv1_allowed);
                let answers = tokio::io::copy(&mut upstream_read, &mut client_write);
                tokio::pin!(frames, answers);
                tokio::select! {
                    _ = &mut frames => {}
                    _ = &mut answers => {}
                }
            }
            let _ = client_write.shutdown().await;
            let _ = upstream_write.shutdown().await;
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
/// `upstream_token` is the editor runtime's connection token (None for a port preview).
pub(crate) async fn bind_editor_proxy(
    data_dir: &str,
    service_id: &str,
    internal_port: u16,
    lease_id: &str,
    upstream_token: Option<String>,
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
                    let (dd2, lease2, sid2, host2, token2) = (dd.clone(), lease.clone(), sid.clone(), proxy_host.clone(), upstream_token.clone());
                    tokio::spawn(async move { handle_conn(inbound, internal_port, public_port, &host2, &lease2, &sid2, &dd2, token2.as_deref()).await; });
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

#[cfg(test)]
mod websocket_accept_tests {
    /// RFC 6455 section 1.3's worked example.
    #[test]
    fn the_accept_value_is_the_rfc_example() {
        assert_eq!(
            super::websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
