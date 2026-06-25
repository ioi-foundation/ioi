//! Pre-applications WS-4 — lease-authenticated WebSocket/HTTP proxy for the browser-IDE.
//!
//! Security infrastructure, not UI plumbing (Locked Decision 5). The OSS runtime listens on a
//! PRIVATE internal port; the daemon never hands out that raw port. This proxy binds a public port
//! per editor service, authenticates the OPENING request against the capability lease (first-
//! message/query token -> principal), and only then forwards the raw connection (HTTP + the WS
//! upgrade) to the internal target. Expiry/revoke fail CLOSED on new connections (existing ones get
//! reconnect grace). Auth reuses the EXISTING capability-lease machinery (`capability_lease_status`).
use std::collections::HashMap;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::authority_routes::capability_lease_status;
use super::{iso_now, persist_record};

/// A live lease-authenticated proxy in front of one editor service's internal runtime port.
pub(crate) struct EditorProxy {
    pub(crate) public_port: u16,
    pub(crate) internal_port: u16,
    pub(crate) lease_id: String,
    pub(crate) service_id: String,
    pub(crate) shutdown: tokio::sync::oneshot::Sender<()>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

fn proxy_event(data_dir: &str, service_id: &str, event: &str, lease_id: &str) {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let id = format!("epx_{nanos:x}");
    let _ = persist_record(data_dir, "editor-proxy-events", &id, &json!({
        "schema_version": "ioi.hypervisor.editor-proxy-event.v1",
        "event_id": id, "service_id": service_id, "lease_id": lease_id, "event": event, "at": iso_now()
    }));
}

fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Extract the lease token from the opening request: `?lease=<token>` on the request-target, or an
/// `x-ioi-lease:` header. The token is the slash-free grant_id (capability lease id).
fn extract_lease_token(buf: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(buf);
    // request line: METHOD <target> HTTP/1.1
    if let Some(line) = head.lines().next() {
        if let Some(target) = line.split_whitespace().nth(1) {
            if let Some(q) = target.split('?').nth(1) {
                for kv in q.split('&') {
                    let mut it = kv.splitn(2, '=');
                    if it.next() == Some("lease") {
                        if let Some(v) = it.next() { return Some(v.trim().to_string()); }
                    }
                }
            }
        }
    }
    for line in head.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("x-ioi-lease:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

async fn handle_conn(mut inbound: TcpStream, internal_port: u16, bound_lease: &str, service_id: &str, data_dir: &str) {
    // Read the opening request up to the end of headers (or a cap).
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        match inbound.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&tmp[..n]); if headers_end(&buf).is_some() || buf.len() > 16384 { break; } }
            Err(_) => return,
        }
    }
    proxy_event(data_dir, service_id, "websocket_intercepted", bound_lease);
    let token = extract_lease_token(&buf);
    let authed = token.as_deref() == Some(bound_lease) && capability_lease_status(data_dir, bound_lease) == "active";
    if !authed {
        proxy_event(data_dir, service_id, "authentication_denied", bound_lease);
        let body = "Hypervisor editor access denied: a valid, unexpired, non-revoked editor capability lease is required. Open through Sessions/Environments, not the raw endpoint.";
        let resp = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = inbound.write_all(resp.as_bytes()).await;
        return;
    }
    proxy_event(data_dir, service_id, "authentication_succeeded", bound_lease);
    let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", internal_port)).await else {
        proxy_event(data_dir, service_id, "target_version_unreachable", bound_lease);
        let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n").await;
        return;
    };
    if outbound.write_all(&buf).await.is_err() { return; }
    proxy_event(data_dir, service_id, "raw_connection_established", bound_lease);
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    proxy_event(data_dir, service_id, "client_disconnected", bound_lease);
}

/// Bind a lease-authenticated proxy in front of `internal_port`. Returns the public port + handle.
pub(crate) async fn bind_editor_proxy(data_dir: &str, service_id: &str, internal_port: u16, lease_id: &str) -> Result<(u16, EditorProxy), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| e.to_string())?;
    let public_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    proxy_event(data_dir, service_id, "proxy_started", lease_id);
    let dd = data_dir.to_string();
    let lease = lease_id.to_string();
    let sid = service_id.to_string();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => { proxy_event(&dd, &sid, "proxy_stopped", &lease); break; }
                accept = listener.accept() => {
                    let Ok((inbound, _peer)) = accept else { continue; };
                    let (dd2, lease2, sid2) = (dd.clone(), lease.clone(), sid.clone());
                    tokio::spawn(async move { handle_conn(inbound, internal_port, &lease2, &sid2, &dd2).await; });
                }
            }
        }
    });
    Ok((public_port, EditorProxy { public_port, internal_port, lease_id: lease_id.to_string(), service_id: service_id.to_string(), shutdown: tx, join }))
}

/// Tear down a service's proxy if present (deterministic socket close).
pub(crate) fn stop_editor_proxy(proxies: &mut HashMap<String, EditorProxy>, service_id: &str) {
    if let Some(p) = proxies.remove(service_id) {
        let _ = p.shutdown.send(());
    }
}
