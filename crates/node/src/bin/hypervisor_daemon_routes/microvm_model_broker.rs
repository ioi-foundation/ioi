//! M13.10 — the HOST end of the brokered model channel (ADR 0053 § 2).
//!
//! THE SHAPE. `microvm.rs` already speaks the host→guest direction: connect the cloud-hypervisor
//! vsock UDS, write `CONNECT <port>\n`, read `OK`. That is how the workspace and exec protocol
//! reach the guest agent on vsock port 1024. This module is the OTHER direction, which nothing in
//! the estate had: cloud-hypervisor/Firecracker's hybrid vsock exposes a guest-initiated connection
//! as a connection to a per-port socket beside the main one — `<sock_path>_<port>` — so a host
//! process that wants to answer the guest binds that path and waits.
//!
//! WHAT CROSSES. The guest runs `scripts/phase1/guest-model-proxy.c`, which presents HTTP on guest
//! loopback and tunnels raw bytes to vsock port `BROKER_VSOCK_PORT`. This end accepts that stream
//! and connects onward to ONE destination resolved ON THE HOST from the run's own model route. The
//! guest names nothing: not the host, not the port, not the route.
//!
//! WHY THE DESTINATION RULE IS SHARP (R-112). A tunnel connects a host and a port, not a path.
//! Whatever service listens there is reachable in full by whatever the guest chooses to write, so
//! the destination has to be a service that is safe to expose in full. Two refusals enforce that,
//! and both are tests rather than comments:
//!
//!   * NOT LOOPBACK → refused. The brokered channel terminates ON the host. If it could name a
//!     remote address the guest would have raw TCP egress through the host, which is the exact
//!     thing "no network device" exists to prevent. A remote model route is served the way M13.9
//!     already serves it — by the DAEMON making the outbound call with the sealed credential — not
//!     by handing the guest a socket to the internet.
//!   * THE DAEMON'S OWN ADDRESS → refused. `executable_route_endpoint` resolves an
//!     `openai_compatible` route to `http://{IOI_HYPERVISOR_DAEMON_ADDR}/v1`, so the daemon address
//!     is a destination that would otherwise arrive here by an ordinary path. The daemon's posture
//!     is local-trust — it binds loopback and trusts local callers — so exposing its port to a
//!     hostile guest exposes its router, not one route.
//!
//! NAMED RESIDUAL. At an admitted local model endpoint the guest can still reach that model
//! server's non-chat API (for Ollama, model pull and delete). That is a disk and availability
//! exposure, not an authority crossing, and it is named here rather than papered over: path
//! scoping is impossible in a tunnel by construction, and checking only a first request line would
//! be a fence that keep-alive walks straight past. The fence, when it is built, is a host-side
//! model-only reverse proxy standing between this end and the model server.
//!
//! THE DECLARATION (R-111). A VM spec carrying a broker binding CANNOT emit a hostile-guest
//! enforcement declaration — `enforcement_declaration` refuses it with
//! `hostile_guest_profile_excludes_model_broker`. The declaration's `guest_channel` is the const
//! `host_initiated_vsock_uds_bounded`, and rather than widen that const so it can describe two
//! profiles, the narrow profile refuses to produce evidence for the wide one. ADR 0053 § 2 asks for
//! exactly that separation: "a different profile from the hostile-guest one".

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// The vsock port the guest dials for the model channel. 1024 is the guest agent's own port and is
/// deliberately not reused: the two channels are separable at the protocol level, not merely by
/// convention, so a broker stream can never be mistaken for an agent command.
pub(crate) const BROKER_VSOCK_PORT: u32 = 1025;

/// The loopback port the in-guest proxy listens on. It matches Ollama's default so that the
/// harness's `base_url` inside the guest is the ordinary one and no harness code learns it is in a
/// VM. The proxy binds loopback only; there is no network device for it to bind anything else.
pub(crate) const GUEST_LISTEN_PORT: u16 = 11434;

/// How long a brokered connection may sit idle before the host end gives up on it.
const BROKER_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// A resolved, ADMITTED model destination for one run. Constructed only through
/// [`admit_model_broker_destination`]; there is no literal constructor that skips the refusals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelBrokerBinding {
    pub(crate) vsock_port: u32,
    /// `host:port` the HOST end dials onward. Never sourced from the guest.
    pub(crate) destination: String,
}

/// Split an `http://host:port/...` endpoint into its authority, refusing anything this channel must
/// not carry. `daemon_addr` is the daemon's own `host:port` when it knows it (R-112).
pub(crate) fn admit_model_broker_destination(
    endpoint: &str,
    daemon_addr: Option<&str>,
) -> Result<ModelBrokerBinding, String> {
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| "model_broker_destination_not_plain_http".to_string())?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err("model_broker_destination_unparsable".into());
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| "model_broker_destination_has_no_port".to_string())?;
    let port: u16 = port
        .parse()
        .map_err(|_| "model_broker_destination_has_no_port".to_string())?;
    if port == 0 {
        return Err("model_broker_destination_has_no_port".into());
    }
    // LOOPBACK ONLY. The brokered channel terminates on the host.
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        return Err("model_broker_destination_not_loopback".into());
    }
    // NEVER THE DAEMON. Compare the PORT, because the daemon's address and a model endpoint are
    // both loopback and only the port separates them.
    if let Some(addr) = daemon_addr {
        let daemon_port = addr.rsplit_once(':').map(|(_, p)| p).unwrap_or(addr);
        if daemon_port.trim() == port.to_string() {
            return Err("model_broker_destination_is_daemon".into());
        }
    }
    Ok(ModelBrokerBinding {
        vsock_port: BROKER_VSOCK_PORT,
        destination: format!("127.0.0.1:{port}"),
    })
}

/// A live host end. Dropping it stops the accept loop, joins its thread and unlinks the socket:
/// every thread this starts is reaped by the handle that started it.
pub(crate) struct ModelBrokerHandle {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

impl ModelBrokerHandle {
    /// The per-port socket cloud-hypervisor connects to when the guest dials. Named so a verifier
    /// can assert the path rather than re-deriving the convention.
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// How many guest-initiated connections this end has accepted. The honest measure of whether
    /// the channel carried anything: a run that never reached the model shows zero.
    pub(crate) fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for ModelBrokerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop's poll by touching the socket once.
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Bind the guest-initiated side and serve it until the handle is dropped.
pub(crate) fn start_model_broker(
    sock_path: &Path,
    binding: &ModelBrokerBinding,
) -> Result<ModelBrokerHandle, String> {
    let socket_path = PathBuf::from(format!("{}_{}", sock_path.display(), binding.vsock_port));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .map_err(|error| format!("model broker bind {}: {error}", socket_path.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("model broker nonblocking: {error}"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let destination = binding.destination.clone();
    let loop_stop = Arc::clone(&stop);
    let loop_accepted = Arc::clone(&accepted);

    let thread = std::thread::spawn(move || {
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        while !loop_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((guest, _)) => {
                    if loop_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    loop_accepted.fetch_add(1, Ordering::SeqCst);
                    let destination = destination.clone();
                    workers.push(std::thread::spawn(move || {
                        serve_one(guest, &destination);
                    }));
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
    });

    Ok(ModelBrokerHandle {
        socket_path,
        stop,
        accepted,
        thread: Some(thread),
    })
}

/// One guest connection: dial the admitted destination and carry bytes both ways verbatim.
///
/// A failed onward connect CLOSES the guest stream rather than answering it. Writing an error page
/// here would put bytes in front of the harness that the model never sent, and the harness would
/// read them as a model answer.
fn serve_one(guest: UnixStream, destination: &str) {
    let Ok(upstream) = TcpStream::connect(destination) else {
        return;
    };
    let _ = guest.set_read_timeout(Some(BROKER_IO_TIMEOUT));
    let _ = guest.set_write_timeout(Some(BROKER_IO_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(BROKER_IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(BROKER_IO_TIMEOUT));
    let (Ok(guest_out), Ok(upstream_out)) = (guest.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || pump_unix_to_tcp(guest, upstream_out));
    pump_tcp_to_unix(upstream, guest_out);
    let _ = up.join();
}

fn pump_unix_to_tcp(mut from: UnixStream, mut to: TcpStream) {
    let mut buf = [0u8; 65536];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

fn pump_tcp_to_unix(mut from: TcpStream, mut to: UnixStream) {
    let mut buf = [0u8; 65536];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn temp_sock(tag: &str) -> PathBuf {
        PathBuf::from(format!(
            "/tmp/ioi-broker-{tag}-{}-{}.sock",
            std::process::id(),
            nanos()
        ))
    }

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// A loopback server that echoes one request back, standing in for the model endpoint.
    fn echo_server() -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn a_destination_must_be_plain_http_with_a_port() {
        for bad in [
            "https://127.0.0.1:11434/v1",
            "127.0.0.1:11434",
            "http://127.0.0.1/v1",
            "http://127.0.0.1:0/v1",
            "http://",
        ] {
            assert!(
                admit_model_broker_destination(bad, None).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn a_destination_off_the_loopback_is_refused_because_the_channel_terminates_on_the_host() {
        // The whole point of "no network device" is that the guest gets no path off the host. A
        // broker that could name a remote address would hand one back.
        for remote in [
            "http://api.openai.com:443/v1",
            "http://10.0.0.5:11434/v1",
            "http://0.0.0.0:11434/v1",
        ] {
            assert_eq!(
                admit_model_broker_destination(remote, None).unwrap_err(),
                "model_broker_destination_not_loopback"
            );
        }
        assert!(admit_model_broker_destination("http://127.0.0.1:11434/v1", None).is_ok());
        assert!(admit_model_broker_destination("http://localhost:11434/v1", None).is_ok());
    }

    #[test]
    fn the_daemons_own_address_is_refused_even_though_it_is_loopback() {
        // `executable_route_endpoint` resolves a remote route to the DAEMON's address, so this is
        // a destination that arrives here by an ordinary path rather than by malice. The daemon
        // trusts local callers; a tunnel reaches every route it serves, not one.
        let daemon = "127.0.0.1:8765";
        assert_eq!(
            admit_model_broker_destination("http://127.0.0.1:8765/v1", Some(daemon)).unwrap_err(),
            "model_broker_destination_is_daemon"
        );
        // A different loopback port is a model server, not the daemon.
        assert!(admit_model_broker_destination("http://127.0.0.1:11434/v1", Some(daemon)).is_ok());
    }

    #[test]
    fn the_socket_is_the_per_port_path_cloud_hypervisor_connects_to() {
        let sock = temp_sock("path");
        let binding = admit_model_broker_destination("http://127.0.0.1:11434/v1", None).unwrap();
        let broker = start_model_broker(&sock, &binding).unwrap();
        let expected = PathBuf::from(format!("{}_{}", sock.display(), BROKER_VSOCK_PORT));
        assert_eq!(broker.socket_path(), expected.as_path());
        assert!(expected.exists(), "the per-port socket must be bound");
        drop(broker);
        // Reaped: the listener is gone, so a later VM's guest cannot reach a stale host end.
        assert!(
            !expected.exists(),
            "dropping the handle must unlink the socket"
        );
    }

    #[test]
    fn bytes_cross_verbatim_in_both_directions() {
        let (port, echo) = echo_server();
        let sock = temp_sock("bytes");
        let binding =
            admit_model_broker_destination(&format!("http://127.0.0.1:{port}/v1"), None).unwrap();
        let broker = start_model_broker(&sock, &binding).unwrap();

        // Play cloud-hypervisor: when the guest dials the vsock port, the VMM connects here.
        let mut guest = UnixStream::connect(broker.socket_path()).expect("vmm connect");
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: model\r\n\r\n{}";
        guest.write_all(request).unwrap();
        guest.shutdown(std::net::Shutdown::Write).unwrap();
        let mut back = Vec::new();
        guest.read_to_end(&mut back).unwrap();

        assert_eq!(
            back.as_slice(),
            request.as_slice(),
            "a tunnel must deliver exactly what was written, unaltered"
        );
        assert_eq!(broker.accepted_connections(), 1);
        drop(broker);
        let _ = echo.join();
    }

    #[test]
    fn an_unreachable_destination_closes_rather_than_inventing_an_answer() {
        // A broker that answered with its own error page would be putting bytes in front of the
        // harness that no model produced, and the harness would read them as a model answer.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);

        let sock = temp_sock("dead");
        let binding =
            admit_model_broker_destination(&format!("http://127.0.0.1:{port}/v1"), None).unwrap();
        let broker = start_model_broker(&sock, &binding).unwrap();
        let mut guest = UnixStream::connect(broker.socket_path()).expect("vmm connect");
        let _ = guest.write_all(b"GET /v1/models HTTP/1.1\r\n\r\n");
        let mut back = Vec::new();
        let _ = guest.read_to_end(&mut back);
        assert!(
            back.is_empty(),
            "no byte may reach the guest that the model did not send, got {back:?}"
        );
        // NOT VACUOUS: an empty read also describes a broker that never accepted anything, so the
        // silence only means what it claims once the connection is known to have been taken up.
        assert_eq!(
            broker.accepted_connections(),
            1,
            "the broker must have accepted the connection and still answered nothing"
        );
        drop(broker);
    }
}
