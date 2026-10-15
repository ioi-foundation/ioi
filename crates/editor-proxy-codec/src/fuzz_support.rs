//! The three fuzz targets' bodies and the bidirectional OPERATION-SEQUENCE interpreter (DESIGN v2
//! (2), "RED and fuzz proof"). Compiled only under `cfg(test)` or `cfg(fuzzing)`. It builds raw
//! wire bytes from raw values for injection; it holds no encoder of decoded (inbound) values.
//!
//! - [`run_p2d_decode`]: raw P2D bytes into the stateless decoder and into a daemon session in a
//!   chosen phase with chosen receive flags.
//! - [`run_d2p_decode`]: raw D2P bytes, with chosen descriptor facts and flags, into the stateless
//!   decoder and a proxy session in a chosen phase.
//! - [`run_sequence`]: a structure-aware program driving a daemon and a proxy session connected by
//!   in-memory queues: receive flags, typed and raw frames, F0 results, send prepare/results, time
//!   advance, verdicts, shutdown, and bounded REPEAT blocks. One input expands to at most
//!   [`MAX_OPS`] operations; memory is bounded independently ([`MAX_QUEUE`] frames per direction).
//!
//! Every invariant failure PANICS with a message starting "INVARIANT" (the fuzzer's crash):
//! latching (after a session's terminal step, only Terminal and no prepared send), at most one
//! refusal per session, pending <= 64 and <= 2000 admissions per window, at most 12 persisted
//! records per strictly increasing window, descriptor conservation (a receive keeps no descriptor;
//! nothing leaks), the session never accepting a frame the stateless decoder refuses, and HONEST
//! LIVENESS: while no tainting operation has run, an honest exchange never refuses.

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use crate::wire::{KIND_ADMIT, KIND_EVENT, KIND_READY, KIND_SHUTDOWN, KIND_VERDICT, KIND_WELCOME};
use crate::{
    decode_d2p, decode_p2d, AdmissionId, D2pRecv, DaemonConfig, DaemonInput, DaemonPhase,
    DaemonSession, DaemonStep, DaemonStepKind, F0Result, FdBatch, FdFacts, InboundD2p, InboundP2d,
    IpcRefusal, ModeKind, OpId, OutboundAdmit, Outcome, P2dRecv, ProxyConfig, ProxyInput,
    ProxyPhase, ProxySession, ProxyStep, ProxyStepKind, Purpose, ReceivedFd, SendOutcome,
    ServingMode, Sha256Digest, SocketClass, StopReason, VerdictSpec, WelcomeSpec, MAX_FRAME,
    MAX_PENDING, RATE_MAX_ADMITS, RATE_WINDOW_NS,
};

/// The most operations one input expands to.
pub const MAX_OPS: usize = 16384;
/// The most frames queued per direction (the allocation ceiling).
pub const MAX_QUEUE: usize = 256;
/// The harness's spawn time.
pub const T0: u64 = 1_000_000_000_000;
/// The harness's verdict deadline (both sides).
pub const VERDICT_DEADLINE_NS: u64 = 3_000_000_000;
/// The harness's public port.
pub const PORT: u16 = 40001;
/// The harness's host label.
pub const LABEL: [u8; 16] = *b"0123456789abcdef";
/// The harness's runtime token (64 lowercase hex bytes).
pub const TOKEN: [u8; 64] = [b'5'; 64];

/// The sequence grammar's opcodes (each takes the fixed argument bytes named).
pub mod op {
    /// No operation.
    pub const NOP: u8 = 0x00;
    /// + u16 ms: advance the shared clock, tick both sides.
    pub const TICK_BOTH: u8 = 0x01;
    /// + u16 ms: advance the shared clock, tick only the daemon.
    pub const TICK_D: u8 = 0x02;
    /// + u16 ms: advance the shared clock, tick only the proxy.
    pub const TICK_P: u8 = 0x03;
    /// Advance the shared clock by exactly one rate window, tick both.
    pub const TICK_WINDOW: u8 = 0x04;
    /// + u16 ns: tick the daemon BACKWARDS by ns+1.
    pub const TICK_BACK_D: u8 = 0x05;
    /// + u16 ns: tick the proxy backwards by ns+1.
    pub const TICK_BACK_P: u8 = 0x06;
    /// + u32 ns: advance the shared clock, tick both.
    pub const TICK_NS: u8 = 0x07;
    /// Proxy: prepare READY.
    pub const P_READY: u8 = 0x10;
    /// + purpose u8 + n u8: proxy: prepare an ADMIT (purpose 0/1 -> forward/exchange; n % 10).
    pub const P_ADMIT: u8 = 0x11;
    /// + code u8 + count u16 (0xffff = u32::MAX): proxy: observe.
    pub const P_OBSERVE: u8 = 0x12;
    /// Proxy: terminate.
    pub const P_TERMINATE: u8 = 0x13;
    /// + result u8 (0 whole, 1 wouldblock, 2 fatal, 3 short, 4 stale op): proxy send result.
    pub const P_SEND: u8 = 0x14;
    /// + flags u8 (1 trunc, 2 ctrunc, 4 unexpected control, 8 extra fd): proxy receives.
    pub const P_RECV: u8 = 0x15;
    /// Proxy: EOF.
    pub const P_EOF: u8 = 0x16;
    /// + u16 k: position the proxy's allocator at u32::MAX - k (test-only builder).
    pub const P_NEAR_EXHAUSTION: u8 = 0x17;
    /// + flags u8 (1 trunc, 2 ctrunc, 4 control): daemon receives.
    pub const D_RECV: u8 = 0x20;
    /// + pass u8 (even = pass): daemon F0 result.
    pub const D_F0: u8 = 0x21;
    /// + mode u8 (0 tcp, 1 unix, 2 static, 3 port 0, 4 bad label, 5 bad token): daemon WELCOME.
    pub const D_WELCOME: u8 = 0x22;
    /// + selector u8 (0 oldest pending, 1 last completed, 2 forged, 3 next) + outcome u8.
    pub const D_VERDICT: u8 = 0x23;
    /// Daemon: prepare SHUTDOWN.
    pub const D_SHUTDOWN: u8 = 0x24;
    /// + result u8: daemon send result.
    pub const D_SEND: u8 = 0x25;
    /// Daemon: terminate.
    pub const D_TERMINATE: u8 = 0x26;
    /// Daemon: EOF.
    pub const D_EOF: u8 = 0x27;
    /// + len u8 + bytes: push raw P2D bytes to the front of the daemon's queue.
    pub const INJECT_P2D: u8 = 0x30;
    /// + nfds u8 (% 5) + facts[nfds] + len u8 + bytes: push raw D2P bytes to the proxy's queue.
    pub const INJECT_D2P: u8 = 0x31;
    /// + id u32 + purpose u8 + n u8: push a raw ADMIT to the daemon's queue.
    pub const INJECT_ADMIT: u8 = 0x32;
    /// + conn u32 + code u16 + count u32: push a raw EVENT to the daemon's queue.
    pub const INJECT_EVENT: u8 = 0x33;
    /// + id selector u8 + outcome u8 + nfds u8 (% 5) + facts[nfds]: push a raw VERDICT.
    pub const INJECT_VERDICT: u8 = 0x34;
    /// + mode u8: the honest startup (READY, F0 pass, WELCOME), both sides.
    pub const HONEST_STARTUP: u8 = 0x40;
    /// + purpose u8: one honest ADMIT/VERDICT exchange, both sides.
    pub const HONEST_ROUNDTRIP: u8 = 0x41;
    /// + count u16 + len u8, then len body bytes: repeat the body's ops (no nesting).
    pub const REPEAT: u8 = 0xF0;
}

/// A harness descriptor: its facts and a live-count (dropping it "closes" it).
pub struct Handle {
    /// The facts the harness assigned.
    pub facts: FdFacts,
    live: Rc<Cell<i64>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}

/// Makes [`Handle`]s and counts the live ones.
#[derive(Clone)]
pub struct Pool {
    live: Rc<Cell<i64>>,
}

impl Pool {
    /// An empty pool.
    pub fn new() -> Pool {
        Pool {
            live: Rc::new(Cell::new(0)),
        }
    }

    /// A new live handle.
    pub fn make(&self, facts: FdFacts) -> Handle {
        self.live.set(self.live.get() + 1);
        Handle {
            facts,
            live: self.live.clone(),
        }
    }

    /// How many handles are live.
    pub fn live(&self) -> i64 {
        self.live.get()
    }
}

impl Default for Pool {
    fn default() -> Pool {
        Pool::new()
    }
}

/// The correct upstream facts for a mode.
pub fn upstream_for(mode: ModeKind) -> FdFacts {
    match mode {
        ModeKind::ForwardUnix => FdFacts::connected_upstream(SocketClass::UnixStream),
        _ => FdFacts::connected_upstream(SocketClass::InetStream),
    }
}

/// Descriptor facts by selector (0 good listener, 1 unix upstream, 2 inet upstream, 3 listening
/// upstream, 4 unconnected, 5 pending error, 6 peer mismatch, 7 other class, 8 listener on the
/// wrong port, 9 the mode's correct upstream).
pub fn facts_for(selector: u8, mode: ModeKind) -> FdFacts {
    let inet = FdFacts::connected_upstream(SocketClass::InetStream);
    match selector % 10 {
        0 => FdFacts::loopback_listener(PORT),
        1 => FdFacts::connected_upstream(SocketClass::UnixStream),
        2 => inet,
        3 => FdFacts {
            accept_conn: true,
            ..inet
        },
        4 => FdFacts {
            connected: false,
            ..inet
        },
        5 => FdFacts {
            pending_error: true,
            ..inet
        },
        6 => FdFacts {
            peer_matches_spec: false,
            ..inet
        },
        7 => FdFacts {
            class: SocketClass::Other,
            ..inet
        },
        8 => FdFacts::loopback_listener(PORT.wrapping_add(1)),
        _ => upstream_for(mode),
    }
}

/// A raw frame: a correct header for `body`.
pub fn raw_frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(b"IP");
    out.push(2);
    out.push(kind);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(body);
    out
}

/// Raw READY.
pub fn ready_bytes() -> Vec<u8> {
    raw_frame(KIND_READY, &[])
}

/// Raw ADMIT from raw values.
pub fn admit_bytes(id: u32, purpose: u8, digests: &[[u8; 32]]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&id.to_le_bytes());
    body.push(purpose);
    body.push(digests.len() as u8);
    for digest in digests {
        body.extend_from_slice(digest);
    }
    raw_frame(KIND_ADMIT, &body)
}

/// Raw EVENT from raw values.
pub fn event_bytes(conn: u32, code: u16, count: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&conn.to_le_bytes());
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    raw_frame(KIND_EVENT, &body)
}

/// Raw WELCOME from raw values.
pub fn welcome_bytes(
    mode: u8,
    upstream: u8,
    port: u16,
    label: &[u8; 16],
    has_token: u8,
    token: &[u8; 64],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(mode);
    body.push(upstream);
    body.extend_from_slice(&port.to_le_bytes());
    body.extend_from_slice(label);
    body.push(has_token);
    body.extend_from_slice(token);
    raw_frame(KIND_WELCOME, &body)
}

/// Raw WELCOME for a mode with the harness's port, label and token.
pub fn welcome_for(mode: ModeKind) -> Vec<u8> {
    match mode {
        ModeKind::ForwardTcp => welcome_bytes(1, 1, PORT, &LABEL, 0, &[0; 64]),
        ModeKind::ForwardUnix => welcome_bytes(1, 2, PORT, &LABEL, 1, &TOKEN),
        ModeKind::Static => welcome_bytes(2, 0, PORT, &LABEL, 0, &[0; 64]),
    }
}

/// Raw VERDICT.
pub fn verdict_bytes(id: u32, outcome: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&id.to_le_bytes());
    body.push(outcome);
    raw_frame(KIND_VERDICT, &body)
}

/// Raw SHUTDOWN.
pub fn shutdown_bytes() -> Vec<u8> {
    raw_frame(KIND_SHUTDOWN, &[])
}

/// The harness's WELCOME spec for a mode.
pub fn welcome_spec(mode: ModeKind) -> WelcomeSpec {
    WelcomeSpec {
        mode: match mode {
            ModeKind::ForwardTcp => ServingMode::ForwardTcp,
            ModeKind::ForwardUnix => ServingMode::ForwardUnix { token: TOKEN },
            ModeKind::Static => ServingMode::Static,
        },
        public_port: PORT,
        host_label: LABEL,
    }
}

/// The mode for a selector (0 tcp, 1 unix, 2 static).
pub fn mode_for(selector: u8) -> ModeKind {
    match selector % 3 {
        0 => ModeKind::ForwardTcp,
        1 => ModeKind::ForwardUnix,
        _ => ModeKind::Static,
    }
}

/// A fresh daemon session at [`T0`].
pub fn daemon_new() -> DaemonSession<Handle> {
    DaemonSession::new(
        T0,
        DaemonConfig {
            verdict_deadline_ns: VERDICT_DEADLINE_NS,
        },
    )
}

/// A fresh proxy session at [`T0`].
pub fn proxy_new() -> ProxySession<Handle> {
    ProxySession::new(
        T0,
        ProxyConfig {
            verdict_deadline_ns: VERDICT_DEADLINE_NS,
        },
    )
}

/// A daemon driven honestly to Active in `mode` (READY, F0 pass, WELCOME sent whole).
pub fn daemon_active(pool: &Pool, mode: ModeKind) -> DaemonSession<Handle> {
    let mut d = daemon_new();
    let ready = ready_bytes();
    let _ = d.step(DaemonInput::Recv(P2dRecv::clean(&ready)));
    let _ = d.step(DaemonInput::F0(F0Result::Pass));
    let listener = pool.make(FdFacts::loopback_listener(PORT));
    if let DaemonStep::Send(op) = d.step(DaemonInput::PrepareWelcome(welcome_spec(mode), listener))
    {
        let _ = d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole));
    }
    d
}

/// A proxy driven honestly to Active in `mode` (READY sent whole, WELCOME received; the listener
/// output is dropped).
pub fn proxy_active(pool: &Pool, mode: ModeKind) -> ProxySession<Handle> {
    let mut p = proxy_awaiting_welcome();
    let welcome = welcome_for(mode);
    let listener = pool.make(FdFacts::loopback_listener(PORT));
    let fd = ReceivedFd {
        handle: listener,
        facts: FdFacts::loopback_listener(PORT),
    };
    let _ = p.step(ProxyInput::Recv(D2pRecv::with_fd(&welcome, fd)));
    p
}

/// A proxy that has sent READY whole and awaits WELCOME.
pub fn proxy_awaiting_welcome() -> ProxySession<Handle> {
    let mut p = proxy_new();
    if let ProxyStep::Send(op) = p.step(ProxyInput::PrepareReady) {
        let _ = p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole));
    }
    p
}

/// Proxy: prepare and send whole one ADMIT; returns its id.
pub fn proxy_send_admit(
    p: &mut ProxySession<Handle>,
    purpose: Purpose,
    n: usize,
) -> Option<AdmissionId> {
    let digests: Vec<Sha256Digest> = (0..n).map(|i| Sha256Digest::of(&[i as u8])).collect();
    let admit = OutboundAdmit::new(purpose, &digests).ok()?;
    match p.step(ProxyInput::PrepareAdmit(admit)) {
        ProxyStep::Send(op) => match p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole)) {
            ProxyStep::AdmitSent(id) => Some(id),
            _ => None,
        },
        _ => None,
    }
}

// ------------------------------------------------------------------------------------------------
// Raw decode targets
// ------------------------------------------------------------------------------------------------

/// Daemon phase by selector: 0 AwaitReady, 1 CheckingF0, 2 Active (TCP), 3 Active (static).
fn daemon_in(selector: u8, pool: &Pool) -> DaemonSession<Handle> {
    match selector % 4 {
        0 => daemon_new(),
        1 => {
            let mut d = daemon_new();
            let ready = ready_bytes();
            let _ = d.step(DaemonInput::Recv(P2dRecv::clean(&ready)));
            d
        }
        2 => daemon_active(pool, ModeKind::ForwardTcp),
        _ => daemon_active(pool, ModeKind::Static),
    }
}

/// The raw P2D decode target: `data[0]` selects the daemon's phase (bits 0-1) and the receive flags
/// (4 trunc, 8 ctrunc, 16 control); the rest is the frame.
pub fn run_p2d_decode(data: &[u8]) {
    let (selector, frame) = match data.split_first() {
        Some((selector, frame)) => (*selector, frame),
        None => return,
    };
    let stateless = decode_p2d(frame);
    if let Ok(InboundP2d::Admit(admit)) = &stateless {
        assert!(
            admit.presented().len() <= 8 && frame.len() <= MAX_FRAME,
            "INVARIANT decode: an accepted ADMIT exceeds its bounds"
        );
    }
    let pool = Pool::new();
    let mut d = daemon_in(selector, &pool);
    let recv = P2dRecv {
        bytes: frame,
        msg_trunc: selector & 4 != 0,
        msg_ctrunc: selector & 8 != 0,
        control_present: selector & 16 != 0,
    };
    let step = d.step(DaemonInput::Recv(recv));
    let refused = matches!(step.kind(), DaemonStepKind::Refused(_));
    if stateless.is_err() {
        assert!(
            refused,
            "INVARIANT decode: the daemon session accepted a frame the stateless decoder refuses"
        );
    }
    drop(step);
    if refused {
        assert_eq!(
            d.step(DaemonInput::Tick(u64::MAX)).kind(),
            DaemonStepKind::Terminal,
            "INVARIANT latch: a refused daemon session answered again"
        );
        assert!(
            d.outgoing().is_none(),
            "INVARIANT latch: refused with a prepared send"
        );
    }
    drop(d);
    assert_eq!(
        pool.live(),
        0,
        "INVARIANT fds: a daemon session leaked a descriptor"
    );
}

/// Proxy phase by selector: 0 AwaitWelcome; 1/2/3 Active (TCP/UNIX/static) with admissions 1 and
/// 2 (forward) and 3 (lease exchange) pending.
fn proxy_in(selector: u8, pool: &Pool) -> (ProxySession<Handle>, ModeKind) {
    match selector % 4 {
        0 => (proxy_awaiting_welcome(), ModeKind::Static),
        s => {
            let mode = mode_for(s - 1);
            let mut p = proxy_active(pool, mode);
            let _ = proxy_send_admit(&mut p, Purpose::Forward, 1);
            let _ = proxy_send_admit(&mut p, Purpose::Forward, 2);
            let _ = proxy_send_admit(&mut p, Purpose::LeaseExchange, 1);
            (p, mode)
        }
    }
}

/// The raw D2P decode target: `data[0]` selects the proxy's phase (bits 0-1) and the flags (4
/// trunc, 8 ctrunc, 16 unexpected control); `data[1] % 5` descriptors follow, one facts selector
/// byte each; the rest is the frame.
pub fn run_d2p_decode(data: &[u8]) {
    let (selector, rest) = match data.split_first() {
        Some((selector, rest)) => (*selector, rest),
        None => return,
    };
    let (count, rest) = match rest.split_first() {
        Some((count, rest)) => ((*count % 5) as usize, rest),
        None => return,
    };
    if rest.len() < count {
        return;
    }
    let (selectors, frame) = rest.split_at(count);
    let stateless = decode_d2p(frame);
    if let Ok(InboundD2p::Welcome(welcome)) = &stateless {
        assert!(
            welcome.public_port() != 0 && welcome.host_label().len() == 16,
            "INVARIANT decode: an accepted WELCOME is out of bounds"
        );
    }
    let pool = Pool::new();
    let (mut p, mode) = proxy_in(selector, &pool);
    let base = pool.live();
    let mut fds = FdBatch::new();
    for s in selectors {
        let facts = facts_for(*s, mode);
        if let Err(back) = fds.push(ReceivedFd {
            handle: pool.make(facts),
            facts,
        }) {
            drop(back);
        }
    }
    let recv = D2pRecv {
        bytes: frame,
        msg_trunc: selector & 4 != 0,
        msg_ctrunc: selector & 8 != 0,
        unexpected_control: selector & 16 != 0,
        fds,
    };
    let step = p.step(ProxyInput::Recv(recv));
    let refused = matches!(step.kind(), ProxyStepKind::Refused(_));
    if stateless.is_err() {
        assert!(
            refused,
            "INVARIANT decode: the proxy session accepted a frame the stateless decoder refuses"
        );
    }
    if let ProxyStep::Verdict(_, outcome, upstream) = &step {
        assert_eq!(
            upstream.is_some(),
            *outcome == Outcome::AdmittedUpstream,
            "INVARIANT fds: a VERDICT's descriptor does not match its outcome"
        );
    }
    drop(step);
    assert_eq!(
        pool.live(),
        base,
        "INVARIANT fds: a proxy receive kept a descriptor"
    );
    if refused {
        assert_eq!(
            p.step(ProxyInput::Tick(u64::MAX)).kind(),
            ProxyStepKind::Terminal,
            "INVARIANT latch: a refused proxy session answered again"
        );
    }
    drop(p);
    assert_eq!(
        pool.live(),
        0,
        "INVARIANT fds: a proxy session leaked a descriptor"
    );
}

// ------------------------------------------------------------------------------------------------
// The sequence interpreter
// ------------------------------------------------------------------------------------------------

/// What one sequence did (for the named-seed replay assertions).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// The daemon's final phase.
    pub daemon: DaemonPhase,
    /// The proxy's final phase.
    pub proxy: ProxyPhase,
    /// The daemon's refusal, if any.
    pub daemon_refusal: Option<IpcRefusal>,
    /// The proxy's refusal, if any.
    pub proxy_refusal: Option<IpcRefusal>,
    /// Daemon Admit steps.
    pub admits: u64,
    /// Daemon VerdictSent steps.
    pub verdicts_sent: u64,
    /// Proxy Verdict steps.
    pub verdicts: u64,
    /// Persisted daemon event records.
    pub persisted: u64,
    /// Proxy AdmitSent steps.
    pub admits_sent: u64,
    /// Operations executed.
    pub ops: usize,
    /// Whether a tainting operation ran.
    pub tainted: bool,
}

struct WireD2p {
    bytes: Vec<u8>,
    fds: Vec<FdFacts>,
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let lo = self.u8()?;
        let hi = self.u8()?;
        Some(u16::from_le_bytes([lo, hi]))
    }

    fn u32(&mut self) -> Option<u32> {
        let a = self.u16()?;
        let b = self.u16()?;
        Some(a as u32 | ((b as u32) << 16))
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.data.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
}

struct World {
    pool: Pool,
    now: u64,
    d: DaemonSession<Handle>,
    p: ProxySession<Handle>,
    d_done: bool,
    p_done: bool,
    report: Report,
    p2d: VecDeque<Vec<u8>>,
    d2p: VecDeque<WireD2p>,
    in_honest: bool,
    last_window: Option<u64>,
}

impl World {
    fn new() -> World {
        let d = daemon_new();
        let p = proxy_new();
        World {
            pool: Pool::new(),
            now: T0,
            report: Report {
                daemon: d.phase(),
                proxy: p.phase(),
                daemon_refusal: None,
                proxy_refusal: None,
                admits: 0,
                verdicts_sent: 0,
                verdicts: 0,
                persisted: 0,
                admits_sent: 0,
                ops: 0,
                tainted: false,
            },
            d,
            p,
            d_done: false,
            p_done: false,
            p2d: VecDeque::new(),
            d2p: VecDeque::new(),
            in_honest: false,
            last_window: None,
        }
    }

    fn taint(&mut self) {
        self.report.tainted = true;
    }

    fn honest_checked(&self) -> bool {
        self.in_honest && !self.report.tainted
    }

    fn dstep(&mut self, input: DaemonInput<'_, Handle>) -> DaemonStep {
        let step = self.d.step(input);
        let kind = step.kind();
        if self.d_done {
            assert_eq!(
                kind,
                DaemonStepKind::Terminal,
                "INVARIANT latch: the daemon answered after its terminal step"
            );
        } else {
            match &step {
                DaemonStep::Refused(code) => {
                    assert!(
                        !self.honest_checked(),
                        "INVARIANT honest: the daemon refused {:?} in an honest exchange",
                        code
                    );
                    self.report.daemon_refusal = Some(*code);
                    self.d_done = true;
                }
                DaemonStep::Teardown => self.d_done = true,
                DaemonStep::Terminal => panic!("INVARIANT latch: daemon Terminal before terminal"),
                DaemonStep::Admit(_) => self.report.admits += 1,
                DaemonStep::VerdictSent(_) => self.report.verdicts_sent += 1,
                DaemonStep::Persist(records) => {
                    assert!(
                        !records.is_empty() && records.len() <= 12,
                        "INVARIANT events: a persisted window holds {} records",
                        records.len()
                    );
                    if let Some(last) = self.last_window {
                        assert!(
                            records.window() > last,
                            "INVARIANT events: window {} persisted again or out of order",
                            records.window()
                        );
                    }
                    self.last_window = Some(records.window());
                    self.report.persisted += records.len() as u64;
                }
                _ => {}
            }
        }
        if self.d_done {
            assert!(
                self.d.outgoing().is_none(),
                "INVARIANT latch: a terminal daemon holds a prepared send"
            );
            assert!(
                matches!(
                    self.d.phase(),
                    DaemonPhase::Closed | DaemonPhase::Refused(_)
                ),
                "INVARIANT latch: the daemon's phase is live after its terminal step"
            );
        }
        assert!(
            self.d.test_only_pending_len() <= MAX_PENDING,
            "INVARIANT limits: daemon pending above 64"
        );
        assert!(
            self.d.test_only_window_admissions() <= RATE_MAX_ADMITS,
            "INVARIANT limits: daemon window admissions above 2000"
        );
        let held = self.d.outgoing().map(|o| o.fd.is_some()).unwrap_or(false) as i64;
        assert_eq!(
            self.pool.live(),
            held,
            "INVARIANT fds: live descriptors other than the daemon's prepared one"
        );
        step
    }

    fn pstep(&mut self, input: ProxyInput<'_, Handle>) -> ProxyStep<Handle> {
        let step = self.p.step(input);
        let kind = step.kind();
        if self.p_done {
            assert_eq!(
                kind,
                ProxyStepKind::Terminal,
                "INVARIANT latch: the proxy answered after its terminal step"
            );
        } else {
            match &step {
                ProxyStep::Refused(code) => {
                    assert!(
                        !self.honest_checked(),
                        "INVARIANT honest: the proxy refused {:?} in an honest exchange",
                        code
                    );
                    self.report.proxy_refusal = Some(*code);
                    self.p_done = true;
                }
                ProxyStep::Close => self.p_done = true,
                ProxyStep::Terminal => panic!("INVARIANT latch: proxy Terminal before terminal"),
                ProxyStep::Verdict(_, outcome, upstream) => {
                    assert_eq!(
                        upstream.is_some(),
                        *outcome == Outcome::AdmittedUpstream,
                        "INVARIANT fds: a VERDICT's descriptor does not match its outcome"
                    );
                    self.report.verdicts += 1;
                }
                ProxyStep::AdmitSent(_) => self.report.admits_sent += 1,
                _ => {}
            }
        }
        if self.p_done {
            assert!(
                self.p.outgoing().is_none(),
                "INVARIANT latch: a terminal proxy holds a prepared send"
            );
        }
        assert!(
            self.p.test_only_pending_len() <= MAX_PENDING,
            "INVARIANT limits: proxy pending above 64"
        );
        assert!(
            self.p.test_only_window_admissions() <= RATE_MAX_ADMITS,
            "INVARIANT limits: proxy window admissions above 2000"
        );
        step
    }

    fn push_p2d(&mut self, front: bool, bytes: Vec<u8>) {
        if self.p2d.len() >= MAX_QUEUE {
            self.taint();
            return;
        }
        if front {
            self.p2d.push_front(bytes);
        } else {
            self.p2d.push_back(bytes);
        }
    }

    fn push_d2p(&mut self, front: bool, wire: WireD2p) {
        if self.d2p.len() >= MAX_QUEUE {
            self.taint();
            return;
        }
        if front {
            self.d2p.push_front(wire);
        } else {
            self.d2p.push_back(wire);
        }
    }

    /// Daemon receive of the next queued frame; returns the committed admission, if any.
    fn d_recv(&mut self, flags: u8) -> Option<(AdmissionId, Purpose)> {
        let bytes = self.p2d.pop_front()?;
        let recv = P2dRecv {
            bytes: &bytes,
            msg_trunc: flags & 1 != 0,
            msg_ctrunc: flags & 2 != 0,
            control_present: flags & 4 != 0,
        };
        match self.dstep(DaemonInput::Recv(recv)) {
            DaemonStep::Admit(admit) => Some((admit.id(), admit.purpose())),
            _ => None,
        }
    }

    fn p_recv(&mut self, flags: u8) {
        let wire = match self.d2p.pop_front() {
            Some(wire) => wire,
            None => return,
        };
        let before = self.pool.live();
        let mut fds = FdBatch::new();
        let mut made = 0;
        for facts in &wire.fds {
            made += 1;
            if let Err(back) = fds.push(ReceivedFd {
                handle: self.pool.make(*facts),
                facts: *facts,
            }) {
                drop(back);
            }
        }
        if flags & 8 != 0 {
            let facts = FdFacts::loopback_listener(PORT);
            made += 1;
            if let Err(back) = fds.push(ReceivedFd {
                handle: self.pool.make(facts),
                facts,
            }) {
                drop(back);
            }
        }
        let _ = made;
        let recv = D2pRecv {
            bytes: &wire.bytes,
            msg_trunc: flags & 1 != 0,
            msg_ctrunc: flags & 2 != 0,
            unexpected_control: flags & 4 != 0,
            fds,
        };
        let step = self.pstep(ProxyInput::Recv(recv));
        drop(step);
        assert_eq!(
            self.pool.live(),
            before,
            "INVARIANT fds: a proxy receive kept a descriptor"
        );
    }

    fn d_send(&mut self, result: u8) {
        let (op, bytes, fd) = match self.d.outgoing() {
            Some(out) => (out.op, out.bytes.to_vec(), out.fd.map(|h| h.facts)),
            None => (OpId::from_raw(1 << 40), Vec::new(), None),
        };
        let (outcome, op) = send_choice(result, op);
        let step = self.dstep(DaemonInput::SendResult(op, outcome));
        let committed = outcome == SendOutcome::SentWhole
            && !bytes.is_empty()
            && matches!(
                step.kind(),
                DaemonStepKind::WelcomeSent
                    | DaemonStepKind::VerdictSent
                    | DaemonStepKind::Teardown
            );
        if committed {
            self.push_d2p(
                false,
                WireD2p {
                    bytes,
                    fds: fd.into_iter().collect(),
                },
            );
        }
    }

    fn p_send(&mut self, result: u8) {
        let (op, bytes, had) = match self.p.outgoing() {
            Some(out) => (out.op, out.bytes.to_vec(), true),
            None => (OpId::from_raw(1 << 40), Vec::new(), false),
        };
        let (outcome, op) = send_choice(result, op);
        let step = self.pstep(ProxyInput::SendResult(op, outcome));
        let committed = had
            && outcome == SendOutcome::SentWhole
            && result % 5 == 0
            && matches!(step.kind(), ProxyStepKind::Idle | ProxyStepKind::AdmitSent);
        if committed {
            self.push_p2d(false, bytes);
        }
    }

    fn tick_both(&mut self) {
        let honest = !self.report.tainted
            && self.d.phase() == DaemonPhase::Active
            && self.p.phase() == ProxyPhase::Active;
        self.in_honest = honest;
        let now = self.now;
        let _ = self.dstep(DaemonInput::Tick(now));
        let _ = self.pstep(ProxyInput::Tick(now));
        if !self.report.tainted {
            self.honest_drain();
        }
        self.in_honest = false;
    }

    /// Sends the proxy's prepared EVENTs whole and delivers them.
    fn honest_drain(&mut self) {
        for _ in 0..16 {
            if self.p.outgoing().is_none() || self.p_done {
                break;
            }
            self.p_send(0);
            let _ = self.d_recv(0);
            let now = self.now;
            let _ = self.pstep(ProxyInput::Tick(now));
        }
    }

    fn honest_startup(&mut self, mode: ModeKind) {
        if self.p.phase() != ProxyPhase::Bootstrap || self.d.phase() != DaemonPhase::AwaitReady {
            return;
        }
        self.in_honest = true;
        if let ProxyStep::Send(_) = self.pstep(ProxyInput::PrepareReady) {
            self.p_send(0);
        }
        let _ = self.d_recv(0);
        if self.d.phase() == DaemonPhase::CheckingF0 {
            let _ = self.dstep(DaemonInput::F0(F0Result::Pass));
        }
        if self.d.phase() == DaemonPhase::WelcomeReady {
            let listener = self.pool.make(FdFacts::loopback_listener(PORT));
            if let DaemonStep::Send(_) =
                self.dstep(DaemonInput::PrepareWelcome(welcome_spec(mode), listener))
            {
                self.d_send(0);
            }
        }
        self.p_recv(0);
        self.in_honest = false;
    }

    fn honest_roundtrip(&mut self, purpose: Purpose) {
        if self.d.phase() != DaemonPhase::Active || self.p.can_prepare_admit().is_err() {
            return;
        }
        self.in_honest = true;
        let serial = self.report.admits_sent;
        let digest = Sha256Digest::of(&serial.to_le_bytes());
        if let Ok(admit) = OutboundAdmit::new(purpose, &[digest]) {
            if let ProxyStep::Send(_) = self.pstep(ProxyInput::PrepareAdmit(admit)) {
                self.p_send(0);
            }
        }
        if let Some((id, purpose)) = self.d_recv(0) {
            let mode = self.d.test_only_mode().unwrap_or(ModeKind::Static);
            let verdict = match (mode, purpose) {
                (ModeKind::ForwardTcp | ModeKind::ForwardUnix, Purpose::Forward) => {
                    VerdictSpec::AdmittedUpstream(self.pool.make(upstream_for(mode)))
                }
                _ => VerdictSpec::AdmittedNoUpstream,
            };
            if let DaemonStep::Send(_) = self.dstep(DaemonInput::PrepareVerdict(id, verdict)) {
                self.d_send(0);
            }
            self.p_recv(0);
        }
        self.in_honest = false;
    }

    fn exec(&mut self, cursor: &mut Cursor<'_>, nested: bool) -> Option<()> {
        let opcode = cursor.u8()?;
        self.report.ops += 1;
        match opcode {
            op::TICK_BOTH => {
                let ms = cursor.u16()? as u64;
                self.now = self.now.saturating_add(ms * 1_000_000);
                self.tick_both();
            }
            op::TICK_D | op::TICK_P => {
                let ms = cursor.u16()? as u64;
                self.taint();
                self.now = self.now.saturating_add(ms * 1_000_000);
                let now = self.now;
                if opcode == op::TICK_D {
                    let _ = self.dstep(DaemonInput::Tick(now));
                } else {
                    let _ = self.pstep(ProxyInput::Tick(now));
                }
            }
            op::TICK_WINDOW => {
                self.now = self.now.saturating_add(RATE_WINDOW_NS);
                self.tick_both();
            }
            op::TICK_BACK_D | op::TICK_BACK_P => {
                let back = cursor.u16()? as u64 + 1;
                self.taint();
                let then = self.now.saturating_sub(back);
                if opcode == op::TICK_BACK_D {
                    let _ = self.dstep(DaemonInput::Tick(then));
                } else {
                    let _ = self.pstep(ProxyInput::Tick(then));
                }
            }
            op::TICK_NS => {
                let ns = cursor.u32()? as u64;
                self.now = self.now.saturating_add(ns);
                self.tick_both();
            }
            op::P_READY => {
                self.taint();
                let _ = self.pstep(ProxyInput::PrepareReady);
            }
            op::P_ADMIT => {
                let purpose = cursor.u8()?;
                let n = (cursor.u8()? % 10) as usize;
                self.taint();
                let purpose = if purpose % 2 == 0 {
                    Purpose::Forward
                } else {
                    Purpose::LeaseExchange
                };
                let digests: Vec<Sha256Digest> = (0..n.min(8))
                    .map(|i| Sha256Digest::of(&[i as u8]))
                    .collect();
                if let Ok(admit) = OutboundAdmit::new(purpose, &digests) {
                    let _ = self.pstep(ProxyInput::PrepareAdmit(admit));
                }
            }
            op::P_OBSERVE => {
                let code = cursor.u8()?;
                let count = cursor.u16()?;
                let count = if count == u16::MAX {
                    u32::MAX
                } else {
                    count as u32
                };
                let code = crate::EventCode::ALL[(code % 12) as usize];
                let _ = self.pstep(ProxyInput::Observe(code, count));
            }
            op::P_TERMINATE => {
                self.taint();
                let _ = self.pstep(ProxyInput::Terminate(StopReason::Shutdown));
            }
            op::P_SEND => {
                let result = cursor.u8()?;
                self.taint();
                self.p_send(result);
            }
            op::P_RECV => {
                let flags = cursor.u8()?;
                self.taint();
                self.p_recv(flags);
            }
            op::P_EOF => {
                self.taint();
                let _ = self.pstep(ProxyInput::TransportEof);
            }
            op::P_NEAR_EXHAUSTION => {
                let k = cursor.u16()? as u32;
                let _ = self.p.test_only_set_next_id(u32::MAX - k);
            }
            op::D_RECV => {
                let flags = cursor.u8()?;
                self.taint();
                let _ = self.d_recv(flags);
            }
            op::D_F0 => {
                let pass = cursor.u8()?;
                self.taint();
                let result = if pass % 2 == 0 {
                    F0Result::Pass
                } else {
                    F0Result::Fail
                };
                let _ = self.dstep(DaemonInput::F0(result));
            }
            op::D_WELCOME => {
                let selector = cursor.u8()?;
                self.taint();
                let mut spec = welcome_spec(mode_for(selector));
                match selector % 6 {
                    3 => spec.public_port = 0,
                    4 => spec.host_label[0] = b'G',
                    5 => spec.mode = ServingMode::ForwardUnix { token: [b'G'; 64] },
                    _ => {}
                }
                let listener = self.pool.make(FdFacts::loopback_listener(PORT));
                let _ = self.dstep(DaemonInput::PrepareWelcome(spec, listener));
            }
            op::D_VERDICT => {
                let selector = cursor.u8()?;
                let outcome = cursor.u8()?;
                self.taint();
                let id = match selector % 4 {
                    0 => self.d.test_only_answerable(),
                    1 => self.d.test_only_last_completed(),
                    2 => Some(AdmissionId::from_raw(0x7fff_ffff)),
                    _ => None,
                }
                .unwrap_or(AdmissionId::from_raw(0x7fff_fffe));
                let mode = self.d.test_only_mode().unwrap_or(ModeKind::Static);
                let verdict = match outcome % 4 {
                    0 => VerdictSpec::Denied,
                    1 => VerdictSpec::AdmittedUpstream(self.pool.make(upstream_for(mode))),
                    2 => VerdictSpec::AdmittedNoUpstream,
                    _ => VerdictSpec::UpstreamUnavailable,
                };
                let _ = self.dstep(DaemonInput::PrepareVerdict(id, verdict));
            }
            op::D_SHUTDOWN => {
                self.taint();
                let _ = self.dstep(DaemonInput::PrepareShutdown);
            }
            op::D_SEND => {
                let result = cursor.u8()?;
                self.taint();
                self.d_send(result);
            }
            op::D_TERMINATE => {
                self.taint();
                let _ = self.dstep(DaemonInput::Terminate(StopReason::Revoked));
            }
            op::D_EOF => {
                self.taint();
                let _ = self.dstep(DaemonInput::TransportEof);
            }
            op::INJECT_P2D => {
                let len = cursor.u8()? as usize;
                let bytes = cursor.bytes(len)?.to_vec();
                self.taint();
                self.push_p2d(true, bytes);
            }
            op::INJECT_D2P => {
                let count = (cursor.u8()? % 5) as usize;
                let selectors = cursor.bytes(count)?;
                let len = cursor.u8()? as usize;
                let bytes = cursor.bytes(len)?.to_vec();
                self.taint();
                let mode = self.d.test_only_mode().unwrap_or(ModeKind::ForwardTcp);
                let fds = selectors.iter().map(|s| facts_for(*s, mode)).collect();
                self.push_d2p(true, WireD2p { bytes, fds });
            }
            op::INJECT_ADMIT => {
                let id = cursor.u32()?;
                let purpose = cursor.u8()?;
                let n = (cursor.u8()? % 10) as usize;
                self.taint();
                let digests: Vec<[u8; 32]> = (0..n).map(|i| [i as u8; 32]).collect();
                self.push_p2d(true, admit_bytes(id, purpose, &digests));
            }
            op::INJECT_EVENT => {
                let conn = cursor.u32()?;
                let code = cursor.u16()?;
                let count = cursor.u32()?;
                self.taint();
                self.push_p2d(true, event_bytes(conn, code, count));
            }
            op::INJECT_VERDICT => {
                let selector = cursor.u8()?;
                let outcome = cursor.u8()?;
                let count = (cursor.u8()? % 5) as usize;
                let selectors = cursor.bytes(count)?;
                self.taint();
                let id = match selector % 3 {
                    0 => self.p.test_only_answerable(),
                    1 => self.p.test_only_last_completed(),
                    _ => None,
                }
                .map(|id| id.get())
                .unwrap_or(0x7fff_ffff);
                let mode = self.d.test_only_mode().unwrap_or(ModeKind::ForwardTcp);
                let fds = selectors.iter().map(|s| facts_for(*s, mode)).collect();
                self.push_d2p(
                    true,
                    WireD2p {
                        bytes: verdict_bytes(id, outcome),
                        fds,
                    },
                );
            }
            op::HONEST_STARTUP => {
                let mode = mode_for(cursor.u8()?);
                self.honest_startup(mode);
            }
            op::HONEST_ROUNDTRIP => {
                let purpose = if cursor.u8()? % 2 == 0 {
                    Purpose::Forward
                } else {
                    Purpose::LeaseExchange
                };
                self.honest_roundtrip(purpose);
            }
            op::REPEAT => {
                let count = cursor.u16()?;
                let len = cursor.u8()? as usize;
                let body = cursor.bytes(len)?;
                if !nested {
                    for _ in 0..count {
                        let mut inner = Cursor { data: body, at: 0 };
                        while inner.at < body.len() {
                            if self.report.ops >= MAX_OPS {
                                return Some(());
                            }
                            if self.exec(&mut inner, true).is_none() {
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Some(())
    }
}

fn send_choice(result: u8, op: OpId) -> (SendOutcome, OpId) {
    match result % 5 {
        0 => (SendOutcome::SentWhole, op),
        1 => (SendOutcome::WouldBlock, op),
        2 => (SendOutcome::Fatal, op),
        3 => (SendOutcome::Short, op),
        _ => (
            SendOutcome::SentWhole,
            OpId::from_raw(op.get().wrapping_add(1000)),
        ),
    }
}

/// Runs one operation-sequence program; panics ("INVARIANT ...") on any invariant failure.
pub fn run_sequence(data: &[u8]) -> Report {
    let mut world = World::new();
    let mut cursor = Cursor { data, at: 0 };
    while cursor.at < data.len() && world.report.ops < MAX_OPS {
        if world.exec(&mut cursor, false).is_none() {
            break;
        }
    }
    world.report.daemon = world.d.phase();
    world.report.proxy = world.p.phase();
    let report = world.report;
    let pool = world.pool.clone();
    drop(world);
    assert_eq!(
        pool.live(),
        0,
        "INVARIANT fds: the sequence leaked a descriptor"
    );
    report
}
