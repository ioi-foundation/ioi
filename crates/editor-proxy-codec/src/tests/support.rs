//! Shared test helpers (built on the fuzz harness's raw builders and honest drivers).
#![allow(unused_imports, dead_code)]

pub(crate) use crate::fuzz_support::{
    admit_bytes, daemon_active, daemon_new, event_bytes, facts_for, mode_for, proxy_active,
    proxy_awaiting_welcome, proxy_new, proxy_send_admit, raw_frame, ready_bytes, shutdown_bytes,
    upstream_for, verdict_bytes, welcome_bytes, welcome_for, welcome_spec, Handle, Pool, LABEL,
    PORT, T0, TOKEN, VERDICT_DEADLINE_NS,
};
use crate::{
    D2pRecv, DaemonInput, DaemonSession, DaemonStep, DaemonStepKind, FdBatch, FdFacts, OpId,
    P2dRecv, ProxyInput, ProxySession, ProxyStep, ProxyStepKind, ReceivedFd, SendOutcome,
};
use std::vec::Vec;

/// Daemon: receive `bytes` cleanly.
pub(crate) fn drecv(d: &mut DaemonSession<Handle>, bytes: &[u8]) -> DaemonStep {
    d.step(DaemonInput::Recv(P2dRecv::clean(bytes)))
}

/// Daemon: receive `bytes` cleanly; the step kind.
pub(crate) fn drecv_k(d: &mut DaemonSession<Handle>, bytes: &[u8]) -> DaemonStepKind {
    drecv(d, bytes).kind()
}

/// Proxy: receive `bytes` with descriptors of `facts`.
pub(crate) fn precv(
    p: &mut ProxySession<Handle>,
    pool: &Pool,
    bytes: &[u8],
    facts: &[FdFacts],
) -> ProxyStep<Handle> {
    let mut fds = FdBatch::new();
    for f in facts {
        if let Err(back) = fds.push(ReceivedFd {
            handle: pool.make(*f),
            facts: *f,
        }) {
            drop(back);
        }
    }
    p.step(ProxyInput::Recv(D2pRecv {
        bytes,
        msg_trunc: false,
        msg_ctrunc: false,
        unexpected_control: false,
        fds,
    }))
}

/// Proxy: receive; the step kind (the step's own handles are dropped).
pub(crate) fn precv_k(
    p: &mut ProxySession<Handle>,
    pool: &Pool,
    bytes: &[u8],
    facts: &[FdFacts],
) -> ProxyStepKind {
    precv(p, pool, bytes, facts).kind()
}

/// Daemon: the prepared op (panics if none).
pub(crate) fn dop(d: &DaemonSession<Handle>) -> OpId {
    d.outgoing().expect("a prepared daemon send").op
}

/// Proxy: the prepared op (panics if none).
pub(crate) fn pop(p: &ProxySession<Handle>) -> OpId {
    p.outgoing().expect("a prepared proxy send").op
}

/// Daemon: report the prepared send whole.
pub(crate) fn dwhole(d: &mut DaemonSession<Handle>) -> DaemonStepKind {
    let op = dop(d);
    d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole))
        .kind()
}

/// Proxy: report the prepared send whole.
pub(crate) fn pwhole(p: &mut ProxySession<Handle>) -> ProxyStepKind {
    let op = pop(p);
    p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole))
        .kind()
}

/// A forward ADMIT frame with one digest block.
pub(crate) fn admit1(id: u32) -> Vec<u8> {
    admit_bytes(id, 1, &[[0x11; 32]])
}

/// Daemon in Active (TCP) with `n` admissions committed (ids 1..=n) and unanswered.
pub(crate) fn daemon_with_pending(pool: &Pool, n: u32) -> DaemonSession<Handle> {
    let mut d = daemon_active(pool, crate::ModeKind::ForwardTcp);
    for id in 1..=n {
        assert_eq!(drecv_k(&mut d, &admit1(id)), DaemonStepKind::Admit);
    }
    d
}

/// One daemon-side exchange: receive ADMIT `id` and answer it Denied, whole.
pub(crate) fn daemon_exchange(
    d: &mut DaemonSession<Handle>,
    id: u32,
) -> (DaemonStepKind, DaemonStepKind) {
    let admitted = drecv_k(d, &admit1(id));
    if admitted != DaemonStepKind::Admit {
        return (admitted, DaemonStepKind::Idle);
    }
    let prepared = d
        .step(DaemonInput::PrepareVerdict(
            crate::AdmissionId::from_raw(id),
            crate::VerdictSpec::Denied,
        ))
        .kind();
    if prepared != DaemonStepKind::Send {
        return (prepared, DaemonStepKind::Idle);
    }
    (DaemonStepKind::Admit, dwhole(d))
}

/// A listener FdFacts on the harness port.
pub(crate) fn listener() -> FdFacts {
    FdFacts::loopback_listener(PORT)
}

pub(crate) use crate::fuzz_support::{run_d2p_decode, run_p2d_decode, run_sequence};

/// A deterministic xorshift64* generator (no external crate).
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}
