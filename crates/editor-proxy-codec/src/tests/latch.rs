//! T-LATCH: after the FIRST refusal a session yields exactly one cleanup request (its one Refused
//! step), then only Terminal for every input class: no decoded value, no send, no callback-worthy
//! step, no retained descriptor, and its phase stays Refused(code). Closed absorbs the same way.

use super::support::*;
use crate::{
    AdmissionId, DaemonInput, DaemonPhase, DaemonSession, DaemonStepKind, EventCode, F0Result,
    IpcRefusal, ModeKind, OpId, OutboundAdmit, ProxyInput, ProxyPhase, ProxySession, ProxyStepKind,
    Purpose, SendOutcome, Sha256Digest, StopReason, VerdictSpec,
};
use std::boxed::Box;
use std::string::String;
use std::vec::Vec;

/// A trigger: the session after its triggering input, the refusal wanted, the step it produced.
type DaemonTrigger = Box<dyn Fn(&Pool) -> (DaemonSession<Handle>, IpcRefusal, DaemonStepKind)>;
type ProxyTrigger = Box<dyn Fn(&Pool) -> (ProxySession<Handle>, IpcRefusal, ProxyStepKind)>;

fn daemon_triggers() -> Vec<DaemonTrigger> {
    std::vec![
        Box::new(|_| {
            let mut d = daemon_new();
            let k = drecv_k(&mut d, &admit1(1));
            (d, IpcRefusal::OutOfOrder, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_active(pool, ModeKind::ForwardTcp);
            let k = drecv_k(&mut d, &admit1(0));
            (d, IpcRefusal::ConnNotIncreasing, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_with_pending(pool, 64);
            let k = drecv_k(&mut d, &admit1(65));
            (d, IpcRefusal::TooManyInFlight, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_with_pending(pool, 1);
            let _ = d.step(DaemonInput::PrepareVerdict(
                AdmissionId::from_raw(1),
                VerdictSpec::AdmittedUpstream(pool.make(upstream_for(ModeKind::ForwardTcp))),
            ));
            let op = dop(&d);
            let k = d
                .step(DaemonInput::SendResult(op, SendOutcome::Fatal))
                .kind();
            (d, IpcRefusal::SendFailed, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_with_pending(pool, 1);
            let k = d.step(DaemonInput::TransportEof).kind();
            (d, IpcRefusal::TransportClosed, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_active(pool, ModeKind::Static);
            let mut bad = ready_bytes();
            bad[0] = b'J';
            let k = drecv_k(&mut d, &bad);
            (d, IpcRefusal::BadMagic, k)
        }),
        Box::new(|_| {
            let mut d = daemon_new();
            let _ = drecv(&mut d, &ready_bytes());
            let k = d.step(DaemonInput::F0(F0Result::Fail)).kind();
            (d, IpcRefusal::BoundaryUnverified, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_with_pending(pool, 1);
            let k = d.step(DaemonInput::Tick(T0 - 1)).kind();
            (d, IpcRefusal::ClockRegression, k)
        }),
        Box::new(|pool| {
            let mut d = daemon_active(pool, ModeKind::ForwardTcp);
            let frame = admit1(1);
            let k = d
                .step(DaemonInput::Recv(crate::P2dRecv {
                    bytes: &frame,
                    msg_trunc: false,
                    msg_ctrunc: true,
                    control_present: false,
                }))
                .kind();
            (d, IpcRefusal::AncillaryFromProxy, k)
        }),
    ]
}

/// Every daemon input class, each carrying a descriptor where it can.
fn daemon_battery(d: &mut DaemonSession<Handle>, pool: &Pool) -> Vec<DaemonStepKind> {
    std::vec![
        d.step(DaemonInput::Tick(T0 + 1)).kind(),
        d.step(DaemonInput::Tick(T0 + 60_000_000_000)).kind(),
        drecv_k(d, &ready_bytes()),
        drecv_k(d, &admit1(1000)),
        drecv_k(d, &event_bytes(0, 1, 1)),
        d.step(DaemonInput::F0(F0Result::Pass)).kind(),
        d.step(DaemonInput::F0(F0Result::Fail)).kind(),
        d.step(DaemonInput::PrepareWelcome(
            welcome_spec(ModeKind::ForwardTcp),
            pool.make(listener())
        ))
        .kind(),
        d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(1),
            VerdictSpec::AdmittedUpstream(pool.make(upstream_for(ModeKind::ForwardTcp))),
        ))
        .kind(),
        d.step(DaemonInput::PrepareShutdown).kind(),
        d.step(DaemonInput::SendResult(
            OpId::from_raw(1),
            SendOutcome::SentWhole
        ))
        .kind(),
        d.step(DaemonInput::SendResult(
            OpId::from_raw(2),
            SendOutcome::Fatal
        ))
        .kind(),
        d.step(DaemonInput::Terminate(StopReason::Revoked)).kind(),
        d.step(DaemonInput::TransportEof).kind(),
        d.step(DaemonInput::TransportError).kind(),
    ]
}

#[test]
fn t_latch_daemon_every_refusal_latches() {
    let mut misses: Vec<String> = Vec::new();
    for (i, trigger) in daemon_triggers().iter().enumerate() {
        let pool = Pool::new();
        let (mut d, code, got) = trigger(&pool);
        if got != DaemonStepKind::Refused(code) || d.phase() != DaemonPhase::Refused(code) {
            misses.push(std::format!(
                "T-LATCH daemon trigger {}: want Refused({:?}), got {:?} / phase {:?}",
                i,
                code,
                got,
                d.phase()
            ));
        }
        if d.outgoing().is_some() || pool.live() != 0 || d.test_only_pending_len() != 0 {
            misses.push(std::format!(
                "T-LATCH daemon trigger {}: the refusal kept a prepared send, {} descriptor(s) or {} pending",
                i,
                pool.live(),
                d.test_only_pending_len()
            ));
        }
        for (j, kind) in daemon_battery(&mut d, &pool).into_iter().enumerate() {
            if kind != DaemonStepKind::Terminal || pool.live() != 0 {
                misses.push(std::format!(
                    "T-LATCH daemon trigger {} ({:?}): battery input {} answered {:?} ({} live)",
                    i,
                    code,
                    j,
                    kind,
                    pool.live()
                ));
            }
        }
        if d.phase() != DaemonPhase::Refused(code) || d.outgoing().is_some() {
            misses.push(std::format!(
                "T-LATCH daemon trigger {}: after the battery the phase is {:?}",
                i,
                d.phase()
            ));
        }
    }
    assert!(
        misses.is_empty(),
        "T-LATCH daemon: {} latch violation(s):\n{}",
        misses.len(),
        misses.join("\n")
    );
}

fn admit() -> OutboundAdmit {
    OutboundAdmit::new(Purpose::Forward, &[Sha256Digest::of(b"l")]).expect("one digest")
}

fn proxy_triggers() -> Vec<ProxyTrigger> {
    std::vec![
        Box::new(|pool| {
            let mut p = proxy_new();
            let k = precv_k(
                &mut p,
                pool,
                &welcome_for(ModeKind::ForwardTcp),
                &[listener()],
            );
            (p, IpcRefusal::OutOfOrder, k)
        }),
        Box::new(|pool| {
            let mut p = proxy_active(pool, ModeKind::ForwardTcp);
            let k = precv_k(&mut p, pool, &verdict_bytes(9, 0), &[]);
            (p, IpcRefusal::UnknownVerdict, k)
        }),
        Box::new(|pool| {
            let mut p = proxy_awaiting_welcome();
            let k = precv_k(&mut p, pool, &welcome_for(ModeKind::ForwardTcp), &[]);
            (p, IpcRefusal::BadFdCount, k)
        }),
        Box::new(|pool| {
            let mut p = proxy_active(pool, ModeKind::ForwardTcp);
            let _ = p.step(ProxyInput::PrepareAdmit(admit()));
            let op = pop(&p);
            let k = p
                .step(ProxyInput::SendResult(op, SendOutcome::Short))
                .kind();
            (p, IpcRefusal::SendFailed, k)
        }),
        Box::new(|pool| {
            let mut p = proxy_active(pool, ModeKind::ForwardUnix);
            let k = p.step(ProxyInput::TransportError).kind();
            (p, IpcRefusal::TransportFailed, k)
        }),
        Box::new(|pool| {
            let mut p = proxy_active(pool, ModeKind::Static);
            let _ = proxy_send_admit(&mut p, Purpose::Forward, 1);
            let k = p.step(ProxyInput::Tick(T0 + VERDICT_DEADLINE_NS)).kind();
            (p, IpcRefusal::OperationTimeout, k)
        }),
    ]
}

fn proxy_battery(p: &mut ProxySession<Handle>, pool: &Pool) -> Vec<ProxyStepKind> {
    std::vec![
        p.step(ProxyInput::Tick(T0 + 1)).kind(),
        p.step(ProxyInput::Tick(T0 + 60_000_000_000)).kind(),
        precv_k(p, pool, &welcome_for(ModeKind::ForwardTcp), &[listener()]),
        precv_k(
            p,
            pool,
            &verdict_bytes(1, 1),
            &[upstream_for(ModeKind::ForwardTcp)]
        ),
        precv_k(p, pool, &shutdown_bytes(), &[]),
        p.step(ProxyInput::PrepareReady).kind(),
        p.step(ProxyInput::PrepareAdmit(admit())).kind(),
        p.step(ProxyInput::Observe(EventCode::HostRefused, 3))
            .kind(),
        p.step(ProxyInput::SendResult(
            OpId::from_raw(1),
            SendOutcome::SentWhole
        ))
        .kind(),
        p.step(ProxyInput::Terminate(StopReason::Shutdown)).kind(),
        p.step(ProxyInput::TransportEof).kind(),
    ]
}

#[test]
fn t_latch_proxy_every_refusal_latches() {
    let mut misses: Vec<String> = Vec::new();
    for (i, trigger) in proxy_triggers().iter().enumerate() {
        let pool = Pool::new();
        let (mut p, code, got) = trigger(&pool);
        if got != ProxyStepKind::Refused(code) || p.phase() != ProxyPhase::Refused(code) {
            misses.push(std::format!(
                "T-LATCH proxy trigger {}: want Refused({:?}), got {:?} / phase {:?}",
                i,
                code,
                got,
                p.phase()
            ));
        }
        if p.outgoing().is_some() || p.test_only_pending_len() != 0 {
            misses.push(std::format!(
                "T-LATCH proxy trigger {}: the refusal kept a prepared send or {} pending",
                i,
                p.test_only_pending_len()
            ));
        }
        for (j, kind) in proxy_battery(&mut p, &pool).into_iter().enumerate() {
            if kind != ProxyStepKind::Terminal || pool.live() != 0 {
                misses.push(std::format!(
                    "T-LATCH proxy trigger {} ({:?}): battery input {} answered {:?} ({} live)",
                    i,
                    code,
                    j,
                    kind,
                    pool.live()
                ));
            }
        }
        if p.phase() != ProxyPhase::Refused(code) {
            misses.push(std::format!(
                "T-LATCH proxy trigger {}: after the battery the phase is {:?}",
                i,
                p.phase()
            ));
        }
    }
    assert!(
        misses.is_empty(),
        "T-LATCH proxy: {} latch violation(s):\n{}",
        misses.len(),
        misses.join("\n")
    );
}

#[test]
fn t_latch_closed_absorbs_like_refused() {
    let pool = Pool::new();
    let mut misses: Vec<String> = Vec::new();
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::PrepareShutdown);
    let closed = dwhole(&mut d);
    for (j, kind) in daemon_battery(&mut d, &pool).into_iter().enumerate() {
        if kind != DaemonStepKind::Terminal {
            misses.push(std::format!(
                "T-LATCH Closed daemon (closed by {:?}): input {} answered {:?}",
                closed,
                j,
                kind
            ));
        }
    }
    if d.phase() != DaemonPhase::Closed || d.final_event_summary().is_some() {
        misses.push(std::format!("T-LATCH Closed daemon: phase {:?}", d.phase()));
    }
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let closed = precv_k(&mut p, &pool, &shutdown_bytes(), &[]);
    for (j, kind) in proxy_battery(&mut p, &pool).into_iter().enumerate() {
        if kind != ProxyStepKind::Terminal {
            misses.push(std::format!(
                "T-LATCH Closed proxy (closed by {:?}): input {} answered {:?}",
                closed,
                j,
                kind
            ));
        }
    }
    if p.phase() != ProxyPhase::Closed || pool.live() != 0 {
        misses.push(std::format!(
            "T-LATCH Closed proxy: phase {:?}, {} live",
            p.phase(),
            pool.live()
        ));
    }
    assert!(
        misses.is_empty(),
        "T-LATCH Closed: {} violation(s):\n{}",
        misses.len(),
        misses.join("\n")
    );
}
