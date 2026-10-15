//! T-SESSION: a table-driven REFERENCE MODEL of both machines (DESIGN v2 (2)'s transition table),
//! checked against every (phase, input class) pair: each allowed row, each forbidden phase/kind
//! pair, each send completion. The reference below is written from the design's table, not from
//! the machines' code. Precedence pairs are in `decode.rs`.

use super::support::*;
use crate::{
    AdmissionId, DaemonInput, DaemonPhase, DaemonSession, DaemonStepKind, EventCode, F0Result,
    IpcRefusal, ModeKind, OpId, OutboundAdmit, ProxyInput, ProxyPhase, ProxySession, ProxyStepKind,
    Purpose, SendOutcome, Sha256Digest, StopReason, VerdictSpec,
};
use std::string::String;
use std::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dp {
    AwaitReady,
    CheckingF0,
    WelcomeReady,
    WelcomePrepared,
    Active,
    ActiveSending,
    Stopping,
    StoppingShutdown,
    Closed,
    Refused,
}

const DPS: [Dp; 10] = [
    Dp::AwaitReady,
    Dp::CheckingF0,
    Dp::WelcomeReady,
    Dp::WelcomePrepared,
    Dp::Active,
    Dp::ActiveSending,
    Dp::Stopping,
    Dp::StoppingShutdown,
    Dp::Closed,
    Dp::Refused,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Di {
    TickSame,
    TickBack,
    RecvReady,
    RecvAdmit,
    RecvEvent,
    F0Pass,
    F0Fail,
    PrepWelcome,
    PrepVerdict,
    PrepShutdown,
    SendWhole,
    SendWouldBlock,
    SendStale,
    SendFatal,
    Terminate,
    Eof,
    Error,
}

const DIS: [Di; 17] = [
    Di::TickSame,
    Di::TickBack,
    Di::RecvReady,
    Di::RecvAdmit,
    Di::RecvEvent,
    Di::F0Pass,
    Di::F0Fail,
    Di::PrepWelcome,
    Di::PrepVerdict,
    Di::PrepShutdown,
    Di::SendWhole,
    Di::SendWouldBlock,
    Di::SendStale,
    Di::SendFatal,
    Di::Terminate,
    Di::Eof,
    Di::Error,
];

fn build_daemon(case: Dp, pool: &Pool) -> DaemonSession<Handle> {
    let mut d = daemon_new();
    match case {
        Dp::AwaitReady => {}
        Dp::CheckingF0 => {
            let _ = drecv(&mut d, &ready_bytes());
        }
        Dp::WelcomeReady | Dp::WelcomePrepared => {
            let _ = drecv(&mut d, &ready_bytes());
            let _ = d.step(DaemonInput::F0(F0Result::Pass));
            if case == Dp::WelcomePrepared {
                let _ = d.step(DaemonInput::PrepareWelcome(
                    welcome_spec(ModeKind::ForwardTcp),
                    pool.make(listener()),
                ));
            }
        }
        Dp::Active | Dp::ActiveSending | Dp::Stopping | Dp::StoppingShutdown | Dp::Closed => {
            d = daemon_with_pending(pool, 1);
            match case {
                Dp::ActiveSending => {
                    let _ = d.step(DaemonInput::PrepareVerdict(
                        AdmissionId::from_raw(1),
                        VerdictSpec::Denied,
                    ));
                }
                Dp::Stopping | Dp::StoppingShutdown | Dp::Closed => {
                    let _ = d.step(DaemonInput::Terminate(StopReason::Revoked));
                    if case != Dp::Stopping {
                        let _ = d.step(DaemonInput::PrepareShutdown);
                    }
                    if case == Dp::Closed {
                        let _ = dwhole(&mut d);
                    }
                }
                _ => {}
            }
        }
        Dp::Refused => {
            let _ = d.step(DaemonInput::TransportEof);
        }
    }
    d
}

fn daemon_phase_of(case: Dp) -> DaemonPhase {
    match case {
        Dp::AwaitReady => DaemonPhase::AwaitReady,
        Dp::CheckingF0 => DaemonPhase::CheckingF0,
        Dp::WelcomeReady => DaemonPhase::WelcomeReady,
        Dp::WelcomePrepared => DaemonPhase::WelcomePrepared,
        Dp::Active | Dp::ActiveSending => DaemonPhase::Active,
        Dp::Stopping | Dp::StoppingShutdown => DaemonPhase::Stopping,
        Dp::Closed => DaemonPhase::Closed,
        Dp::Refused => DaemonPhase::Refused(IpcRefusal::TransportClosed),
    }
}

fn daemon_has_prepared(case: Dp) -> bool {
    matches!(
        case,
        Dp::WelcomePrepared | Dp::ActiveSending | Dp::StoppingShutdown
    )
}

/// THE REFERENCE (DESIGN v2 (2)'s table and refusal rows), for the daemon.
fn expect_daemon(case: Dp, input: Di) -> (DaemonStepKind, DaemonPhase) {
    use DaemonPhase as P;
    use DaemonStepKind as K;
    use IpcRefusal::*;
    let here = daemon_phase_of(case);
    let refuse = |code| (K::Refused(code), P::Refused(code));
    if matches!(case, Dp::Closed | Dp::Refused) {
        return (K::Terminal, here);
    }
    match input {
        Di::TickBack => refuse(ClockRegression),
        Di::Eof => refuse(TransportClosed),
        Di::Error => refuse(TransportFailed),
        Di::F0Fail => refuse(BoundaryUnverified),
        Di::SendFatal => refuse(SendFailed),
        Di::TickSame => (K::Idle, here),
        Di::RecvReady if case == Dp::AwaitReady => (K::RunF0, P::CheckingF0),
        Di::RecvAdmit if case == Dp::Active => (K::Admit, P::Active),
        Di::RecvEvent if case == Dp::Active => (K::Idle, P::Active),
        Di::F0Pass if case == Dp::CheckingF0 => (K::Idle, P::WelcomeReady),
        Di::PrepWelcome if case == Dp::WelcomeReady => (K::Send, P::WelcomePrepared),
        Di::PrepVerdict if case == Dp::Active => (K::Send, P::Active),
        Di::PrepShutdown
            if matches!(
                case,
                Dp::CheckingF0 | Dp::WelcomeReady | Dp::Active | Dp::Stopping
            ) =>
        {
            (K::Send, P::Stopping)
        }
        Di::SendWhole if case == Dp::WelcomePrepared => (K::WelcomeSent, P::Active),
        Di::SendWhole if case == Dp::ActiveSending => (K::VerdictSent, P::Active),
        Di::SendWhole if case == Dp::StoppingShutdown => (K::Teardown, P::Closed),
        Di::SendWouldBlock if daemon_has_prepared(case) => (K::Idle, here),
        Di::Terminate if case == Dp::AwaitReady => (K::Teardown, P::Closed),
        Di::Terminate if matches!(case, Dp::Stopping | Dp::StoppingShutdown) => (K::Idle, here),
        Di::Terminate => (K::Stopping, P::Stopping),
        _ => refuse(OutOfOrder),
    }
}

fn apply_daemon(d: &mut DaemonSession<Handle>, input: Di, pool: &Pool) -> DaemonStepKind {
    let current = d.outgoing().map(|o| o.op).unwrap_or(OpId::from_raw(999));
    let step = match input {
        Di::TickSame => d.step(DaemonInput::Tick(T0)),
        Di::TickBack => d.step(DaemonInput::Tick(T0 - 1)),
        Di::RecvReady => drecv(d, &ready_bytes()),
        Di::RecvAdmit => drecv(d, &admit1(2)),
        Di::RecvEvent => drecv(d, &event_bytes(0, 3, 1)),
        Di::F0Pass => d.step(DaemonInput::F0(F0Result::Pass)),
        Di::F0Fail => d.step(DaemonInput::F0(F0Result::Fail)),
        Di::PrepWelcome => d.step(DaemonInput::PrepareWelcome(
            welcome_spec(ModeKind::ForwardTcp),
            pool.make(listener()),
        )),
        Di::PrepVerdict => d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(1),
            VerdictSpec::Denied,
        )),
        Di::PrepShutdown => d.step(DaemonInput::PrepareShutdown),
        Di::SendWhole => d.step(DaemonInput::SendResult(current, SendOutcome::SentWhole)),
        Di::SendWouldBlock => d.step(DaemonInput::SendResult(current, SendOutcome::WouldBlock)),
        Di::SendStale => d.step(DaemonInput::SendResult(
            OpId::from_raw(current.get() + 1000),
            SendOutcome::SentWhole,
        )),
        Di::SendFatal => d.step(DaemonInput::SendResult(current, SendOutcome::Fatal)),
        Di::Terminate => d.step(DaemonInput::Terminate(StopReason::Revoked)),
        Di::Eof => d.step(DaemonInput::TransportEof),
        Di::Error => d.step(DaemonInput::TransportError),
    };
    step.kind()
}

#[test]
fn t_session_daemon_transition_table() {
    let mut misses: Vec<String> = Vec::new();
    let mut rows = 0;
    for case in DPS {
        for input in DIS {
            rows += 1;
            let pool = Pool::new();
            let mut d = build_daemon(case, &pool);
            if d.phase() != daemon_phase_of(case) {
                misses.push(std::format!(
                    "T-SESSION daemon ({:?}): the setup reached {:?}, not the case's phase",
                    case,
                    d.phase()
                ));
            }
            let (want_kind, want_phase) = expect_daemon(case, input);
            let kind = apply_daemon(&mut d, input, &pool);
            let prepared = d.outgoing().is_some();
            let want_prepared = match want_kind {
                DaemonStepKind::Send => true,
                DaemonStepKind::Idle => daemon_has_prepared(case),
                _ => false,
            };
            if kind != want_kind || d.phase() != want_phase || prepared != want_prepared {
                misses.push(std::format!(
                    "T-SESSION daemon ({:?}, {:?}): want {:?}/{:?}/prepared={} got {:?}/{:?}/prepared={}",
                    case,
                    input,
                    want_kind,
                    want_phase,
                    want_prepared,
                    kind,
                    d.phase(),
                    prepared
                ));
            }
            let held = d.outgoing().map(|o| o.fd.is_some()).unwrap_or(false) as i64;
            if pool.live() != held {
                misses.push(std::format!(
                    "T-SESSION daemon ({:?}, {:?}): {} live descriptor(s), the session holds {}",
                    case,
                    input,
                    pool.live(),
                    held
                ));
            }
        }
    }
    assert_eq!(rows, 170);
    assert!(
        misses.is_empty(),
        "T-SESSION daemon: {} difference(s) from the reference over {} rows:\n{}",
        misses.len(),
        rows,
        misses.join("\n")
    );
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pp {
    Bootstrap,
    ReadyPrepared,
    AwaitWelcome,
    Active,
    ActiveSending,
    Stopping,
    StoppingSending,
    Closed,
    Refused,
}

const PPS: [Pp; 9] = [
    Pp::Bootstrap,
    Pp::ReadyPrepared,
    Pp::AwaitWelcome,
    Pp::Active,
    Pp::ActiveSending,
    Pp::Stopping,
    Pp::StoppingSending,
    Pp::Closed,
    Pp::Refused,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pi {
    TickSame,
    TickBack,
    RecvWelcome,
    RecvVerdict,
    RecvShutdown,
    PrepReady,
    PrepAdmit,
    Observe,
    SendWhole,
    SendWouldBlock,
    SendStale,
    SendFatal,
    Terminate,
    Eof,
    Error,
}

const PIS: [Pi; 15] = [
    Pi::TickSame,
    Pi::TickBack,
    Pi::RecvWelcome,
    Pi::RecvVerdict,
    Pi::RecvShutdown,
    Pi::PrepReady,
    Pi::PrepAdmit,
    Pi::Observe,
    Pi::SendWhole,
    Pi::SendWouldBlock,
    Pi::SendStale,
    Pi::SendFatal,
    Pi::Terminate,
    Pi::Eof,
    Pi::Error,
];

fn one_admit() -> OutboundAdmit {
    OutboundAdmit::new(Purpose::Forward, &[Sha256Digest::of(b"t")]).expect("one digest")
}

fn build_proxy(case: Pp, pool: &Pool) -> ProxySession<Handle> {
    match case {
        Pp::Bootstrap => proxy_new(),
        Pp::ReadyPrepared => {
            let mut p = proxy_new();
            let _ = p.step(ProxyInput::PrepareReady);
            p
        }
        Pp::AwaitWelcome => proxy_awaiting_welcome(),
        Pp::Closed => {
            let mut p = proxy_awaiting_welcome();
            let _ = p.step(ProxyInput::Terminate(StopReason::Shutdown));
            p
        }
        Pp::Refused => {
            let mut p = proxy_new();
            let _ = p.step(ProxyInput::TransportEof);
            p
        }
        _ => {
            let mut p = proxy_active(pool, ModeKind::ForwardTcp);
            let _ = proxy_send_admit(&mut p, Purpose::Forward, 1);
            match case {
                Pp::ActiveSending => {
                    let _ = p.step(ProxyInput::PrepareAdmit(one_admit()));
                }
                Pp::Stopping => {
                    let _ = p.step(ProxyInput::Terminate(StopReason::Shutdown));
                }
                Pp::StoppingSending => {
                    let _ = p.step(ProxyInput::Observe(EventCode::ProxyStarted, 1));
                    let _ = p.step(ProxyInput::Terminate(StopReason::Shutdown));
                    let _ = p.step(ProxyInput::Tick(T0));
                }
                _ => {}
            }
            p
        }
    }
}

fn proxy_phase_of(case: Pp) -> ProxyPhase {
    match case {
        Pp::Bootstrap => ProxyPhase::Bootstrap,
        Pp::ReadyPrepared => ProxyPhase::ReadyPrepared,
        Pp::AwaitWelcome => ProxyPhase::AwaitWelcome,
        Pp::Active | Pp::ActiveSending => ProxyPhase::Active,
        Pp::Stopping | Pp::StoppingSending => ProxyPhase::Stopping,
        Pp::Closed => ProxyPhase::Closed,
        Pp::Refused => ProxyPhase::Refused(IpcRefusal::TransportClosed),
    }
}

fn proxy_has_prepared(case: Pp) -> bool {
    matches!(
        case,
        Pp::ReadyPrepared | Pp::ActiveSending | Pp::StoppingSending
    )
}

/// THE REFERENCE (DESIGN v2 (2)'s table and refusal rows), for the proxy.
fn expect_proxy(case: Pp, input: Pi) -> (ProxyStepKind, ProxyPhase) {
    use IpcRefusal::*;
    use ProxyPhase as P;
    use ProxyStepKind as K;
    let here = proxy_phase_of(case);
    let refuse = |code| (K::Refused(code), P::Refused(code));
    if matches!(case, Pp::Closed | Pp::Refused) {
        return (K::Terminal, here);
    }
    match input {
        Pi::TickBack => refuse(ClockRegression),
        Pi::Eof => refuse(TransportClosed),
        Pi::Error => refuse(TransportFailed),
        Pi::SendFatal => refuse(SendFailed),
        // Stopping with nothing to flush closes at once; the flush never delays teardown.
        Pi::TickSame if case == Pp::Stopping => (K::Close, P::Closed),
        Pi::TickSame => (K::Idle, here),
        Pi::RecvWelcome if case == Pp::AwaitWelcome => (K::Welcome, P::Active),
        Pi::RecvVerdict if case == Pp::Active => (K::Verdict, P::Active),
        Pi::RecvShutdown if matches!(case, Pp::AwaitWelcome | Pp::Active | Pp::Stopping) => {
            (K::Close, P::Closed)
        }
        Pi::PrepReady if case == Pp::Bootstrap => (K::Send, P::ReadyPrepared),
        Pi::PrepAdmit if case == Pp::Active => (K::Send, P::Active),
        Pi::Observe => (K::Idle, here),
        Pi::SendWhole if case == Pp::ReadyPrepared => (K::Idle, P::AwaitWelcome),
        Pi::SendWhole if case == Pp::ActiveSending => (K::AdmitSent, P::Active),
        Pi::SendWhole if case == Pp::StoppingSending => (K::Idle, P::Stopping),
        Pi::SendWouldBlock if proxy_has_prepared(case) => (K::Idle, here),
        Pi::Terminate if matches!(case, Pp::Bootstrap | Pp::ReadyPrepared | Pp::AwaitWelcome) => {
            (K::Close, P::Closed)
        }
        Pi::Terminate if matches!(case, Pp::Stopping | Pp::StoppingSending) => (K::Idle, here),
        Pi::Terminate => (K::Stopping, P::Stopping),
        _ => refuse(OutOfOrder),
    }
}

fn apply_proxy(p: &mut ProxySession<Handle>, input: Pi, pool: &Pool) -> ProxyStepKind {
    let current = p.outgoing().map(|o| o.op).unwrap_or(OpId::from_raw(999));
    match input {
        Pi::TickSame => p.step(ProxyInput::Tick(T0)).kind(),
        Pi::TickBack => p.step(ProxyInput::Tick(T0 - 1)).kind(),
        Pi::RecvWelcome => precv_k(p, pool, &welcome_for(ModeKind::ForwardTcp), &[listener()]),
        Pi::RecvVerdict => precv_k(p, pool, &verdict_bytes(1, 0), &[]),
        Pi::RecvShutdown => precv_k(p, pool, &shutdown_bytes(), &[]),
        Pi::PrepReady => p.step(ProxyInput::PrepareReady).kind(),
        Pi::PrepAdmit => p.step(ProxyInput::PrepareAdmit(one_admit())).kind(),
        Pi::Observe => p
            .step(ProxyInput::Observe(EventCode::HostRefused, 1))
            .kind(),
        Pi::SendWhole => p
            .step(ProxyInput::SendResult(current, SendOutcome::SentWhole))
            .kind(),
        Pi::SendWouldBlock => p
            .step(ProxyInput::SendResult(current, SendOutcome::WouldBlock))
            .kind(),
        Pi::SendStale => p
            .step(ProxyInput::SendResult(
                OpId::from_raw(current.get() + 1000),
                SendOutcome::SentWhole,
            ))
            .kind(),
        Pi::SendFatal => p
            .step(ProxyInput::SendResult(current, SendOutcome::Fatal))
            .kind(),
        Pi::Terminate => p.step(ProxyInput::Terminate(StopReason::Shutdown)).kind(),
        Pi::Eof => p.step(ProxyInput::TransportEof).kind(),
        Pi::Error => p.step(ProxyInput::TransportError).kind(),
    }
}

#[test]
fn t_session_proxy_transition_table() {
    let mut misses: Vec<String> = Vec::new();
    let mut rows = 0;
    for case in PPS {
        for input in PIS {
            rows += 1;
            let pool = Pool::new();
            let mut p = build_proxy(case, &pool);
            if p.phase() != proxy_phase_of(case) {
                misses.push(std::format!(
                    "T-SESSION proxy ({:?}): the setup reached {:?}, not the case's phase",
                    case,
                    p.phase()
                ));
            }
            let (want_kind, want_phase) = expect_proxy(case, input);
            let kind = apply_proxy(&mut p, input, &pool);
            let prepared = p.outgoing().is_some();
            let want_prepared = match (want_kind, input) {
                (ProxyStepKind::Send, _) => true,
                (ProxyStepKind::Idle, Pi::SendWhole) => false,
                (ProxyStepKind::Idle, _) => proxy_has_prepared(case),
                _ => false,
            };
            if kind != want_kind || p.phase() != want_phase || prepared != want_prepared {
                misses.push(std::format!(
                    "T-SESSION proxy ({:?}, {:?}): want {:?}/{:?}/prepared={} got {:?}/{:?}/prepared={}",
                    case,
                    input,
                    want_kind,
                    want_phase,
                    want_prepared,
                    kind,
                    p.phase(),
                    prepared
                ));
            }
            if pool.live() != 0 {
                misses.push(std::format!(
                    "T-SESSION proxy ({:?}, {:?}): {} descriptor(s) still live",
                    case,
                    input,
                    pool.live()
                ));
            }
        }
    }
    assert_eq!(rows, 135);
    assert!(
        misses.is_empty(),
        "T-SESSION proxy: {} difference(s) from the reference over {} rows:\n{}",
        misses.len(),
        rows,
        misses.join("\n")
    );
}
