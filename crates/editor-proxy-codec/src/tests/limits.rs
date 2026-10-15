//! T-LIMITS (ids, pending, rate windows), T-TIME (clock, deadlines), T-SEND (prepared-send
//! semantics) and T-VERDICT (bookkeeping and the legality table), on both machines.

use super::support::*;
use crate::{
    AdmissionId, AdmitBlocked, DaemonInput, DaemonPhase, DaemonStepKind, F0Result, IpcRefusal,
    ModeKind, OpId, OutboundAdmit, ProxyInput, ProxyPhase, ProxyStepKind, Purpose, SendOutcome,
    Sha256Digest, StopReason, VerdictSpec, RATE_WINDOW_NS, SEND_DEADLINE_NS, STARTUP_DEADLINE_NS,
};

use DaemonStepKind as Dk;
use IpcRefusal::*;
use ProxyStepKind as Pk;

const VD: u64 = VERDICT_DEADLINE_NS;

fn admit() -> OutboundAdmit {
    OutboundAdmit::new(Purpose::Forward, &[Sha256Digest::of(b"x")]).expect("one digest")
}

// ---- T-LIMITS, daemon ----------------------------------------------------------------------------

#[test]
fn t_limits_daemon_the_65th_unanswered_admit_refuses() {
    let pool = Pool::new();
    let mut d = daemon_with_pending(&pool, 64);
    assert_eq!(d.test_only_pending_len(), 64);
    assert_eq!(
        drecv_k(&mut d, &admit1(65)),
        Dk::Refused(TooManyInFlight),
        "T-LIMITS 65th"
    );
}

#[test]
fn t_limits_daemon_2000_admissions_fit_one_window_and_the_2001st_refuses() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    for id in 1..=2000 {
        assert_eq!(
            daemon_exchange(&mut d, id),
            (Dk::Admit, Dk::VerdictSent),
            "exchange {}",
            id
        );
    }
    assert_eq!(
        drecv_k(&mut d, &admit1(2001)),
        Dk::Refused(RateExceeded),
        "T-LIMITS 2001st"
    );
}

#[test]
fn t_limits_daemon_the_window_boundary_resets_the_count() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    for id in 1..=2000 {
        let _ = daemon_exchange(&mut d, id);
    }
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + RATE_WINDOW_NS - 1)).kind(),
        Dk::Idle
    );
    assert_eq!(
        drecv_k(&mut d, &admit1(2001)),
        Dk::Refused(RateExceeded),
        "still window 0"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    for id in 1..=2000 {
        let _ = daemon_exchange(&mut d, id);
    }
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + RATE_WINDOW_NS)).kind(),
        Dk::Idle
    );
    assert_eq!(
        drecv_k(&mut d, &admit1(2001)),
        Dk::Admit,
        "window 1 starts at epoch + 10 s"
    );
}

#[test]
fn t_limits_daemon_ids_strictly_increase_with_gaps_and_max_once() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        drecv_k(&mut d, &admit1(0)),
        Dk::Refused(ConnNotIncreasing),
        "id 0"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(drecv_k(&mut d, &admit1(5)), Dk::Admit);
    assert_eq!(drecv_k(&mut d, &admit1(9)), Dk::Admit, "gaps are allowed");
    assert_eq!(
        drecv_k(&mut d, &admit1(9)),
        Dk::Refused(ConnNotIncreasing),
        "a repeat"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(drecv_k(&mut d, &admit1(5)), Dk::Admit);
    assert_eq!(
        drecv_k(&mut d, &admit1(3)),
        Dk::Refused(ConnNotIncreasing),
        "a decrease"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        drecv_k(&mut d, &admit1(u32::MAX)),
        Dk::Admit,
        "u32::MAX is usable once"
    );
    assert_eq!(
        drecv_k(&mut d, &admit1(u32::MAX)),
        Dk::Refused(ConnExhausted)
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(drecv_k(&mut d, &admit1(u32::MAX)), Dk::Admit);
    assert_eq!(
        drecv_k(&mut d, &admit1(0)),
        Dk::Refused(ConnExhausted),
        "exhausted first"
    );
}

// ---- T-LIMITS, proxy ----------------------------------------------------------------------------

#[test]
fn t_limits_proxy_allocates_ids_from_one_by_one() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    for want in 1..=5u32 {
        let id = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("sent");
        assert_eq!(
            id.get(),
            want,
            "T-LIMITS honest allocation increments by one from 1"
        );
    }
}

#[test]
fn t_limits_proxy_the_65th_admit_is_blocked_then_refused() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    for _ in 0..64 {
        assert!(proxy_send_admit(&mut p, Purpose::Forward, 1).is_some());
    }
    assert_eq!(p.can_prepare_admit(), Err(AdmitBlocked::InFlightFull));
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(admit())).kind(),
        Pk::Refused(TooManyInFlight)
    );
}

#[test]
fn t_limits_proxy_rate_mirror_blocks_the_2001st_and_resets_at_the_boundary() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    for _ in 0..2000 {
        let id = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("sent");
        assert_eq!(
            precv_k(&mut p, &pool, &verdict_bytes(id.get(), 0), &[]),
            Pk::Verdict
        );
    }
    assert_eq!(
        p.can_prepare_admit(),
        Err(AdmitBlocked::RateLimited),
        "T-LIMITS proxy mirror"
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + RATE_WINDOW_NS)).kind(),
        Pk::Idle
    );
    assert_eq!(p.can_prepare_admit(), Ok(()), "a new window");
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    for _ in 0..2000 {
        let id = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("sent");
        let _ = precv_k(&mut p, &pool, &verdict_bytes(id.get(), 0), &[]);
    }
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(admit())).kind(),
        Pk::Refused(RateExceeded)
    );
}

#[test]
fn t_limits_proxy_exhaustion_uses_max_once_then_stops_after_pending_results() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert!(
        p.test_only_set_next_id(u32::MAX - 1),
        "the test-only state builder"
    );
    let a = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("MAX - 1");
    let b = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("MAX");
    assert_eq!((a.get(), b.get()), (u32::MAX - 1, u32::MAX), "no wrap");
    assert_eq!(p.can_prepare_admit(), Err(AdmitBlocked::Exhausted));
    assert!(
        !p.test_only_set_next_id(7),
        "the builder refuses after an ADMIT"
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0)).kind(),
        Pk::Idle,
        "pending results first"
    );
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(a.get(), 0), &[]),
        Pk::Verdict
    );
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(b.get(), 0), &[]),
        Pk::Verdict
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0)).kind(),
        Pk::Stopping,
        "then the actor stops"
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0)).kind(),
        Pk::Close,
        "nothing to flush"
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert!(p.test_only_set_next_id(u32::MAX));
    assert!(proxy_send_admit(&mut p, Purpose::Forward, 1).is_some());
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(admit())).kind(),
        Pk::Refused(ConnExhausted)
    );
}

// ---- T-TIME -------------------------------------------------------------------------------------

#[test]
fn t_time_clock_regression_latches_both_sides() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(d.step(DaemonInput::Tick(T0 + 5)).kind(), Dk::Idle);
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + 5)).kind(),
        Dk::Idle,
        "equal time is legal"
    );
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + 4)).kind(),
        Dk::Refused(ClockRegression)
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(p.step(ProxyInput::Tick(T0 + 5)).kind(), Pk::Idle);
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + 4)).kind(),
        Pk::Refused(ClockRegression)
    );
}

#[test]
fn t_time_startup_deadline_is_five_seconds_from_spawn() {
    let mut d = daemon_new();
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + STARTUP_DEADLINE_NS - 1))
            .kind(),
        Dk::Idle
    );
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + STARTUP_DEADLINE_NS)).kind(),
        Dk::Refused(OperationTimeout)
    );
    let mut d = daemon_new();
    let _ = drecv(&mut d, &ready_bytes());
    let _ = d.step(DaemonInput::F0(F0Result::Pass));
    assert_eq!(d.phase(), DaemonPhase::WelcomeReady);
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + STARTUP_DEADLINE_NS)).kind(),
        Dk::Refused(OperationTimeout)
    );
    let mut p = proxy_awaiting_welcome();
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + STARTUP_DEADLINE_NS - 1))
            .kind(),
        Pk::Idle
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + STARTUP_DEADLINE_NS)).kind(),
        Pk::Refused(OperationTimeout)
    );
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::Static);
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + STARTUP_DEADLINE_NS)).kind(),
        Dk::Idle,
        "Active is past startup"
    );
}

#[test]
fn t_time_send_deadlines_are_one_second() {
    let pool = Pool::new();
    let mut d = daemon_new();
    let _ = drecv(&mut d, &ready_bytes());
    let _ = d.step(DaemonInput::F0(F0Result::Pass));
    let _ = d.step(DaemonInput::PrepareWelcome(
        welcome_spec(ModeKind::ForwardTcp),
        pool.make(listener()),
    ));
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + SEND_DEADLINE_NS - 1)).kind(),
        Dk::Idle
    );
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + SEND_DEADLINE_NS)).kind(),
        Dk::Refused(OperationTimeout)
    );
    assert_eq!(
        pool.live(),
        0,
        "the prepared listener was dropped by the refusal"
    );
    let mut p = proxy_new();
    let _ = p.step(ProxyInput::PrepareReady);
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + SEND_DEADLINE_NS)).kind(),
        Pk::Refused(OperationTimeout)
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Tick(T0 + 7));
    let _ = p.step(ProxyInput::PrepareAdmit(admit()));
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + 7 + SEND_DEADLINE_NS - 1))
            .kind(),
        Pk::Idle
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + 7 + SEND_DEADLINE_NS)).kind(),
        Pk::Refused(OperationTimeout)
    );
}

#[test]
fn t_time_verdict_deadline_on_both_sides() {
    let pool = Pool::new();
    let mut d = daemon_with_pending(&pool, 1);
    assert_eq!(d.step(DaemonInput::Tick(T0 + VD - 1)).kind(), Dk::Idle);
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + VD)).kind(),
        Dk::Refused(OperationTimeout)
    );
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::Denied,
    ));
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + VD)).kind(),
        Dk::Refused(OperationTimeout),
        "a prepared VERDICT too"
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = proxy_send_admit(&mut p, Purpose::Forward, 1);
    assert_eq!(p.step(ProxyInput::Tick(T0 + VD - 1)).kind(), Pk::Idle);
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + VD)).kind(),
        Pk::Refused(OperationTimeout)
    );
}

#[test]
fn t_time_daemon_stopping_tears_down_at_its_grace_deadline() {
    let pool = Pool::new();
    let mut d = daemon_with_pending(&pool, 3);
    assert_eq!(
        d.step(DaemonInput::Terminate(StopReason::Expired)).kind(),
        Dk::Stopping
    );
    assert_eq!(d.test_only_pending_len(), 0, "work is cancelled");
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + SEND_DEADLINE_NS - 1)).kind(),
        Dk::Idle
    );
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + SEND_DEADLINE_NS)).kind(),
        Dk::Teardown
    );
    assert_eq!(d.phase(), DaemonPhase::Closed);
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::Terminate(StopReason::Expired));
    assert_eq!(d.step(DaemonInput::PrepareShutdown).kind(), Dk::Send);
    assert_eq!(
        d.step(DaemonInput::Tick(T0 + SEND_DEADLINE_NS)).kind(),
        Dk::Teardown,
        "a stuck SHUTDOWN never delays teardown"
    );
    let mut d = daemon_new();
    assert_eq!(
        d.step(DaemonInput::Terminate(StopReason::Revoked)).kind(),
        Dk::Teardown,
        "before READY"
    );
    let mut d = daemon_with_pending(&pool, 1);
    assert_eq!(
        d.step(DaemonInput::PrepareShutdown).kind(),
        Dk::Send,
        "SHUTDOWN from Active"
    );
    assert_eq!(d.phase(), DaemonPhase::Stopping);
    assert_eq!(dwhole(&mut d), Dk::Teardown);
}

// ---- T-SEND -------------------------------------------------------------------------------------

#[test]
fn t_send_wouldblock_retains_the_same_frame_and_descriptor() {
    let pool = Pool::new();
    let mut d = daemon_new();
    let _ = drecv(&mut d, &ready_bytes());
    let _ = d.step(DaemonInput::F0(F0Result::Pass));
    let op = match d.step(DaemonInput::PrepareWelcome(
        welcome_spec(ModeKind::ForwardUnix),
        pool.make(listener()),
    )) {
        crate::DaemonStep::Send(op) => op,
        _ => panic!("WELCOME prepared"),
    };
    let before = d.outgoing().map(|o| o.bytes.to_vec()).expect("prepared");
    assert_eq!(pool.live(), 1);
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::WouldBlock))
            .kind(),
        Dk::Idle
    );
    let out = d.outgoing().expect("still prepared");
    assert_eq!(
        (out.op, out.bytes.to_vec(), out.fd.is_some()),
        (op, before, true),
        "same frame and fd"
    );
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        Dk::WelcomeSent
    );
    assert_eq!(
        pool.live(),
        0,
        "the daemon's listener copy is closed when WelcomeSent returns"
    );
    assert!(d.outgoing().is_none());

    let mut d = daemon_with_pending(&pool, 1);
    let up = pool.make(upstream_for(ModeKind::ForwardTcp));
    let op = match d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::AdmittedUpstream(up),
    )) {
        crate::DaemonStep::Send(op) => op,
        _ => panic!("VERDICT prepared"),
    };
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::WouldBlock))
            .kind(),
        Dk::Idle
    );
    assert_eq!(
        d.test_only_pending_len(),
        1,
        "a prepared VERDICT does not remove its entry"
    );
    assert_eq!(pool.live(), 1);
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        Dk::VerdictSent
    );
    assert_eq!(
        d.test_only_pending_len(),
        0,
        "only the whole send removes it"
    );
    assert_eq!(pool.live(), 0);

    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::PrepareAdmit(admit()));
    let op = pop(&p);
    assert_eq!(
        p.step(ProxyInput::SendResult(op, SendOutcome::WouldBlock))
            .kind(),
        Pk::Idle
    );
    assert_eq!(
        p.test_only_pending_len(),
        0,
        "the proxy inserts only on the whole send"
    );
    assert_eq!(
        p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        Pk::AdmitSent
    );
    assert_eq!(p.test_only_pending_len(), 1);
}

#[test]
fn t_send_one_prepared_send_at_a_time_and_stale_results_refuse() {
    let pool = Pool::new();
    let mut d = daemon_with_pending(&pool, 2);
    let _ = d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::Denied,
    ));
    assert_eq!(
        d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(2),
            VerdictSpec::Denied
        ))
        .kind(),
        Dk::Refused(OutOfOrder),
        "a second prepared send"
    );
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::Denied,
    ));
    let op = dop(&d);
    assert_eq!(
        d.step(DaemonInput::SendResult(
            OpId::from_raw(op.get() + 1),
            SendOutcome::SentWhole
        ))
        .kind(),
        Dk::Refused(OutOfOrder),
        "a stale op"
    );
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::Denied,
    ));
    let op = dop(&d);
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        Dk::VerdictSent
    );
    assert_eq!(
        d.step(DaemonInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        Dk::Refused(OutOfOrder),
        "a duplicate completion"
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::PrepareAdmit(admit()));
    assert_eq!(p.can_prepare_admit(), Err(AdmitBlocked::SendInProgress));
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(admit())).kind(),
        Pk::Refused(OutOfOrder)
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        p.step(ProxyInput::SendResult(
            OpId::from_raw(1),
            SendOutcome::SentWhole
        ))
        .kind(),
        Pk::Refused(OutOfOrder),
        "a result with nothing prepared"
    );
}

#[test]
fn t_send_inbound_is_suspended_while_a_send_is_prepared() {
    let pool = Pool::new();
    let mut d = daemon_with_pending(&pool, 1);
    let _ = d.step(DaemonInput::PrepareVerdict(
        AdmissionId::from_raw(1),
        VerdictSpec::Denied,
    ));
    assert_eq!(drecv_k(&mut d, &admit1(2)), Dk::Refused(OutOfOrder));
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = proxy_send_admit(&mut p, Purpose::Forward, 1);
    let _ = p.step(ProxyInput::PrepareAdmit(admit()));
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(1, 0), &[]),
        Pk::Refused(OutOfOrder)
    );
}

#[test]
fn t_send_failed_and_short_sends_latch_send_failed() {
    let pool = Pool::new();
    for outcome in [SendOutcome::Fatal, SendOutcome::Short] {
        let mut d = daemon_with_pending(&pool, 1);
        let _ = d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(1),
            VerdictSpec::AdmittedUpstream(pool.make(upstream_for(ModeKind::ForwardTcp))),
        ));
        let op = dop(&d);
        assert_eq!(
            d.step(DaemonInput::SendResult(op, outcome)).kind(),
            Dk::Refused(SendFailed)
        );
        assert_eq!(pool.live(), 0, "the prepared fd is dropped");
        let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
        let _ = p.step(ProxyInput::PrepareAdmit(admit()));
        let op = pop(&p);
        assert_eq!(
            p.step(ProxyInput::SendResult(op, outcome)).kind(),
            Pk::Refused(SendFailed)
        );
    }
}

// ---- T-VERDICT ----------------------------------------------------------------------------------

#[test]
fn t_verdict_duplicate_unknown_and_completed_fifo_eviction() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    let _ = daemon_exchange(&mut d, 1);
    assert_eq!(
        d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(1),
            VerdictSpec::Denied
        ))
        .kind(),
        Dk::Refused(DuplicateVerdict)
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        d.step(DaemonInput::PrepareVerdict(
            AdmissionId::from_raw(5),
            VerdictSpec::Denied
        ))
        .kind(),
        Dk::Refused(UnknownVerdict)
    );
    for (probe, want) in [(1u32, UnknownVerdict), (2, DuplicateVerdict)] {
        let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
        for id in 1..=65 {
            let _ = daemon_exchange(&mut d, id);
        }
        assert_eq!(
            d.step(DaemonInput::PrepareVerdict(
                AdmissionId::from_raw(probe),
                VerdictSpec::Denied
            ))
            .kind(),
            Dk::Refused(want),
            "the 64-id FIFO after 65 completions, id {}",
            probe
        );
    }
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let id = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("sent");
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(id.get(), 0), &[]),
        Pk::Verdict
    );
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(id.get(), 0), &[]),
        Pk::Refused(DuplicateVerdict)
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::PrepareAdmit(admit()));
    let op = pop(&p);
    let _ = p.step(ProxyInput::SendResult(op, SendOutcome::WouldBlock));
    let _ = p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole));
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(2, 0), &[]),
        Pk::Refused(UnknownVerdict),
        "never sent"
    );
}

/// The legality table, written from DESIGN v2 (2) independently of `Outcome::legal_for`.
fn table_legal(mode: ModeKind, purpose: Purpose, outcome: u8) -> bool {
    match (purpose, mode) {
        (Purpose::Forward, ModeKind::ForwardTcp | ModeKind::ForwardUnix) => {
            matches!(outcome, 0 | 1 | 3)
        }
        (Purpose::Forward, ModeKind::Static) => matches!(outcome, 0 | 2),
        (Purpose::LeaseExchange, _) => matches!(outcome, 0 | 2),
    }
}

#[test]
fn t_verdict_legality_table_on_both_sides() {
    let pool = Pool::new();
    for mode in [
        ModeKind::ForwardTcp,
        ModeKind::ForwardUnix,
        ModeKind::Static,
    ] {
        for (purpose, wire) in [(Purpose::Forward, 1u8), (Purpose::LeaseExchange, 2u8)] {
            for outcome in 0u8..=3 {
                let legal = table_legal(mode, purpose, outcome);
                let mut d = daemon_active(&pool, mode);
                assert_eq!(
                    drecv_k(&mut d, &admit_bytes(1, wire, &[[3; 32]])),
                    Dk::Admit
                );
                let verdict = match outcome {
                    0 => VerdictSpec::Denied,
                    1 => VerdictSpec::AdmittedUpstream(pool.make(upstream_for(mode))),
                    2 => VerdictSpec::AdmittedNoUpstream,
                    _ => VerdictSpec::UpstreamUnavailable,
                };
                let got = d
                    .step(DaemonInput::PrepareVerdict(
                        AdmissionId::from_raw(1),
                        verdict,
                    ))
                    .kind();
                let want = if legal {
                    Dk::Send
                } else {
                    Dk::Refused(BadOutcomeForPurpose)
                };
                assert_eq!(
                    got, want,
                    "T-VERDICT daemon {:?} {:?} outcome {}",
                    mode, purpose, outcome
                );
                drop(d);
                let mut p = proxy_active(&pool, mode);
                let id = proxy_send_admit(&mut p, purpose, 1).expect("sent");
                let fds = if outcome == 1 {
                    std::vec![upstream_for(mode)]
                } else {
                    std::vec![]
                };
                let got = precv_k(&mut p, &pool, &verdict_bytes(id.get(), outcome), &fds);
                let want = if outcome == 1 && mode == ModeKind::Static {
                    Pk::Refused(BadFdKind)
                } else if legal {
                    Pk::Verdict
                } else {
                    Pk::Refused(BadOutcomeForPurpose)
                };
                assert_eq!(
                    got, want,
                    "T-VERDICT proxy {:?} {:?} outcome {}",
                    mode, purpose, outcome
                );
                assert_eq!(pool.live(), 0);
            }
        }
    }
    assert_eq!(pool.live(), 0);
    let _ = ProxyPhase::Active;
}
