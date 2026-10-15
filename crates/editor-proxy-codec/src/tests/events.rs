//! T-EVENT (bounded aggregation on both sides) and T-CANDIDATES (U1's part: the cap type and
//! the outbound ADMIT shapes). DESIGN v2 (3).

use super::support::*;
use crate::{
    decode_p2d, DaemonInput, DaemonStep, DaemonStepKind, EventCode, InboundP2d, LeaseCandidates,
    ModeKind, OutboundAdmit, ProxyInput, ProxyStepKind, Purpose, SendOutcome, Sha256Digest,
    StopReason, TooManyLeaseCandidates, DAEMON_EVENT_WINDOW_NS, PROXY_EVENT_WINDOW_NS,
};
use std::vec::Vec;

/// The (code, count) of the proxy's prepared EVENT.
fn prepared_event(p: &crate::ProxySession<Handle>) -> (EventCode, u32) {
    let bytes = p.outgoing().expect("a prepared EVENT").bytes.to_vec();
    match decode_p2d(&bytes) {
        Ok(InboundP2d::Event(event)) => (event.code(), event.count()),
        _ => panic!("the prepared frame is an EVENT"),
    }
}

/// The daemon's window index at `now` (its local ten-second windows).
fn window_of(now: u64) -> u64 {
    now / DAEMON_EVENT_WINDOW_NS
}

#[test]
fn t_event_daemon_persists_at_most_one_record_per_code_per_window() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    let start = window_of(T0);
    let mut persists = 0;
    for i in 0..2400u32 {
        let code = (i % 12) as u16 + 1;
        let step = drecv(&mut d, &event_bytes(0, code, 1 + i % 3));
        assert_eq!(
            step.kind(),
            DaemonStepKind::Idle,
            "T-EVENT: ordinary parser output never refuses"
        );
        if i % 100 == 0 {
            let now = T0 + (i as u64) * 1_000_000;
            if let DaemonStep::Persist(_) = d.step(DaemonInput::Tick(now)) {
                persists += 1;
            }
        }
    }
    assert_eq!(
        persists, 0,
        "T-EVENT: no record per peer frame inside a window"
    );
    let next = (start + 1) * DAEMON_EVENT_WINDOW_NS;
    let records = match d.step(DaemonInput::Tick(next)) {
        DaemonStep::Persist(records) => records,
        _ => panic!("T-EVENT: the window closes with ONE persist"),
    };
    assert!(
        records.len() <= 12,
        "T-EVENT: at most 12 records per window"
    );
    assert_eq!(records.len(), 12);
    assert_eq!(records.window(), start);
    let total: u64 = records.records().map(|(_, c)| c as u64).sum();
    let want: u64 = (0..2400u64).map(|i| 1 + i % 3).sum();
    assert_eq!(total, want, "the counts are summed, not dropped");
    assert_eq!(
        d.step(DaemonInput::Tick(next + 1)).kind(),
        DaemonStepKind::Idle,
        "once per window"
    );
}

#[test]
fn t_event_daemon_counts_saturate() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    for _ in 0..3 {
        assert_eq!(
            drecv_k(&mut d, &event_bytes(0, 12, u32::MAX)),
            DaemonStepKind::Idle
        );
    }
    let next = (window_of(T0) + 1) * DAEMON_EVENT_WINDOW_NS;
    match d.step(DaemonInput::Tick(next)) {
        DaemonStep::Persist(records) => {
            assert_eq!(
                records.count(EventCode::SessionCookieDropped),
                u32::MAX,
                "saturated"
            );
            assert_eq!(records.len(), 1);
        }
        _ => panic!("a persist"),
    }
}

#[test]
fn t_event_daemon_windows_are_local_and_the_final_summary_is_once() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    let mut windows: Vec<u64> = Vec::new();
    let mut now = T0;
    for round in 0..5u64 {
        let _ = drecv(&mut d, &event_bytes(0, 5, 2));
        now += DAEMON_EVENT_WINDOW_NS * (1 + round % 2) + 7;
        if let DaemonStep::Persist(records) = d.step(DaemonInput::Tick(now)) {
            windows.push(records.window());
        }
    }
    assert_eq!(windows.len(), 5, "each window with events persists once");
    assert!(
        windows.windows(2).all(|w| w[0] < w[1]),
        "windows strictly increase"
    );
    let _ = drecv(&mut d, &event_bytes(0, 6, 9));
    assert_eq!(d.final_event_summary(), None, "no final summary while live");
    let _ = d.step(DaemonInput::Terminate(StopReason::Shutdown));
    let _ = d.step(DaemonInput::Tick(now + DAEMON_EVENT_WINDOW_NS / 20));
    assert_eq!(
        d.step(DaemonInput::Tick(now + 2_000_000_000)).kind(),
        DaemonStepKind::Teardown
    );
    let summary = d.final_event_summary().expect("one final summary");
    assert_eq!(summary.count(EventCode::AuthenticationDenied), 9);
    assert_eq!(d.final_event_summary(), None, "only once");
}

#[test]
fn t_event_proxy_aggregates_1025_pairs_and_saturates() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::SessionCookieDropped, 1025));
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Send);
    assert_eq!(
        prepared_event(&p),
        (EventCode::SessionCookieDropped, 1025),
        "ONE EVENT of 1025"
    );
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    assert_eq!(p.test_only_counter(EventCode::SessionCookieDropped), 0);
    let _ = p.step(ProxyInput::Observe(EventCode::HostRefused, u32::MAX));
    let _ = p.step(ProxyInput::Observe(EventCode::HostRefused, u32::MAX));
    assert_eq!(
        p.test_only_counter(EventCode::HostRefused),
        u32::MAX,
        "T-EVENT: saturating"
    );
    let _ = p.step(ProxyInput::Tick(T0 + PROXY_EVENT_WINDOW_NS));
    assert_eq!(prepared_event(&p), (EventCode::HostRefused, u32::MAX));
}

#[test]
fn t_event_proxy_offers_at_most_one_event_per_nonzero_counter_per_window() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::ClientDisconnected, 2));
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Send);
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    let _ = p.step(ProxyInput::Observe(EventCode::ClientDisconnected, 4));
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + PROXY_EVENT_WINDOW_NS - 1))
            .kind(),
        ProxyStepKind::Idle,
        "T-EVENT: no second EVENT for the same code in one window"
    );
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + PROXY_EVENT_WINDOW_NS)).kind(),
        ProxyStepKind::Send
    );
    assert_eq!(prepared_event(&p), (EventCode::ClientDisconnected, 4));
}

#[test]
fn t_event_proxy_backpressure_merges_into_the_counter() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::RequestHeadRefused, 5));
    let _ = p.step(ProxyInput::Tick(T0));
    let op = pop(&p);
    assert_eq!(
        p.step(ProxyInput::SendResult(op, SendOutcome::WouldBlock))
            .kind(),
        ProxyStepKind::Idle
    );
    let _ = p.step(ProxyInput::Observe(EventCode::RequestHeadRefused, 3));
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + 1)).kind(),
        ProxyStepKind::Idle,
        "no more frames queued"
    );
    assert_eq!(
        prepared_event(&p),
        (EventCode::RequestHeadRefused, 5),
        "the same snapshot"
    );
    assert_eq!(
        p.step(ProxyInput::SendResult(op, SendOutcome::SentWhole))
            .kind(),
        ProxyStepKind::Idle
    );
    assert_eq!(
        p.test_only_counter(EventCode::RequestHeadRefused),
        3,
        "snapshot/subtract: 3 kept"
    );
}

#[test]
fn t_event_proxy_final_flush_is_bounded() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::ProxyStarted, 1));
    let _ = p.step(ProxyInput::Observe(EventCode::ProxyStopped, 1));
    assert_eq!(
        p.step(ProxyInput::Terminate(StopReason::Shutdown)).kind(),
        ProxyStepKind::Stopping
    );
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Send);
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Send);
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    assert_eq!(
        p.step(ProxyInput::Tick(T0)).kind(),
        ProxyStepKind::Close,
        "flushed, then closed"
    );
    // A code already offered in this window is still flushed at Stopping (the final flush ignores
    // the per-window marks).
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::HostRefused, 1));
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Send);
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    let _ = p.step(ProxyInput::Observe(EventCode::HostRefused, 2));
    let _ = p.step(ProxyInput::Terminate(StopReason::Shutdown));
    assert_eq!(
        p.step(ProxyInput::Tick(T0)).kind(),
        ProxyStepKind::Send,
        "the final flush sends a code already offered in this window"
    );
    assert_eq!(prepared_event(&p), (EventCode::HostRefused, 2));
    assert_eq!(pwhole(&mut p), ProxyStepKind::Idle);
    assert_eq!(p.step(ProxyInput::Tick(T0)).kind(), ProxyStepKind::Close);
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = p.step(ProxyInput::Observe(EventCode::ProxyStarted, 1));
    let _ = p.step(ProxyInput::Terminate(StopReason::Shutdown));
    let _ = p.step(ProxyInput::Tick(T0));
    assert_eq!(
        p.step(ProxyInput::Tick(T0 + crate::SEND_DEADLINE_NS))
            .kind(),
        ProxyStepKind::Close,
        "a stuck flush never delays teardown"
    );
}

// ---- T-CANDIDATES (U1's part) -------------------------------------------------------------------

#[test]
fn t_candidates_eight_with_the_valid_bearer_last_are_all_sent() {
    let mut c = LeaseCandidates::new();
    for i in 0..7u8 {
        assert_eq!(c.push(&[b'x', i]), Ok(()));
    }
    assert_eq!(c.push(b"valid"), Ok(()), "the eighth");
    let admit = OutboundAdmit::forward(&c).expect("eight fit");
    assert_eq!(admit.digest_count(), 8);
    let frame = crate::encode_p2d(&crate::OutboundP2d::Admit(
        crate::AdmissionId::from_raw(1),
        admit,
    ));
    match decode_p2d(frame.as_bytes()) {
        Ok(InboundP2d::Admit(inbound)) => {
            let stored: std::string::String = Sha256Digest::of(b"valid")
                .as_bytes()
                .iter()
                .map(|b| std::format!("{:02x}", b))
                .collect();
            assert!(
                inbound.any_matches_stored_hex(&stored),
                "the eighth (valid) bearer is sent"
            );
        }
        _ => panic!("an ADMIT"),
    }
}

#[test]
fn t_candidates_a_ninth_occurrence_refuses_before_any_ipc() {
    let mut c = LeaseCandidates::new();
    for i in 0..8u8 {
        assert_eq!(c.push(&[i + 1]), Ok(()));
    }
    assert_eq!(
        c.push(b"valid"),
        Err(TooManyLeaseCandidates),
        "T-CANDIDATES: the ninth refuses"
    );
    assert!(c.is_refused());
    assert_eq!(
        OutboundAdmit::forward(&c).err(),
        Some(TooManyLeaseCandidates),
        "no ADMIT"
    );
    assert_eq!(
        c.push(b"more"),
        Err(TooManyLeaseCandidates),
        "and stays refused"
    );
    assert_eq!(
        c.push(b""),
        Err(TooManyLeaseCandidates),
        "even for an empty candidate"
    );
    let mut dup = LeaseCandidates::new();
    for _ in 0..8 {
        assert_eq!(dup.push(b"same"), Ok(()));
    }
    assert_eq!(
        dup.push(b"same"),
        Err(TooManyLeaseCandidates),
        "duplicate occurrences count"
    );
    let mut empties = LeaseCandidates::new();
    for i in 0..8u8 {
        assert_eq!(empties.push(b""), Ok(()));
        assert_eq!(empties.push(&[i + 1]), Ok(()));
    }
    assert_eq!(empties.count(), 8, "empty candidates do not count");
    let raw: Vec<Sha256Digest> = (0..9u8).map(|i| Sha256Digest::of(&[i])).collect();
    assert_eq!(
        OutboundAdmit::new(Purpose::Forward, &raw).err(),
        Some(TooManyLeaseCandidates)
    );
}

#[test]
fn t_candidates_a_lease_exchange_carries_only_the_form_token() {
    let form = Sha256Digest::of(b"form-token");
    let admit = OutboundAdmit::lease_exchange(Some(&form));
    assert_eq!(
        (admit.purpose(), admit.digest_count()),
        (Purpose::LeaseExchange, 1)
    );
    let none = OutboundAdmit::lease_exchange(None);
    assert_eq!(
        (none.purpose(), none.digest_count()),
        (Purpose::LeaseExchange, 0)
    );
}
