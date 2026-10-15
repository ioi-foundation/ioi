//! T-SHAPE: the ADMIT digest-count limits by purpose and serving mode (DESIGN v2 (3): "Lease_exchange
//! ADMIT carries only the submitted form token (n=0/1)"; static mode's ADMIT "contains only that
//! selected token (n=0/1)"). A forward admission in a forward mode carries every counted
//! candidate (0..=8); a lease exchange (any mode) and a static-mode admission carry at most ONE
//! digest. Enforced on every outbound construction path (the exchange), in the proxy session's
//! prepare (static mode) and in the daemon's admission validation (both), with TooManyDigests at
//! precedence row 6 (the `n` field, after the purpose and before the exact body length): after
//! the phase (row 5) and before the id, capacity and rate rules (row 8). Codex #85 U1 r1 MAJOR 1.
//!
//! Each test's FIRST assertion is its rule (so a RED fails at that rule, by name); controls follow.

use super::support::*;
use crate::{
    decode_p2d, DaemonStepKind, IpcRefusal, ModeKind, OutboundAdmit, ProxyInput, ProxyStepKind,
    Purpose, Sha256Digest,
};
use std::vec::Vec;

use DaemonStepKind as Dk;
use IpcRefusal::*;
use ProxyStepKind as Pk;

fn digests(n: usize) -> Vec<Sha256Digest> {
    (0..n)
        .map(|i| Sha256Digest::of(&[0x40 + i as u8]))
        .collect()
}

fn blocks(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| [0x50 + i as u8; 32]).collect()
}

const MODES: [ModeKind; 3] = [
    ModeKind::ForwardTcp,
    ModeKind::ForwardUnix,
    ModeKind::Static,
];

#[test]
fn t_shape_construction_refuses_a_lease_exchange_above_one_digest() {
    for n in 2..=8usize {
        assert!(
            OutboundAdmit::new(Purpose::LeaseExchange, &digests(n)).is_err(),
            "T-SHAPE: OutboundAdmit::new(LeaseExchange, {} digests) is refused at construction",
            n
        );
    }
    for n in 0..=1usize {
        let admit = OutboundAdmit::new(Purpose::LeaseExchange, &digests(n))
            .unwrap_or_else(|_| panic!("control: a lease exchange with {} digest(s) builds", n));
        assert_eq!(admit.digest_count(), n);
        assert_eq!(admit.purpose(), Purpose::LeaseExchange);
    }
    for n in 0..=8usize {
        assert!(
            OutboundAdmit::new(Purpose::Forward, &digests(n)).is_ok(),
            "control: a forward admission carries {} digests",
            n
        );
    }
    assert!(
        OutboundAdmit::new(Purpose::Forward, &digests(9)).is_err(),
        "control: nine never build"
    );
}

#[test]
fn t_shape_the_stateless_decoder_refuses_a_lease_exchange_above_one_digest() {
    for n in 2..=8usize {
        assert_eq!(
            decode_p2d(&admit_bytes(1, 2, &blocks(n))).err(),
            Some(TooManyDigests),
            "T-SHAPE: the stateless decoder refuses a lease exchange with {} digests",
            n
        );
    }
    for n in 0..=1usize {
        assert!(
            decode_p2d(&admit_bytes(1, 2, &blocks(n))).is_ok(),
            "control: a lease exchange with {} digest(s) decodes",
            n
        );
    }
    assert!(
        decode_p2d(&admit_bytes(1, 1, &blocks(8))).is_ok(),
        "control: without a mode, a forward ADMIT with eight decodes (the session applies the mode)"
    );
}

#[test]
fn t_shape_the_daemon_refuses_a_lease_exchange_with_two_digests_in_every_mode() {
    for mode in MODES {
        let pool = Pool::new();
        let mut d = daemon_active(&pool, mode);
        assert_eq!(
            drecv_k(&mut d, &admit_bytes(1, 2, &blocks(2))),
            Dk::Refused(TooManyDigests),
            "T-SHAPE: the daemon ({:?}) refuses a raw lease-exchange ADMIT with n = 2",
            mode
        );
        assert_eq!(d.test_only_pending_len(), 0, "nothing was committed");
    }
    for mode in MODES {
        for n in 0..=1usize {
            let pool = Pool::new();
            let mut d = daemon_active(&pool, mode);
            assert_eq!(
                drecv_k(&mut d, &admit_bytes(1, 2, &blocks(n))),
                Dk::Admit,
                "control: a lease exchange with {} digest(s) is admitted ({:?})",
                n,
                mode
            );
        }
    }
}

#[test]
fn t_shape_the_daemon_refuses_a_static_admit_with_two_digests() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::Static);
    assert_eq!(
        drecv_k(&mut d, &admit_bytes(1, 1, &blocks(2))),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: the daemon (static) refuses a forward ADMIT with n = 2"
    );
    for n in 0..=1usize {
        let mut d = daemon_active(&pool, ModeKind::Static);
        assert_eq!(
            drecv_k(&mut d, &admit_bytes(1, 1, &blocks(n))),
            Dk::Admit,
            "control: static with {} digest(s)",
            n
        );
    }
    for mode in [ModeKind::ForwardTcp, ModeKind::ForwardUnix] {
        let mut d = daemon_active(&pool, mode);
        assert_eq!(
            drecv_k(&mut d, &admit_bytes(1, 1, &blocks(8))),
            Dk::Admit,
            "control: a forward mode ({:?}) admits eight",
            mode
        );
    }
}

#[test]
fn t_shape_the_proxy_refuses_to_prepare_a_static_admit_with_two_digests() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::Static);
    let two = OutboundAdmit::new(Purpose::Forward, &digests(2)).expect("two digests build");
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(two)).kind(),
        Pk::Refused(TooManyDigests),
        "T-SHAPE: the proxy (static) refuses to prepare a forward ADMIT with n = 2"
    );
    assert!(p.outgoing().is_none(), "nothing is prepared for sending");
    let mut p = proxy_active(&pool, ModeKind::Static);
    assert!(
        proxy_send_admit(&mut p, Purpose::Forward, 1).is_some(),
        "control: static with one digest is sent"
    );
    assert!(
        proxy_send_admit(&mut p, Purpose::Forward, 0).is_some(),
        "control: static with none is sent"
    );
    assert!(
        proxy_send_admit(&mut p, Purpose::LeaseExchange, 1).is_some(),
        "control: static, a lease exchange with its form token is sent"
    );
    for mode in [ModeKind::ForwardTcp, ModeKind::ForwardUnix] {
        let mut p = proxy_active(&pool, mode);
        assert!(
            proxy_send_admit(&mut p, Purpose::Forward, 8).is_some(),
            "control: a forward mode ({:?}) sends eight",
            mode
        );
    }
}

#[test]
fn t_shape_daemon_row_6_n_before_the_exact_body_length() {
    let pool = Pool::new();
    let mut short = admit_bytes(1, 2, &blocks(1));
    short[13] = 2;
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        drecv_k(&mut d, &short),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: row 6's n field before the exact body length (exchange n = 2, one block)"
    );
    let mut short = admit_bytes(1, 1, &blocks(1));
    short[13] = 2;
    let mut d = daemon_active(&pool, ModeKind::Static);
    assert_eq!(
        drecv_k(&mut d, &short),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: row 6's n field before the exact body length (static n = 2, one block)"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        drecv_k(&mut d, &short),
        Dk::Refused(LengthMismatch),
        "control: a forward mode allows n = 2, so the exact length refuses"
    );
}

#[test]
fn t_shape_daemon_row_6_before_row_8() {
    let pool = Pool::new();
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(drecv_k(&mut d, &admit_bytes(5, 1, &blocks(1))), Dk::Admit);
    assert_eq!(
        drecv_k(&mut d, &admit_bytes(3, 2, &blocks(2))),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: row 6 before row 8 (exchange n = 2 with a nonincreasing id)"
    );
    let mut d = daemon_with_pending(&pool, 64);
    assert_eq!(
        drecv_k(&mut d, &admit_bytes(65, 2, &blocks(2))),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: row 6 before row 8 (exchange n = 2 with the pending map full)"
    );
    let mut d = daemon_active(&pool, ModeKind::Static);
    assert_eq!(drecv_k(&mut d, &admit_bytes(5, 1, &blocks(1))), Dk::Admit);
    assert_eq!(
        drecv_k(&mut d, &admit_bytes(5, 1, &blocks(2))),
        Dk::Refused(TooManyDigests),
        "T-SHAPE: row 6 before row 8 (static n = 2 with a repeated id)"
    );
}

#[test]
fn t_shape_proxy_row_6_before_row_8() {
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::Static);
    for _ in 0..64 {
        assert!(proxy_send_admit(&mut p, Purpose::Forward, 1).is_some());
    }
    assert_eq!(p.test_only_pending_len(), 64, "the pending map is full");
    let two = OutboundAdmit::new(Purpose::Forward, &digests(2)).expect("two digests build");
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(two)).kind(),
        Pk::Refused(TooManyDigests),
        "T-SHAPE: the proxy's row 6 before row 8 (static n = 2 with the pending map full)"
    );
}

#[test]
fn t_shape_row_5_before_row_6_on_both_sides() {
    let mut d = daemon_new();
    assert_eq!(
        drecv_k(&mut d, &admit_bytes(1, 2, &blocks(2))),
        Dk::Refused(OutOfOrder),
        "T-SHAPE: the daemon's row 5 (an ADMIT before WELCOME) before row 6"
    );
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::Static);
    let one = OutboundAdmit::new(Purpose::Forward, &digests(1)).expect("one digest");
    assert_eq!(p.step(ProxyInput::PrepareAdmit(one)).kind(), Pk::Send);
    let two = OutboundAdmit::new(Purpose::Forward, &digests(2)).expect("two digests build");
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(two)).kind(),
        Pk::Refused(OutOfOrder),
        "T-SHAPE: the proxy's row 5 (a send in progress) before row 6"
    );
    let mut p = proxy_awaiting_welcome();
    let two = OutboundAdmit::new(Purpose::Forward, &digests(2)).expect("two digests build");
    assert_eq!(
        p.step(ProxyInput::PrepareAdmit(two)).kind(),
        Pk::Refused(OutOfOrder),
        "T-SHAPE: the proxy's row 5 (not Active) before row 6"
    );
}
