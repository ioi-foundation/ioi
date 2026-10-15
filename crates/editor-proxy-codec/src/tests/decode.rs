//! The stateless decoders' field refusals and the decoder-level precedence pairs (rows 3, 4, 6),
//! plus the session-level pairs that involve rows 1, 2, 5, 7 and 8.

use super::support::*;
use crate::{
    decode_d2p, decode_p2d, DaemonInput, DaemonStepKind, FdFacts, IpcRefusal, ModeKind, P2dRecv,
    ProxyStepKind, SocketClass,
};
use std::vec::Vec;

fn p2d_err(frame: &[u8]) -> Option<IpcRefusal> {
    decode_p2d(frame).err()
}

fn d2p_err(frame: &[u8]) -> Option<IpcRefusal> {
    decode_d2p(frame).err()
}

fn with_header(mut frame: Vec<u8>, at: usize, value: u8) -> Vec<u8> {
    frame[at] = value;
    frame
}

#[test]
fn t_decode_size_rows_truncated_and_oversized() {
    use IpcRefusal::*;
    assert_eq!(p2d_err(&[]), Some(Truncated), "empty");
    assert_eq!(
        p2d_err(&ready_bytes()[..7]),
        Some(Truncated),
        "7 header bytes"
    );
    let mut big = raw_frame(0x02, &[0u8; 505]);
    assert_eq!(big.len(), 513);
    assert_eq!(
        p2d_err(&big),
        Some(Oversized),
        "513 bytes (the receive buffer's extra byte)"
    );
    big.truncate(512);
    assert_ne!(p2d_err(&big), Some(Oversized), "512 bytes is not oversized");
    assert_eq!(
        d2p_err(&[0u8; 600]),
        Some(Oversized),
        "D2P oversized before BadMagic"
    );
}

#[test]
fn t_decode_header_rows_in_order() {
    use IpcRefusal::*;
    let ready = ready_bytes();
    assert_eq!(
        p2d_err(&with_header(ready.clone(), 0, b'X')),
        Some(BadMagic)
    );
    assert_eq!(
        p2d_err(&with_header(ready.clone(), 2, 1)),
        Some(BadVersion),
        "no version-1 path"
    );
    assert_eq!(
        p2d_err(&with_header(ready.clone(), 3, 0x81)),
        Some(UnknownKind),
        "a D2P kind"
    );
    assert_eq!(
        d2p_err(&with_header(ready.clone(), 3, 0x01)),
        Some(UnknownKind),
        "a P2D kind"
    );
    assert_eq!(
        p2d_err(&with_header(ready.clone(), 6, 1)),
        Some(ReservedNonzero)
    );
    assert_eq!(
        p2d_err(&with_header(ready.clone(), 4, 1)),
        Some(LengthMismatch),
        "body_len"
    );
    // Multidefect pairs: each earlier field wins.
    let both = with_header(with_header(ready.clone(), 0, b'X'), 2, 9);
    assert_eq!(p2d_err(&both), Some(BadMagic), "magic before version");
    let both = with_header(with_header(ready.clone(), 2, 9), 3, 0x7f);
    assert_eq!(p2d_err(&both), Some(BadVersion), "version before kind");
    let both = with_header(with_header(ready.clone(), 3, 0x7f), 6, 1);
    assert_eq!(p2d_err(&both), Some(UnknownKind), "kind before reserved");
    let both = with_header(with_header(ready.clone(), 6, 1), 4, 9);
    assert_eq!(
        p2d_err(&both),
        Some(ReservedNonzero),
        "reserved before body_len"
    );
    let mut short = ready.clone();
    short.truncate(7);
    short[0] = b'X';
    assert_eq!(p2d_err(&short), Some(Truncated), "size before magic");
}

#[test]
fn t_decode_p2d_body_rows_in_wire_order() {
    use IpcRefusal::*;
    // Minimum body first, without reading fields: a 5-byte ADMIT body with a bad purpose byte.
    assert_eq!(
        p2d_err(&raw_frame(0x02, &[1, 0, 0, 0, 9])),
        Some(LengthMismatch)
    );
    assert_eq!(
        p2d_err(&raw_frame(0x02, &[1, 0, 0, 0, 9, 0])),
        Some(BadPurpose)
    );
    assert_eq!(
        p2d_err(&raw_frame(0x02, &[1, 0, 0, 0, 9, 9])),
        Some(BadPurpose),
        "purpose before n"
    );
    assert_eq!(
        p2d_err(&raw_frame(0x02, &[1, 0, 0, 0, 1, 9])),
        Some(TooManyDigests),
        "n before length"
    );
    assert_eq!(
        p2d_err(&raw_frame(0x02, &[1, 0, 0, 0, 1, 1])),
        Some(LengthMismatch),
        "6+32n"
    );
    let mut long = admit_bytes(1, 1, &[[1; 32]]);
    long.push(0);
    long[4] += 1;
    assert_eq!(p2d_err(&long), Some(LengthMismatch), "a trailing byte");
    assert_eq!(
        p2d_err(&raw_frame(0x01, &[0])),
        Some(LengthMismatch),
        "READY body"
    );
    assert_eq!(
        p2d_err(&raw_frame(0x03, &[0; 9])),
        Some(LengthMismatch),
        "EVENT minimum"
    );
    assert_eq!(
        p2d_err(&event_bytes(1, 0, 0)),
        Some(BadEventConnection),
        "conn before code"
    );
    assert_eq!(
        p2d_err(&event_bytes(0, 13, 0)),
        Some(BadEventCode),
        "code before count"
    );
    assert_eq!(p2d_err(&event_bytes(0, 0, 1)), Some(BadEventCode));
    assert_eq!(p2d_err(&event_bytes(0, 12, 0)), Some(BadEventCount));
    let mut long_event = event_bytes(0, 1, 1);
    long_event.push(0);
    long_event[4] += 1;
    assert_eq!(p2d_err(&long_event), Some(LengthMismatch), "EVENT exact");
    assert!(
        p2d_err(&event_bytes(0, 1, u32::MAX)).is_none(),
        "count u32::MAX is valid"
    );
    assert!(
        p2d_err(&admit_bytes(0, 2, &[[0; 32]; 8])).is_none(),
        "id 0 decodes (row 8 refuses)"
    );
}

#[test]
fn t_decode_d2p_body_rows_in_wire_order() {
    use IpcRefusal::*;
    assert_eq!(
        d2p_err(&raw_frame(0x81, &[0; 84])),
        Some(LengthMismatch),
        "WELCOME minimum"
    );
    for (mode, upstream, has_token) in [
        (1u8, 1u8, 1u8),
        (1, 2, 0),
        (2, 1, 0),
        (2, 0, 1),
        (0, 0, 0),
        (3, 1, 0),
    ] {
        let token = if has_token == 1 { TOKEN } else { [0; 64] };
        let frame = welcome_bytes(mode, upstream, PORT, &LABEL, has_token, &token);
        assert_eq!(
            d2p_err(&frame),
            Some(BadWelcome),
            "tuple ({}, {}, {})",
            mode,
            upstream,
            has_token
        );
    }
    assert_eq!(
        d2p_err(&welcome_bytes(1, 1, 0, &LABEL, 0, &[0; 64])),
        Some(BadWelcome),
        "port 0"
    );
    let mut upper = LABEL;
    upper[3] = b'A';
    assert_eq!(
        d2p_err(&welcome_bytes(1, 1, PORT, &upper, 0, &[0; 64])),
        Some(BadWelcome),
        "label"
    );
    let mut bad_token = TOKEN;
    bad_token[63] = b'g';
    assert_eq!(
        d2p_err(&welcome_bytes(1, 2, PORT, &LABEL, 1, &bad_token)),
        Some(BadWelcome),
        "token"
    );
    assert_eq!(
        d2p_err(&welcome_bytes(1, 1, PORT, &LABEL, 0, &[b'0'; 64])),
        Some(BadWelcome),
        "an absent token is 64 ZERO bytes, not ASCII '0'"
    );
    let mut long = welcome_for(ModeKind::Static);
    long.push(0);
    long[4] += 1;
    assert_eq!(d2p_err(&long), Some(LengthMismatch), "WELCOME exact");
    assert_eq!(
        d2p_err(&raw_frame(0x82, &[0; 4])),
        Some(LengthMismatch),
        "VERDICT minimum"
    );
    assert_eq!(d2p_err(&verdict_bytes(1, 4)), Some(BadOutcome));
    let mut long_verdict = verdict_bytes(1, 9);
    long_verdict.push(0);
    long_verdict[4] += 1;
    assert_eq!(
        d2p_err(&long_verdict),
        Some(BadOutcome),
        "outcome before exact length"
    );
    assert_eq!(
        d2p_err(&raw_frame(0x83, &[0])),
        Some(LengthMismatch),
        "SHUTDOWN body"
    );
}

#[test]
fn t_precedence_session_rows_across_layers() {
    use IpcRefusal::*;
    let pool = Pool::new();
    // Row 2 before row 3/4: MSG_CTRUNC with a bad magic.
    let mut d = daemon_new();
    let bad = with_header(ready_bytes(), 0, b'X');
    let step = d.step(DaemonInput::Recv(P2dRecv {
        bytes: &bad,
        msg_trunc: true,
        msg_ctrunc: true,
        control_present: false,
    }));
    assert_eq!(
        step.kind(),
        DaemonStepKind::Refused(AncillaryFromProxy),
        "row 2 first"
    );
    // Row 3 before row 4: MSG_TRUNC with a bad magic.
    let mut d = daemon_new();
    let step = d.step(DaemonInput::Recv(P2dRecv {
        bytes: &bad,
        msg_trunc: true,
        msg_ctrunc: false,
        control_present: false,
    }));
    assert_eq!(
        step.kind(),
        DaemonStepKind::Refused(Truncated),
        "MSG_TRUNC is Truncated"
    );
    // Row 5 before row 6: an ADMIT with a bad purpose before READY.
    let mut d = daemon_new();
    assert_eq!(
        drecv_k(&mut d, &raw_frame(0x02, &[1, 0, 0, 0, 9, 0])),
        DaemonStepKind::Refused(OutOfOrder),
        "phase before fields"
    );
    // Row 6 in Active: bad purpose and too many digests.
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        drecv_k(&mut d, &raw_frame(0x02, &[1, 0, 0, 0, 9, 9])),
        DaemonStepKind::Refused(BadPurpose)
    );
    // Row 8 order: a nonincreasing id with the pending map full -> ConnNotIncreasing.
    let mut d = daemon_with_pending(&pool, 64);
    assert_eq!(
        drecv_k(&mut d, &admit1(3)),
        DaemonStepKind::Refused(ConnNotIncreasing)
    );
    // Row 1: a fatal send result for a stale op is SendFailed.
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    let step = d.step(DaemonInput::SendResult(
        crate::OpId::from_raw(77),
        crate::SendOutcome::Fatal,
    ));
    assert_eq!(
        step.kind(),
        DaemonStepKind::Refused(SendFailed),
        "row 1 before row 5"
    );
    // Row 1: F0 failure outside CheckingF0 is BoundaryUnverified; a pass there is OutOfOrder.
    let mut d = daemon_new();
    assert_eq!(
        d.step(DaemonInput::F0(crate::F0Result::Fail)).kind(),
        DaemonStepKind::Refused(BoundaryUnverified)
    );
    let mut d = daemon_new();
    assert_eq!(
        d.step(DaemonInput::F0(crate::F0Result::Pass)).kind(),
        DaemonStepKind::Refused(OutOfOrder),
        "a forged F0 pass outside CheckingF0"
    );
    // Proxy: row 2 order (ctrunc before unexpected control).
    let mut p = proxy_awaiting_welcome();
    let welcome = welcome_for(ModeKind::ForwardTcp);
    let step = p.step(crate::ProxyInput::Recv(crate::D2pRecv {
        bytes: &welcome,
        msg_trunc: true,
        msg_ctrunc: true,
        unexpected_control: true,
        fds: crate::FdBatch::new(),
    }));
    assert_eq!(step.kind(), ProxyStepKind::Refused(AncillaryTruncated));
    let mut p = proxy_awaiting_welcome();
    let step = p.step(crate::ProxyInput::Recv(crate::D2pRecv {
        bytes: &welcome,
        msg_trunc: true,
        msg_ctrunc: false,
        unexpected_control: true,
        fds: crate::FdBatch::new(),
    }));
    assert_eq!(step.kind(), ProxyStepKind::Refused(UnexpectedAncillary));
    // Proxy: row 6 before row 7 (a bad outcome byte with a wrong fd count).
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let _ = proxy_send_admit(&mut p, crate::Purpose::Forward, 1);
    assert_eq!(
        precv_k(
            &mut p,
            &pool,
            &verdict_bytes(1, 7),
            &[listener(), listener()]
        ),
        ProxyStepKind::Refused(BadOutcome)
    );
    // Proxy: row 7 before row 8 (outcome 1 with no fd, for an unknown id).
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(99, 1), &[]),
        ProxyStepKind::Refused(BadFdCount)
    );
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let unix = FdFacts::connected_upstream(SocketClass::UnixStream);
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(99, 1), &[unix]),
        ProxyStepKind::Refused(BadFdKind)
    );
    // Proxy: row 8 order (a completed id with an illegal outcome -> DuplicateVerdict).
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    let id = proxy_send_admit(&mut p, crate::Purpose::Forward, 1).expect("sent");
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(id.get(), 0), &[]),
        ProxyStepKind::Verdict
    );
    assert_eq!(
        precv_k(&mut p, &pool, &verdict_bytes(id.get(), 2), &[]),
        ProxyStepKind::Refused(DuplicateVerdict)
    );
    assert_eq!(
        pool.live(),
        0,
        "every refused receive closed its descriptors"
    );
}

/// Two precedence orders no earlier test distinguished (S1-85D: t1's codec mutants M11 and M29
/// survived the suite). Row 3: a datagram longer than the 513-byte receive buffer arrives as 513
/// bytes WITH MSG_TRUNC, and that is Truncated, never Oversized, on both machines (513 bytes
/// without MSG_TRUNC stays Oversized). Row 8: a valid ADMIT checks the id, then pending < 64, then
/// the window count < 2000, so with the pending map full AND 2000 admissions in the window the
/// refusal is TooManyInFlight, never RateExceeded.
#[test]
fn t_precedence_row_3_truncation_and_row_8_pending_before_rate() {
    use IpcRefusal::*;
    let pool = Pool::new();
    let big = raw_frame(0x02, &[0u8; 505]);
    assert_eq!(big.len(), 513);
    let mut d = daemon_new();
    let step = d.step(DaemonInput::Recv(P2dRecv {
        bytes: &big,
        msg_trunc: true,
        msg_ctrunc: false,
        control_present: false,
    }));
    assert_eq!(
        step.kind(),
        DaemonStepKind::Refused(Truncated),
        "row 3: MSG_TRUNC before Oversized (daemon)"
    );
    let mut d = daemon_new();
    assert_eq!(
        drecv_k(&mut d, &big),
        DaemonStepKind::Refused(Oversized),
        "513 bytes without MSG_TRUNC is Oversized (daemon)"
    );
    let big_d2p = raw_frame(0x81, &[0u8; 505]);
    assert_eq!(big_d2p.len(), 513);
    let mut p = proxy_awaiting_welcome();
    let step = p.step(crate::ProxyInput::Recv(crate::D2pRecv {
        bytes: &big_d2p,
        msg_trunc: true,
        msg_ctrunc: false,
        unexpected_control: false,
        fds: crate::FdBatch::new(),
    }));
    assert_eq!(
        step.kind(),
        ProxyStepKind::Refused(Truncated),
        "row 3: MSG_TRUNC before Oversized (proxy)"
    );
    let mut d = daemon_active(&pool, ModeKind::ForwardTcp);
    for id in 1..=1936 {
        assert_eq!(
            daemon_exchange(&mut d, id),
            (DaemonStepKind::Admit, DaemonStepKind::VerdictSent),
            "exchange {}",
            id
        );
    }
    for id in 1937..=2000 {
        assert_eq!(
            drecv_k(&mut d, &admit1(id)),
            DaemonStepKind::Admit,
            "unanswered {}",
            id
        );
    }
    assert_eq!(d.test_only_pending_len(), 64, "the pending map is full");
    assert_eq!(
        d.test_only_window_admissions(),
        2000,
        "the window count is at its limit"
    );
    assert_eq!(
        drecv_k(&mut d, &admit1(2001)),
        DaemonStepKind::Refused(TooManyInFlight),
        "row 8: pending < 64 before count < 2000"
    );
}
