//! T-CANONICAL: the TEST-ONLY encoder of decoded (inbound) values. It lives only in this
//! `cfg(test)` module, so no shipped build (no feature exists) contains it; T-API in the
//! compile-fail crate pins that the `tests` module is declared `#[cfg(test)]`, and cf16 pins that
//! the production encoder accepts no inbound type.

use super::support::*;
use crate::daemon::{encode_shutdown, encode_verdict, encode_welcome};
use crate::{
    decode_d2p, decode_p2d, encode_p2d, AdmissionId, EventCode, InboundD2p, InboundP2d, ModeKind,
    OutboundAdmit, OutboundEvent, OutboundP2d, Outcome, Purpose, Sha256Digest,
};
use std::vec::Vec;

/// The test-only canonical re-encoder of a decoded P2D message.
pub(crate) fn test_encode_p2d(message: &InboundP2d) -> Vec<u8> {
    match message {
        InboundP2d::Ready => raw_frame(crate::wire::KIND_READY, &[]),
        InboundP2d::Admit(admit) => {
            let digests: Vec<[u8; 32]> = admit
                .presented()
                .iter()
                .map(|d| *d.test_only_bytes())
                .collect();
            admit_bytes(admit.id().get(), admit.purpose().wire(), &digests)
        }
        InboundP2d::Event(event) => event_bytes(0, event.code().wire(), event.count()),
    }
}

/// The test-only canonical re-encoder of a decoded D2P message.
pub(crate) fn test_encode_d2p(message: &InboundD2p) -> Vec<u8> {
    match message {
        InboundD2p::Welcome(welcome) => {
            let (mode, upstream, has_token) = match welcome.mode() {
                ModeKind::ForwardTcp => (1, 1, 0),
                ModeKind::ForwardUnix => (1, 2, 1),
                ModeKind::Static => (2, 0, 0),
            };
            welcome_bytes(
                mode,
                upstream,
                welcome.public_port(),
                &welcome.host_label,
                has_token,
                &welcome.token,
            )
        }
        InboundD2p::Verdict(id, outcome) => verdict_bytes(id.get(), outcome.wire()),
        InboundD2p::Shutdown => shutdown_bytes(),
    }
}

/// Every P2D shape the corpus builder covers: READY, ADMIT n = 0..=8 for both purposes and several
/// ids with arbitrary digest blocks, EVENT for every code at boundary counts. A lease exchange
/// with n >= 2 is among them but is NOT accepted (T-SHAPE: TooManyDigests); [`p2d_frames`] is the
/// accepted subset.
pub(crate) fn p2d_shapes() -> Vec<Vec<u8>> {
    let mut rng = Rng(0x85_c0de);
    let mut out = std::vec![ready_bytes()];
    for purpose in [1u8, 2] {
        for n in 0..=8usize {
            for id in [1u32, 7, 0x8000_0000, u32::MAX] {
                let digests: Vec<[u8; 32]> = (0..n)
                    .map(|_| {
                        let mut d = [0u8; 32];
                        d.copy_from_slice(&rng.bytes(32));
                        d
                    })
                    .collect();
                out.push(admit_bytes(id, purpose, &digests));
            }
        }
    }
    for code in 1u16..=12 {
        for count in [1u32, 1025, u32::MAX] {
            out.push(event_bytes(0, code, count));
        }
    }
    out
}

/// True for an ADMIT frame whose shape no mode accepts: a lease exchange with n >= 2 (DESIGN v2
/// (3): it carries only its form token).
pub(crate) fn is_refused_exchange_shape(frame: &[u8]) -> bool {
    frame.len() >= 14 && frame[3] == crate::wire::KIND_ADMIT && frame[12] == 2 && frame[13] >= 2
}

/// Every ACCEPTED P2D shape: [`p2d_shapes`] without the lease exchanges above one digest (ADMIT
/// n = 0..=8 forward, n = 0..=1 lease exchange).
pub(crate) fn p2d_frames() -> Vec<Vec<u8>> {
    p2d_shapes()
        .into_iter()
        .filter(|frame| !is_refused_exchange_shape(frame))
        .collect()
}

/// Every accepted D2P shape: WELCOME in the three configurations at boundary ports with several
/// labels and tokens, VERDICT for every outcome, SHUTDOWN.
pub(crate) fn d2p_frames() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let labels = [
        *b"0123456789abcdef",
        *b"ffffffffffffffff",
        *b"0000000000000000",
    ];
    let tokens = [[b'5'; 64], [b'a'; 64], [b'0'; 64]];
    for port in [1u16, PORT, u16::MAX] {
        for (label, token) in labels.iter().zip(tokens.iter()) {
            out.push(welcome_bytes(1, 1, port, label, 0, &[0; 64]));
            out.push(welcome_bytes(1, 2, port, label, 1, token));
            out.push(welcome_bytes(2, 0, port, label, 0, &[0; 64]));
        }
    }
    for id in [0u32, 1, 64, u32::MAX] {
        for outcome in 0u8..=3 {
            out.push(verdict_bytes(id, outcome));
        }
    }
    out.push(shutdown_bytes());
    out
}

#[test]
fn t_canonical_every_accepted_p2d_frame_reencodes_byte_for_byte() {
    for frame in p2d_frames() {
        let decoded = decode_p2d(&frame).unwrap_or_else(|code| {
            panic!(
                "T-CANONICAL: a valid P2D frame was refused {:?}: {:02x?}",
                code, frame
            )
        });
        assert_eq!(
            test_encode_p2d(&decoded),
            frame,
            "T-CANONICAL: a P2D frame does not re-encode byte for byte"
        );
    }
}

#[test]
fn t_canonical_every_accepted_d2p_frame_reencodes_byte_for_byte() {
    for frame in d2p_frames() {
        let decoded = decode_d2p(&frame).unwrap_or_else(|code| {
            panic!(
                "T-CANONICAL: a valid D2P frame was refused {:?}: {:02x?}",
                code, frame
            )
        });
        assert_eq!(
            test_encode_d2p(&decoded),
            frame,
            "T-CANONICAL: a D2P frame does not re-encode byte for byte"
        );
    }
}

#[test]
fn t_canonical_the_outbound_encoder_writes_the_specified_layout() {
    let digests = [Sha256Digest::of(b"a"), Sha256Digest::of(b"b")];
    let admit = OutboundAdmit::new(Purpose::Forward, &digests).expect("two digests");
    let frame = encode_p2d(&OutboundP2d::Admit(
        AdmissionId::from_raw(0x0102_0304),
        admit,
    ));
    let bytes = frame.as_bytes();
    assert_eq!(bytes.len(), 14 + 64, "ADMIT total = 14 + 32n");
    assert_eq!(
        &bytes[0..8],
        &[b'I', b'P', 2, 0x02, 70, 0, 0, 0],
        "ADMIT header"
    );
    assert_eq!(&bytes[8..12], &[0x04, 0x03, 0x02, 0x01], "conn u32 LE");
    assert_eq!(&bytes[12..14], &[1, 2], "purpose, n");
    assert_eq!(&bytes[14..46], Sha256Digest::of(b"a").as_bytes());
    assert_eq!(&bytes[46..78], Sha256Digest::of(b"b").as_bytes());
    let decoded = decode_p2d(bytes).expect("the outbound ADMIT decodes");
    assert_eq!(
        test_encode_p2d(&decoded),
        bytes,
        "outbound encode == canonical"
    );

    let ready = encode_p2d(&OutboundP2d::Ready);
    assert_eq!(
        ready.as_bytes(),
        &[b'I', b'P', 2, 0x01, 0, 0, 0, 0],
        "READY = 8 bytes"
    );
    let event = OutboundEvent::new(EventCode::SessionCookieDropped, 1025).expect("nonzero");
    let event = encode_p2d(&OutboundP2d::Event(event));
    assert_eq!(event.as_bytes().len(), 18, "EVENT = 18 bytes");
    assert_eq!(
        &event.as_bytes()[8..18],
        &[0, 0, 0, 0, 12, 0, 0x01, 0x04, 0, 0]
    );
    assert!(
        OutboundEvent::new(EventCode::ProxyStarted, 0).is_none(),
        "zero counters are never sent"
    );
}

#[test]
fn t_canonical_the_daemon_encoders_write_the_specified_layout() {
    for mode in [
        ModeKind::ForwardTcp,
        ModeKind::ForwardUnix,
        ModeKind::Static,
    ] {
        let frame = encode_welcome(&welcome_spec(mode))
            .ok()
            .expect("a valid WELCOME");
        assert_eq!(frame.as_bytes().len(), 93, "WELCOME = 93 bytes");
        assert_eq!(
            frame.as_bytes(),
            welcome_for(mode).as_slice(),
            "WELCOME layout"
        );
        let token = &frame.as_bytes()[29..93];
        if mode == ModeKind::ForwardUnix {
            assert_eq!(token, &TOKEN[..], "the UNIX token");
        } else {
            assert!(
                token.iter().all(|b| *b == 0),
                "an absent token is 64 ZERO bytes, not '0'"
            );
        }
    }
    for outcome in [
        Outcome::Denied,
        Outcome::AdmittedUpstream,
        Outcome::AdmittedNoUpstream,
        Outcome::UpstreamUnavailable,
    ] {
        let frame = encode_verdict(AdmissionId::from_raw(9), outcome);
        assert_eq!(
            frame.as_bytes(),
            verdict_bytes(9, outcome.wire()).as_slice(),
            "VERDICT = 13"
        );
    }
    assert_eq!(
        encode_shutdown().as_bytes(),
        shutdown_bytes().as_slice(),
        "SHUTDOWN = 8"
    );
}
