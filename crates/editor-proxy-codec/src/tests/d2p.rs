//! T-D2P (pure level): the received descriptors' facts against each message's rules (row 7, in
//! order), and closure of every received descriptor on rejection. The REAL-descriptor half
//! (socketpairs, wrong domains, listening and unconnected sockets) is the fd adapter's, U3/U4.

use super::support::*;
use crate::{
    D2pRecv, FdBatch, FdFacts, IpcRefusal, ModeKind, ProxyInput, ProxyStep, ProxyStepKind, Purpose,
    ReceivedFd, SocketClass,
};

use IpcRefusal::*;
use ProxyStepKind as Pk;

#[test]
fn t_d2p_welcome_listener_rules() {
    let inet = FdFacts::connected_upstream(SocketClass::InetStream);
    let cases: [(&[FdFacts], Pk); 9] = [
        (&[], Pk::Refused(BadFdCount)),
        (&[listener(), listener()], Pk::Refused(BadFdCount)),
        (
            &[FdFacts {
                class: SocketClass::UnixStream,
                ..listener()
            }],
            Pk::Refused(BadFdKind),
        ),
        (
            &[FdFacts {
                class: SocketClass::Other,
                ..listener()
            }],
            Pk::Refused(BadFdKind),
        ),
        (&[inet], Pk::Refused(BadListener)),
        (
            &[FdFacts {
                pending_error: true,
                ..listener()
            }],
            Pk::Refused(BadListener),
        ),
        (
            &[FdFacts::loopback_listener(PORT + 1)],
            Pk::Refused(BadListener),
        ),
        (
            &[FdFacts {
                local_inet: Some(([0, 0, 0, 0], PORT)),
                ..listener()
            }],
            Pk::Refused(BadListener),
        ),
        (&[listener()], Pk::Welcome),
    ];
    for (i, (facts, want)) in cases.iter().enumerate() {
        let pool = Pool::new();
        let mut p = proxy_awaiting_welcome();
        let got = precv_k(&mut p, &pool, &welcome_for(ModeKind::ForwardTcp), facts);
        assert_eq!(got, *want, "T-D2P WELCOME case {}", i);
        assert_eq!(
            pool.live(),
            0,
            "T-D2P WELCOME case {}: a descriptor stayed open",
            i
        );
    }
}

#[test]
fn t_d2p_verdict_upstream_rules_per_mode() {
    let inet = FdFacts::connected_upstream(SocketClass::InetStream);
    let unix = FdFacts::connected_upstream(SocketClass::UnixStream);
    let cases: [(ModeKind, u8, &[FdFacts], Pk); 12] = [
        (ModeKind::ForwardTcp, 1, &[], Pk::Refused(BadFdCount)),
        (
            ModeKind::ForwardTcp,
            1,
            &[inet, inet],
            Pk::Refused(BadFdCount),
        ),
        (ModeKind::ForwardTcp, 1, &[unix], Pk::Refused(BadFdKind)),
        (
            ModeKind::ForwardTcp,
            1,
            &[FdFacts {
                accept_conn: true,
                ..inet
            }],
            Pk::Refused(NotConnected),
        ),
        (
            ModeKind::ForwardTcp,
            1,
            &[FdFacts {
                connected: false,
                ..inet
            }],
            Pk::Refused(NotConnected),
        ),
        (
            ModeKind::ForwardTcp,
            1,
            &[FdFacts {
                pending_error: true,
                ..inet
            }],
            Pk::Refused(NotConnected),
        ),
        (
            ModeKind::ForwardTcp,
            1,
            &[FdFacts {
                peer_matches_spec: false,
                ..inet
            }],
            Pk::Refused(EndpointMismatch),
        ),
        (ModeKind::ForwardTcp, 1, &[inet], Pk::Verdict),
        (ModeKind::ForwardUnix, 1, &[inet], Pk::Refused(BadFdKind)),
        (ModeKind::ForwardUnix, 1, &[unix], Pk::Verdict),
        (ModeKind::ForwardTcp, 0, &[inet], Pk::Refused(BadFdCount)),
        (ModeKind::Static, 1, &[inet], Pk::Refused(BadFdKind)),
    ];
    for (i, (mode, outcome, facts, want)) in cases.iter().enumerate() {
        let pool = Pool::new();
        let mut p = proxy_active(&pool, *mode);
        let id = proxy_send_admit(&mut p, Purpose::Forward, 1).expect("sent");
        let step = precv(&mut p, &pool, &verdict_bytes(id.get(), *outcome), facts);
        assert_eq!(step.kind(), *want, "T-D2P VERDICT case {}", i);
        if let ProxyStep::Verdict(_, _, upstream) = &step {
            assert!(
                upstream.is_some(),
                "T-D2P case {}: the upstream is handed over",
                i
            );
            assert_eq!(pool.live(), 1, "only the handed-over upstream is live");
        }
        drop(step);
        assert_eq!(
            pool.live(),
            0,
            "T-D2P VERDICT case {}: a descriptor stayed open",
            i
        );
    }
    let pool = Pool::new();
    let mut p = proxy_active(&pool, ModeKind::ForwardTcp);
    assert_eq!(
        precv_k(&mut p, &pool, &shutdown_bytes(), &[listener()]),
        Pk::Refused(BadFdCount)
    );
    assert_eq!(pool.live(), 0);
}

#[test]
fn t_d2p_a_refused_receive_closes_every_descriptor() {
    let pool = Pool::new();
    let mut p = proxy_awaiting_welcome();
    let mut bad = welcome_for(ModeKind::ForwardTcp);
    bad[2] = 1;
    let step = precv(
        &mut p,
        &pool,
        &bad,
        &[listener(), listener(), listener(), listener()],
    );
    assert_eq!(step.kind(), Pk::Refused(BadVersion));
    drop(step);
    assert_eq!(pool.live(), 0, "four descriptors closed on rejection");
    let mut p = proxy_awaiting_welcome();
    let mut fds = FdBatch::new();
    for _ in 0..4 {
        let _ = fds.push(ReceivedFd {
            handle: pool.make(listener()),
            facts: listener(),
        });
    }
    let welcome = welcome_for(ModeKind::ForwardTcp);
    let step = p.step(ProxyInput::Recv(D2pRecv {
        bytes: &welcome,
        msg_trunc: false,
        msg_ctrunc: true,
        unexpected_control: false,
        fds,
    }));
    assert_eq!(step.kind(), Pk::Refused(AncillaryTruncated));
    drop(step);
    assert_eq!(
        pool.live(),
        0,
        "MSG_CTRUNC: every received descriptor closed"
    );
}

#[test]
fn t_d2p_the_fd_batch_is_bounded() {
    let pool = Pool::new();
    let mut fds: FdBatch<Handle> = FdBatch::new();
    for _ in 0..crate::wire::MAX_ANCILLARY_FDS {
        assert!(fds
            .push(ReceivedFd {
                handle: pool.make(listener()),
                facts: listener()
            })
            .is_ok());
    }
    let back = fds.push(ReceivedFd {
        handle: pool.make(listener()),
        facts: listener(),
    });
    assert!(back.is_err(), "a full batch hands the descriptor back");
    drop(back);
    assert_eq!(fds.len(), 4);
    drop(fds);
    assert_eq!(pool.live(), 0);
}
