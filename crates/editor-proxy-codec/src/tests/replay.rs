//! The STABLE CORPUS REPLAY (no nightly): the committed seeds of the three fuzz targets equal their
//! builders below; every NAMED sequence seed reaches its named boundary; every corpus file holds
//! the harness invariants; the decode corpora re-encode canonically (T-CANONICAL); and a
//! deterministic bounded random run holds the invariants. `IPC_SEED_OUT=<dir>` writes the seeds
//! to <dir>/<target>/ instead of comparing (how the committed corpus was produced).

use super::canonical::{d2p_frames, p2d_frames, test_encode_d2p, test_encode_p2d};
use super::support::*;
use crate::fuzz_support::op;
use crate::{decode_d2p, decode_p2d, IpcRefusal, ProxyPhase};
use std::string::{String, ToString};
use std::vec::Vec;

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fuzz/editor-proxy-ipc/corpus"
);

/// What a named sequence seed must produce.
#[derive(Clone, Copy, Default)]
struct Expect {
    daemon: Option<Option<IpcRefusal>>,
    proxy: Option<Option<IpcRefusal>>,
    admits: Option<u64>,
    verdicts: Option<u64>,
    proxy_closed: bool,
    untainted: bool,
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

fn startup(mode: u8) -> Vec<u8> {
    std::vec![op::HONEST_STARTUP, mode]
}

fn repeat(count: u16, body: &[u8]) -> Vec<u8> {
    let mut out = std::vec![op::REPEAT];
    out.extend_from_slice(&count.to_le_bytes());
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    out
}

fn roundtrips(count: u16, purpose: u8) -> Vec<u8> {
    repeat(count, &[op::HONEST_ROUNDTRIP, purpose])
}

fn inject_admit(id: u32, purpose: u8, n: u8) -> Vec<u8> {
    let mut out = std::vec![op::INJECT_ADMIT];
    out.extend_from_slice(&id.to_le_bytes());
    out.push(purpose);
    out.push(n);
    out
}

const UNANSWERED: [u8; 7] = [op::P_ADMIT, 0, 1, op::P_SEND, 0, op::D_RECV, 0];
const ONE_ADMIT_AT_DAEMON: [u8; 7] = UNANSWERED;

fn named_sequence_seeds() -> Vec<(String, Vec<u8>, Expect)> {
    use IpcRefusal::*;
    let none = Some(None);
    let mut seeds: Vec<(String, Vec<u8>, Expect)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>, expect: Expect| {
        seeds.push((name.to_string(), bytes, expect));
    };
    add(
        "admit-65-unanswered-daemon",
        cat(&[
            &startup(0),
            &repeat(64, &UNANSWERED),
            &inject_admit(65, 1, 1),
            &[op::D_RECV, 0],
        ]),
        Expect {
            daemon: Some(Some(TooManyInFlight)),
            proxy: none,
            admits: Some(64),
            ..Expect::default()
        },
    );
    add(
        "admit-65-unanswered-proxy",
        cat(&[&startup(0), &repeat(64, &UNANSWERED), &[op::P_ADMIT, 0, 1]]),
        Expect {
            daemon: none,
            proxy: Some(Some(TooManyInFlight)),
            admits: Some(64),
            ..Expect::default()
        },
    );
    add(
        "rate-2000-then-2001-daemon",
        cat(&[
            &startup(0),
            &roundtrips(2000, 0),
            &inject_admit(2001, 1, 1),
            &[op::D_RECV, 0],
        ]),
        Expect {
            daemon: Some(Some(RateExceeded)),
            proxy: none,
            admits: Some(2000),
            verdicts: Some(2000),
            ..Expect::default()
        },
    );
    add(
        "rate-2000-then-2001-proxy",
        cat(&[&startup(0), &roundtrips(2000, 0), &[op::P_ADMIT, 0, 1]]),
        Expect {
            daemon: none,
            proxy: Some(Some(RateExceeded)),
            admits: Some(2000),
            ..Expect::default()
        },
    );
    add(
        "rate-2000-window-boundary",
        cat(&[
            &startup(0),
            &roundtrips(2000, 0),
            &[op::TICK_WINDOW, op::HONEST_ROUNDTRIP, 0],
        ]),
        Expect {
            daemon: none,
            proxy: none,
            admits: Some(2001),
            verdicts: Some(2001),
            untainted: true,
            ..Expect::default()
        },
    );
    add(
        "verdict-duplicate-daemon",
        cat(&[&startup(0), &roundtrips(1, 0), &[op::D_VERDICT, 1, 0]]),
        Expect {
            daemon: Some(Some(DuplicateVerdict)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "verdict-unknown-daemon",
        cat(&[&startup(0), &[op::D_VERDICT, 2, 0]]),
        Expect {
            daemon: Some(Some(UnknownVerdict)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "verdict-duplicate-proxy",
        cat(&[
            &startup(0),
            &roundtrips(1, 0),
            &[op::INJECT_VERDICT, 1, 0, 0, op::P_RECV, 0],
        ]),
        Expect {
            daemon: none,
            proxy: Some(Some(DuplicateVerdict)),
            ..Expect::default()
        },
    );
    add(
        "verdict-unknown-proxy",
        cat(&[&startup(0), &[op::INJECT_VERDICT, 2, 0, 0, op::P_RECV, 0]]),
        Expect {
            daemon: none,
            proxy: Some(Some(UnknownVerdict)),
            ..Expect::default()
        },
    );
    add(
        "send-fatal-daemon",
        cat(&[
            &startup(0),
            &ONE_ADMIT_AT_DAEMON,
            &[op::D_VERDICT, 0, 0, op::D_SEND, 2],
        ]),
        Expect {
            daemon: Some(Some(SendFailed)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "send-short-proxy",
        cat(&[&startup(0), &[op::P_ADMIT, 0, 1, op::P_SEND, 3]]),
        Expect {
            daemon: none,
            proxy: Some(Some(SendFailed)),
            ..Expect::default()
        },
    );
    add(
        "send-wouldblock-then-whole",
        cat(&[
            &startup(0),
            &[
                op::P_ADMIT,
                0,
                1,
                op::P_SEND,
                1,
                op::P_SEND,
                0,
                op::D_RECV,
                0,
            ],
            &[
                op::D_VERDICT,
                0,
                0,
                op::D_SEND,
                1,
                op::D_SEND,
                0,
                op::P_RECV,
                0,
            ],
        ]),
        Expect {
            daemon: none,
            proxy: none,
            admits: Some(1),
            verdicts: Some(1),
            ..Expect::default()
        },
    );
    add(
        "send-stale-daemon",
        cat(&[
            &startup(0),
            &ONE_ADMIT_AT_DAEMON,
            &[op::D_VERDICT, 0, 0, op::D_SEND, 4],
        ]),
        Expect {
            daemon: Some(Some(OutOfOrder)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "welcome-second-daemon",
        cat(&[&startup(0), &[op::D_WELCOME, 0]]),
        Expect {
            daemon: Some(Some(OutOfOrder)),
            proxy: none,
            ..Expect::default()
        },
    );
    let welcome = welcome_for(crate::ModeKind::ForwardTcp);
    add(
        "welcome-second-proxy",
        cat(&[
            &startup(0),
            &[op::INJECT_D2P, 1, 0, welcome.len() as u8],
            &welcome,
            &[op::P_RECV, 0],
        ]),
        Expect {
            daemon: none,
            proxy: Some(Some(OutOfOrder)),
            ..Expect::default()
        },
    );
    add(
        "msg-trunc-daemon",
        cat(&[
            &startup(0),
            &[op::P_ADMIT, 0, 1, op::P_SEND, 0, op::D_RECV, 1],
        ]),
        Expect {
            daemon: Some(Some(Truncated)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "msg-ctrunc-daemon",
        cat(&[
            &startup(0),
            &[op::P_ADMIT, 0, 1, op::P_SEND, 0, op::D_RECV, 2],
        ]),
        Expect {
            daemon: Some(Some(AncillaryFromProxy)),
            proxy: none,
            ..Expect::default()
        },
    );
    let answered = [op::D_VERDICT, 0, 0, op::D_SEND, 0];
    add(
        "msg-trunc-proxy",
        cat(&[
            &startup(0),
            &ONE_ADMIT_AT_DAEMON,
            &answered,
            &[op::P_RECV, 1],
        ]),
        Expect {
            daemon: none,
            proxy: Some(Some(Truncated)),
            ..Expect::default()
        },
    );
    add(
        "msg-ctrunc-proxy",
        cat(&[
            &startup(0),
            &ONE_ADMIT_AT_DAEMON,
            &answered,
            &[op::P_RECV, 2],
        ]),
        Expect {
            daemon: none,
            proxy: Some(Some(AncillaryTruncated)),
            ..Expect::default()
        },
    );
    add(
        "id-max-daemon",
        cat(&[
            &startup(0),
            &inject_admit(u32::MAX, 1, 0),
            &[op::D_RECV, 0],
            &inject_admit(5, 1, 0),
            &[op::D_RECV, 0],
        ]),
        Expect {
            daemon: Some(Some(ConnExhausted)),
            proxy: none,
            admits: Some(1),
            ..Expect::default()
        },
    );
    add(
        "id-exhaustion-proxy-stops",
        cat(&[
            &[op::P_NEAR_EXHAUSTION, 1, 0],
            &startup(0),
            &roundtrips(2, 0),
            &[op::TICK_BOTH, 1, 0, op::TICK_BOTH, 1, 0],
        ]),
        Expect {
            daemon: none,
            proxy: none,
            admits: Some(2),
            verdicts: Some(2),
            proxy_closed: true,
            untainted: true,
        },
    );
    add(
        "id-exhaustion-proxy-refuses-more",
        cat(&[
            &[op::P_NEAR_EXHAUSTION, 0, 0],
            &startup(0),
            &roundtrips(1, 0),
            &[op::P_ADMIT, 0, 1],
        ]),
        Expect {
            daemon: none,
            proxy: Some(Some(ConnExhausted)),
            admits: Some(1),
            ..Expect::default()
        },
    );
    add(
        "clock-regression-daemon",
        cat(&[&startup(0), &[op::TICK_BACK_D, 0, 0]]),
        Expect {
            daemon: Some(Some(ClockRegression)),
            proxy: none,
            ..Expect::default()
        },
    );
    add(
        "clock-regression-proxy",
        cat(&[&startup(1), &[op::TICK_BACK_P, 0, 0]]),
        Expect {
            daemon: none,
            proxy: Some(Some(ClockRegression)),
            ..Expect::default()
        },
    );
    add(
        "startup-deadline",
        std::vec![op::TICK_BOTH, 0x88, 0x13],
        Expect {
            daemon: Some(Some(OperationTimeout)),
            proxy: Some(Some(OperationTimeout)),
            ..Expect::default()
        },
    );
    add(
        "honest-long-run-with-events",
        cat(&[
            &startup(2),
            &repeat(
                300,
                &[
                    op::P_OBSERVE,
                    11,
                    0x01,
                    0x04,
                    op::HONEST_ROUNDTRIP,
                    1,
                    op::TICK_BOTH,
                    0x2c,
                    0x01,
                ],
            ),
        ]),
        Expect {
            daemon: none,
            proxy: none,
            admits: Some(300),
            verdicts: Some(300),
            untainted: true,
            ..Expect::default()
        },
    );
    // Every mode x purpose x outcome on the daemon's typed path.
    for mode in 0u8..3 {
        for purpose in 0u8..2 {
            for outcome in 0u8..4 {
                let legal = table_legal(mode, purpose, outcome);
                add(
                    &std::format!("combo-daemon-m{}-p{}-o{}", mode, purpose, outcome),
                    cat(&[
                        &startup(mode),
                        &[op::P_ADMIT, purpose, 1, op::P_SEND, 0, op::D_RECV, 0],
                        &[op::D_VERDICT, 0, outcome, op::D_SEND, 0, op::P_RECV, 0],
                    ]),
                    Expect {
                        daemon: Some(if legal {
                            None
                        } else {
                            Some(BadOutcomeForPurpose)
                        }),
                        proxy: none,
                        verdicts: Some(legal as u64),
                        ..Expect::default()
                    },
                );
            }
        }
    }
    // Every mode x purpose x outcome x descriptor count on the proxy's receive path.
    for mode in 0u8..3 {
        for purpose in 0u8..2 {
            for outcome in 0u8..4 {
                for fds in 0u8..2 {
                    let mut bytes =
                        cat(&[&startup(mode), &[op::P_ADMIT, purpose, 1, op::P_SEND, 0]]);
                    bytes.extend_from_slice(&[op::INJECT_VERDICT, 0, outcome, fds]);
                    if fds == 1 {
                        bytes.push(9);
                    }
                    bytes.extend_from_slice(&[op::P_RECV, 0]);
                    let want = proxy_combo(mode, purpose, outcome, fds);
                    add(
                        &std::format!("combo-proxy-m{}-p{}-o{}-f{}", mode, purpose, outcome, fds),
                        bytes,
                        Expect {
                            daemon: none,
                            proxy: Some(want),
                            verdicts: Some(want.is_none() as u64),
                            ..Expect::default()
                        },
                    );
                }
            }
        }
    }
    seeds
}

/// DESIGN v2 (2)'s legality table by selector (mode 0 tcp, 1 unix, 2 static; purpose 0 forward,
/// 1 exchange), written independently of the code.
fn table_legal(mode: u8, purpose: u8, outcome: u8) -> bool {
    match (purpose, mode) {
        (0, 0 | 1) => matches!(outcome, 0 | 1 | 3),
        (0, _) => matches!(outcome, 0 | 2),
        _ => matches!(outcome, 0 | 2),
    }
}

/// The proxy's expected refusal for a raw VERDICT: row 7 (descriptor count, then kind), then row 8.
fn proxy_combo(mode: u8, purpose: u8, outcome: u8, fds: u8) -> Option<IpcRefusal> {
    if outcome == 1 {
        if fds != 1 {
            return Some(IpcRefusal::BadFdCount);
        }
        if mode == 2 {
            return Some(IpcRefusal::BadFdKind);
        }
    } else if fds != 0 {
        return Some(IpcRefusal::BadFdCount);
    }
    if table_legal(mode, purpose, outcome) {
        None
    } else {
        Some(IpcRefusal::BadOutcomeForPurpose)
    }
}

fn p2d_decode_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (i, frame) in p2d_frames()
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % 5 == 0)
    {
        for selector in [0u8, 2, 3] {
            out.push((
                std::format!("valid-{}-s{}", i, selector),
                cat(&[&[selector], &frame]),
            ));
        }
    }
    let ready = ready_bytes();
    let mut bad: Vec<(&str, Vec<u8>)> = Vec::new();
    bad.push(("empty", Vec::new()));
    bad.push(("short", ready[..7].to_vec()));
    bad.push(("oversized", raw_frame(0x02, &[0; 505])));
    for (name, at, value) in [
        ("magic", 0usize, b'X'),
        ("version", 2, 1),
        ("kind", 3, 0x81),
        ("reserved", 7, 1),
        ("length", 4, 3),
    ] {
        let mut f = ready.clone();
        f[at] = value;
        bad.push((name, f));
    }
    bad.push(("purpose", raw_frame(0x02, &[1, 0, 0, 0, 9, 0])));
    bad.push(("digests", raw_frame(0x02, &[1, 0, 0, 0, 1, 9])));
    bad.push(("admit-min", raw_frame(0x02, &[1, 0, 0, 0, 1])));
    bad.push(("event-conn", event_bytes(1, 1, 1)));
    bad.push(("event-code", event_bytes(0, 13, 1)));
    bad.push(("event-count", event_bytes(0, 1, 0)));
    bad.push(("admit-id0", admit_bytes(0, 1, &[[7; 32]])));
    for (name, frame) in bad {
        for selector in [0u8, 2, 6, 10, 18] {
            out.push((
                std::format!("refuse-{}-s{}", name, selector),
                cat(&[&[selector], &frame]),
            ));
        }
    }
    out
}

fn d2p_decode_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (i, frame) in d2p_frames()
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % 3 == 0)
    {
        for (selector, fds) in [(0u8, &[0u8][..]), (1, &[]), (1, &[2]), (2, &[1]), (3, &[])] {
            let mut seed = std::vec![selector, fds.len() as u8];
            seed.extend_from_slice(fds);
            seed.extend_from_slice(&frame);
            out.push((
                std::format!("valid-{}-s{}-f{}", i, selector, fds.len()),
                seed,
            ));
        }
    }
    let mut bad: Vec<(&str, Vec<u8>)> = Vec::new();
    bad.push(("welcome-port0", welcome_bytes(1, 1, 0, &LABEL, 0, &[0; 64])));
    bad.push((
        "welcome-tuple",
        welcome_bytes(2, 1, PORT, &LABEL, 0, &[0; 64]),
    ));
    bad.push((
        "welcome-ascii-zero-token",
        welcome_bytes(1, 1, PORT, &LABEL, 0, &[b'0'; 64]),
    ));
    bad.push(("verdict-outcome", verdict_bytes(1, 4)));
    bad.push(("shutdown-body", raw_frame(0x83, &[0])));
    for (name, frame) in bad {
        for (selector, fds) in [(0u8, &[0u8][..]), (1, &[3]), (9, &[0, 0]), (17, &[])] {
            let mut seed = std::vec![selector, fds.len() as u8];
            seed.extend_from_slice(fds);
            seed.extend_from_slice(&frame);
            out.push((std::format!("refuse-{}-s{}", name, selector), seed));
        }
    }
    for (name, facts) in [
        ("listener-unix", 1u8),
        ("listener-wrongport", 8),
        ("upstream-listening", 3),
        ("upstream-unconnected", 4),
        ("upstream-error", 5),
        ("upstream-peer", 6),
        ("upstream-other", 7),
    ] {
        for selector in [0u8, 1, 2] {
            let frame = if selector == 0 {
                welcome_for(crate::ModeKind::ForwardTcp)
            } else {
                verdict_bytes(1, 1)
            };
            let mut seed = std::vec![selector, 1, facts];
            seed.extend_from_slice(&frame);
            out.push((std::format!("fds-{}-s{}", name, selector), seed));
        }
    }
    out
}

fn all_seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, bytes, _) in named_sequence_seeds() {
        out.push(("ipc_sequence", name, bytes));
    }
    for (name, bytes) in p2d_decode_seeds() {
        out.push(("p2d_decode", name, bytes));
    }
    for (name, bytes) in d2p_decode_seeds() {
        out.push(("d2p_decode", name, bytes));
    }
    out
}

#[test]
fn t_replay_committed_seeds_equal_their_builders() {
    if let Ok(dir) = std::env::var("IPC_SEED_OUT") {
        for (target, name, bytes) in all_seeds() {
            let path = std::format!("{}/{}/seed-{}", dir, target, name);
            std::fs::create_dir_all(std::format!("{}/{}", dir, target)).expect("seed dir");
            std::fs::write(&path, &bytes).expect("seed write");
        }
        return;
    }
    let mut misses: Vec<String> = Vec::new();
    let seeds = all_seeds();
    for (target, name, bytes) in &seeds {
        let path = std::format!("{}/{}/seed-{}", CORPUS, target, name);
        match std::fs::read(&path) {
            Ok(committed) if committed == *bytes => {}
            Ok(_) => misses.push(std::format!("{}: differs from its builder", path)),
            Err(_) => misses.push(std::format!("{}: missing", path)),
        }
    }
    assert!(seeds.len() > 200, "{} seeds", seeds.len());
    assert!(
        misses.is_empty(),
        "corpus seeds (regenerate with IPC_SEED_OUT):\n{}",
        misses.join("\n")
    );
}

#[test]
fn t_replay_named_sequence_seeds_reach_their_named_boundaries() {
    let mut misses: Vec<String> = Vec::new();
    let seeds = named_sequence_seeds();
    for (name, bytes, expect) in &seeds {
        let report = match std::panic::catch_unwind(|| run_sequence(bytes)) {
            Ok(report) => report,
            Err(panic) => {
                let what = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                misses.push(std::format!("seed {}: {}", name, what));
                continue;
            }
        };
        let mut check = |what: &str, ok: bool| {
            if !ok {
                misses.push(std::format!(
                    "seed {}: {} (report {:?})",
                    name,
                    what,
                    report
                ));
            }
        };
        if let Some(want) = expect.daemon {
            check("daemon refusal", report.daemon_refusal == want);
        }
        if let Some(want) = expect.proxy {
            check("proxy refusal", report.proxy_refusal == want);
        }
        if let Some(want) = expect.admits {
            check("daemon admits", report.admits == want);
        }
        if let Some(want) = expect.verdicts {
            check("proxy verdicts", report.verdicts == want);
        }
        if expect.proxy_closed {
            check("proxy closed", report.proxy == ProxyPhase::Closed);
        }
        if expect.untainted {
            check("untainted", !report.tainted);
        }
        check("within MAX_OPS", report.ops <= crate::fuzz_support::MAX_OPS);
    }
    assert!(seeds.len() >= 98, "{} named seeds", seeds.len());
    assert!(
        misses.is_empty(),
        "named fuzz seeds missed their boundaries:\n{}",
        misses.join("\n")
    );
}

fn run_sequence_unit(bytes: &[u8]) {
    let _ = run_sequence(bytes);
}

fn corpus_files(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = std::format!("{}/{}", CORPUS, target);
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let bytes = std::fs::read(std::format!("{}/{}", dir, n)).expect("corpus read");
            (n, bytes)
        })
        .collect()
}

#[test]
fn t_replay_every_corpus_file_holds_the_invariants() {
    let mut count = 0;
    for (target, run) in [
        ("p2d_decode", run_p2d_decode as fn(&[u8])),
        ("d2p_decode", run_d2p_decode as fn(&[u8])),
        ("ipc_sequence", run_sequence_unit as fn(&[u8])),
    ] {
        let files = corpus_files(target);
        assert!(!files.is_empty(), "the {} corpus is present", target);
        for (name, bytes) in files {
            count += 1;
            let result = std::panic::catch_unwind(|| run(&bytes));
            assert!(
                result.is_ok(),
                "corpus {}/{} broke an invariant",
                target,
                name
            );
        }
    }
    assert!(count > 200, "{} corpus files", count);
}

#[test]
fn t_canonical_corpus_frames_reencode_byte_for_byte() {
    let mut checked = 0;
    for (name, bytes) in corpus_files("p2d_decode") {
        let frame = &bytes[1.min(bytes.len())..];
        if let Ok(decoded) = decode_p2d(frame) {
            assert_eq!(
                test_encode_p2d(&decoded),
                frame,
                "T-CANONICAL p2d corpus {}",
                name
            );
            checked += 1;
        }
    }
    for (name, bytes) in corpus_files("d2p_decode") {
        if bytes.len() < 2 {
            continue;
        }
        let skip = 2 + (bytes[1] % 5) as usize;
        if bytes.len() < skip {
            continue;
        }
        let frame = &bytes[skip..];
        if let Ok(decoded) = decode_d2p(frame) {
            assert_eq!(
                test_encode_d2p(&decoded),
                frame,
                "T-CANONICAL d2p corpus {}",
                name
            );
            checked += 1;
        }
    }
    assert!(
        checked > 50,
        "{} accepted corpus frames re-encoded",
        checked
    );
}

fn random_campaign(per_target: usize, seed: u64) {
    let mut rng = Rng(seed);
    let p2d: Vec<Vec<u8>> = corpus_files("p2d_decode")
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    let d2p: Vec<Vec<u8>> = corpus_files("d2p_decode")
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    let seq: Vec<Vec<u8>> = corpus_files("ipc_sequence")
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    let mutate = |rng: &mut Rng, base: &[u8], max: usize| -> Vec<u8> {
        let mut out = if base.is_empty() || rng.below(4) == 0 {
            let n = rng.below(max as u64) as usize;
            rng.bytes(n)
        } else {
            base.to_vec()
        };
        for _ in 0..(1 + rng.below(6)) {
            match rng.below(3) {
                0 if !out.is_empty() => {
                    let at = rng.below(out.len() as u64) as usize;
                    out[at] = rng.byte();
                }
                1 if out.len() < max => {
                    let at = rng.below(out.len() as u64 + 1) as usize;
                    out.insert(at, rng.byte());
                }
                _ if !out.is_empty() => {
                    let at = rng.below(out.len() as u64) as usize;
                    out.remove(at);
                }
                _ => {}
            }
        }
        out.truncate(max);
        out
    };
    for _ in 0..per_target {
        let base = &p2d[rng.below(p2d.len() as u64) as usize];
        run_p2d_decode(&mutate(&mut rng, base, 600));
        let base = &d2p[rng.below(d2p.len() as u64) as usize];
        run_d2p_decode(&mutate(&mut rng, base, 600));
        let base = &seq[rng.below(seq.len() as u64) as usize];
        let _ = run_sequence(&mutate(&mut rng, base, 4096));
    }
}

#[test]
fn t_replay_stable_bounded_random_run() {
    random_campaign(300, 0x85c1);
}

/// The ticket's longer stable campaign (run with --ignored).
#[test]
#[ignore]
fn t_replay_stable_bounded_random_run_long() {
    random_campaign(20_000, 0x85c2);
}
