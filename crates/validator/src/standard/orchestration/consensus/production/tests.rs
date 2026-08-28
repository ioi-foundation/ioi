use super::{
    format_proposal_wait_line, parse_failed_tx_index, resolve_ordering_cadence,
    retain_nonce_heads_for_canonical_order, workload_tip_requires_hydration,
    BENCH_PROPOSAL_WAIT_TAG,
};
use ioi_types::app::{
    AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction,
};

fn system_tx(account_id: AccountId, nonce: u64) -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".to_string(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".to_string(),
            params: Vec::new(),
        },
        signature_proof: SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: Vec::new(),
            signature: Vec::new(),
        },
    }))
}

#[test]
fn parses_failed_tx_index_from_execution_errors() {
    assert_eq!(
        parse_failed_tx_index("Transaction processing error: tx_index=3: Invalid transaction"),
        Some(3)
    );
    assert_eq!(
        parse_failed_tx_index("Execution client transport error: tx_index=17: boom"),
        Some(17)
    );
    assert_eq!(parse_failed_tx_index("no tx index here"), None);
}

#[test]
fn canonical_order_selection_retains_only_each_accounts_lowest_nonce() {
    let first_account = AccountId([1u8; 32]);
    let second_account = AccountId([2u8; 32]);
    let transactions = vec![
        system_tx(first_account, 4),
        system_tx(second_account, 7),
        system_tx(first_account, 2),
        system_tx(second_account, 8),
    ];

    let retained = retain_nonce_heads_for_canonical_order(&transactions);
    let retained_scopes = retained
        .iter()
        .map(|tx| super::nonce_scope(tx).expect("system transaction has nonce scope"))
        .collect::<Vec<_>>();

    assert_eq!(
        retained_scopes,
        vec![(second_account, 7), (first_account, 2)]
    );
}

#[test]
fn unchanged_workload_tip_does_not_require_hydration() {
    let hash = [0x11; 32];
    assert!(!workload_tip_requires_hydration(
        184,
        Some(&hash),
        184,
        Some(&hash),
    ));
}

#[test]
fn advanced_or_forked_workload_tip_requires_hydration() {
    let local = [0x11; 32];
    let fork = [0x22; 32];
    assert!(workload_tip_requires_hydration(
        185,
        Some(&local),
        184,
        Some(&local),
    ));
    assert!(workload_tip_requires_hydration(
        184,
        Some(&fork),
        184,
        Some(&local),
    ));
}

#[test]
fn cold_workload_tip_requires_hydration() {
    let hash = [0x11; 32];
    assert!(workload_tip_requires_hydration(1, Some(&hash), 0, None,));
}

#[test]
fn unhashable_local_tip_fails_toward_hydration() {
    let hash = [0x11; 32];
    assert!(workload_tip_requires_hydration(184, Some(&hash), 184, None,));
}

// ---------------------------------------------------------------------------
// Ordering cadence resolution
// ---------------------------------------------------------------------------
//
// `resolve_ordering_cadence` exists to report the cadence the SCHEDULER is
// running, so its whole value is that it agrees with
// `lifecycle.rs::run_consensus_ticker` on that scheduler's edge cases. These
// tests pin each of those edges. If the scheduler's precedence ever changes and
// this copy does not, one of these goes red rather than the artifact quietly
// reporting a cadence no node ran.

const CONFIG_SECS: u64 = 7;

#[test]
fn the_millisecond_override_outranks_seconds_and_config() {
    let cadence = resolve_ordering_cadence(Some("250"), Some("3"), None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, 250);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_MS"
    );
}

#[test]
fn the_seconds_override_outranks_config_and_is_reported_in_milliseconds() {
    let cadence = resolve_ordering_cadence(None, Some("3"), None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, 3_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_SECS"
    );
}

#[test]
fn config_is_used_only_when_neither_override_is_present() {
    let cadence = resolve_ordering_cadence(None, None, None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, CONFIG_SECS * 1_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn a_zero_or_unparseable_millisecond_override_falls_through_exactly_as_the_scheduler_does() {
    // The scheduler filters the ms override on `> 0`, so a literal 0 is NOT a
    // request for a zero-period ticker -- it falls through to the next source.
    // Reporting 0 here would name a cadence the scheduler never adopted.
    for ignored in ["0", "", "-5", "abc", "1.5"] {
        let cadence = resolve_ordering_cadence(Some(ignored), Some("3"), None, None, CONFIG_SECS);
        assert_eq!(
            cadence.ticker_interval_ms, 3_000,
            "ORCH_BLOCK_INTERVAL_MS={ignored:?} must fall through to the seconds override"
        );
        assert_eq!(
            cadence.ticker_interval_provenance, "env:ORCH_BLOCK_INTERVAL_SECS",
            "ORCH_BLOCK_INTERVAL_MS={ignored:?} must not be credited with the value"
        );
    }
    // ...and with no seconds override behind it, all the way to config.
    let cadence = resolve_ordering_cadence(Some("0"), None, None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, CONFIG_SECS * 1_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn an_unparseable_seconds_override_falls_back_to_config() {
    let cadence = resolve_ordering_cadence(None, Some("later"), None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, CONFIG_SECS * 1_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn a_halting_ticker_is_reported_as_zero_rather_than_smoothed_over() {
    // `ORCH_BLOCK_INTERVAL_SECS=0` and a zero config both make
    // `run_consensus_ticker` return BEFORE the `select!` that owns the kick
    // receiver. Neither timed ticks nor kicks are serviced afterwards, so
    // consensus HALTS -- this is not a "kick-driven only" mode, and describing
    // it as one would tell a reader a chain still progresses when it does not.
    // The value is still reported as 0; substituting a plausible non-zero
    // number would describe a run that did not happen.
    let from_env = resolve_ordering_cadence(None, Some("0"), None, None, CONFIG_SECS);
    assert_eq!(from_env.ticker_interval_ms, 0);
    assert_eq!(
        from_env.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_SECS"
    );

    let from_config = resolve_ordering_cadence(None, None, None, None, 0);
    assert_eq!(from_config.ticker_interval_ms, 0);
    assert_eq!(
        from_config.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn the_minimum_kick_spacing_honours_zero_but_defaults_to_fifty() {
    // The scheduler applies no `> 0` filter to this one, so 0 IS honoured here
    // even though 0 is ignored for the ticker. The asymmetry is the scheduler's;
    // this mirrors it rather than tidying it.
    let zero = resolve_ordering_cadence(None, None, Some("0"), None, CONFIG_SECS);
    assert_eq!(zero.min_tick_ms, 0);
    assert_eq!(zero.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

    let set = resolve_ordering_cadence(None, None, Some("10"), None, CONFIG_SECS);
    assert_eq!(set.min_tick_ms, 10);
    assert_eq!(set.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

    for absent_or_bad in [None, Some(""), Some("abc"), Some("-1")] {
        let cadence = resolve_ordering_cadence(None, None, absent_or_bad, None, CONFIG_SECS);
        assert_eq!(
            cadence.min_tick_ms, 50,
            "ORCH_CONSENSUS_MIN_TICK_MS={absent_or_bad:?} must fall back to the scheduler default"
        );
        assert_eq!(
            cadence.min_tick_provenance, "default",
            "a fallback must not be labelled as an environment value"
        );
    }
}

#[test]
fn the_two_cadence_controls_are_resolved_independently() {
    // They are separate scheduler knobs and separate wrapper flags. A change to
    // one must not move the other, or a parity run that varied only the ticker
    // would silently have varied the kick spacing too.
    let base = resolve_ordering_cadence(Some("250"), None, Some("10"), None, CONFIG_SECS);
    let ticker_changed =
        resolve_ordering_cadence(Some("1000"), None, Some("10"), None, CONFIG_SECS);
    let min_tick_changed =
        resolve_ordering_cadence(Some("250"), None, Some("25"), None, CONFIG_SECS);

    assert_eq!(ticker_changed.min_tick_ms, base.min_tick_ms);
    assert_eq!(ticker_changed.ticker_interval_ms, 1_000);
    assert_eq!(min_tick_changed.ticker_interval_ms, base.ticker_interval_ms);
    assert_eq!(min_tick_changed.min_tick_ms, 25);
}

#[test]
fn the_genesis_block_interval_floor_is_reported_with_its_provenance() {
    // The floor -- not the ticker -- is what actually spaces blocks, so the
    // artifact needs it and needs to know where it came from. An absent
    // override is the historical 1000ms test genesis, not "unknown".
    let default_floor = resolve_ordering_cadence(None, None, None, None, CONFIG_SECS);
    assert_eq!(default_floor.genesis_block_interval_ms, 1_000);
    assert_eq!(
        default_floor.genesis_block_interval_provenance,
        "default:test-genesis"
    );

    let overridden = resolve_ordering_cadence(None, None, None, Some("50"), CONFIG_SECS);
    assert_eq!(overridden.genesis_block_interval_ms, 50);
    assert_eq!(
        overridden.genesis_block_interval_provenance,
        "env:IOI_BENCH_BLOCK_INTERVAL_MS"
    );
    // Whitespace is tolerated exactly as the genesis builder tolerates it, so
    // the two cannot disagree about whether a value was accepted.
    assert_eq!(
        resolve_ordering_cadence(None, None, None, Some(" 50 "), CONFIG_SECS)
            .genesis_block_interval_ms,
        50
    );
}

#[test]
fn a_floor_the_genesis_builder_would_have_rejected_is_reported_as_unresolved() {
    // The builder panics on these, so no chain carrying such a floor exists.
    // Echoing the number would name a floor nothing ran at; reporting the
    // historical default would be worse still, since it would look valid.
    for rejected in ["0", "60001", "-1", "abc", "1.5", ""] {
        let cadence = resolve_ordering_cadence(None, None, None, Some(rejected), CONFIG_SECS);
        assert_eq!(
            cadence.genesis_block_interval_provenance, "unresolved",
            "IOI_BENCH_BLOCK_INTERVAL_MS={rejected:?} must not be reported as resolved"
        );
        assert_eq!(
            cadence.genesis_block_interval_ms, 0,
            "an unresolved floor must not carry a plausible-looking number"
        );
    }
    // Guards the above from passing vacuously: the range boundaries resolve.
    for accepted in ["1", "60000"] {
        assert_eq!(
            resolve_ordering_cadence(None, None, None, Some(accepted), CONFIG_SECS)
                .genesis_block_interval_provenance,
            "env:IOI_BENCH_BLOCK_INTERVAL_MS",
            "IOI_BENCH_BLOCK_INTERVAL_MS={accepted:?} is in range and must resolve"
        );
    }
}

#[test]
fn the_ticker_and_the_block_floor_are_resolved_independently() {
    // They are separate mechanisms: the ticker decides how often consensus is
    // POLLED, the floor decides when a block is DUE. A parity run sets both
    // from one flag, but the resolver must keep them distinguishable so the
    // artifact can show a ticker faster than the floor buying nothing.
    let base = resolve_ordering_cadence(Some("250"), None, None, Some("250"), CONFIG_SECS);
    let ticker_only = resolve_ordering_cadence(Some("50"), None, None, Some("250"), CONFIG_SECS);
    let floor_only = resolve_ordering_cadence(Some("250"), None, None, Some("50"), CONFIG_SECS);

    assert_eq!(
        ticker_only.genesis_block_interval_ms,
        base.genesis_block_interval_ms
    );
    assert_eq!(ticker_only.ticker_interval_ms, 50);
    assert_eq!(floor_only.ticker_interval_ms, base.ticker_interval_ms);
    assert_eq!(floor_only.genesis_block_interval_ms, 50);
}

// ---------------------------------------------------------------------------
// [BENCH-PROPOSAL-WAIT]: the per-transaction mempool-to-proposal observation
// ---------------------------------------------------------------------------
//
// M04.9 recorded this wait as unmeasured: "no seam brackets a transaction's
// mempool-to-proposal wait". These tests bind the line shape the profiler
// parses, and the one property that makes the observation attributable at all
// -- that it is keyed by TRANSACTION HASH rather than by height.

#[test]
fn the_proposal_wait_line_is_keyed_by_transaction_hash_not_height() {
    let hash = "ab".repeat(32);
    let line =
        format_proposal_wait_line(&hash, 412, 3, 1_000, 1_250).expect("ordered observation clocks");

    assert!(
        line.starts_with(&format!("{BENCH_PROPOSAL_WAIT_TAG} selected ")),
        "the tag and operation must be exact so a log drain can locate the line: {line}"
    );
    // The correlation key.
    assert!(line.contains(&format!("tx_hash={hash}")));
    // Dimensions, not keys.
    assert!(line.contains(" height=412 "));
    assert!(line.contains(" view=3 "));
    // The measurement and both of its edges, so a reader can recompute it.
    assert!(line.contains(" first_seen_at_ms=1000 "));
    assert!(line.contains(" proposal_selected_at_ms=1250 "));
    assert!(line.ends_with(" proposal_wait_ms=250"));
}

#[test]
fn two_transactions_at_one_height_yield_two_independent_waits() {
    // The reason the line is hash-keyed. Both transactions below are picked up
    // by the SAME proposal at the same instant, but they entered the mempool
    // 850ms apart, so exactly one of them waited 900ms.
    let early = format_proposal_wait_line(&"11".repeat(32), 412, 0, 1_000, 1_900)
        .expect("ordered observation clocks");
    let late = format_proposal_wait_line(&"22".repeat(32), 412, 0, 1_850, 1_900)
        .expect("ordered observation clocks");

    assert!(early.ends_with(" proposal_wait_ms=900"));
    assert!(late.ends_with(" proposal_wait_ms=50"));
    assert_ne!(
        early, late,
        "a height-keyed observation would have collapsed these to one value"
    );
}

#[test]
fn a_backwards_clock_refuses_instead_of_becoming_a_plausible_zero_wait() {
    let error = format_proposal_wait_line(&"33".repeat(32), 9, 0, 2_000, 1_500)
        .expect_err("a backwards observation clock must fail closed");
    assert!(error.to_string().contains("clock moved backwards"));

    // A same-millisecond pickup is a real zero, not a fault.
    let instant = format_proposal_wait_line(&"44".repeat(32), 9, 0, 2_000, 2_000)
        .expect("equal observation instants are a real zero wait");
    assert!(instant.ends_with(" proposal_wait_ms=0"));
}

// ---------------------------------------------------------------------------
// Planted-delay seam wiring
// ---------------------------------------------------------------------------

/// The producer source this ordering invariant lives in.
const PRODUCTION_SOURCE: &str = include_str!("../production.rs");

#[test]
fn the_planted_delay_seam_is_wired_after_the_proposal_wait_is_sampled() {
    // Ordering, read off the source. The closing edge of the proposal wait
    // must be sampled BEFORE the planted delay sleeps, or a delay planted in
    // selection would inflate every reported proposal wait as well as
    // select_ms -- and "exactly one phase moved" would be false.
    let sample_at = PRODUCTION_SOURCE
        .find("let proposal_selected_at_ms =")
        .expect("the producer must sample the proposal-wait closing edge");
    let plant_at = PRODUCTION_SOURCE
        .find("planted_delay_for(PlantedPhase::ProposalSelection)?")
        .expect("the producer must carry the planted-delay seam");
    let select_elapsed_at = PRODUCTION_SOURCE
        .find("let selection_elapsed = select_started.elapsed();")
        .expect("the producer must close the selection span");

    assert!(
        sample_at < plant_at,
        "the proposal-wait edge must be sampled before the planted delay sleeps"
    );
    assert!(
        plant_at < select_elapsed_at,
        "the planted delay must sleep INSIDE the selection span it is meant to inflate; \
         outside it, select_ms would not move and the mutation would prove nothing"
    );
}
