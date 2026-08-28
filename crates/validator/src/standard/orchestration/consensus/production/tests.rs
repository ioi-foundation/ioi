use super::{
    parse_failed_tx_index, resolve_ordering_cadence, retain_nonce_heads_for_canonical_order,
    workload_tip_requires_hydration,
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
    let cadence = resolve_ordering_cadence(Some("250"), Some("3"), None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, 250);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_MS"
    );
}

#[test]
fn the_seconds_override_outranks_config_and_is_reported_in_milliseconds() {
    let cadence = resolve_ordering_cadence(None, Some("3"), None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, 3_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_SECS"
    );
}

#[test]
fn config_is_used_only_when_neither_override_is_present() {
    let cadence = resolve_ordering_cadence(None, None, None, CONFIG_SECS);
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
        let cadence = resolve_ordering_cadence(Some(ignored), Some("3"), None, CONFIG_SECS);
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
    let cadence = resolve_ordering_cadence(Some("0"), None, None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, CONFIG_SECS * 1_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn an_unparseable_seconds_override_falls_back_to_config() {
    let cadence = resolve_ordering_cadence(None, Some("later"), None, CONFIG_SECS);
    assert_eq!(cadence.ticker_interval_ms, CONFIG_SECS * 1_000);
    assert_eq!(
        cadence.ticker_interval_provenance,
        "config:block_production_interval_secs"
    );
}

#[test]
fn a_disabled_ticker_is_reported_as_zero_rather_than_smoothed_over() {
    // `ORCH_BLOCK_INTERVAL_SECS=0` and a zero config both genuinely disable the
    // ticker in the scheduler (kick-driven only). That is a real cadence and is
    // reported as one; substituting a plausible non-zero number would describe a
    // run that did not happen.
    let from_env = resolve_ordering_cadence(None, Some("0"), None, CONFIG_SECS);
    assert_eq!(from_env.ticker_interval_ms, 0);
    assert_eq!(
        from_env.ticker_interval_provenance,
        "env:ORCH_BLOCK_INTERVAL_SECS"
    );

    let from_config = resolve_ordering_cadence(None, None, None, 0);
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
    let zero = resolve_ordering_cadence(None, None, Some("0"), CONFIG_SECS);
    assert_eq!(zero.min_tick_ms, 0);
    assert_eq!(zero.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

    let set = resolve_ordering_cadence(None, None, Some("10"), CONFIG_SECS);
    assert_eq!(set.min_tick_ms, 10);
    assert_eq!(set.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

    for absent_or_bad in [None, Some(""), Some("abc"), Some("-1")] {
        let cadence = resolve_ordering_cadence(None, None, absent_or_bad, CONFIG_SECS);
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
    let base = resolve_ordering_cadence(Some("250"), None, Some("10"), CONFIG_SECS);
    let ticker_changed = resolve_ordering_cadence(Some("1000"), None, Some("10"), CONFIG_SECS);
    let min_tick_changed = resolve_ordering_cadence(Some("250"), None, Some("25"), CONFIG_SECS);

    assert_eq!(ticker_changed.min_tick_ms, base.min_tick_ms);
    assert_eq!(ticker_changed.ticker_interval_ms, 1_000);
    assert_eq!(min_tick_changed.ticker_interval_ms, base.ticker_interval_ms);
    assert_eq!(min_tick_changed.min_tick_ms, 25);
}
