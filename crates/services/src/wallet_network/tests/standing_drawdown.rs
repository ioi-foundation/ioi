//! M03.11 / M03.12 — draw-down consumption and the standing-lease lifecycle on the EXISTING
//! `StandingApprovalGrant` / `StandingApprovalGrantState` objects: N bounded draws under one
//! grant, a refused over-envelope draw that names the remaining balance, a concurrent double
//! draw that cannot exceed the envelope, the journal re-derivation that refuses a rotted
//! counter, revocation that fences the next draw within one commit, and recovery that renders
//! the lease with usages and balance unchanged — never reset, never widened.

use super::approvals_and_injection::{install_effect_binding, EffectBindingFixture};
use super::*;
use crate::agentic::runtime::policy_lease::standing_grant_lease;
use crate::wallet_network::keys::{
    standing_approval_grant_journal_key, standing_approval_grant_state_key,
};
use crate::wallet_network::{
    RevokeStandingApprovalGrantParams, StandingApprovalGrantJournal, StandingApprovalGrantState,
    StandingApprovalGrantStatus,
};
use std::sync::{Arc, Mutex};

const EFFECT_PRINCIPAL_REF: &str = "org://wallet-network/effect-owner";
const OPERATOR_PRINCIPAL_REF: &str = "user://wallet-network/standing-operator";
const EFFECT_NOW_MS: u64 = 1_750_000_000_000;

struct Lease {
    service: WalletNetworkService,
    state: MockState,
    grant_hash: [u8; 32],
    envelope_hash: [u8; 32],
    policy_hash: [u8; 32],
    binding: EffectBindingFixture,
}

fn mint(max_usages: u32, max_deposit: u64, max_spend: u64, marker: u8) -> Lease {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let approver = new_approval_signer();
    let policy_hash = [0xd2; 32];
    let fixture = signed_standing_approval_grant_for_principal(
        &approver,
        policy_hash,
        [7; 32],
        [marker; 32],
        1,
        max_usages,
        max_deposit,
        max_spend,
        marker,
        EFFECT_PRINCIPAL_REF,
        OPERATOR_PRINCIPAL_REF,
    );
    let grant = fixture.grant.clone();
    let envelope_hash = grant.standing_envelope_hash;
    let grant_hash = grant.artifact_hash().expect("standing grant hash");
    with_ctx(|ctx| {
        run_async(
            service.handle_service_call(
                &mut state,
                "register_approval_authority@v1",
                &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                    authority: approver.authority.clone(),
                })
                .expect("encode authority"),
                ctx,
            ),
        )
        .expect("register authority");
        run_async(service.handle_service_call(
            &mut state,
            "record_standing_approval_grant@v1",
            &codec::to_bytes_canonical(&fixture.record_params()).expect("encode standing grant"),
            ctx,
        ))
        .expect("record standing grant");
    });
    let binding = install_effect_binding(
        &service,
        &mut state,
        &approver.authority,
        EFFECT_NOW_MS + 10_000,
    );
    Lease {
        service,
        state,
        grant_hash,
        envelope_hash,
        policy_hash,
        binding,
    }
}

fn draw_params(
    lease: &Lease,
    request: u8,
    consumption: u8,
    deposit: u64,
    spend: u64,
) -> ConsumeStandingApprovalGrantForEffectParams {
    ConsumeStandingApprovalGrantForEffectParams {
        grant_hash: lease.grant_hash,
        standing_envelope_hash: lease.envelope_hash,
        policy_hash: lease.policy_hash,
        request_hash: [request; 32],
        consumption_id: [consumption; 32],
        estimated_deposit_microusd: deposit,
        estimated_spend_microusd: spend,
        expected_principal_authority: lease.binding.expected.clone(),
        expected_target_label: "provider.create".into(),
    }
}

fn consume(
    service: &WalletNetworkService,
    state: &mut MockState,
    request: ConsumeStandingApprovalGrantForEffectParams,
) -> Result<(), ioi_types::error::TransactionError> {
    let encoded = codec::to_bytes_canonical(&request).expect("encode standing draw");
    let mut output = None;
    with_ctx(|ctx| {
        output = Some(run_async(service.handle_service_call(
            state,
            "consume_standing_approval_grant_for_effect@v1",
            &encoded,
            ctx,
        )));
    });
    output.expect("standing draw result")
}

fn draw(
    lease: &mut Lease,
    request: u8,
    consumption: u8,
    deposit: u64,
    spend: u64,
) -> Result<(), ioi_types::error::TransactionError> {
    let params = draw_params(lease, request, consumption, deposit, spend);
    consume(&lease.service, &mut lease.state, params)
}

fn stored(state: &MockState, grant_hash: &[u8; 32]) -> StandingApprovalGrantState {
    load_typed::<StandingApprovalGrantState>(state, &standing_approval_grant_state_key(grant_hash))
        .expect("read grant state")
        .expect("grant state present")
}

#[test]
fn n_bounded_draws_succeed_and_the_over_envelope_draw_refuses_naming_the_remaining_balance() {
    // Envelope: 10 usages, 1_000 deposit, 350 spend. Each draw reserves 100 deposit / 100 spend.
    let mut lease = mint(10, 1_000, 350, 0xe1);
    for index in 0..3u8 {
        draw(&mut lease, 0x10 + index, 0x20 + index, 100, 100)
            .unwrap_or_else(|error| panic!("draw {index} within the envelope: {error}"));
    }
    let after_three = stored(&lease.state, &lease.grant_hash);
    assert_eq!(after_three.uses_consumed, 3);
    assert_eq!(after_three.cumulative_spend_reserved_microusd, 300);
    assert_eq!(after_three.status, StandingApprovalGrantStatus::Active);

    // Draw 4 would take spend to 400 > 350: refused, the remaining balance is named, and the
    // refusal changes nothing (usages, reservations and status are exactly as after draw 3).
    let refused =
        draw(&mut lease, 0x14, 0x24, 100, 100).expect_err("draw N+1 crosses the spend envelope");
    let message = refused.to_string();
    assert!(
        message.contains("cumulative spend envelope exceeded")
            && message.contains("remaining spend 50 microusd")
            && message.contains("requested 100"),
        "{message}"
    );
    assert_eq!(stored(&lease.state, &lease.grant_hash), after_three);

    // A smaller draw that fits the remaining 50 still admits: the bound is the balance, not the
    // count of prior refusals.
    draw(&mut lease, 0x15, 0x25, 50, 50).expect("a draw inside the remaining balance admits");
    let exact = stored(&lease.state, &lease.grant_hash);
    assert_eq!(exact.cumulative_spend_reserved_microusd, 350);
    assert_eq!(exact.uses_consumed, 4);
    // Every draw is journaled; the journal is the source the counters are re-derived from.
    let journal = load_typed::<StandingApprovalGrantJournal>(
        &lease.state,
        &standing_approval_grant_journal_key(&lease.grant_hash),
    )
    .expect("read journal")
    .expect("journal present");
    assert_eq!(journal.consumption_ids.len(), 4);
    assert!(
        !journal.consumption_ids.contains(&[0x24; 32]),
        "a refused draw is never journaled"
    );
}

#[test]
fn the_usage_bound_refuses_with_the_remaining_count_and_exhausts_exactly_at_max() {
    let mut lease = mint(2, 1_000_000, 1_000_000, 0xe2);
    draw(&mut lease, 1, 1, 10, 10).expect("one");
    draw(&mut lease, 2, 2, 10, 10).expect("two");
    let exhausted = stored(&lease.state, &lease.grant_hash);
    assert_eq!(exhausted.status, StandingApprovalGrantStatus::Exhausted);
    let refused = draw(&mut lease, 3, 3, 10, 10).expect_err("third draw");
    assert!(
        refused.to_string().contains("not active: exhausted"),
        "{refused}"
    );
}

#[test]
fn a_concurrent_double_draw_cannot_exceed_the_envelope() {
    // Two drawers race for one envelope of 100 spend, each wanting 60: exactly one can win,
    // whatever the interleaving, because consumption is serialized through the wallet's
    // single writer and every draw re-reads the committed counters.
    let lease = mint(10, 1_000, 100, 0xe3);
    let params_a = draw_params(&lease, 0xa1, 0xb1, 60, 60);
    let params_b = draw_params(&lease, 0xa2, 0xb2, 60, 60);
    let grant_hash = lease.grant_hash;
    let shared = Arc::new(Mutex::new(lease.state));
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        for params in [params_a, params_b] {
            let shared = Arc::clone(&shared);
            let outcomes = Arc::clone(&outcomes);
            scope.spawn(move || {
                let service = WalletNetworkService;
                let mut state = shared.lock().expect("single writer");
                let result = consume(&service, &mut state, params);
                outcomes.lock().expect("outcomes").push(result.is_ok());
            });
        }
    });
    let outcomes = outcomes.lock().expect("outcomes");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "exactly one of two 60-of-100 draws admits: {outcomes:?}"
    );
    let state = shared.lock().expect("state");
    let record = stored(&state, &grant_hash);
    assert_eq!(record.uses_consumed, 1);
    assert_eq!(record.cumulative_spend_reserved_microusd, 60);
    assert!(
        record.cumulative_spend_reserved_microusd <= record.grant.max_cumulative_spend_microusd
    );
}

#[test]
fn a_counter_that_diverges_from_the_journal_refuses_the_next_draw() {
    let mut lease = mint(10, 1_000, 1_000, 0xe4);
    draw(&mut lease, 1, 1, 100, 100).expect("one");
    // Plant a rotted counter: the state says 0 spend reserved while the journal holds one
    // receipt of 100. A draw that trusted the counter would widen the envelope by 100.
    let key = standing_approval_grant_state_key(&lease.grant_hash);
    let mut rotted = stored(&lease.state, &lease.grant_hash);
    rotted.cumulative_spend_reserved_microusd = 0;
    lease
        .state
        .insert(&key, &codec::to_bytes_canonical(&rotted).expect("encode"))
        .expect("plant");
    let refused = draw(&mut lease, 2, 2, 100, 100).expect_err("divergent ledger");
    let message = refused.to_string();
    assert!(message.contains("ledger divergence"), "{message}");
    assert!(
        message.contains("spend=100") && message.contains("spend=0"),
        "{message}"
    );
    // Nothing was consumed by the refused draw.
    let journal = load_typed::<StandingApprovalGrantJournal>(
        &lease.state,
        &standing_approval_grant_journal_key(&lease.grant_hash),
    )
    .expect("read journal")
    .expect("journal present");
    assert_eq!(journal.consumption_ids, vec![[1u8; 32]]);
}

#[test]
fn revocation_refuses_the_very_next_draw_and_recovery_never_widens_or_resets() {
    let mut lease = mint(5, 1_000, 500, 0xe5);
    draw(&mut lease, 1, 1, 100, 100).expect("one");
    draw(&mut lease, 2, 2, 100, 100).expect("two");
    let before = stored(&lease.state, &lease.grant_hash);
    let rendered_before = standing_grant_lease("aa", &before, EFFECT_NOW_MS);
    let envelope = rendered_before
        .standing_envelope
        .as_ref()
        .expect("projection");
    assert_eq!(envelope.usages_consumed, 2);
    assert_eq!(envelope.remaining_usages, 3);
    assert_eq!(envelope.remaining_spend_microusd, 300);
    assert_eq!(rendered_before.status, "active");
    assert_eq!(rendered_before.kind, "standing_envelope");

    // Recovery: a fresh state built from the durable bytes renders the same lease — the
    // counters are what the wallet journal justifies, never reset.
    let recovered = MockState {
        data: lease.state.data.clone(),
    };
    let after_recovery = stored(&recovered, &lease.grant_hash);
    assert_eq!(after_recovery, before);
    assert_eq!(
        standing_grant_lease("aa", &after_recovery, EFFECT_NOW_MS),
        rendered_before
    );

    // Re-recording the same grant after consumption (the idempotent replay a device transition
    // or crash recovery performs) must NOT reset usages or balances.
    let approver_key_material = before.grant.clone();
    let _ = approver_key_material;
    let replay = RecordStandingApprovalGrantParams {
        grant: before.grant.clone(),
        standing_envelope_json: before.standing_envelope_json.clone(),
        approval_ceremony_context_json: before.approval_ceremony_context_json.clone(),
        auth_factor_receipt_json: before.auth_factor_receipt_json.clone(),
    };
    with_ctx(|ctx| {
        run_async(lease.service.handle_service_call(
            &mut lease.state,
            "record_standing_approval_grant@v1",
            &codec::to_bytes_canonical(&replay).expect("encode replay"),
            ctx,
        ))
        .expect("byte-identical replay is idempotent");
    });
    assert_eq!(
        stored(&lease.state, &lease.grant_hash),
        before,
        "replay reset nothing"
    );

    // Revoke, then draw in the very next transaction: refused, and the only change between
    // the two commits is the status.
    with_ctx(|ctx| {
        run_async(
            lease.service.handle_service_call(
                &mut lease.state,
                "revoke_standing_approval_grant@v1",
                &codec::to_bytes_canonical(&RevokeStandingApprovalGrantParams {
                    grant_hash: lease.grant_hash,
                })
                .expect("encode revoke"),
                ctx,
            ),
        )
        .expect("revoke");
    });
    let revoked = stored(&lease.state, &lease.grant_hash);
    assert_eq!(revoked.status, StandingApprovalGrantStatus::Revoked);
    assert_eq!(
        StandingApprovalGrantState {
            status: StandingApprovalGrantStatus::Active,
            ..revoked.clone()
        },
        before,
        "revocation changed only the status"
    );
    let refused = draw(&mut lease, 3, 3, 100, 100).expect_err("next draw after revoke");
    assert!(
        refused.to_string().contains("not active: revoked"),
        "{refused}"
    );
    assert_eq!(
        stored(&lease.state, &lease.grant_hash),
        revoked,
        "the refused draw changed nothing"
    );
    let rendered_after = standing_grant_lease("aa", &revoked, EFFECT_NOW_MS);
    assert_eq!(rendered_after.status, "revoked");
    assert_eq!(
        rendered_after
            .standing_envelope
            .as_ref()
            .expect("projection")
            .usages_consumed,
        2,
        "a revoked lease keeps its consumed history; nothing is restored"
    );

    // A recovered revoked lease is still revoked: recovery never resurrects.
    let recovered = MockState {
        data: lease.state.data.clone(),
    };
    let params = draw_params(&lease, 4, 4, 100, 100);
    let refused = consume(
        &lease.service,
        &mut MockState {
            data: recovered.data.clone(),
        },
        params,
    )
    .expect_err("recovered revoked lease");
    assert!(
        refused.to_string().contains("not active: revoked"),
        "{refused}"
    );
}

#[test]
fn the_projection_derives_expiry_and_exhaustion_without_deciding_anything() {
    let lease = mint(1, 1_000, 1_000, 0xe6);
    let record = stored(&lease.state, &lease.grant_hash);
    let expired = standing_grant_lease("aa", &record, record.grant.expires_at_ms + 1);
    assert_eq!(expired.status, "expired");
    assert_eq!(
        expired.authority_status.as_deref(),
        Some("active"),
        "the wallet status is reported verbatim; the clock only narrows"
    );
    let early = standing_grant_lease("aa", &record, record.grant.issued_at_ms - 1);
    assert_eq!(early.status, "not_yet_valid");
    let mut consumed = record.clone();
    consumed.uses_consumed = 1;
    consumed.status = StandingApprovalGrantStatus::Exhausted;
    let rendered = standing_grant_lease("aa", &consumed, EFFECT_NOW_MS);
    assert_eq!(rendered.status, "exhausted");
    assert_eq!(
        rendered
            .standing_envelope
            .expect("projection")
            .remaining_usages,
        0
    );
}
