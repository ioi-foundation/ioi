use super::honest_ring;
use super::*;
use crate::aft::ring_membership_sim::BoundaryRingMembershipSim;
use ioi_types::app::{AccountId, BoundaryRingConfig, WatchtowerCountersignRecord};

fn account(b: u8) -> AccountId {
    AccountId([b; 32])
}

fn byzantine_ring(members: &[u8], honest: &[bool]) -> BoundaryRingMembershipSim {
    let config = BoundaryRingConfig {
        version: 1,
        members: members.iter().map(|b| account(*b)).collect(),
        member_bonds: Default::default(),
        activated_at_event: 0,
        closed_by: None,
    };
    BoundaryRingMembershipSim::new(config, honest).expect("sim")
}

/// PARTITION drill (T4a two-tier separation + T1 uniqueness): an honest
/// split cannot seal (n-of-n unmet) while the live tier keeps producing;
/// healing yields the unique seal. Assumption: A2 + the two-tier
/// boundary.
#[test]
fn partition_stalls_seals_but_not_the_live_tier_then_heals_to_a_unique_seal() {
    let mut sim = honest_ring(&[1, 2, 3, 4]);
    let root = [0xA0; 32];
    for m in [1u8, 2] {
        sim.honest_final_ack(&account(m), 1, root).expect("ack");
    }
    assert!(!sim.try_seal(1, root).expect("try"), "split cannot seal");
    for _ in 0..5 {
        sim.live_tier_produce();
    }
    assert_eq!(
        sim.live_tier_height, 5,
        "live tier continued through the partition"
    );

    for m in [3u8, 4] {
        sim.honest_final_ack(&account(m), 1, root).expect("ack");
    }
    assert!(sim.try_seal(1, root).expect("try"), "healed ring seals");
    assert!(!sim.has_conflicting_seals(), "the seal is unique");
}

/// ECLIPSE drill (real sim, T2 completeness under A4 reach): an artifact
/// that reaches NO honest signer collects no ack, so `try_seal` never
/// assembles it — the exclusion is the A4 reach boundary, named, not a
/// completeness failure. The control: the SAME artifact seals once it
/// reaches the ring, so the drill distinguishes "unreached" from "broken
/// completeness" rather than asserting a constant.
///
/// Mutation drill (RED): delete the missing-ack `return Ok(false)` guard
/// in `BoundaryRingMembershipSim::try_seal` → the eclipsed artifact seals
/// with zero acks → the first assertion fails.
#[test]
fn eclipse_names_reach_on_the_real_sim_while_a_reached_artifact_seals() {
    let mut sim = honest_ring(&[1, 2, 3, 4]);
    let eclipsed = [0xEC; 32];

    // The eclipsed artifact reaches no signer: no member ever acked it.
    assert!(
        !sim.try_seal(1, eclipsed).expect("try"),
        "an unreached artifact cannot seal — the A4 reach boundary, not a T2 failure"
    );
    assert!(sim.seals.is_empty(), "the eclipsed slot stayed empty");

    // A4 named, not violated: had it reached all four honest signers it
    // WOULD seal — so the absence above is reach, not broken completeness.
    for m in [1u8, 2, 3, 4] {
        sim.honest_final_ack(&account(m), 2, eclipsed).expect("ack");
    }
    assert!(
        sim.try_seal(2, eclipsed).expect("try"),
        "the SAME artifact seals once it reaches the ring"
    );
    assert!(!sim.has_conflicting_seals(), "the reached seal is unique");
}

/// CUSTODY-DELETION drill (T3 availability, A2): n−1 delete post-seal;
/// one honest holder still serves. The all-delete corner is where A2 is
/// named (nothing to serve).
#[test]
fn custody_deletion_still_serves_while_one_honest_holder_remains() {
    let model = CustodyModel::after_seal_with_deletions(4, &[0, 1, 2]);
    assert!(
        model.bytes_served(),
        "the one honest holder still serves (T3)"
    );
    assert_eq!(model.holders.len(), 1);
    assert_eq!(model.ring_size, 4);

    let all_deleted = CustodyModel::after_seal_with_deletions(4, &[0, 1, 2, 3]);
    assert!(
        !all_deleted.bytes_served(),
        "zero holders => A2 violated, out of guarantee"
    );
}

/// n−1-BYZANTINE RING drill (T1 uniqueness): three Byzantine of four
/// equivocate on two roots; the one honest journal yields zero
/// conflicting seals.
#[test]
fn n_minus_one_byzantine_ring_produces_no_conflicting_seal() {
    let mut sim = byzantine_ring(&[1, 2, 3, 4], &[true, false, false, false]);
    let (rx, ry) = ([0xB0; 32], [0xB1; 32]);
    for m in [2u8, 3, 4] {
        sim.byzantine_emit(&account(m), 1, rx).expect("emit");
        sim.byzantine_emit(&account(m), 1, ry).expect("emit");
    }
    sim.honest_final_ack(&account(1), 1, rx).expect("ack");
    assert!(
        sim.honest_final_ack(&account(1), 1, ry).is_err(),
        "journal refuses the second root"
    );
    assert!(sim.try_seal(1, rx).expect("try"));
    assert!(!sim.try_seal(1, ry).expect("try"));
    assert!(!sim.has_conflicting_seals());
}

/// LONG-RANGE BOOTSTRAP drill (T5b / L-LR): with a live A6 anchor the
/// newcomer rejects forged history; without one the case is documented
/// out-of-model — never a false defense.
#[test]
fn long_range_bootstrap_rejects_with_anchor_and_is_out_of_model_without() {
    assert_eq!(
        bootstrap_decision(true),
        BootstrapOutcome::RejectedViaAnchor
    );
    assert_eq!(bootstrap_decision(false), BootstrapOutcome::OutOfModel);
}

/// PROOF-OF-SILENCE drill (real sim, R5 type enforcement + T4a): an
/// attested non-response campaign — watchtower countersignatures from
/// anyone, at any volume, with every ring member withholding — moves NO
/// state. The sim advances only on real n-of-n acks (`try_seal`) or a
/// real approved `handover`; it never reads a watchtower record back, so
/// no flood of them seals a slot or replaces the ring. Silence has no
/// constructor. This holds structurally — it does not even need A2.
///
/// Mutation drill (RED): give `BoundaryRingMembershipSim::try_seal` a
/// watchtower-derived shortcut (seal when `!self.watchtower_records
/// .is_empty()`) → the campaign seals a slot from silence → the
/// `!sealed` assertion fails.
#[test]
fn proof_of_silence_campaign_moves_no_state_on_the_real_sim() {
    let mut sim = honest_ring(&[1, 2, 3, 4]);
    let start_version = sim.config.version;
    let (slot, root) = (1u64, [0x5A; 32]);

    // Every ring member goes silent: withholds all acks.
    for m in [1u8, 2, 3, 4] {
        sim.members
            .get_mut(&account(m))
            .expect("member")
            .withholding = true;
    }

    // The adversary floods attested non-response: watchtower
    // countersignatures from arbitrary accounts, at volume.
    for i in 0..1000u64 {
        sim.record_watchtower(WatchtowerCountersignRecord {
            height: slot,
            watcher_account_id: account((i % 251) as u8),
            seal_hash: root,
            signature_bytes: vec![0xFF; 8],
        });
    }

    // No seal formed from silence, at this slot or anywhere.
    assert!(
        !sim.try_seal(slot, root).expect("try"),
        "silence seals nothing"
    );
    assert!(sim.seals.is_empty(), "the campaign sealed no slot");
    assert!(!sim.has_conflicting_seals());

    // No strong-ring transition: the live configuration is unchanged and
    // nothing was closed — silence has no handover path.
    assert_eq!(
        sim.config.version, start_version,
        "no silence-derived ring transition"
    );
    assert!(
        sim.closed_configs.is_empty(),
        "no ring was closed by silence"
    );

    // The 1000 records were recorded but gated nothing.
    assert_eq!(sim.watchtower_records.len(), 1000);
}

/// POST-COMPROMISE drill (A8 everlasting safety): a re-genesis root
/// severs lineage — post-root compromise of former members cannot
/// rewrite pre-root history into one continuous lineage.
#[test]
fn post_compromise_history_is_unforgeable_across_a_regenesis_root() {
    let root = regenesis_root_at(100);
    assert_eq!(
        lineage_across(std::slice::from_ref(&root), 50, 150),
        LineageRelation::NewLineage
    );
    assert_eq!(
        lineage_across(std::slice::from_ref(&root), 10, 50),
        LineageRelation::SameLineage
    );
}
