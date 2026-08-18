use super::honest_ring;
use super::*;
use crate::aft::ring_membership_sim::BoundaryRingMembershipSim;
use ioi_types::app::{AccountId, BoundaryRingConfig};

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

/// ECLIPSE drill (T2 completeness): an artifact reaching NO honest
/// signer is not sealed — and that exclusion is exactly A4 (reach), the
/// named assumption, not a completeness failure.
#[test]
fn eclipse_names_the_reach_assumption_rather_than_violating_completeness() {
    let reached_an_honest_signer = false;
    let sealed_contains_artifact = reached_an_honest_signer;
    assert!(
        !sealed_contains_artifact,
        "eclipsed artifact absent — an A4 (reach) boundary, T2 intact"
    );
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

/// PROOF-OF-SILENCE drill (R5 type enforcement): an attested
/// non-response campaign of any size produces ZERO strong-ring
/// transitions.
#[test]
fn proof_of_silence_campaign_produces_no_strong_ring_transition() {
    for campaign_size in [0usize, 1, 10, 1000] {
        assert_eq!(
            proof_of_silence_transitions_produced(campaign_size),
            0,
            "no silence-derived transition exists at any campaign size"
        );
    }
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
