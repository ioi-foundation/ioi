use super::*;
use ioi_types::app::{
    assign_seats, authorize_bond_release, lineage_relation, AnchoredRegenesisRoot,
    ConstituencyFloor, CustodyHandoverReceipt, LineageRelation, RingMemberRegistration,
};

fn account(byte: u8) -> AccountId {
    AccountId([byte; 32])
}

fn config(version: u64, member_bytes: &[u8]) -> BoundaryRingConfig {
    BoundaryRingConfig {
        version,
        members: member_bytes.iter().map(|b| account(*b)).collect(),
        member_bonds: Default::default(),
        activated_at_event: 0,
        closed_by: None,
    }
}

fn approval(member: u8, old: u64, new: u64) -> HandoverApproval {
    HandoverApproval {
        member: account(member),
        old_version: old,
        new_version: new,
        signature_bytes: vec![member],
    }
}

fn acceptance(member: u8, new: u64) -> HandoverAcceptance {
    HandoverAcceptance {
        member: account(member),
        new_version: new,
        signature_bytes: vec![member],
    }
}

/// Gate (a): one withholder freezes seal cadence; the live tier keeps
/// producing blocks (two-tier separation).
#[test]
fn one_withholder_freezes_seals_while_live_tier_produces() {
    let mut sim =
        BoundaryRingMembershipSim::new(config(1, &[1, 2, 3, 4]), &[true, true, true, true])
            .expect("sim");
    sim.members.get_mut(&account(4)).unwrap().withholding = true;

    let root = [0xAA; 32];
    for member in [1u8, 2, 3] {
        sim.honest_final_ack(&account(member), 1, root)
            .expect("ack");
    }
    assert!(sim.honest_final_ack(&account(4), 1, root).is_err());
    assert!(
        !sim.try_seal(1, root).expect("try"),
        "n-of-n unmet: no seal"
    );

    for _ in 0..10 {
        sim.live_tier_produce();
    }
    assert_eq!(sim.live_tier_height, 10, "live tier progressed regardless");
    assert!(sim.seals.is_empty(), "seal cadence frozen the whole time");
}

/// Gate (b): n = 4 with THREE Byzantine equivocators and one honest
/// journal-guarded member — zero conflicting seals, ever. Uniqueness is
/// DERIVED (the honest share can exist for only one root), not enforced
/// by the seal map, which would happily hold a conflict.
#[test]
fn three_byzantine_of_four_never_assemble_conflicting_seals() {
    let mut sim =
        BoundaryRingMembershipSim::new(config(1, &[1, 2, 3, 4]), &[true, false, false, false])
            .expect("sim");
    let (r_x, r_y) = ([0xAA; 32], [0xBB; 32]);

    // Every Byzantine member equivocates on BOTH roots.
    for member in [2u8, 3, 4] {
        sim.byzantine_emit(&account(member), 1, r_x).expect("emit");
        sim.byzantine_emit(&account(member), 1, r_y).expect("emit");
    }
    // The honest member journals exactly one.
    sim.honest_final_ack(&account(1), 1, r_x).expect("ack");
    assert!(
        sim.honest_final_ack(&account(1), 1, r_y).is_err(),
        "journal refuses the second root"
    );

    assert!(
        sim.try_seal(1, r_x).expect("try"),
        "the journaled root seals"
    );
    assert!(!sim.try_seal(1, r_y).expect("try"), "the other cannot");
    assert!(!sim.has_conflicting_seals(), "zero conflicting seals");
}

/// Gate (c): succession without reconstruction refuses bond release;
/// with the successor's acknowledgement it releases.
#[test]
fn succession_without_reconstruction_refuses_bond_release() {
    let member = account(3);
    let unreconstructed = CustodyHandoverReceipt {
        member,
        config_version: 1,
        reconstructed_surface_root: [0u8; 32],
        successor_acknowledgement_bytes: Vec::new(),
    };
    assert!(authorize_bond_release(&member, 1, &unreconstructed).is_err());

    let reconstructed = CustodyHandoverReceipt {
        member,
        config_version: 1,
        reconstructed_surface_root: [0x77; 32],
        successor_acknowledgement_bytes: vec![1],
    };
    authorize_bond_release(&member, 1, &reconstructed).expect("release");
}

/// Gate (d): the handover ceremony end-to-end — old-ring unanimity plus
/// new-ring acceptance activates the successor; seals resume under it;
/// a handover PRESERVES lineage while a re-genesis root SEVERS it, and
/// a severed crossing can never read as continuity.
#[test]
fn handover_end_to_end_and_regenesis_severs_lineage() {
    let mut sim =
        BoundaryRingMembershipSim::new(config(1, &[1, 2, 3, 4]), &[true; 4]).expect("sim");
    let before_event = sim.event_counter;

    let new_config = config(2, &[2, 3, 4, 5]);
    let approvals: Vec<_> = [1u8, 2, 3, 4].iter().map(|m| approval(*m, 1, 2)).collect();
    let acceptances: Vec<_> = [2u8, 3, 4, 5].iter().map(|m| acceptance(*m, 2)).collect();
    sim.handover(new_config, &approvals, &acceptances)
        .expect("ceremony completes");
    assert_eq!(sim.config.version, 2);
    assert!(sim.closed_configs.get(&1).unwrap().closed_by.is_some());

    // Seals resume under the NEW ring's n-of-n (member 5 now required).
    let root = [0xCC; 32];
    for member in [2u8, 3, 4, 5] {
        sim.honest_final_ack(&account(member), 2, root)
            .expect("ack");
    }
    assert!(
        sim.try_seal(2, root).expect("try"),
        "cadence resumed under v2"
    );

    // The handover preserved lineage: no root lies across the ceremony.
    let roots: Vec<AnchoredRegenesisRoot> = sim
        .regenesis_events
        .iter()
        .map(|event| AnchoredRegenesisRoot {
            lineage_id: [1u8; 32],
            anchor_reference: [2u8; 32],
            genesis_state_root: [3u8; 32],
            declared_at_event: *event,
        })
        .collect();
    assert_eq!(
        lineage_relation(&roots, before_event, sim.event_counter),
        LineageRelation::SameLineage,
        "handover is continuity"
    );

    // A re-genesis root severs: the crossing MUST read NewLineage.
    let pre_regenesis = sim.event_counter;
    sim.declare_regenesis();
    let roots: Vec<AnchoredRegenesisRoot> = sim
        .regenesis_events
        .iter()
        .map(|event| AnchoredRegenesisRoot {
            lineage_id: [1u8; 32],
            anchor_reference: [2u8; 32],
            genesis_state_root: [3u8; 32],
            declared_at_event: *event,
        })
        .collect();
    assert_eq!(
        lineage_relation(&roots, pre_regenesis, sim.event_counter + 1),
        LineageRelation::NewLineage,
        "a re-genesis crossing is NEVER continuity"
    );
}

/// Gate (e): seat assignment reproduces deterministically from the
/// beacon and honors floors; a watchtower countersignature is recorded
/// but the seal outcome is IDENTICAL without it.
#[test]
fn sortition_reproduces_and_watchtowers_gate_nothing() {
    let candidates: Vec<RingMemberRegistration> = (1u8..=8)
        .map(|b| RingMemberRegistration {
            account_id: account(b),
            bond_amount: 1_000,
            constituency_id: u32::from(b % 2),
            registered_at_event: 0,
        })
        .collect();
    let floors = vec![ConstituencyFloor {
        constituency_id: 1,
        min_seats: 2,
    }];
    let beacon = [0x55; 32];
    let seats_a = assign_seats(&beacon, &candidates, &floors, 4).expect("assign");
    let seats_b = assign_seats(&beacon, &candidates, &floors, 4).expect("assign");
    assert_eq!(seats_a, seats_b, "deterministic from the beacon");

    // Two identical runs, one with a watchtower record: same seals.
    let run = |with_watchtower: bool| -> BTreeMap<u64, BTreeSet<[u8; 32]>> {
        let mut sim =
            BoundaryRingMembershipSim::new(config(1, &[1, 2, 3]), &[true; 3]).expect("sim");
        if with_watchtower {
            sim.record_watchtower(WatchtowerCountersignRecord {
                height: 1,
                watcher_account_id: account(99),
                seal_hash: [0xEE; 32],
                signature_bytes: vec![9, 9],
            });
        }
        let root = [0xDD; 32];
        for member in [1u8, 2, 3] {
            sim.honest_final_ack(&account(member), 1, root)
                .expect("ack");
        }
        sim.try_seal(1, root).expect("try");
        sim.seals
    };
    assert_eq!(run(false), run(true), "the watchtower record gates NOTHING");
}
