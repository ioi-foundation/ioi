//! SCQ-8.10 (OBS-6) with SCQ-8.10a-f and the INHERITED-PHASE tenure rule: the parameters'
//! constraints; seat phases (a joiner inherits its seat's phase) and the analysed model's tenure
//! convention (B1-R v1, M7 (vi)); the departures (every forced rotation, never deferred) and the
//! fill order (forced rotations, then the oldest vacancy, then exits; an unfilled departure leaves
//! a vacancy); the two red controls (a member off its seat's phase is refused; a deferred forced
//! rotation is refused); the per-seat draw (its derivation, and the dedicated correlation test of
//! TX's dependence condition); floors first, cut to the fill set, and an `assign_seats` error (an
//! exhausted floor pool, or a pool smaller than the fill set) leaving the WHOLE fill set VACANT;
//! the alarms; the genesis ring as a selector draw; the balanced genesis offsets; the PROPERTY
//! TESTS at the deployed n = 7 over long seeded random runs (Lemma FR; Lemma LV with the vacancies
//! beyond the rate bounded and refilled and the safe halt); full-n thresholds; and the ratchet (a
//! steady-state SHARE, never cited as a bound).

use super::*;
use crate::app::BoundaryRingConfig;

fn account_n(n: u32) -> AccountId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    bytes[31] = 0xAA;
    AccountId(bytes)
}

fn params() -> RingSelectionParams {
    // Fixture values only: the production numbers are the numbers author's.
    RingSelectionParams {
        ring_seats: 3,
        tenure_handovers: 4,
        churn_cap: 2,
        bond_floor: 100,
        bond_lock_events: 4 * 10 + 5,
        handover_interval_events: 10,
        exit_challenge_window_events: 5,
        activation_depth_events: 3,
        snapshot_to_beacon_events: 3,
        floors: vec![],
    }
}

fn registration(n: u32, constituency: u32) -> RingMemberRegistration {
    RingMemberRegistration {
        account_id: account_n(n),
        bond_amount: 100,
        constituency_id: constituency,
        registered_at_event: 0,
    }
}

fn beacon(i: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&i.to_be_bytes());
    out[8..16].copy_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
    out[16..24].copy_from_slice(&(!i).rotate_left(17).to_be_bytes());
    out
}

fn vacancy(seat: u32, since_version: u64) -> RingVacancy {
    RingVacancy {
        seat,
        since_version,
    }
}

/// A live handover snapshot at version 5 after `handover_index` handovers. Every seated member
/// holds its seat's phase (its tenure is derived from `offsets`), and the departures are planned
/// as the registry plans them (declared exits of forced occupants count as forced).
fn live_snapshot(
    members: &[AccountId],
    vacancies: &[RingVacancy],
    offsets: &[u32],
    handover_index: u64,
    exits: &[AccountId],
    candidates: Vec<RingMemberRegistration>,
    p: &RingSelectionParams,
) -> RingHandoverSnapshot {
    let seats = seat_layout(members, vacancies).unwrap();
    assert_eq!(seats.len(), offsets.len(), "one offset per seat");
    let tenure: BTreeMap<AccountId, u32> = seats
        .iter()
        .zip(offsets)
        .filter_map(|(member, offset)| {
            member.map(|member| {
                (
                    member,
                    seat_phase(*offset, handover_index, p.tenure_handovers),
                )
            })
        })
        .collect();
    let exit_set: BTreeSet<AccountId> = exits.iter().copied().collect();
    let plan = plan_handover_vacancies(members, &tenure, &exit_set, p.tenure_handovers);
    RingHandoverSnapshot {
        live_version: 5,
        snapshot_event: 10,
        seat_count: seats.len() as u32,
        members: members.to_vec(),
        vacancies: vacancies.to_vec(),
        handover_index,
        seat_offsets: offsets.to_vec(),
        tenure_counters: tenure.into_iter().collect(),
        member_constituencies: vec![],
        vacated_set: plan
            .exits
            .iter()
            .chain(plan.forced_rotations.iter())
            .copied()
            .collect(),
        exits: plan.exits,
        forced_rotations: plan.forced_rotations,
        churn_cap: p.churn_cap,
        tenure_handovers: p.tenure_handovers,
        candidates,
        floors: p.floors.clone(),
        floors_ref: p.floors_ref().unwrap(),
    }
}

fn config_of(version: u64, draw: &RingSeatDraw) -> BoundaryRingConfig {
    BoundaryRingConfig {
        version,
        members: draw.successor_members.clone(),
        vacant_seats: draw.successor_vacancies.clone(),
        ..Default::default()
    }
}

fn tenure_of(snapshot: &RingHandoverSnapshot, member: AccountId) -> u32 {
    snapshot
        .tenure_counters
        .iter()
        .find(|(m, _)| *m == member)
        .unwrap()
        .1
}

// --- The parameters (n, D1-D3, c ≥ n/T) --------------------------------------------------------

#[test]
fn the_parameters_enforce_n_d1_d2_d3_and_c_at_least_n_over_t() {
    params().validate(None).unwrap();
    params().validate(Some(3)).unwrap();
    assert!(params()
        .validate(Some(4))
        .unwrap_err()
        .contains("the parameters say n=3"));
    let mut p = params();
    p.ring_seats = 0;
    assert!(p.validate(None).is_err());
    // c × T = 8 < 9 seats.
    let mut p = params();
    p.ring_seats = 9;
    assert!(p.validate(None).unwrap_err().contains("c ≥ n/T"));
    let mut p = params();
    p.bond_floor = 0;
    assert!(p.validate(None).unwrap_err().contains("D1"));
    let mut p = params();
    p.bond_lock_events = 4 * 10 + 5 - 1;
    assert!(p.validate(None).unwrap_err().contains("D2"));
    let mut p = params();
    p.activation_depth_events = p.snapshot_to_beacon_events - 1;
    assert!(p.validate(None).unwrap_err().contains("D3"));
    let mut p = params();
    p.tenure_handovers = 0;
    assert!(p.validate(None).is_err());
    let mut p = params();
    p.floors = vec![ConstituencyFloor {
        constituency_id: 1,
        min_seats: 4,
    }];
    assert!(p.validate(None).unwrap_err().contains("exceed"));
    let mut p = params();
    p.floors = vec![
        ConstituencyFloor {
            constituency_id: 1,
            min_seats: 1,
        },
        ConstituencyFloor {
            constituency_id: 1,
            min_seats: 1,
        },
    ];
    assert!(p.validate(None).unwrap_err().contains("two floors"));
}

// --- Seat phases: the tenure rule is INHERITED PHASE --------------------------------------------

#[test]
fn a_seats_phase_is_its_genesis_offset_advanced_by_the_handovers_modulo_t() {
    assert_eq!(seat_phase(0, 0, 4), 0);
    assert_eq!(seat_phase(3, 0, 4), 3);
    assert_eq!(
        seat_phase(3, 1, 4),
        0,
        "offset T-1 reaches T at the first handover"
    );
    assert_eq!(seat_phase(1, 5, 4), 2);
    assert_eq!(seat_phase(2, 6, 4), 0);
    assert_eq!(
        seat_phase(0, 9, 1),
        0,
        "T = 1: every handover rotates every seat"
    );
    assert_eq!(seat_phase(5, u64::MAX, 7), ((5 + u64::MAX % 7) % 7) as u32);
}

/// INHERITED PHASE (module docs, 3.): whatever emptied the seat (an exit, a forced rotation, an
/// old vacancy), the joiner's tenure is the SEAT's counter after this handover, never a fresh
/// counter. T = 4, five handovers done (h = 5), so the successor is at h = 6.
#[test]
fn a_joiner_inherits_its_seats_phase_never_a_fresh_counter() {
    // Seats: 0 m1 (offset 1: phase 2, exits), 1 m2 (offset 2: phase 3, forced), 2 vacant (offset
    // 3), 3 m4 (offset 0: phase 1, stays), 4 m5 (offset 1: phase 2, stays).
    let members = [account_n(1), account_n(2), account_n(4), account_n(5)];
    let offsets = [1, 2, 3, 0, 1];
    let mut p = params();
    p.churn_cap = 4;
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(
        &members,
        &[vacancy(2, 3)],
        &offsets,
        5,
        &[account_n(1)],
        candidates,
        &p,
    );
    assert_eq!(s.forced_rotations, vec![account_n(2)]);
    assert_eq!(s.exits, vec![account_n(1)]);
    let draw = draw_vacated_seats(&s, &beacon(9)).unwrap();
    let seats = config_of(6, &draw).seats().unwrap();
    let start: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
    assert_eq!(start.len(), 3);
    assert_eq!(start[&seats[0].unwrap()], 3, "exit seat: (1 + 6) mod 4");
    assert_eq!(start[&seats[1].unwrap()], 0, "forced seat: (2 + 6) mod 4");
    assert_eq!(start[&seats[2].unwrap()], 1, "old vacancy: (3 + 6) mod 4");
    for seat in [0usize, 1, 2] {
        assert_eq!(
            start[&seats[seat].unwrap()],
            seat_phase(offsets[seat], 6, 4),
            "seat {seat}: the joiner holds the seat's phase"
        );
    }
    // The kept members stay, and their next counter (tenure + 1) is their seat's phase too.
    assert_eq!(seats[3], Some(account_n(4)));
    assert_eq!(tenure_of(&s, account_n(4)) + 1, seat_phase(0, 6, 4));
    assert_eq!(tenure_of(&s, account_n(5)) + 1, seat_phase(1, 6, 4));
}

/// RED CONTROL (the tenure rule rests on the phase belonging to the seat): a snapshot in which a
/// seated member does not hold its seat's phase is REFUSED: a joiner reset to a fresh counter,
/// another non-assigned phase, an overdue counter (what a deferral would leave), a member with
/// no counter, a short offset list, an offset not below T.
#[test]
fn a_member_off_its_seats_phase_is_refused() {
    let members = [account_n(1), account_n(2), account_n(3)];
    let offsets = [1, 2, 3];
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let good = live_snapshot(&members, &[], &offsets, 6, &[], candidates, &params());
    draw_vacated_seats(&good, &beacon(1)).unwrap();
    let with_tenure = |member: AccountId, tenure: Option<u32>| {
        let mut s = good.clone();
        s.tenure_counters.retain(|(m, _)| *m != member);
        if let Some(tenure) = tenure {
            s.tenure_counters.push((member, tenure));
        }
        s
    };
    // m1's seat phase is (1 + 6) mod 4 = 3.
    assert_eq!(tenure_of(&good, account_n(1)), 3);
    for (label, tenure) in [
        ("a fresh counter", Some(0)),
        ("another phase", Some(1)),
        ("an overdue counter", Some(4)),
        ("no counter", None),
    ] {
        let err = draw_vacated_seats(&with_tenure(account_n(1), tenure), &beacon(1)).unwrap_err();
        assert!(err.contains("assigned phase"), "{label}: {err}");
    }
    let mut short = good.clone();
    short.seat_offsets.pop();
    assert!(draw_vacated_seats(&short, &beacon(1))
        .unwrap_err()
        .contains("seat offsets"));
    let mut wide = good.clone();
    wide.seat_offsets[0] = 4;
    assert!(draw_vacated_seats(&wide, &beacon(1))
        .unwrap_err()
        .contains("not below T"));
    // The same check as a function, as the registry calls it.
    let tenure: BTreeMap<AccountId, u32> = good.tenure_counters.iter().copied().collect();
    verify_seat_phases(&members, &[], &tenure, &offsets, 6, 4).unwrap();
    assert!(verify_seat_phases(&members, &[], &tenure, &offsets, 7, 4).is_err());
}

/// The tenure convention is the ANALYSED model's (B1-R v1, M7 (vi) and §2): a genesis occupant
/// of a seat with offset o is forced at handover T − o ∈ [1, T], and a seat refilled at a forced
/// rotation at handover d is forced again at d + T (an occupant serves at most T configurations).
#[test]
fn the_tenure_convention_is_the_analysed_models_t_minus_offset_then_every_t() {
    for (t, c) in [(4u32, 2u32), (7, 1), (3, 3), (1, 7)] {
        let p = n7_params(t, c);
        let mut sim = Sim::new(&p, beacon(77 + u64::from(t)));
        let offsets = sim.offsets.clone();
        let horizon = 3 * u64::from(t) + 1;
        let mut forced_at: Vec<Vec<u64>> = vec![Vec::new(); 7];
        for h in 1..=horizon {
            let seats = sim.config.seats().unwrap();
            let candidates = sim.fresh(3 * c, 0);
            let (s, _) = sim.handover(&BTreeSet::new(), candidates, beacon(5_000 + h));
            for member in &s.forced_rotations {
                let seat = seats.iter().position(|x| *x == Some(*member)).unwrap();
                forced_at[seat].push(h);
            }
        }
        for seat in 0..7 {
            let first = u64::from(t - offsets[seat]);
            let expected: Vec<u64> = (0u64..)
                .map(|k| first + k * u64::from(t))
                .take_while(|h| *h <= horizon)
                .collect();
            assert_eq!(
                forced_at[seat], expected,
                "seat {seat}, offset {}, T={t}",
                offsets[seat]
            );
        }
    }
}

// --- Departures and the fill order (SCQ-8.10d FINAL (A); no deferral) ---------------------------

#[test]
fn every_occupant_whose_counter_reaches_t_is_forced_and_the_cap_never_cuts_the_list() {
    // T = 4. Tenure 3 reaches T at this handover.
    let members: Vec<AccountId> = (1..=5).map(account_n).collect();
    let tenure: BTreeMap<AccountId, u32> = [
        (account_n(1), 3),
        (account_n(2), 3),
        (account_n(3), 1),
        (account_n(4), 0),
        (account_n(5), 3),
    ]
    .into_iter()
    .collect();
    let exits: BTreeSet<AccountId> = [account_n(1), account_n(4)].into_iter().collect();
    let plan = plan_handover_vacancies(&members, &tenure, &exits, 4);
    // Three forced (more than any cap here): none is cut, none deferred. A declared exit at
    // expiry is a forced rotation, not a pre-expiry exit.
    assert_eq!(
        plan.forced_rotations,
        vec![account_n(1), account_n(2), account_n(5)]
    );
    assert_eq!(plan.exits, vec![account_n(4)]);
    // Oldest first, then seat order.
    let mut overdue = tenure.clone();
    overdue.insert(account_n(5), 9);
    assert_eq!(
        plan_handover_vacancies(&members, &overdue, &BTreeSet::new(), 4).forced_rotations,
        vec![account_n(5), account_n(1), account_n(2)]
    );
}

#[test]
fn seats_fill_forced_first_then_the_oldest_vacancy_then_exits_and_an_unfilled_exit_stays_vacant() {
    // Seats: 0 m1 (forced), 1 m2, 2 vacant since version 3, 3 m4, 4 m5 (exit), 5 m6 (exit).
    let members = [
        account_n(1),
        account_n(2),
        account_n(4),
        account_n(5),
        account_n(6),
    ];
    let offsets = [3, 0, 0, 1, 2, 0];
    let mut p = params();
    p.churn_cap = 3;
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(
        &members,
        &[vacancy(2, 3)],
        &offsets,
        0,
        &[account_n(5), account_n(6)],
        candidates,
        &p,
    );
    assert_eq!(s.forced_rotations, vec![account_n(1)]);
    let draw = draw_vacated_seats(&s, &beacon(1)).unwrap();
    assert_eq!(draw.joiners.len(), 3, "the cap is c = 3");
    assert_eq!(
        draw.departed,
        vec![account_n(1), account_n(5), account_n(6)]
    );
    // The last exit in the fill order (seat 5) is left vacant, since this handover.
    assert_eq!(draw.successor_vacancies, vec![vacancy(5, 5)]);
    let seats = config_of(6, &draw).seats().unwrap();
    assert_eq!(seats.len(), 6, "a vacancy never reduces n");
    assert_eq!(seats[1], Some(account_n(2)));
    assert_eq!(seats[3], Some(account_n(4)));
    assert_eq!(seats[5], None);
    // Seats 0 (forced), 2 (the old vacancy) and 4 (the first exit) took the joiners, in order.
    assert_eq!(
        [seats[0].unwrap(), seats[2].unwrap(), seats[4].unwrap()].to_vec(),
        draw.joiners
    );
    assert!(draw.alarms.is_empty(), "{:?}", draw.alarms);
    assert!(!draw.outside_selection_model);
}

/// NO DEFERRAL (SCQ-8.10d FINAL; SCQ-8.10f (b)): a forced rotation the pool cannot refill still
/// happens. The occupant leaves, its seat goes VACANT, and the alarm names the cause. (Fill set,
/// c = 3: seat 0 forced, seat 2 the old vacancy, seat 4 the exit.) The empty pool is an
/// `assign_seats` error, so EVERY fill seat, the old vacancy at seat 2 included, becomes a FRESH
/// vacancy (b1r_inherit_check.py:86 `b2[s] = (VAC, (0 if ph >= T else ph, 0))`; Q3 as ordered
/// 2026-10-08 15:19): since_version 5, and no aged alarm (this pin asserted the pre-ruling age,
/// since 3 with an aged alarm, until the Q3 fix).
#[test]
fn a_forced_rotation_the_pool_cannot_refill_leaves_its_seat_vacant_never_deferred() {
    let members = [
        account_n(1),
        account_n(2),
        account_n(4),
        account_n(5),
        account_n(6),
    ];
    let offsets = [3, 0, 0, 1, 2, 0];
    let mut p = params();
    p.churn_cap = 3;
    let s = live_snapshot(
        &members,
        &[vacancy(2, 3)],
        &offsets,
        0,
        &[account_n(5)],
        vec![],
        &p,
    );
    let draw = draw_vacated_seats(&s, &beacon(2)).unwrap();
    assert_eq!(draw.departed, vec![account_n(1), account_n(5)]);
    assert!(!draw.successor_members.contains(&account_n(1)));
    assert_eq!(
        draw.alarms,
        vec![
            RingSelectionAlarm::ForcedRotationVacated {
                member: account_n(1),
                seat: 0,
                tenure: 3,
                cause: RingUnfilledCause::CandidatePoolExhausted,
            },
        ]
    );
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(2, 5), vacancy(4, 5)]
    );
    // PIN (NET's verified model, B1-R v1 M7 (i)): a pool SMALLER than the fill set (one registrant
    // for three seats) is an `assign_seats` error too: the whole fill set stays vacant, with no
    // partial fill.
    let mut short = s.clone();
    short.candidates = vec![registration(10, 0)];
    let draw = draw_vacated_seats(&short, &beacon(2)).unwrap();
    assert!(
        draw.joiners.is_empty(),
        "no partial fill: {:?}",
        draw.joiners
    );
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(2, 5), vacancy(4, 5)]
    );
    // Exactly enough registrants: the whole fill set is drawn.
    let mut enough = s.clone();
    enough.candidates = (10..13).map(|n| registration(n, 0)).collect();
    let draw = draw_vacated_seats(&enough, &beacon(2)).unwrap();
    assert_eq!(draw.joiners.len(), 3);
    assert!(draw.successor_vacancies.is_empty());
    assert!(draw.alarms.is_empty());
}

/// The churn cap's premise made visible (SCQ-8.10b (3)): when more forced rotations are due than
/// c (impossible from a balanced genesis, Lemma FR; here four seats share a phase), every one of
/// them still rotates; c seats are refilled and the rest go VACANT with the cap alarm.
#[test]
fn forced_rotations_beyond_the_cap_all_happen_and_the_cap_alarm_fires() {
    let members: Vec<AccountId> = (1..=4).map(account_n).collect();
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(&members, &[], &[3, 3, 3, 3], 0, &[], candidates, &params());
    assert_eq!(s.forced_rotations.len(), 4);
    let draw = draw_vacated_seats(&s, &beacon(3)).unwrap();
    assert_eq!(draw.departed, members);
    assert_eq!(draw.joiners.len(), 2);
    assert_eq!(draw.successor_vacancies, vec![vacancy(2, 5), vacancy(3, 5)]);
    assert_eq!(
        draw.alarms,
        vec![
            RingSelectionAlarm::ForcedRotationVacated {
                member: account_n(3),
                seat: 2,
                tenure: 3,
                cause: RingUnfilledCause::ChurnCapSpent,
            },
            RingSelectionAlarm::ForcedRotationVacated {
                member: account_n(4),
                seat: 3,
                tenure: 3,
                cause: RingUnfilledCause::ChurnCapSpent,
            },
        ]
    );
}

/// RED CONTROL (no deferral): a snapshot that DEFERS a forced rotation (omits an occupant whose
/// counter reaches T from its forced rotations), forces an occupant early, or misrecords its
/// vacated set, is REFUSED.
#[test]
fn a_snapshot_deferring_a_forced_rotation_is_refused() {
    let members = [account_n(1), account_n(2), account_n(3)];
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let good = live_snapshot(
        &members,
        &[],
        &[3, 0, 3],
        0,
        &[account_n(2)],
        candidates,
        &params(),
    );
    assert_eq!(good.forced_rotations, vec![account_n(1), account_n(3)]);
    draw_vacated_seats(&good, &beacon(4)).unwrap();
    let mut deferred = good.clone();
    deferred.forced_rotations = vec![account_n(1)];
    deferred.vacated_set = vec![account_n(2), account_n(1)];
    assert!(draw_vacated_seats(&deferred, &beacon(4))
        .unwrap_err()
        .contains("no deferral"));
    let mut early = good.clone();
    early.forced_rotations.push(account_n(2));
    assert!(draw_vacated_seats(&early, &beacon(4))
        .unwrap_err()
        .contains("no deferral"));
    let mut misrecorded = good.clone();
    misrecorded.vacated_set.reverse();
    assert!(draw_vacated_seats(&misrecorded, &beacon(4)).is_err());
}

#[test]
fn the_oldest_vacancy_is_refilled_first() {
    // Seats 0..=5; seat 1 vacant since version 3, seat 4 vacant since version 2. c = 1.
    let members = [account_n(1), account_n(3), account_n(4), account_n(6)];
    let mut p = params();
    p.churn_cap = 1;
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(
        &members,
        &[vacancy(1, 3), vacancy(4, 2)],
        &[0, 1, 2, 0, 1, 2],
        0,
        &[],
        candidates,
        &p,
    );
    let draw = draw_vacated_seats(&s, &beacon(5)).unwrap();
    let seats = config_of(6, &draw).seats().unwrap();
    assert_eq!(
        seats[4],
        Some(draw.joiners[0]),
        "the older vacancy (seat 4) is refilled"
    );
    assert_eq!(seats[1], None);
    assert_eq!(
        draw.alarms,
        vec![RingSelectionAlarm::VacancyAged {
            seat: 1,
            since_version: 3,
        }]
    );
}

// --- The per-seat draw (TX's dependence condition) ---------------------------------------------

#[test]
fn the_per_seat_value_is_derived_from_the_beacon_and_the_seat_index() {
    // Mirror of the derivation: SHA-256("aft::ring::seat-draw::v1" ‖ beacon ‖ seat ‖ attempt),
    // first 8 bytes big-endian, uniform over the pool in canonical account order.
    fn mirror(beacon: &[u8; 32], seat: u32, len: u64) -> usize {
        let limit = (u64::MAX / len) * len;
        for attempt in 0u64..64 {
            let mut material = b"aft::ring::seat-draw::v1".to_vec();
            material.extend_from_slice(beacon);
            material.extend_from_slice(&u64::from(seat).to_be_bytes());
            material.extend_from_slice(&attempt.to_be_bytes());
            use dcrypt::algorithms::hash::{HashFunction, Sha256};
            let digest = Sha256::digest(&material).unwrap();
            let word = u64::from_be_bytes(digest.as_ref()[..8].try_into().unwrap());
            if word < limit {
                return (word % len) as usize;
            }
        }
        unreachable!()
    }
    // Seats 0 (m1) and 2 (m3) rotate; the pool is ten registrants, given in reverse order.
    let members = [account_n(1), account_n(2), account_n(3)];
    let candidates: Vec<_> = (10..20).rev().map(|n| registration(n, 0)).collect();
    let s = live_snapshot(&members, &[], &[3, 0, 3], 0, &[], candidates, &params());
    for i in 0..16u64 {
        let b = beacon(i);
        let draw = draw_vacated_seats(&s, &b).unwrap();
        let mut pool: Vec<AccountId> = (10..20).map(account_n).collect();
        let first = pool.remove(mirror(&b, 0, 10));
        let second = pool.remove(mirror(&b, 2, 9));
        assert_eq!(draw.joiners, vec![first, second], "beacon {i}");
    }
}

/// THE DEDICATED CORRELATION TEST (SCQ-8.10 TX, design condition 1): no single random value may
/// decide the type of several vacated seats. Two seats are filled from a pool of ten whose first
/// five (in canonical order) are adversarial. Without replacement and per-seat values, the
/// covariance of the two seats' adversarial indicators is −p(1−p)/(N−1) = −1/36; a draw that
/// derives both seats from one value (a contiguous block, one coin) is positively correlated.
#[test]
fn two_vacated_seats_are_negatively_associated_never_decided_by_one_value() {
    let members = [account_n(1), account_n(2), account_n(3)];
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let adversarial: BTreeSet<AccountId> = (10..15).map(account_n).collect();
    let s = live_snapshot(&members, &[], &[3, 3, 0], 0, &[], candidates, &params());
    let runs = 4_000u64;
    let (mut a, mut b, mut both) = (0u64, 0u64, 0u64);
    for i in 0..runs {
        let draw = draw_vacated_seats(&s, &beacon(1_000 + i)).unwrap();
        assert_eq!(draw.joiners.len(), 2);
        let x = adversarial.contains(&draw.joiners[0]) as u64;
        let y = adversarial.contains(&draw.joiners[1]) as u64;
        a += x;
        b += y;
        both += x * y;
    }
    let n = runs as f64;
    let (pa, pb) = (a as f64 / n, b as f64 / n);
    let covariance = both as f64 / n - pa * pb;
    assert!(
        (pa - 0.5).abs() < 0.05 && (pb - 0.5).abs() < 0.05,
        "{pa} {pb}"
    );
    assert!(
        covariance < 0.0,
        "the two seats' types are not negatively associated: covariance {covariance}"
    );
}

// --- Floors first, and an exhausted floor pool (SCQ-8.10f (b)) ----------------------------------

#[test]
fn floors_are_filled_first_from_their_own_pools() {
    let mut p = params();
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let members = [account_n(1), account_n(2), account_n(3)];
    let mut candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    candidates.push(registration(99, 9));
    let mut s = live_snapshot(&members, &[], &[3, 0, 0], 0, &[], candidates, &p);
    // The rotating member held the floored seat.
    s.member_constituencies = vec![(account_n(1), 9), (account_n(2), 0), (account_n(3), 0)];
    for i in 0..8 {
        let draw = draw_vacated_seats(&s, &beacon(i)).unwrap();
        assert_eq!(draw.joiners, vec![account_n(99)], "beacon {i}");
        assert!(!draw.outside_selection_model);
        assert!(draw.alarms.is_empty());
    }
}

/// SCQ-8.10f (b): 8.10 item 2's floor_pool_empty DEFERRAL is WITHDRAWN. A floored member's forced
/// rotation whose floor pool is empty still happens: the member leaves and its seat goes VACANT
/// (no outsider takes it), with the alarm; the unmet floor puts the ring outside the selection
/// model. When the floor's pool has a registrant again, the vacancy is refilled from it.
#[test]
fn an_empty_floor_pool_leaves_the_floored_seat_vacant_never_deferred() {
    let mut p = params();
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let members = [account_n(1), account_n(2), account_n(3)];
    let offsets = [3, 0, 1];
    let candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    let mut s = live_snapshot(&members, &[], &offsets, 0, &[], candidates, &p);
    s.member_constituencies = vec![(account_n(1), 9), (account_n(2), 0), (account_n(3), 0)];
    let draw = draw_vacated_seats(&s, &beacon(4)).unwrap();
    assert_eq!(draw.departed, vec![account_n(1)], "never deferred");
    assert!(
        draw.joiners.is_empty(),
        "no outsider takes the floored seat"
    );
    assert_eq!(draw.successor_members, vec![account_n(2), account_n(3)]);
    assert_eq!(draw.successor_vacancies, vec![vacancy(0, 5)]);
    assert_eq!(
        draw.alarms,
        vec![RingSelectionAlarm::ForcedRotationVacated {
            member: account_n(1),
            seat: 0,
            tenure: 3,
            cause: RingUnfilledCause::FloorPoolExhausted,
        }]
    );
    assert!(draw.outside_selection_model);

    // The next handover (h = 1, version 6): a floor-9 registrant exists; the vacancy is refilled
    // from the floor pool, at the seat's phase, and the floor is met again.
    let mut candidates: Vec<_> = (40..50).map(|n| registration(n, 0)).collect();
    candidates.push(registration(98, 9));
    let mut next = live_snapshot(
        &draw.successor_members,
        &draw.successor_vacancies,
        &offsets,
        1,
        &[],
        candidates,
        &p,
    );
    next.live_version = 6;
    next.member_constituencies = vec![(account_n(2), 0), (account_n(3), 0)];
    let refill = draw_vacated_seats(&next, &beacon(5)).unwrap();
    assert_eq!(refill.joiners, vec![account_n(98)]);
    assert_eq!(refill.successor_members[0], account_n(98));
    assert!(refill.successor_vacancies.is_empty());
    assert!(!refill.outside_selection_model);
    assert_eq!(
        refill.joiner_tenure,
        vec![(account_n(98), seat_phase(3, 2, 4))]
    );
}

/// PIN (Director, 10-05: MATCH NET'S VERIFIED MODEL, B1-R v1 M7 (i)): an exhausted floor pool is
/// an `assign_seats` error, and on it the WHOLE fill set stays VACANT, not only the floored
/// constituency's seats, although the whole pool could fill the rest. Fill set (c = 4): seat 0
/// (m1, floored, forced), seat 1 (m2, forced), seat 2 (an old vacancy), seat 3 (m3's exit). Every
/// fill seat becomes a FRESH vacancy, the old one at seat 2 included (b1r_inherit_check.py:86; Q3
/// as ordered 2026-10-08 15:19): since_version 5 and no aged alarm (this pin asserted the
/// pre-ruling since 3 with an aged alarm until the Q3 fix).
#[test]
fn an_exhausted_floor_pool_leaves_the_whole_fill_set_vacant() {
    let mut p = params();
    p.churn_cap = 4;
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let members = [
        account_n(1),
        account_n(2),
        account_n(3),
        account_n(4),
        account_n(5),
    ];
    let candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    let mut s = live_snapshot(
        &members,
        &[vacancy(2, 3)],
        &[3, 3, 0, 1, 0, 2],
        0,
        &[account_n(3)],
        candidates,
        &p,
    );
    s.member_constituencies = vec![
        (account_n(1), 9),
        (account_n(2), 0),
        (account_n(3), 0),
        (account_n(4), 0),
        (account_n(5), 0),
    ];
    assert_eq!(s.forced_rotations, vec![account_n(1), account_n(2)]);
    let draw = draw_vacated_seats(&s, &beacon(6)).unwrap();
    assert!(
        draw.joiners.is_empty(),
        "no partial fill: {:?}",
        draw.joiners
    );
    assert_eq!(
        draw.departed,
        vec![account_n(1), account_n(2), account_n(3)]
    );
    assert_eq!(draw.successor_members, vec![account_n(4), account_n(5)]);
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(1, 5), vacancy(2, 5), vacancy(3, 5)]
    );
    assert_eq!(
        draw.alarms,
        vec![
            RingSelectionAlarm::ForcedRotationVacated {
                member: account_n(1),
                seat: 0,
                tenure: 3,
                cause: RingUnfilledCause::FloorPoolExhausted,
            },
            RingSelectionAlarm::ForcedRotationVacated {
                member: account_n(2),
                seat: 1,
                tenure: 3,
                cause: RingUnfilledCause::FloorPoolExhausted,
            },
        ]
    );
    assert!(draw.outside_selection_model);
    // The same ring with one floor-9 registrant: no error, the whole fill set is drawn, the floor
    // seat first (seat 0 takes the floor registrant).
    let mut stocked = s.clone();
    stocked.candidates.push(registration(99, 9));
    let draw = draw_vacated_seats(&stocked, &beacon(6)).unwrap();
    assert_eq!(draw.joiners.len(), 4);
    assert_eq!(draw.joiners[0], account_n(99));
    assert!(draw.successor_vacancies.is_empty());
    assert!(!draw.outside_selection_model);
}

/// PIN (NET's ruling, 10-05: the trigger): the per-group `assign_seats` error fires when a floor's
/// UNSEATED eligible pool is SMALLER than its fill count this handover (A_i + H_i < k_i), not only
/// when it is EMPTY, and the pool counts UNSEATED identities only (M7 (iii)). A floor missing two
/// seats (both floored members rotate) with ONE floor registrant leaves the WHOLE fill set vacant
/// (c = 3: seats 0 and 1 forced, seat 2's exit), although the floor pool is not empty and the whole
/// pool could fill every seat.
#[test]
fn a_floor_pool_smaller_than_its_fill_count_leaves_the_whole_fill_set_vacant() {
    let mut p = params();
    p.churn_cap = 3;
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 2,
    }];
    let members = [account_n(1), account_n(2), account_n(3), account_n(4)];
    let mut candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    candidates.push(registration(98, 9));
    let mut s = live_snapshot(
        &members,
        &[],
        &[3, 3, 0, 1],
        0,
        &[account_n(3)],
        candidates,
        &p,
    );
    s.member_constituencies = vec![
        (account_n(1), 9),
        (account_n(2), 9),
        (account_n(3), 0),
        (account_n(4), 0),
    ];
    let draw = draw_vacated_seats(&s, &beacon(7)).unwrap();
    assert!(
        draw.joiners.is_empty(),
        "no partial fill: {:?}",
        draw.joiners
    );
    assert_eq!(
        draw.departed,
        vec![account_n(1), account_n(2), account_n(3)]
    );
    assert_eq!(draw.successor_members, vec![account_n(4)]);
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(1, 5), vacancy(2, 5)]
    );
    assert!(draw.alarms.iter().all(|alarm| matches!(
        alarm,
        RingSelectionAlarm::ForcedRotationVacated {
            cause: RingUnfilledCause::FloorPoolExhausted,
            ..
        }
    )));
    assert_eq!(draw.alarms.len(), 2);
    assert!(draw.outside_selection_model);
    // The pool counts UNSEATED identities only (B1-R v1, M7 (iii)): a SEATED floor identity listed
    // among the candidates (here member 1, which is rotating out) is not in the pool, so the floor
    // pool is still 1 < 2 and the whole fill set stays vacant; no seated identity is redrawn.
    let mut listed = s.clone();
    listed.candidates.push(registration(1, 9));
    let draw = draw_vacated_seats(&listed, &beacon(7)).unwrap();
    assert!(
        draw.joiners.is_empty(),
        "no partial fill: {:?}",
        draw.joiners
    );
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(1, 5), vacancy(2, 5)]
    );
    // Two floor registrants: no error; the floor's two seats come first, from its pool.
    let mut stocked = s.clone();
    stocked.candidates.push(registration(99, 9));
    let draw = draw_vacated_seats(&stocked, &beacon(7)).unwrap();
    assert_eq!(draw.joiners.len(), 3);
    let mut floor_joiners = draw.joiners[..2].to_vec();
    floor_joiners.sort();
    assert_eq!(floor_joiners, vec![account_n(98), account_n(99)]);
    assert!(draw.successor_vacancies.is_empty());
    assert!(!draw.outside_selection_model);
}

/// The instance floors are CUT to the fill set (B1-R v1, M7 (i)): a floor missing two seats, with
/// a fill set of one (c = 1) and one floor registrant, is no `assign_seats` error; the one seat
/// takes the floor registrant, and the still-unmet floor flags the ring outside the selection
/// model.
#[test]
fn an_instance_floor_is_cut_to_the_fill_set() {
    let mut p = params();
    p.churn_cap = 1;
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 2,
    }];
    let members = [account_n(1), account_n(2), account_n(3)];
    let mut candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    candidates.push(registration(98, 9));
    let mut s = live_snapshot(&members, &[], &[3, 0, 1], 0, &[], candidates, &p);
    s.member_constituencies = vec![(account_n(1), 9), (account_n(2), 0), (account_n(3), 0)];
    for i in 0..4 {
        let draw = draw_vacated_seats(&s, &beacon(40 + i)).unwrap();
        assert_eq!(draw.joiners, vec![account_n(98)], "beacon {i}");
        assert!(draw.successor_vacancies.is_empty());
        assert!(draw.alarms.is_empty());
        assert!(
            draw.outside_selection_model,
            "the floor still misses one seat"
        );
    }
}

// --- The genesis ring and its balanced offsets -------------------------------------------------

#[test]
fn the_genesis_ring_is_a_per_seat_draw_from_the_activatable_pool() {
    let mut p = params();
    let pool: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = genesis_snapshot(4, 3, pool.clone(), &p).unwrap();
    let draw = draw_genesis_ring(&s, &beacon(7)).unwrap();
    assert_eq!(draw.successor_members.len(), 3);
    assert!(draw.successor_vacancies.is_empty() && draw.alarms.is_empty());
    let distinct: BTreeSet<AccountId> = draw.successor_members.iter().copied().collect();
    assert_eq!(distinct.len(), 3);
    assert!(draw
        .successor_members
        .iter()
        .all(|m| pool.iter().any(|c| c.account_id == *m)));
    assert_eq!(draw_genesis_ring(&s, &beacon(7)).unwrap(), draw);
    // The genesis members start at the balanced offsets.
    let offsets: BTreeMap<AccountId, u32> =
        genesis_tenure_offsets(&beacon(7), &draw.successor_members, p.tenure_handovers)
            .into_iter()
            .collect();
    let start: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
    assert_eq!(start, offsets);
    // Too few registrants: the ring cannot start.
    let short = genesis_snapshot(4, 3, pool[..2].to_vec(), &p).unwrap();
    assert!(draw_genesis_ring(&short, &beacon(7))
        .unwrap_err()
        .contains("too few"));
    // Only a genesis snapshot is a genesis draw.
    let members = [account_n(1), account_n(2), account_n(3)];
    let live = live_snapshot(&members, &[], &[0, 1, 2], 0, &[], pool.clone(), &p);
    assert!(draw_genesis_ring(&live, &beacon(7)).is_err());
    // Floors hold at genesis, or the ring cannot start.
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let mut floored_pool = pool.clone();
    floored_pool.push(registration(99, 9));
    let floored = genesis_snapshot(4, 3, floored_pool, &p).unwrap();
    for i in 0..8 {
        let draw = draw_genesis_ring(&floored, &beacon(i)).unwrap();
        assert!(
            draw.successor_members.contains(&account_n(99)),
            "beacon {i}"
        );
    }
    let unmet = genesis_snapshot(4, 3, pool, &p).unwrap();
    assert!(draw_genesis_ring(&unmet, &beacon(7)).is_err());
}

#[test]
fn balanced_genesis_offsets_put_at_most_ceil_n_over_t_seats_in_a_phase() {
    for (n, t) in [
        (7u32, 4u32),
        (7, 8),
        (4, 4),
        (10, 3),
        (3, 2),
        (5, 16),
        (9, 1),
    ] {
        let members: Vec<AccountId> = (0..n).map(|i| account_n(100 + i)).collect();
        let mut expected: Vec<u32> = (0..n).map(|k| k * t / n).collect();
        expected.sort();
        let mut assignments = BTreeSet::new();
        for i in 0..24 {
            let offsets = genesis_tenure_offsets(&beacon(i), &members, t);
            assert_eq!(offsets, genesis_tenure_offsets(&beacon(i), &members, t));
            assert_eq!(offsets.iter().map(|(m, _)| *m).collect::<Vec<_>>(), members);
            let mut values: Vec<u32> = offsets.iter().map(|(_, o)| *o).collect();
            assignments.insert(values.clone());
            values.sort();
            assert_eq!(values, expected, "n={n} T={t}");
            let ceiling = n.div_ceil(t) as usize;
            for phase in 0..t {
                assert!(values.iter().filter(|o| **o == phase).count() <= ceiling);
            }
        }
        if n > 1 && t > 1 {
            assert!(assignments.len() > 1, "the permutation follows the beacon");
        }
    }
}

// --- A ring simulator (the registry's settlement, mirrored) -------------------------------------

/// A seeded xorshift generator (no external randomness in the tests).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn beacon(&mut self, label: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&self.next().to_be_bytes());
        b[8..16].copy_from_slice(&label.to_be_bytes());
        b
    }
}

fn n7_params(t: u32, c: u32) -> RingSelectionParams {
    let mut p = params();
    p.ring_seats = 7;
    p.tenure_handovers = t;
    p.churn_cap = c;
    p.bond_lock_events = u64::from(t) * 10 + 5;
    p.validate(None).unwrap();
    p
}

/// A ring from a selector-drawn genesis with balanced offsets, handed over as the registry hands
/// it over: the snapshot planned from the ledger, the draw, then the ledger settled (kept members
/// + 1, joiners at the draw's tenure). After EVERY handover it checks that n never shrinks and
/// that every seated member holds its seat's phase (inherited phase, never a fresh phase).
struct Sim {
    p: RingSelectionParams,
    config: BoundaryRingConfig,
    tenure: BTreeMap<AccountId, u32>,
    offsets: Vec<u32>,
    handover_index: u64,
    next_id: u32,
}

impl Sim {
    fn new(p: &RingSelectionParams, genesis_beacon: [u8; 32]) -> Self {
        let mut sim = Sim {
            p: p.clone(),
            config: BoundaryRingConfig::default(),
            tenure: BTreeMap::new(),
            offsets: Vec::new(),
            handover_index: 0,
            next_id: 1_000_000,
        };
        let pool = sim.fresh(3 * p.ring_seats, 0);
        let genesis = genesis_snapshot(1, p.ring_seats, pool, p).unwrap();
        let draw = draw_genesis_ring(&genesis, &genesis_beacon).unwrap();
        sim.config = config_of(1, &draw);
        let offsets =
            genesis_tenure_offsets(&genesis_beacon, &sim.config.members, p.tenure_handovers);
        sim.offsets = offsets.iter().map(|(_, offset)| *offset).collect();
        sim.tenure = offsets.into_iter().collect();
        assert_eq!(
            draw.joiner_tenure
                .iter()
                .copied()
                .collect::<BTreeMap<_, _>>(),
            sim.tenure
        );
        sim
    }

    fn fresh(&mut self, count: u32, constituency: u32) -> Vec<RingMemberRegistration> {
        let out = (self.next_id..self.next_id + count)
            .map(|n| registration(n, constituency))
            .collect();
        self.next_id += count;
        out
    }

    /// The occupied seats whose counter reaches T at the next handover, from the offsets alone
    /// (a mirror of the rule, independent of the ledger).
    fn forced_seats_next(&self) -> BTreeSet<u32> {
        let t = self.p.tenure_handovers;
        self.config
            .seats()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(seat, occupant)| {
                occupant.is_some()
                    && seat_phase(self.offsets[*seat], self.handover_index + 1, t) == 0
            })
            .map(|(seat, _)| seat as u32)
            .collect()
    }

    /// The seated members whose counter does not reach T at the next handover, in seat order,
    /// each with its seat's phase after the next handover (larger: forced sooner after it).
    fn unforced_next(&self) -> Vec<(AccountId, u32)> {
        let t = self.p.tenure_handovers;
        let forced = self.forced_seats_next();
        self.config
            .seats()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(seat, occupant)| {
                occupant
                    .filter(|_| !forced.contains(&(seat as u32)))
                    .map(|m| {
                        (
                            m,
                            seat_phase(self.offsets[seat], self.handover_index + 1, t),
                        )
                    })
            })
            .collect()
    }

    fn handover(
        &mut self,
        exits: &BTreeSet<AccountId>,
        candidates: Vec<RingMemberRegistration>,
        beacon: [u8; 32],
    ) -> (RingHandoverSnapshot, RingSeatDraw) {
        let plan = plan_handover_vacancies(
            &self.config.members,
            &self.tenure,
            exits,
            self.p.tenure_handovers,
        );
        let s = RingHandoverSnapshot {
            live_version: self.config.version,
            snapshot_event: 0,
            seat_count: self.config.seat_count() as u32,
            members: self.config.members.clone(),
            vacancies: self.config.vacant_seats.clone(),
            handover_index: self.handover_index,
            seat_offsets: self.offsets.clone(),
            tenure_counters: self.tenure.iter().map(|(a, t)| (*a, *t)).collect(),
            member_constituencies: vec![],
            vacated_set: plan
                .exits
                .iter()
                .chain(plan.forced_rotations.iter())
                .copied()
                .collect(),
            exits: plan.exits,
            forced_rotations: plan.forced_rotations,
            churn_cap: self.p.churn_cap,
            tenure_handovers: self.p.tenure_handovers,
            candidates,
            floors: self.p.floors.clone(),
            floors_ref: self.p.floors_ref().unwrap(),
        };
        let draw = draw_vacated_seats(&s, &beacon).unwrap();
        let joined: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
        let tenure: BTreeMap<AccountId, u32> = draw
            .successor_members
            .iter()
            .map(|m| {
                let held = match joined.get(m) {
                    Some(start) => *start,
                    None => self.tenure[m] + 1,
                };
                (*m, held)
            })
            .collect();
        self.tenure = tenure;
        self.config = config_of(self.config.version + 1, &draw);
        self.handover_index += 1;
        assert_eq!(
            self.config.seat_count(),
            self.p.ring_seats as usize,
            "a vacancy never reduces n"
        );
        verify_seat_phases(
            &self.config.members,
            &self.config.vacant_seats,
            &self.tenure,
            &self.offsets,
            self.handover_index,
            self.p.tenure_handovers,
        )
        .expect("inherited phase holds after every handover");
        (s, draw)
    }
}

fn pick_random(rng: &mut XorShift, mut from: Vec<AccountId>, count: usize) -> BTreeSet<AccountId> {
    let mut out = BTreeSet::new();
    while out.len() < count && !from.is_empty() {
        let at = (rng.next() % from.len() as u64) as usize;
        out.insert(from.swap_remove(at));
    }
    out
}

/// The full-n threshold never drops (n = 7 → 5 of 7), and the seated members reach it exactly
/// when at least 5 seats are filled: with more vacancies the ring HALTS, never unsafely.
fn assert_full_n_halt(config: &BoundaryRingConfig) -> bool {
    let threshold = config.full_n_threshold(2, 3);
    assert_eq!(threshold, 5, "thresholds are over the full n");
    let seated: BTreeSet<AccountId> = config.members.iter().copied().collect();
    let reached = config.reaches_threshold(&seated, threshold);
    assert_eq!(reached, config.members.len() >= 5);
    !reached
}

// --- PROPERTY TESTS at the deployed n = 7 (rulings 10-05 16:58, 17:56) --------------------------

/// LEMMA FR, over long seeded random runs at n = 7: phases never move, so the forced rotations
/// per handover never exceed ⌈n/T⌉; the forced occupants are exactly the occupied seats whose
/// phase reaches T (a mirror from the offsets alone); every forced occupant leaves (never
/// deferred, even when the pool is starved); the churn cap is never spent by forced rotations;
/// and every seated member holds its seat's phase after every handover (in `Sim`). Exit hazards
/// from calm to heavy, and pools from starved (0) to ample (3c), per handover.
#[test]
fn lemma_fr_at_n_7_forced_rotations_per_handover_never_exceed_ceil_n_over_t() {
    let mut total_forced = 0usize;
    let mut vacated_forced = 0usize;
    let mut handovers = 0usize;
    for (t, c) in [(4u32, 2u32), (4, 3), (3, 3), (5, 2), (7, 1), (7, 2), (2, 4)] {
        let p = n7_params(t, c);
        let bound = 7u32.div_ceil(t) as usize;
        for seed in 1..=4u64 {
            let mut rng = XorShift(0x5EED_0000 + seed * 7_919 + u64::from(t * 31 + c));
            let mut sim = Sim::new(&p, rng.beacon(u64::from(t * 100 + c)));
            let hazard = [0.02, 0.15, 0.35, 0.6][(seed - 1) as usize];
            for h in 0..1_000u64 {
                let forced_next = sim.forced_seats_next();
                let seats_before = sim.config.seats().unwrap();
                let exits: BTreeSet<AccountId> = sim
                    .config
                    .members
                    .clone()
                    .into_iter()
                    .filter(|_| rng.unit() < hazard)
                    .collect();
                let pool = (rng.next() % u64::from(3 * c + 1)) as u32;
                let candidates = sim.fresh(pool, 0);
                let (s, draw) = sim.handover(&exits, candidates, rng.beacon(h));
                assert!(
                    s.forced_rotations.len() <= bound,
                    "Lemma FR: {} forced > ⌈7/{t}⌉ = {bound} (c={c}, seed {seed}, h={h})",
                    s.forced_rotations.len()
                );
                let forced_seats: BTreeSet<u32> = s
                    .forced_rotations
                    .iter()
                    .map(|m| seats_before.iter().position(|x| *x == Some(*m)).unwrap() as u32)
                    .collect();
                assert_eq!(forced_seats, forced_next, "T={t} c={c} seed {seed} h={h}");
                for member in &s.forced_rotations {
                    assert!(draw.departed.contains(member));
                    assert!(!draw.successor_members.contains(member), "never deferred");
                }
                for alarm in &draw.alarms {
                    if let RingSelectionAlarm::ForcedRotationVacated { cause, .. } = alarm {
                        assert_ne!(*cause, RingUnfilledCause::ChurnCapSpent);
                        vacated_forced += 1;
                    }
                }
                total_forced += s.forced_rotations.len();
                handovers += 1;
            }
        }
    }
    // The runs engaged: thousands of forced rotations, and starved pools left forced seats
    // vacant (each still rotated).
    assert_eq!(handovers, 28_000);
    assert!(total_forced > 5_000, "only {total_forced} forced rotations");
    assert!(vacated_forced > 0, "no forced rotation met a starved pool");
}

/// Review r1 MAJOR-2: the genesis feasibility check agrees with the genesis draw for every beacon,
/// over feasible and infeasible pools (too few candidates; a floor its pool cannot meet; a floor met
/// exactly; a pool exactly n).
#[test]
fn the_genesis_feasibility_check_agrees_with_the_draw_for_every_beacon() {
    let reg = |b: u8, constituency: u32| RingMemberRegistration {
        account_id: AccountId([b; 32]),
        bond_amount: 100,
        constituency_id: constituency,
        registered_at_event: 0,
    };
    let mut shapes: Vec<(&str, RingSelectionParams, Vec<RingMemberRegistration>, bool)> =
        Vec::new();
    let base = n7_params(4, 2);
    shapes.push((
        "seven of seven",
        base.clone(),
        (1..=7).map(|b| reg(b, 0)).collect(),
        true,
    ));
    shapes.push((
        "ten for seven",
        base.clone(),
        (1..=10).map(|b| reg(b, 0)).collect(),
        true,
    ));
    shapes.push((
        "six for seven",
        base.clone(),
        (1..=6).map(|b| reg(b, 0)).collect(),
        false,
    ));
    shapes.push(("none", base.clone(), vec![], false));
    let mut floored = base.clone();
    floored.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 2,
    }];
    let one_of_nine: Vec<RingMemberRegistration> =
        (1..=9).map(|b| reg(b, 0)).chain([reg(20, 9)]).collect();
    let two_of_nine: Vec<RingMemberRegistration> = (1..=9)
        .map(|b| reg(b, 0))
        .chain([reg(20, 9), reg(21, 9)])
        .collect();
    let floor_only: Vec<RingMemberRegistration> = (1..=5)
        .map(|b| reg(b, 0))
        .chain([reg(20, 9), reg(21, 9)])
        .collect();
    shapes.push((
        "a floor its pool cannot meet",
        floored.clone(),
        one_of_nine,
        false,
    ));
    shapes.push(("a floor met exactly", floored.clone(), two_of_nine, true));
    shapes.push(("a floor met, pool exactly n", floored, floor_only, true));
    for (name, params, candidates, feasible) in shapes {
        let snapshot = genesis_snapshot(1, params.ring_seats, candidates, &params).unwrap();
        assert_eq!(
            check_genesis_draw_feasible(&snapshot).is_ok(),
            feasible,
            "{name}"
        );
        for b in 0..64u64 {
            assert_eq!(
                draw_genesis_ring(&snapshot, &beacon(5_000 + b)).is_ok(),
                feasible,
                "{name}: beacon {b} disagrees with the check"
            );
        }
    }
}

/// MODEL MIRROR (b1r_inherit_check.py:86 `b2[s] = (VAC, (0 if ph >= T else ph, 0))`): the assign_seats-error path.
/// Q3 (rulings 2026-10-08, as clarified 15:16+ by NET's model): on an `assign_seats` error EVERY
/// fill seat resets to a fresh vacancy (VAC, age 0: `since_version` = the version handed over), an old
/// vacancy inside the fill set included, and raises no VacancyAged alarm (its age is 0). An old
/// vacancy BEYOND the fill set keeps its age and its alarm. Fill set (c = 3): seat 0 (m1, floored,
/// forced), seat 1 (m2, forced), seat 2 (a vacancy since 3); beyond it, seat 5 (a vacancy since 4).
#[test]
fn an_assign_error_resets_every_fill_seat_to_a_fresh_vacancy() {
    let mut p = params();
    p.churn_cap = 3;
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let members = [account_n(1), account_n(2), account_n(3), account_n(4)];
    let candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    let mut s = live_snapshot(
        &members,
        &[vacancy(2, 3), vacancy(5, 4)],
        &[3, 3, 0, 1, 0, 2],
        0,
        &[],
        candidates,
        &p,
    );
    s.member_constituencies = vec![
        (account_n(1), 9),
        (account_n(2), 0),
        (account_n(3), 0),
        (account_n(4), 0),
    ];
    assert_eq!(s.forced_rotations, vec![account_n(1), account_n(2)]);
    let draw = draw_vacated_seats(&s, &beacon(7)).unwrap();
    assert!(draw.joiners.is_empty());
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(0, 5), vacancy(1, 5), vacancy(2, 5), vacancy(5, 4)],
        "the fill set's old vacancy (seat 2) resets; seat 5, beyond the fill set, keeps its age"
    );
    let aged: Vec<_> = draw
        .alarms
        .iter()
        .filter(|a| matches!(a, RingSelectionAlarm::VacancyAged { .. }))
        .collect();
    assert_eq!(
        aged,
        vec![&RingSelectionAlarm::VacancyAged {
            seat: 5,
            since_version: 4
        }]
    );
}

/// MODEL MIRROR (b1r_inherit_check.py:102 `aged.append((k, ((ph + 1) % T, min(own + 1, cap))))` and b1r_inherit_check.py:79 `return 0 if (ph >= T or s in resets) else ph`): a VACANT seat's phase keeps advancing and wraps mod T for as
/// long as it stays vacant, and a later (non-forced) refill INHERITS it: seat 2, vacant since
/// version 1, refilled at handover h + 1 for every h in 0..3T, gives its joiner (o_2 + h + 1) mod T,
/// never 0 by default and never the vacancy's age.
#[test]
fn model_mirror_a_vacant_seats_phase_keeps_advancing_and_wraps_and_a_refill_inherits_it() {
    let mut p = params();
    p.churn_cap = 4;
    let members = [account_n(1), account_n(2), account_n(3)];
    let offsets = [0, 1, 2, 3];
    for h in 0..12u64 {
        let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
        let s = live_snapshot(&members, &[vacancy(2, 1)], &offsets, h, &[], candidates, &p);
        let draw = draw_vacated_seats(&s, &beacon(100 + h)).unwrap();
        let seats = seat_layout(&draw.successor_members, &draw.successor_vacancies).unwrap();
        let joiner = seats[2].expect("the vacancy is refilled");
        let tenure: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
        assert_eq!(tenure[&joiner], ((2 + h + 1) % 4) as u32, "h={h}");
        assert_eq!(tenure[&joiner], seat_phase(2, h + 1, 4));
    }
}

/// MODEL MIRROR (b1r_inherit_check.py:104 `aged.append((k, (min(ph + 1, cap), min(own + 1, cap))))`, b1r_inherit_check.py:110 `forced = [s for s in occ if aged[s][1][0] >= T]` and b1r_inherit_check.py:79 `return 0 if (ph >= T or s in resets) else ph`): an occupant is FORCED exactly at the handover at which
/// its seat's counter reaches T, and a forced seat's refill restarts at 0.
#[test]
fn model_mirror_an_occupant_is_forced_when_its_counter_reaches_t_and_its_refill_starts_at_0() {
    let mut p = params();
    p.churn_cap = 4;
    let members = [account_n(1), account_n(2), account_n(3), account_n(4)];
    let offsets = [0u32, 1, 2, 3];
    for h in 0..12u64 {
        let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
        let s = live_snapshot(&members, &[], &offsets, h, &[], candidates, &p);
        let draw = draw_vacated_seats(&s, &beacon(200 + h)).unwrap();
        let seats = seat_layout(&draw.successor_members, &draw.successor_vacancies).unwrap();
        let tenure: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
        for (seat, o) in offsets.iter().enumerate() {
            let due = (u64::from(*o) + h + 1) % 4 == 0;
            assert_eq!(
                s.forced_rotations.contains(&members[seat]),
                due,
                "h={h} seat {seat}"
            );
            if due {
                assert_eq!(
                    tenure[&seats[seat].unwrap()],
                    0,
                    "h={h} seat {seat}: a forced refill"
                );
            } else {
                assert_eq!(seats[seat], Some(members[seat]), "h={h} seat {seat} kept");
            }
        }
    }
}

/// MODEL MIRROR (b1r_inherit_check.py:127 `ff = sorted(forced, key=lambda s: (-aged[s][1][0], s))[:c]` and b1r_inherit_check.py:129 `vf = sorted(vac, key=lambda s: (-aged[s][1][1], s))[:room]`, then the departures; c caps the fill set): forced seats first,
/// then the vacancies OLDEST first (the longest vacant; ties by seat), then the departures. Seats:
/// 0 m1 (forced), 1 vacant since 3, 2 m2 (exits), 3 m3, 4 vacant since 2, 5 vacant since 2; c = 3:
/// the fill set is seats 0, 4, 5; seat 1 keeps waiting (its age kept) and m2's seat becomes a vacancy.
#[test]
fn model_mirror_the_fill_order_is_forced_then_the_oldest_vacancies_then_the_departures() {
    let mut p = params();
    p.churn_cap = 3;
    let members = [account_n(1), account_n(2), account_n(3)];
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(
        &members,
        &[vacancy(1, 3), vacancy(4, 2), vacancy(5, 2)],
        &[3, 0, 0, 1, 0, 0],
        0,
        &[account_n(2)],
        candidates,
        &p,
    );
    assert_eq!(s.forced_rotations, vec![account_n(1)]);
    let draw = draw_vacated_seats(&s, &beacon(300)).unwrap();
    let seats = seat_layout(&draw.successor_members, &draw.successor_vacancies).unwrap();
    assert!(
        seats[0].is_some() && seats[4].is_some() && seats[5].is_some(),
        "{seats:?}"
    );
    assert_eq!(seats[3], Some(account_n(3)));
    assert_eq!(draw.successor_vacancies, vec![vacancy(1, 3), vacancy(2, 5)]);
    let tenure: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
    assert_eq!(tenure[&seats[0].unwrap()], 0, "the forced seat restarts");
    assert_eq!(
        tenure[&seats[4].unwrap()],
        seat_phase(0, 1, 4),
        "a vacancy refill inherits"
    );
}

/// MODEL MIRROR (b1r_inherit_check.py:141 `base[s] = (VAC, (base[s][1][0], 0))`): a departure the cap cannot refill becomes a VACANCY whose AGE starts at 0
/// (since_version = the version handed over, never the departed occupant's age) and whose PHASE
/// continues: refilled one handover later, its joiner holds the seat's phase then.
#[test]
fn model_mirror_an_unfilled_departure_is_a_fresh_vacancy_whose_phase_continues() {
    let mut p = params();
    p.churn_cap = 1;
    let members = [account_n(1), account_n(2), account_n(3), account_n(4)];
    let offsets = [2u32, 1, 0, 0];
    let candidates: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let s = live_snapshot(
        &members,
        &[],
        &offsets,
        0,
        &[account_n(1), account_n(2)],
        candidates,
        &p,
    );
    assert!(s.forced_rotations.is_empty());
    let draw = draw_vacated_seats(&s, &beacon(400)).unwrap();
    assert_eq!(
        draw.successor_vacancies,
        vec![vacancy(1, 5)],
        "age 0, not m2's counter"
    );
    // One handover later (c = 2): seat 0's joiner is forced, and seat 1's refill inherits its phase.
    p.churn_cap = 2;
    let candidates: Vec<_> = (30..40).map(|n| registration(n, 0)).collect();
    let s2 = live_snapshot(
        &draw.successor_members,
        &draw.successor_vacancies,
        &offsets,
        1,
        &[],
        candidates,
        &p,
    );
    let draw2 = draw_vacated_seats(&s2, &beacon(401)).unwrap();
    let seats2 = seat_layout(&draw2.successor_members, &draw2.successor_vacancies).unwrap();
    let tenure2: BTreeMap<AccountId, u32> = draw2.joiner_tenure.iter().copied().collect();
    assert_eq!(
        tenure2[&seats2[1].unwrap()],
        seat_phase(1, 2, 4),
        "the vacant seat's phase continued"
    );
    assert_eq!(tenure2[&seats2[1].unwrap()], 3);
}

/// MODEL MIRROR (b1r_inherit_check.py:86 `b2[s] = (VAC, (0 if ph >= T else ph, 0))`, then the next handover's b1r_inherit_check.py:102 `aged.append((k, ((ph + 1) % T, min(own + 1, cap))))` and b1r_inherit_check.py:129 `vf = sorted(vac, key=lambda s: (-aged[s][1][1], s))[:room]`): after an assign_seats error the
/// fill seats are fresh vacancies (age 0) whose phases CONTINUE (a forced seat's from 0, its phase
/// point having passed); the next handover refills the OLDEST vacancy first (seat 5, which kept its
/// age), and each refill inherits its seat's phase.
#[test]
fn model_mirror_after_an_assign_error_phases_continue_and_ages_order_the_refill() {
    let mut p = params();
    p.churn_cap = 3;
    p.floors = vec![ConstituencyFloor {
        constituency_id: 9,
        min_seats: 1,
    }];
    let members = [account_n(1), account_n(2), account_n(3), account_n(4)];
    let offsets = [3u32, 3, 0, 1, 0, 2];
    let constituencies = vec![
        (account_n(1), 9),
        (account_n(2), 0),
        (account_n(3), 0),
        (account_n(4), 0),
    ];
    let candidates: Vec<_> = (10..30).map(|n| registration(n, 0)).collect();
    let mut s = live_snapshot(
        &members,
        &[vacancy(2, 3), vacancy(5, 4)],
        &offsets,
        0,
        &[],
        candidates,
        &p,
    );
    s.member_constituencies = constituencies.clone();
    let draw = draw_vacated_seats(&s, &beacon(500)).unwrap();
    assert!(draw.joiners.is_empty());
    let candidates: Vec<_> = (40..50)
        .map(|n| registration(n, 0))
        .chain([registration(60, 9)])
        .collect();
    let mut s2 = live_snapshot(
        &draw.successor_members,
        &draw.successor_vacancies,
        &offsets,
        1,
        &[],
        candidates,
        &p,
    );
    s2.member_constituencies = constituencies;
    let draw2 = draw_vacated_seats(&s2, &beacon(501)).unwrap();
    let seats2 = seat_layout(&draw2.successor_members, &draw2.successor_vacancies).unwrap();
    assert!(
        seats2[5].is_some(),
        "the oldest vacancy (seat 5) is refilled first: {seats2:?}"
    );
    assert!(
        seats2[2].is_none(),
        "seat 2's age restarted at the error, so it waits behind seats 0 and 1 (ties by seat): {seats2:?}"
    );
    let tenure2: BTreeMap<AccountId, u32> = draw2.joiner_tenure.iter().copied().collect();
    for seat in [0usize, 1, 5] {
        if let Some(j) = seats2[seat] {
            assert_eq!(tenure2[&j], seat_phase(offsets[seat], 2, 4), "seat {seat}");
        }
    }
    assert_eq!(
        tenure2[&seats2[0].unwrap()],
        1,
        "forced at handover 0: phase 0 then, 1 now"
    );
}

/// MODEL MIRROR (b1r_inherit_check.py:149 `return [[(tuple((k, (a, a)) for k, a in st), p) for st, p in g] for g in gens]`): the genesis members start at their balanced offsets (phase = own = the
/// offset).
#[test]
fn model_mirror_the_genesis_members_start_at_their_balanced_offsets() {
    let p = params();
    let pool: Vec<_> = (10..20).map(|n| registration(n, 0)).collect();
    let genesis = genesis_snapshot(1, p.ring_seats, pool, &p).unwrap();
    let b = beacon(600);
    let draw = draw_genesis_ring(&genesis, &b).unwrap();
    let offsets: BTreeMap<AccountId, u32> =
        genesis_tenure_offsets(&b, &draw.successor_members, p.tenure_handovers)
            .into_iter()
            .collect();
    for (member, tenure) in &draw.joiner_tenure {
        assert_eq!(*tenure, offsets[member]);
    }
}

/// B1 (NET's B1-R R1 finding): the genesis offsets come from the BEACON alone, under their own
/// domain tag (`aft::ring::genesis-offsets::v1`): the same beacon gives every seat the same offset
/// whoever occupies it (identities and constituencies never enter the derivation).
#[test]
fn the_genesis_offsets_come_from_the_beacon_alone() {
    let b = beacon(700);
    let first: Vec<AccountId> = (1..=7).map(account_n).collect();
    let other: Vec<AccountId> = (50..=56).map(account_n).collect();
    let by_seat = |members: &[AccountId]| -> Vec<u32> {
        genesis_tenure_offsets(&b, members, 4)
            .into_iter()
            .map(|(_, o)| o)
            .collect()
    };
    assert_eq!(by_seat(&first), by_seat(&other));
    let mut reversed = first.clone();
    reversed.reverse();
    assert_eq!(by_seat(&first), by_seat(&reversed));
    assert_ne!(
        by_seat(&first),
        genesis_tenure_offsets(&beacon(701), &first, 4)
            .into_iter()
            .map(|(_, o)| o)
            .collect::<Vec<u32>>(),
        "a different beacon permutes the seats"
    );
}

/// LEMMA LV, over long seeded runs at n = 7 with an ample pool: (1) WITHIN the stated departure
/// rate, e ≤ c − ⌈n/T⌉ exits per handover (chosen at random, or adversarially: always the
/// maximum, from the seats rotating soonest), there is NO vacancy and no alarm, ever; (2) BEYOND
/// it (e = rate + 1), vacancies appear; a heavy burst (every unforced occupant exits) drives the
/// ring below the full-n threshold, where it HALTS SAFE (the threshold stays 5 of 7; a vacancy is
/// an absent vote); (3) back within the rate, the vacancies are bounded and REFILLED, oldest
/// first, each at its seat's phase (checked in `Sim`). At (T, c) = (4, 2) the rate is 0 at n = 7:
/// that set's within-rate arm has NO departures (forced rotations alone); the other six sets have
/// rates 1-2, and the counters below assert their departures happened and the adversarial arm
/// spent the whole cap (forced + exits = c) at some handover (review r1 MINOR-5).
#[test]
fn lemma_lv_at_n_7_no_vacancy_within_the_departure_rate_beyond_it_refilled_and_a_safe_halt() {
    let mut halted_configs = 0usize;
    let mut slowest_drain = 0u64;
    for (t, c) in [(4u32, 2u32), (4, 3), (3, 4), (7, 2), (4, 4), (7, 3), (2, 5)] {
        let p = n7_params(t, c);
        let rate = (c - 7u32.div_ceil(t)) as usize;
        for seed in 1..=3u64 {
            for adversarial in [false, true] {
                let mut rng = XorShift(0x1A7E_0000 + seed * 104_729 + u64::from(t * 17 + c));
                let mut sim = Sim::new(&p, rng.beacon(seed));
                // (1) Within the rate.
                let mut within_exits = 0usize;
                let mut cap_spent = 0usize;
                for h in 0..600u64 {
                    let unforced = sim.unforced_next();
                    let exits: BTreeSet<AccountId> = if adversarial {
                        let mut soonest = unforced;
                        soonest.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                        soonest.into_iter().take(rate).map(|(m, _)| m).collect()
                    } else {
                        let count = (rng.next() % (rate as u64 + 1)) as usize;
                        pick_random(
                            &mut rng,
                            unforced.into_iter().map(|(m, _)| m).collect(),
                            count,
                        )
                    };
                    let candidates = sim.fresh(2 * c + 2, 0);
                    within_exits += exits.len();
                    let (plan, draw) = sim.handover(&exits, candidates, rng.beacon(h));
                    cap_spent += (plan.forced_rotations.len() + exits.len() == c as usize) as usize;
                    assert!(
                        draw.successor_vacancies.is_empty() && draw.alarms.is_empty(),
                        "Lemma LV: a vacancy within the rate e ≤ {rate} (T={t} c={c} seed {seed} adversarial {adversarial} h={h}): {draw:?}"
                    );
                    assert!(!assert_full_n_halt(&sim.config));
                }
                if rate == 0 {
                    assert_eq!(within_exits, 0, "a rate of 0 admits no departure");
                } else {
                    assert!(within_exits > 0, "T={t} c={c} seed {seed} adversarial {adversarial}: no within-rate departure");
                    if adversarial {
                        assert!(
                            cap_spent > 0,
                            "T={t} c={c} seed {seed}: the adversary never spent the whole cap"
                        );
                    }
                }
                // (2) Beyond the rate: rate + 1 departures per handover.
                let mut max_vacant = 0usize;
                for h in 0..(3 * u64::from(t)) {
                    let unforced: Vec<AccountId> =
                        sim.unforced_next().into_iter().map(|(m, _)| m).collect();
                    let exits = pick_random(&mut rng, unforced, rate + 1);
                    let candidates = sim.fresh(2 * c + 2, 0);
                    sim.handover(&exits, candidates, rng.beacon(10_000 + h));
                    max_vacant = max_vacant.max(sim.config.vacant_seats.len());
                    halted_configs += assert_full_n_halt(&sim.config) as usize;
                }
                assert!(
                    max_vacant > 0,
                    "beyond the rate (T={t} c={c} seed {seed}) no vacancy appeared"
                );
                // A heavy burst: every unforced occupant exits, twice.
                for h in 0..2u64 {
                    let unforced: BTreeSet<AccountId> =
                        sim.unforced_next().into_iter().map(|(m, _)| m).collect();
                    let candidates = sim.fresh(2 * c + 2, 0);
                    sim.handover(&unforced, candidates, rng.beacon(20_000 + h));
                    halted_configs += assert_full_n_halt(&sim.config) as usize;
                }
                assert!(!sim.config.vacant_seats.is_empty());
                // (3) Back within the rate (no departures): bounded, refilled, oldest first.
                let mut drained = None;
                for h in 0..(60 * u64::from(t)) {
                    let before = sim.config.vacant_seats.clone();
                    let candidates = sim.fresh(2 * c + 2, 0);
                    let (_, draw) =
                        sim.handover(&BTreeSet::new(), candidates, rng.beacon(30_000 + h));
                    let still: BTreeSet<u32> =
                        draw.successor_vacancies.iter().map(|v| v.seat).collect();
                    let (refilled, waiting): (Vec<RingVacancy>, Vec<RingVacancy>) = before
                        .iter()
                        .copied()
                        .partition(|v| !still.contains(&v.seat));
                    for r in &refilled {
                        for w in &waiting {
                            assert!(
                                (r.since_version, r.seat) < (w.since_version, w.seat),
                                "oldest first: {r:?} refilled before {w:?}"
                            );
                        }
                    }
                    assert!(sim.config.vacant_seats.len() <= before.len(), "bounded");
                    assert_full_n_halt(&sim.config);
                    if sim.config.vacant_seats.is_empty() {
                        drained = Some(h + 1);
                        break;
                    }
                }
                let drained = drained.unwrap_or_else(|| {
                    panic!("T={t} c={c} seed {seed}: vacancies not refilled within 60T handovers")
                });
                slowest_drain = slowest_drain.max(drained);
            }
        }
    }
    assert!(halted_configs > 0, "no run reached the safe halt");
    assert!(slowest_drain > 0);
}

/// The contrast for Lemma FR's premise: a SIMULTANEOUS genesis (every seat at offset 0) puts all
/// seven seats in one phase; at handover T all seven are forced, c are refilled and the rest go
/// VACANT with the cap alarm. Balanced offsets are what keep the cap unspent.
#[test]
fn a_simultaneous_genesis_breaks_lemma_frs_premise_and_the_cap_alarm_fires() {
    let p = n7_params(4, 2);
    let mut sim = Sim::new(&p, beacon(900));
    sim.offsets = vec![0; 7];
    sim.tenure = sim.config.members.iter().map(|m| (*m, 0)).collect();
    let mut cap_alarms = 0usize;
    for h in 1..=4u64 {
        let candidates = sim.fresh(6, 0);
        let (s, draw) = sim.handover(&BTreeSet::new(), candidates, beacon(901 + h));
        if h == 4 {
            assert_eq!(s.forced_rotations.len(), 7);
            assert_eq!(draw.departed.len(), 7);
            assert_eq!(draw.successor_vacancies.len(), 5);
        }
        cap_alarms += draw
            .alarms
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    RingSelectionAlarm::ForcedRotationVacated {
                        cause: RingUnfilledCause::ChurnCapSpent,
                        ..
                    }
                )
            })
            .count();
    }
    assert_eq!(cap_alarms, 5);
}

// --- Full-n thresholds (SCQ-8.10d, condition 1) ------------------------------------------------

#[test]
fn a_vacant_seat_is_an_absent_vote_and_never_reduces_n() {
    let config = BoundaryRingConfig {
        version: 2,
        members: (1..=5).map(account_n).collect(),
        vacant_seats: vec![vacancy(3, 1)],
        ..Default::default()
    };
    assert_eq!(config.seat_count(), 6);
    assert_eq!(config.full_n_threshold(2, 3), 4);
    assert_eq!(config.full_n_threshold(1, 1), 6);
    let everyone: BTreeSet<AccountId> = (1..=9).map(account_n).collect();
    // Unanimity over the full n cannot be reached with a vacancy: the ring halts safe.
    assert!(!config.reaches_threshold(&everyone, config.full_n_threshold(1, 1)));
    // Signers who hold no seat never count.
    let four: BTreeSet<AccountId> = [1, 2, 7, 8].into_iter().map(account_n).collect();
    assert!(!config.reaches_threshold(&four, 4));
    assert!(config.reaches_threshold(&everyone, 4));
    let seats = config.seats().unwrap();
    assert_eq!(seats[3], None);
    assert_eq!(seats[4], Some(account_n(4)));
    // A malformed layout is refused.
    assert!(seat_layout(&config.members, &[vacancy(6, 1)]).is_err());
    assert!(seat_layout(&config.members[..4], &[vacancy(1, 1), vacancy(1, 2)]).is_err());
}

#[test]
fn the_reference_beacon_is_bound_to_the_snapshot_commitment() {
    let members = [account_n(1), account_n(2)];
    let s = live_snapshot(&members, &[], &[0, 1], 0, &[], vec![], &params());
    let commitment = s.commitment().unwrap();
    let reference = reference_handover_beacon(&commitment, 100, 7).unwrap();
    let mut other = s.clone();
    other.snapshot_event += 1;
    assert_ne!(
        reference_handover_beacon(&other.commitment().unwrap(), 100, 7).unwrap(),
        reference
    );
    assert_ne!(
        reference_handover_beacon(&commitment, 101, 7).unwrap(),
        reference
    );
}

// --- The ratchet (a seeded property simulation, after NET's ratchet_sim.py) -------------------
// These measure a steady-state SHARE. Per SCQ-8.10a it is NOT a per-handover bound and is never
// cited as one; the bounds are in the module docs.

/// The seated adversarial share (vacancies count as non-adversarial, as NET's model does),
/// averaged over the second half of `handovers`, for n = 7, c = 3, a pool whose adversarial
/// fraction is α = 0.3, honest occupants exiting with probability 0.05 per handover and
/// adversarial ones never (the worst case), from a selector-drawn genesis with balanced offsets.
fn steady_adversarial_share(tenure_handovers: u32, seed: u64, handovers: u32) -> f64 {
    let n = 7u32;
    let mut rng = XorShift(seed);
    let mut p = params();
    p.ring_seats = n;
    p.tenure_handovers = tenure_handovers;
    p.churn_cap = 3;
    let mut sim = Sim::new(&p, rng.beacon(seed));
    let mut adversarial: BTreeSet<AccountId> = BTreeSet::new();
    let mut total = 0.0;
    let mut counted = 0u32;
    for handover in 0..handovers {
        let exits: BTreeSet<AccountId> = sim
            .config
            .members
            .clone()
            .into_iter()
            .filter(|m| !adversarial.contains(m) && rng.unit() < 0.05)
            .collect();
        let candidates = sim.fresh(40, 0);
        for candidate in &candidates {
            if rng.unit() < 0.3 {
                adversarial.insert(candidate.account_id);
            }
        }
        sim.handover(&exits, candidates, rng.beacon(u64::from(handover)));
        if handover >= handovers / 2 {
            total += sim
                .config
                .members
                .iter()
                .filter(|m| adversarial.contains(m))
                .count() as f64
                / f64::from(n);
            counted += 1;
        }
    }
    total / f64::from(counted)
}

#[test]
fn without_a_tenure_cap_voluntary_only_vacating_ratchets_the_adversarial_share_up() {
    // "No tenure cap" = a tenure no run reaches.
    for seed in [1u64, 2, 3] {
        let share = steady_adversarial_share(u32::MAX, seed * 7919, 3_000);
        assert!(share > 0.9, "seed {seed}: share {share} did not ratchet up");
    }
}

#[test]
fn the_tenure_cap_holds_the_steady_state_share_near_its_stationary_value() {
    // The stationary per-seat SHARE under INHERITED phase: a seat is drawn afresh when its phase
    // reaches T, and an honest occupant's exit (probability q = 0.05 per handover) is refilled
    // for the rest of the seat's phase, so P(adversarial at phase k) = 1 − (1 − α)(1 − qα)^k and
    // the share is its mean over k = 0..T−1 (T=4 → ≈0.316, T=8 → ≈0.335; the genesis draw is
    // excluded by averaging over the second half). A share, not a per-handover bound
    // (SCQ-8.10a).
    let stationary = |t: u32| {
        let (alpha, q) = (0.3f64, 0.05f64);
        let mean: f64 = (0..t)
            .map(|k| 1.0 - (1.0 - alpha) * (1.0 - q * alpha).powi(k as i32))
            .sum::<f64>()
            / f64::from(t);
        mean
    };
    for t in [4u32, 8] {
        for seed in [11u64, 12] {
            let share = steady_adversarial_share(t, seed * 104_729, 3_000);
            assert!(
                (share - stationary(t)).abs() < 0.07,
                "T={t} seed {seed}: share {share} vs the stationary share {}",
                stationary(t)
            );
        }
    }
}
