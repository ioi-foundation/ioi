//! SCQ-8.10 (OBS-6; build Ruling 12, P7), with SCQ-8.10a-f and the INHERITED-PHASE tenure rule
//! (build rulings, 10-05 16:58 "OBS-6's TENURE RULE RULED: INHERITED PHASE" and 17:56 "NET's
//! EXACT INHERITED-PHASE CHECKER PASSES"): ring seat assignment by VACATED-SEAT SORTITION with an
//! identity-blind TENURE CAP, the genesis ring as a selector draw, and the re-entry bound (D1-D3).
//!
//! The rule the registry RECOMPUTES at genesis and at every handover (a publisher names the
//! outcome; the registry refuses any outcome that differs):
//!
//! 1. **The genesis ring is a selector draw** (SCQ-8.10c, condition (v)): every one of the n seats
//!    is filled by the per-seat draw (5.) from the activatable registrants, under a recorded
//!    beacon ([`draw_genesis_ring`]). No configuration chooses a genesis member.
//! 2. **Balanced genesis tenure offsets** (SCQ-8.10b (2)): seat s gets the offset
//!    o_s = ⌊π(s)·T/n⌋ for a beacon-derived permutation π of the seats
//!    ([`genesis_tenure_offsets`]), so at most ⌈n/T⌉ seats share an offset. Their role is
//!    STRUCTURAL (de-synchronized rotations, and the ⌈n/T⌉ bound the fill order relies on); no
//!    improvement factor over a simultaneous draw is claimed (SCQ-8.10e).
//! 3. **The tenure rule is INHERITED PHASE: a joiner inherits its seat's phase.** A tenure counter
//!    belongs to the SEAT, never to an occupant: after handover h (h = 0 is the genesis draw) seat
//!    s's counter, its PHASE, is (o_s + h) mod T ([`seat_phase`]). A seated member's tenure is
//!    always its seat's phase. A joiner INHERITS its seat's phase, whatever emptied the seat (a
//!    forced rotation, an exit, a vacancy); it never starts a fresh counter, and never a fresh
//!    random phase. A vacant seat's phase keeps cycling. The occupant of seat s is FORCED to rotate
//!    at the handover at which the counter reaches T, i.e. at every handover h with
//!    (o_s + h) ≡ 0 (mod T): a seat refilled at a forced rotation at handover d is forced again at
//!    d + T, and a genesis occupant at T − o_s ∈ [1, T] (B1-R v1, M7 (vi)). Phases never move, so at
//!    most ⌈n/T⌉ ≤ c occupants are forced at any handover, for the ring's life (Lemma FR). A joiner
//!    that refills an exit or a vacancy serves only the remainder of its seat's phase: an ECONOMIC
//!    exposure, not a safety one (short service is a deployment parameter). The registry refuses a
//!    ledger or a snapshot in which a seated member's tenure is not its seat's phase
//!    ([`verify_seat_phases`]), and a successor naming a joiner in a seat the draw did not assign
//!    it: a joiner on a non-assigned seat or phase is REFUSED.
//! 4. **Departures and the fill order** ([`plan_handover_vacancies`], [`draw_vacated_seats`];
//!    SCQ-8.10d FINAL, option (A); SCQ-8.10f (b)):
//!    - every occupant whose counter reaches T rotates (a FORCED rotation, declared exit or not),
//!      and every other declared exit departs;
//!    - **a forced rotation is NEVER deferred**: its occupant always leaves. A seat the draw
//!      cannot refill goes VACANT (vacant = absent over the full n). The snapshot's forced
//!      rotations must be exactly the occupants whose counter reaches T, or the draw is refused;
//!    - the FILL SET is the first c slots of this order: the forced rotations (oldest first, then
//!      seat order), then the OLDEST vacancies, then this handover's exits (seat order). A
//!      departure outside the fill set leaves its seat VACANT;
//!    - the floors: at R = 0 (the floors sum to n; B1-R v1 M7 (i); rulings 2026-10-08 Q4) every
//!      seat carries its constituency LABEL, fixed by the genesis draw ([`genesis_seat_labels`]),
//!      and each fill seat is refilled ONLY from its own label's pool (the instance floor of i =
//!      the fill seats labelled i), so no constituency's vacated seat is refilled from another. At
//!      R >= 1, floored constituencies the ring would miss are filled FIRST, from their own pools
//!      (the instance floors, cut to the fill set in floor order), then the rest from the whole
//!      pool; NO checker family covers R >= 1 yet, so every chain configuration REFUSES R >= 1
//!      parameters (rulings 2026-10-08 15:16; the registry's test admission alone admits them);
//!    - **on an `assign_seats` error EVERY seat of the fill set stays VACANT** (B1-R v1, M7 (i):
//!      the model NET's exact checker verified): a floored constituency whose pool cannot meet its
//!      instance floor (SCQ-8.10f (b) withdrew 8.10 item 2's `floor_pool_empty` DEFERRAL), or a
//!      pool smaller than the fill set. No forced rotation is deferred, no partial fill is made,
//!      and no second beacon is drawn. Each such seat is a FRESH vacancy: its AGE restarts at 0
//!      (NET's `b1r_inherit_check.py` `_apply_inh`, `(VAC, (0 if ph >= T else ph, 0))`), its PHASE
//!      continuing (a forced seat's from 0, its phase point having passed), and it raises no
//!      VacancyAged alarm. A floor the successor misses flags the configuration as outside the
//!      selection model.
//!    - **the seat state mirrors NET's (kind, (phase, own))** (rulings 2026-10-08 15:16 and 15:19,
//!      Q3 as reversed): the PHASE is the seat's counter, implicit here ([`seat_phase`]), kept and
//!      wrapping mod T while the seat is vacant, restarted only at a forced seat's refill (and, on
//!      an `assign_seats` error, at a forced seat whose phase point has passed); a non-forced
//!      refill inherits it. OWN is the occupant's age since its draw, and for a vacant seat the
//!      vacancy AGE, `since_version`: the version whose handover left the seat vacant (age 0 at
//!      that handover, growing by one per handover). It restarts at 0 on vacating and is NEVER the
//!      departed occupant's age. The oldest-first refill reads it.
//! 5. **The per-seat draw** (Theorem TX's dependence condition; SCQ-8.10b/c): each seat is filled
//!    by its OWN value, derived from the beacon and the seat index
//!    (`SHA-256("aft::ring::seat-draw::v1" ‖ beacon ‖ seat ‖ attempt)`), choosing uniformly among
//!    the remaining candidates of its pool (in canonical account order), WITHOUT REPLACEMENT. One
//!    random value never decides the type of several vacated seats.
//! 6. **Vacancy and liveness** (SCQ-8.10d, conditions 1 and 3; Lemma LV): a vacant seat is an
//!    ABSENT vote and never reduces n ([`super::BoundaryRingConfig::full_n_threshold`]). With an
//!    ample activatable pool there is no vacancy within the stated departure rate (Lemma LV: at
//!    most c − ⌈n/T⌉ exits per handover); beyond it vacancies are bounded and refilled (oldest
//!    first), with the safe halt beyond the liveness bound (a threshold over the full n becomes
//!    unreachable: the ring halts, never unsafely).
//! 7. **Alarms** ([`RingSelectionAlarm`], recorded in every handover record): a forced rotation
//!    whose seat went vacant, with its cause (the floor's pool, the whole pool, or the churn cap;
//!    the last means Lemma FR's premise was false, so the churn-cap premise of SCQ-8.10b (3) is
//!    never silent), and a vacancy older than one handover (SCQ-8.10d).
//!
//! **What the bounds are, and what they are not** (SCQ-8.10a-e):
//! - The selection term's HEADLINE bound is the timed-exit form, (1 − (1 − ᾱ)^T)^n per handover.
//!   It holds under adaptively INDUCED exits (Theorem TX as corrected by SCQ-8.10c), given
//!   negatively associated per-seat draws (5.), a genesis ring drawn by the selector (1.), and an
//!   occupant's type fixed at its draw. π*(ᾱ)^n is a CONDITIONAL figure: it assumes independent
//!   honest exits and a non-binding churn cap, and it excludes induced exits. T here is exactly the
//!   analysed model's T: an occupant serves at most T configurations (3.).
//! - TX does NOT cover post-seating conversion (the bribery of a seated member). That is T8's
//!   adaptive term, composed separately.
//! - ᾱ is the per-constituency maximum, ᾱ = max_i ᾱ_i, with ᾱ_i ≤ A_i / (A_i + H_i) and
//!   A_i ≤ ⌊B_adv,i / b⌋ (D1). ᾱ also covers adversarial SUPPRESSION of honest eligibility: a
//!   suppressed honest registrant does not count in H_i.
//! - The beacon: drawn STRICTLY AFTER the eligibility snapshot is committed, recorded with it,
//!   never derived from old-ring signatures or approvals. The REFERENCE beacon
//!   ([`reference_handover_beacon`]) is predictable at snapshot time and recorder-choosable
//!   (REFERENCE-UNBOUNDED: no grinding bound exists for it), so EVERY chain configuration refuses
//!   it (rulings 2026-10-08 Q1 (C), SCQ-8.10 (a)); only the registry's TEST admission admits it.
//!   The ring plane fails closed until a bounded source lands: OBS-6b, a UNIQUE-OUTPUT beacon (a
//!   threshold signature, a VRF with uniqueness, or R11's VDF) over inputs fixed before the
//!   snapshot, with no producer-chosen field, domain-separated per use.
//!
//! **Every number here is a CONFIGURATION POINT** whose value comes from the numbers author. No
//! production value is hard-coded; the constraints between the values are enforced in code
//! ([`RingSelectionParams::validate`]). The bond's escrow lives outside the registry (a named
//! residual).

use super::{seat_layout, AccountId, ConstituencyFloor, RingMemberRegistration, RingVacancy};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The ring selection parameters (SCQ-8.10 and D1-D3). Set once in the registry (a genesis key);
/// a later change goes through the governance timelock (N8), which is not built here.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingSelectionParams {
    /// n: the ring's seat count. The genesis draw fills exactly n seats; a vacancy never reduces
    /// it.
    pub ring_seats: u32,
    /// T: the tenure, in handovers: an occupant is forced to rotate at the handover at which its
    /// seat's counter reaches T, so it serves at most T configurations (identity-blind).
    pub tenure_handovers: u32,
    /// c: the most seats one handover may fill (and so the most joiners).
    pub churn_cap: u32,
    /// b (D1): the least bond a registration may post.
    pub bond_floor: u128,
    /// W (D2): how many ring events a rotated or exited member's bond stays locked.
    pub bond_lock_events: u64,
    /// The planned interval between handovers, in ring events (W's lower bound uses it).
    pub handover_interval_events: u64,
    /// The exit and challenge window, in ring events (W's lower bound uses it).
    pub exit_challenge_window_events: u64,
    /// D_act (D3): how many ring events a registration waits before it is activatable.
    pub activation_depth_events: u64,
    /// How many ring events after the snapshot commitment the beacon may be recorded.
    pub snapshot_to_beacon_events: u64,
    /// The constituency floors (C5): validity conditions on every configuration record.
    pub floors: Vec<ConstituencyFloor>,
}

impl RingSelectionParams {
    /// Enforces the constraints between the configuration points (the values stay the numbers
    /// author's). `live_seat_count` is the live ring's n, when a live ring exists: it must equal
    /// `ring_seats`.
    pub fn validate(&self, live_seat_count: Option<usize>) -> Result<(), String> {
        if self.ring_seats == 0 {
            return Err("ring selection: the ring needs at least one seat".into());
        }
        if self.tenure_handovers == 0 {
            return Err("ring selection: the tenure T must be at least one handover".into());
        }
        if self.churn_cap == 0 {
            return Err("ring selection: the churn cap c must be at least one seat".into());
        }
        if self.bond_floor == 0 {
            return Err("ring selection (D1): the bond floor b must be positive".into());
        }
        if self.handover_interval_events == 0 || self.snapshot_to_beacon_events == 0 {
            return Err(
                "ring selection: the handover interval and the snapshot-to-beacon interval must be positive"
                    .into(),
            );
        }
        let lock_floor = u64::from(self.tenure_handovers)
            .checked_mul(self.handover_interval_events)
            .and_then(|tenure_span| tenure_span.checked_add(self.exit_challenge_window_events))
            .ok_or("ring selection (D2): T × the handover interval overflows")?;
        if self.bond_lock_events < lock_floor {
            return Err(format!(
                "ring selection (D2): the bond lock W={} is below T × the handover interval plus the exit and challenge window ({lock_floor})",
                self.bond_lock_events
            ));
        }
        if self.activation_depth_events < self.snapshot_to_beacon_events {
            return Err(format!(
                "ring selection (D3): D_act={} is below the snapshot-to-beacon interval ({})",
                self.activation_depth_events, self.snapshot_to_beacon_events
            ));
        }
        let mut constituencies = BTreeSet::new();
        for floor in &self.floors {
            if !constituencies.insert(floor.constituency_id) {
                return Err("ring selection: a constituency has two floors".into());
            }
        }
        let seats = u64::from(self.ring_seats);
        // c ≥ ⌈n/T⌉, i.e. c·T ≥ n: the balanced phases' forced rotations fit within the cap.
        if u64::from(self.churn_cap) * u64::from(self.tenure_handovers) < seats {
            return Err(format!(
                "ring selection: c={} and T={} violate c ≥ n/T for n={seats}",
                self.churn_cap, self.tenure_handovers
            ));
        }
        let floor_total: u64 = self.floors.iter().map(|f| u64::from(f.min_seats)).sum();
        if floor_total > seats {
            return Err(format!(
                "ring selection: the floors ({floor_total} seats) exceed the ring size n={seats}"
            ));
        }
        if let Some(live) = live_seat_count {
            if live as u64 != seats {
                return Err(format!(
                    "ring selection: the live ring has {live} seats, the parameters say n={seats}"
                ));
            }
        }
        Ok(())
    }

    /// The canonical reference to the floors, recorded in every handover record.
    pub fn floors_ref(&self) -> Result<[u8; 32], String> {
        domain_hash(
            b"aft::ring::floors::v1",
            &parity_scale_codec::Encode::encode(&self.floors),
        )
    }
}

/// The per-seat ledger the registry keeps beside the live configuration (module docs, 3.).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingSeatLedger {
    /// The live configuration version this ledger describes.
    pub version: u64,
    /// The handovers since the genesis draw (0 for the genesis ring). With the seat offsets it
    /// fixes every seat's phase ([`seat_phase`]).
    pub handover_index: u64,
    /// Each seated member's tenure counter: always its seat's phase.
    pub tenure: BTreeMap<AccountId, u32>,
    /// Constituency, per member.
    pub constituencies: BTreeMap<AccountId, u32>,
    /// The balanced genesis offsets, by seat index, fixed for the ring's life (the seat's phase
    /// at the genesis draw).
    pub seat_offsets: Vec<u32>,
    /// R = 0 only (the floors sum to n; B1-R v1 M7 (i)): each seat's constituency label, by seat
    /// index, assigned by the genesis draw and fixed for the ring's life ([`genesis_seat_labels`]).
    /// Empty when R >= 1.
    pub seat_constituencies: Vec<u32>,
}

/// INHERITED PHASE (module docs, 3.): seat s's tenure counter after handover `handover_index`
/// (0 = the genesis draw), (o_s + h) mod T. Whoever holds the seat holds this counter.
pub fn seat_phase(seat_offset: u32, handover_index: u64, tenure_handovers: u32) -> u32 {
    let period = u64::from(tenure_handovers.max(1));
    ((u64::from(seat_offset) % period + handover_index % period) % period) as u32
}

/// Refuses a ring whose seated members do not each hold their seat's phase after
/// `handover_index` handovers (module docs, 3.: a joiner on a non-assigned seat or phase is
/// refused), a seat offset not below T, or an offset list that does not cover every seat.
pub fn verify_seat_phases(
    members: &[AccountId],
    vacancies: &[RingVacancy],
    tenure: &BTreeMap<AccountId, u32>,
    seat_offsets: &[u32],
    handover_index: u64,
    tenure_handovers: u32,
) -> Result<(), String> {
    if tenure_handovers == 0 {
        return Err("ring selection: the tenure T must be at least one handover".into());
    }
    let seats = seat_layout(members, vacancies)?;
    if seat_offsets.len() != seats.len() {
        return Err(format!(
            "the ring has {} seats but {} seat offsets",
            seats.len(),
            seat_offsets.len()
        ));
    }
    for (seat, (occupant, offset)) in seats.iter().zip(seat_offsets).enumerate() {
        if *offset >= tenure_handovers {
            return Err(format!(
                "seat {seat}'s offset {offset} is not below T={tenure_handovers}"
            ));
        }
        if let Some(member) = occupant {
            let assigned = seat_phase(*offset, handover_index, tenure_handovers);
            let held = tenure.get(member).copied();
            if held != Some(assigned) {
                return Err(format!(
                    "inherited phase: seat {seat}'s occupant holds tenure {held:?}, not the seat's assigned phase {assigned} (a joiner on a non-assigned seat or phase is refused)"
                ));
            }
        }
    }
    Ok(())
}

/// The departures a handover's snapshot fixes (SCQ-8.10d FINAL (A)).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RingVacancyPlan {
    /// The declared exits of occupants NOT forced at this handover (pre-expiry departures), in
    /// seat order: every one departs.
    pub exits: Vec<AccountId>,
    /// The forced rotations: every occupant whose counter reaches T at this handover (tenure + 1
    /// ≥ T), declared exit or not; oldest first, then seat order. Never cut by the churn cap: a
    /// forced rotation is never deferred.
    pub forced_rotations: Vec<AccountId>,
}

/// The departures at a handover (module docs, 4.): every occupant whose counter reaches
/// `tenure_handovers` rotates; every other declared exit departs.
pub fn plan_handover_vacancies(
    members: &[AccountId],
    tenure: &BTreeMap<AccountId, u32>,
    exits: &BTreeSet<AccountId>,
    tenure_handovers: u32,
) -> RingVacancyPlan {
    let mut due: Vec<(u32, usize, AccountId)> = members
        .iter()
        .enumerate()
        .filter_map(|(seat, member)| {
            let served = tenure.get(member).copied().unwrap_or(0);
            (served.saturating_add(1) >= tenure_handovers).then_some((served, seat, *member))
        })
        .collect();
    // Oldest first; seat order breaks ties.
    due.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let forced: Vec<AccountId> = due.iter().map(|(_, _, member)| *member).collect();
    let forced_set: BTreeSet<AccountId> = forced.iter().copied().collect();
    RingVacancyPlan {
        exits: members
            .iter()
            .filter(|member| exits.contains(member) && !forced_set.contains(member))
            .copied()
            .collect(),
        forced_rotations: forced,
    }
}

/// The eligibility snapshot a handover (or the genesis draw) draws from, committed BEFORE its
/// beacon exists.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingHandoverSnapshot {
    /// The live configuration version being handed over (0 for the genesis draw).
    pub live_version: u64,
    /// The ring event ordinal at which the snapshot was committed.
    pub snapshot_event: u64,
    /// n.
    pub seat_count: u32,
    /// The seated members of the live ring, in seat order (empty for the genesis draw).
    pub members: Vec<AccountId>,
    /// The live ring's vacant seats (every seat, for the genesis draw).
    pub vacancies: Vec<RingVacancy>,
    /// The live ring's handovers since the genesis draw.
    pub handover_index: u64,
    /// The balanced genesis offsets, by seat index (empty for the genesis draw).
    pub seat_offsets: Vec<u32>,
    /// Each seated member's tenure counter (its seat's phase), at the snapshot.
    pub tenure_counters: Vec<(AccountId, u32)>,
    /// Known constituencies, per member.
    pub member_constituencies: Vec<(AccountId, u32)>,
    /// R = 0 only: the seats' constituency labels (the ledger's), by seat index. Empty when R >= 1
    /// and for the genesis draw (which assigns them).
    pub seat_constituencies: Vec<u32>,
    /// The declared exits of occupants not forced at this handover (seat order).
    pub exits: Vec<AccountId>,
    /// The departing members: the exits, then the forced rotations.
    pub vacated_set: Vec<AccountId>,
    /// The forced rotations, in priority order (never deferred).
    pub forced_rotations: Vec<AccountId>,
    /// The most seats this draw may fill: c at a handover, n at genesis.
    pub churn_cap: u32,
    /// T.
    pub tenure_handovers: u32,
    /// The activatable registrants at the snapshot (past `D_act`), in queue order.
    pub candidates: Vec<RingMemberRegistration>,
    /// The floors in force.
    pub floors: Vec<ConstituencyFloor>,
    /// Their canonical reference.
    pub floors_ref: [u8; 32],
}

impl RingHandoverSnapshot {
    /// The snapshot commitment the beacon is bound to.
    pub fn commitment(&self) -> Result<[u8; 32], String> {
        domain_hash(
            b"aft::ring::handover-snapshot::v1",
            &parity_scale_codec::Encode::encode(self),
        )
    }

    /// Whether this is the genesis draw (no live ring yet).
    pub fn is_genesis(&self) -> bool {
        self.live_version == 0
    }
}

/// Where a recorded beacon came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RingBeaconSource {
    /// The reference beacon the registry derives itself (until R11): labelled REFERENCE.
    #[default]
    Reference,
    /// A beacon derived from old-ring signatures or approvals: always refused (grindable by a
    /// last revealer).
    OldRingSignatures,
    /// R11's VDF beacon over the snapshot commitment: not available yet, refused until it is.
    Vdf,
}

/// The reference handover beacon (REFERENCE until R11): a domain-separated hash of the snapshot
/// commitment and the block the beacon is recorded in, derived by the registry itself.
pub fn reference_handover_beacon(
    snapshot_commitment: &[u8; 32],
    block_height: u64,
    block_timestamp: u64,
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(32 + 16);
    material.extend_from_slice(snapshot_commitment);
    material.extend_from_slice(&block_height.to_be_bytes());
    material.extend_from_slice(&block_timestamp.to_be_bytes());
    domain_hash(b"aft::ring::beacon::reference::v1", &material)
}

/// Why a forced rotation's seat went VACANT (it is never deferred: its occupant left anyway). The
/// first two are `assign_seats` errors, on which EVERY seat of the fill set stays vacant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RingUnfilledCause {
    /// A floored constituency's pool could not meet its instance floor (SCQ-8.10f (b): 8.10 item
    /// 2's deferral is withdrawn).
    FloorPoolExhausted,
    /// The activatable pool was smaller than the fill set.
    CandidatePoolExhausted,
    /// The churn cap was spent: more forced rotations were due than c, so Lemma FR's premise (at
    /// most ⌈n/T⌉ ≤ c forced rotations per handover) was false.
    ChurnCapSpent,
}

/// A typed alarm a handover records (SCQ-8.10b (3), SCQ-8.10d). Each makes visible a premise of
/// the selection bound, or of liveness, becoming false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RingSelectionAlarm {
    /// A forced rotation's occupant left and its seat went VACANT.
    ForcedRotationVacated {
        /// The member that rotated out.
        member: AccountId,
        /// The seat now vacant.
        seat: u32,
        /// Its tenure at the snapshot.
        tenure: u32,
        /// Why the seat was not refilled.
        cause: RingUnfilledCause,
    },
    /// A seat vacant since an earlier handover is still vacant after this one.
    VacancyAged {
        /// The seat.
        seat: u32,
        /// The version whose handover left it vacant.
        since_version: u64,
    },
}

/// The outcome of a draw: the successor ring and how it was reached.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingSeatDraw {
    /// The successor's seated members, in seat order.
    pub successor_members: Vec<AccountId>,
    /// The successor's vacant seats, in seat order.
    pub successor_vacancies: Vec<RingVacancy>,
    /// The joiners, in fill order.
    pub joiners: Vec<AccountId>,
    /// Each joiner's tenure in the successor, in fill order: its seat's phase (module docs, 3.);
    /// at genesis, the balanced offsets.
    pub joiner_tenure: Vec<(AccountId, u32)>,
    /// The members who leave (the exits and every forced rotation), in seat order.
    pub departed: Vec<AccountId>,
    /// The alarms this handover records.
    pub alarms: Vec<RingSelectionAlarm>,
    /// A floor stayed unmet: the configuration is outside the selection model (T8 is
    /// recomputed).
    pub outside_selection_model: bool,
}

/// A uniform index in `0..len` from the beacon, a domain, a label (a seat index or a
/// permutation step) and a rejection counter, so the result is unbiased. `len` must be positive.
fn uniform_index(beacon: &[u8; 32], domain: &[u8], label: u64, len: usize) -> usize {
    let len = len as u64;
    // Accept u < limit, a multiple of len, so u % len is uniform.
    let limit = (u64::MAX / len) * len;
    let mut last = 0u64;
    for attempt in 0u64..64 {
        let mut material = Vec::with_capacity(32 + 16);
        material.extend_from_slice(beacon);
        material.extend_from_slice(&label.to_be_bytes());
        material.extend_from_slice(&attempt.to_be_bytes());
        let digest = domain_hash(domain, &material).unwrap_or([0u8; 32]);
        let mut word = [0u8; 8];
        word.copy_from_slice(&digest[..8]);
        last = u64::from_be_bytes(word);
        if last < limit {
            return (last % len) as usize;
        }
    }
    // Unreachable in practice: each attempt is rejected with probability below 1/2.
    (last % len) as usize
}

/// The per-seat draw (module docs, 5.): the seat's OWN value chooses uniformly among the
/// `eligible` candidates still in `pool`, and the chosen one leaves the pool (without
/// replacement). `None` if no eligible candidate remains.
fn draw_seat(
    beacon: &[u8; 32],
    seat: u32,
    pool: &mut Vec<RingMemberRegistration>,
    eligible: impl Fn(&RingMemberRegistration) -> bool,
) -> Option<RingMemberRegistration> {
    let eligible_at: Vec<usize> = pool
        .iter()
        .enumerate()
        .filter(|(_, candidate)| eligible(candidate))
        .map(|(at, _)| at)
        .collect();
    if eligible_at.is_empty() {
        return None;
    }
    let pick = uniform_index(
        beacon,
        b"aft::ring::seat-draw::v1",
        u64::from(seat),
        eligible_at.len(),
    );
    Some(pool.remove(eligible_at[pick]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotKind {
    Forced(AccountId),
    Vacancy,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Open,
    Filled(AccountId),
    Vacant,
}

/// Draws the seats a snapshot leaves to fill (module docs, 3.-7.). Deterministic in
/// (snapshot, beacon). Refuses a malformed snapshot, a seated member off its seat's phase, and a
/// snapshot whose departures are not exactly the plan's (a deferred forced rotation).
pub fn draw_vacated_seats(
    snapshot: &RingHandoverSnapshot,
    beacon: &[u8; 32],
) -> Result<RingSeatDraw, String> {
    let tenure_handovers = snapshot.tenure_handovers;
    if tenure_handovers == 0 {
        return Err("ring selection: the tenure T must be at least one handover".into());
    }
    let seats = seat_layout(&snapshot.members, &snapshot.vacancies)?;
    if seats.len() != snapshot.seat_count as usize {
        return Err(format!(
            "the snapshot's seat layout has {} seats, its seat count is {}",
            seats.len(),
            snapshot.seat_count
        ));
    }
    let genesis = snapshot.is_genesis();
    let tenure: BTreeMap<AccountId, u32> = snapshot.tenure_counters.iter().copied().collect();
    if !genesis {
        verify_seat_phases(
            &snapshot.members,
            &snapshot.vacancies,
            &tenure,
            &snapshot.seat_offsets,
            snapshot.handover_index,
            tenure_handovers,
        )?;
    }
    // Q4 (B1-R v1 M7 (i)): at R = 0 (the floors sum to n) every seat carries its constituency
    // label, and each fill seat is filled only from its own label's pool. The labels are the
    // ledger's, never a publisher's; a snapshot without them at R = 0 is refused.
    let floor_total: u64 = snapshot
        .floors
        .iter()
        .map(|floor| u64::from(floor.min_seats))
        .sum();
    let seat_labelled = !genesis && floor_total == u64::from(snapshot.seat_count);
    if seat_labelled {
        if snapshot.seat_constituencies.len() != seats.len() {
            return Err(
                "R = 0: the snapshot must carry every seat's constituency label (B1-R v1 M7 (i))"
                    .into(),
            );
        }
        if let Some(label) = snapshot.seat_constituencies.iter().find(|label| {
            !snapshot
                .floors
                .iter()
                .any(|floor| floor.constituency_id == **label)
        }) {
            return Err(format!(
                "R = 0: seat label {label} names no floored constituency"
            ));
        }
    } else if !snapshot.seat_constituencies.is_empty() {
        return Err(
            "seat constituency labels are carried only at R = 0, after the genesis draw".into(),
        );
    }
    // No deferral: the departures are exactly the plan's.
    let declared: BTreeSet<AccountId> = snapshot.exits.iter().copied().collect();
    let plan = plan_handover_vacancies(&snapshot.members, &tenure, &declared, tenure_handovers);
    if plan.forced_rotations != snapshot.forced_rotations {
        return Err(
            "no deferral: the snapshot's forced rotations are not exactly the occupants whose tenure reaches T (a forced rotation is never deferred)"
                .into(),
        );
    }
    let planned_vacated: Vec<AccountId> = plan
        .exits
        .iter()
        .chain(plan.forced_rotations.iter())
        .copied()
        .collect();
    if plan.exits != snapshot.exits || planned_vacated != snapshot.vacated_set {
        return Err("the snapshot's exits or vacated set differ from the plan".into());
    }

    let exits: BTreeSet<AccountId> = snapshot.exits.iter().copied().collect();
    let forced: BTreeSet<AccountId> = snapshot.forced_rotations.iter().copied().collect();
    let constituencies: BTreeMap<AccountId, u32> =
        snapshot.member_constituencies.iter().copied().collect();
    let seat_of: BTreeMap<AccountId, u32> = seats
        .iter()
        .enumerate()
        .filter_map(|(seat, member)| member.map(|member| (member, seat as u32)))
        .collect();
    let seated: BTreeSet<AccountId> = seat_of.keys().copied().collect();

    // Kept: seated, neither exiting nor rotating. Nothing is ever added back (no deferral).
    let kept: BTreeSet<AccountId> = seated
        .iter()
        .filter(|member| !exits.contains(member) && !forced.contains(member))
        .copied()
        .collect();

    // The fill order: forced rotations (priority order), the oldest vacancies, then the exits.
    let mut slots: Vec<(u32, SlotKind)> = Vec::new();
    for member in &snapshot.forced_rotations {
        let seat = *seat_of
            .get(member)
            .ok_or("a forced rotation names a member who holds no seat")?;
        slots.push((seat, SlotKind::Forced(*member)));
    }
    let mut vacancies = snapshot.vacancies.clone();
    vacancies.sort_by_key(|vacancy| (vacancy.since_version, vacancy.seat));
    for vacancy in &vacancies {
        slots.push((vacancy.seat, SlotKind::Vacancy));
    }
    for (seat, member) in seats.iter().enumerate() {
        if let Some(member) = member {
            if exits.contains(member) {
                slots.push((seat as u32, SlotKind::Exit));
            }
        }
    }
    // THE FILL SET V_h (SCQ-8.10d FINAL; B1-R v1, M7 (i)): the first c slots of the fill order. A
    // slot beyond it stays VACANT (under Lemma FR no forced rotation is ever beyond it).
    let cap = snapshot.churn_cap as usize;
    let fill_len = slots.len().min(cap);
    let mut state = vec![SlotState::Open; slots.len()];
    // The fill set's seats (on an assign_seats error each becomes a FRESH vacancy, Q3).
    let fill_seats: BTreeSet<u32> = slots[..fill_len].iter().map(|(seat, _)| *seat).collect();

    // The pool: activatable registrants holding no seat, in canonical account order, once each.
    let mut pool: Vec<RingMemberRegistration> = snapshot
        .candidates
        .iter()
        .filter(|candidate| !seated.contains(&candidate.account_id))
        .cloned()
        .collect();
    pool.sort_by(|left, right| left.account_id.0.cmp(&right.account_id.0));
    pool.dedup_by(|left, right| left.account_id == right.account_id);

    // The instance floors. R >= 1: each floor the kept ring misses, in floor order, cut to the
    // fill set. R = 0 (Q4): the instance floor of i is |V_h ∩ g⁻¹(i)|, the fill seats labelled i.
    let mut instance_floors: Vec<(u32, usize)> = Vec::new();
    if seat_labelled {
        for floor in &snapshot.floors {
            let need = slots[..fill_len]
                .iter()
                .filter(|(seat, _)| {
                    snapshot.seat_constituencies[*seat as usize] == floor.constituency_id
                })
                .count();
            if need > 0 {
                instance_floors.push((floor.constituency_id, need));
            }
        }
    } else {
        let mut room = fill_len;
        for floor in &snapshot.floors {
            let kept_count = kept
                .iter()
                .filter(|member| constituencies.get(member) == Some(&floor.constituency_id))
                .count();
            let need = (floor.min_seats as usize)
                .saturating_sub(kept_count)
                .min(room);
            room -= need;
            if need > 0 {
                instance_floors.push((floor.constituency_id, need));
            }
        }
    }
    // `assign_seats`' errors (canon's `assign_seats`, and the model NET's exact checker verified):
    // a floored constituency whose pool is smaller than its instance floor (SCQ-8.10f (b): the
    // floor_pool_empty DEFERRAL is withdrawn), or a pool smaller than the fill set. On an error
    // EVERY seat of the fill set stays VACANT: no forced rotation is deferred, no partial fill is
    // made, and no second beacon is drawn.
    let floor_short = instance_floors.iter().any(|(constituency, need)| {
        pool.iter()
            .filter(|candidate| candidate.constituency_id == *constituency)
            .count()
            < *need
    });
    let assign_error = if floor_short {
        Some(RingUnfilledCause::FloorPoolExhausted)
    } else if pool.len() < fill_len {
        Some(RingUnfilledCause::CandidatePoolExhausted)
    } else {
        None
    };

    let mut joiners: Vec<AccountId> = Vec::new();
    let mut joiner_constituency: BTreeMap<AccountId, u32> = BTreeMap::new();
    let mut alarms: Vec<RingSelectionAlarm> = Vec::new();
    if assign_error.is_none() {
        // Floors first, each from its own pool, into the fill set's first slots; then the rest of
        // the fill set from the whole pool. Every draw succeeds (the pools were counted above).
        let mut next = 0usize;
        let mut fill = |next: &mut usize,
                        pool: &mut Vec<RingMemberRegistration>,
                        eligible: &dyn Fn(&RingMemberRegistration) -> bool|
         -> Result<(), String> {
            let seat = slots[*next].0;
            let pick = draw_seat(beacon, seat, pool, eligible)
                .ok_or("the counted pool ran dry during the draw")?;
            state[*next] = SlotState::Filled(pick.account_id);
            joiners.push(pick.account_id);
            joiner_constituency.insert(pick.account_id, pick.constituency_id);
            *next += 1;
            Ok(())
        };
        if seat_labelled {
            // R = 0 (Q4): each fill seat, in fill order, from its own label's pool.
            while next < fill_len {
                let label = snapshot.seat_constituencies[slots[next].0 as usize];
                fill(&mut next, &mut pool, &|candidate| {
                    candidate.constituency_id == label
                })?;
            }
        } else {
            for (constituency, need) in &instance_floors {
                for _ in 0..*need {
                    fill(&mut next, &mut pool, &|candidate| {
                        candidate.constituency_id == *constituency
                    })?;
                }
            }
            while next < fill_len {
                fill(&mut next, &mut pool, &|_| true)?;
            }
        }
    }
    // Every slot not filled is VACANT. A forced rotation's seat left vacant raises the alarm; it is
    // never deferred: its occupant leaves anyway.
    for at in 0..slots.len() {
        if state[at] != SlotState::Open {
            continue;
        }
        state[at] = SlotState::Vacant;
        if let (seat, SlotKind::Forced(member)) = slots[at] {
            let cause = match assign_error {
                Some(cause) if at < fill_len => cause,
                _ => RingUnfilledCause::ChurnCapSpent,
            };
            alarms.push(RingSelectionAlarm::ForcedRotationVacated {
                member,
                seat,
                tenure: tenure.get(&member).copied().unwrap_or(0),
                cause,
            });
        }
    }
    // A floor the successor misses puts the configuration outside the selection model.
    let outside_selection_model = snapshot.floors.iter().any(|floor| {
        let kept_count = kept
            .iter()
            .filter(|member| constituencies.get(member) == Some(&floor.constituency_id))
            .count();
        let joined_count = joiner_constituency
            .values()
            .filter(|constituency| **constituency == floor.constituency_id)
            .count();
        kept_count + joined_count < floor.min_seats as usize
    });

    // The successor, seat by seat. A joiner INHERITS ITS SEAT'S PHASE: the seat's counter after
    // this handover (at genesis the balanced offsets replace it, in `draw_genesis_ring`).
    let next_handover = snapshot.handover_index.saturating_add(1);
    let joiner_phase = |seat: u32| -> u32 {
        if genesis {
            0
        } else {
            seat_phase(
                snapshot.seat_offsets[seat as usize],
                next_handover,
                tenure_handovers,
            )
        }
    };
    let filled_at: BTreeMap<u32, AccountId> = slots
        .iter()
        .zip(&state)
        .filter_map(|((seat, _), slot)| match slot {
            SlotState::Filled(account) => Some((*seat, *account)),
            _ => None,
        })
        .collect();
    let old_vacancy: BTreeMap<u32, RingVacancy> = snapshot
        .vacancies
        .iter()
        .map(|vacancy| (vacancy.seat, *vacancy))
        .collect();
    let mut start_tenure: BTreeMap<AccountId, u32> = BTreeMap::new();
    let mut successor_members = Vec::with_capacity(seats.len());
    let mut successor_vacancies = Vec::new();
    let mut departed = Vec::new();
    for (seat, occupant) in seats.iter().enumerate() {
        let seat = seat as u32;
        match occupant {
            Some(member) if kept.contains(member) => successor_members.push(*member),
            Some(member) => {
                departed.push(*member);
                match filled_at.get(&seat) {
                    Some(joiner) => {
                        successor_members.push(*joiner);
                        start_tenure.insert(*joiner, joiner_phase(seat));
                    }
                    None => successor_vacancies.push(RingVacancy {
                        seat,
                        since_version: snapshot.live_version,
                    }),
                }
            }
            None => {
                let vacancy = old_vacancy.get(&seat).copied().unwrap_or(RingVacancy {
                    seat,
                    since_version: snapshot.live_version,
                });
                match filled_at.get(&seat) {
                    Some(joiner) => {
                        successor_members.push(*joiner);
                        start_tenure.insert(*joiner, joiner_phase(seat));
                    }
                    // NET's model (b1r_inherit_check.py:86, the assign_seats-error path): every
                    // fill seat becomes a FRESH vacancy, its age restarting at 0 (its phase,
                    // implicit here, continues), so it raises no VacancyAged alarm.
                    None if assign_error.is_some() && fill_seats.contains(&seat) => {
                        successor_vacancies.push(RingVacancy {
                            seat,
                            since_version: snapshot.live_version,
                        });
                    }
                    None => {
                        successor_vacancies.push(vacancy);
                        alarms.push(RingSelectionAlarm::VacancyAged {
                            seat,
                            since_version: vacancy.since_version,
                        });
                    }
                }
            }
        }
    }
    let joiner_tenure = joiners
        .iter()
        .map(|joiner| (*joiner, start_tenure.get(joiner).copied().unwrap_or(0)))
        .collect();
    Ok(RingSeatDraw {
        successor_members,
        successor_vacancies,
        joiners,
        joiner_tenure,
        departed,
        alarms,
        outside_selection_model,
    })
}

/// The genesis snapshot (module docs, 1.): no live ring, every one of the `seat_count` seats
/// vacant, and the draw may fill all of them.
pub fn genesis_snapshot(
    snapshot_event: u64,
    seat_count: u32,
    candidates: Vec<RingMemberRegistration>,
    params: &RingSelectionParams,
) -> Result<RingHandoverSnapshot, String> {
    Ok(RingHandoverSnapshot {
        live_version: 0,
        snapshot_event,
        seat_count,
        members: Vec::new(),
        vacancies: (0..seat_count)
            .map(|seat| RingVacancy {
                seat,
                since_version: 0,
            })
            .collect(),
        churn_cap: seat_count,
        tenure_handovers: params.tenure_handovers,
        candidates,
        floors: params.floors.clone(),
        floors_ref: params.floors_ref()?,
        ..Default::default()
    })
}

/// The genesis ring (module docs, 1.): the per-seat draw over an all-vacant ring. Every seat must
/// be filled and every floor met, or the ring cannot start.
pub fn draw_genesis_ring(
    snapshot: &RingHandoverSnapshot,
    beacon: &[u8; 32],
) -> Result<RingSeatDraw, String> {
    if !snapshot.is_genesis()
        || !snapshot.members.is_empty()
        || snapshot.vacancies.len() != snapshot.seat_count as usize
        || snapshot.churn_cap != snapshot.seat_count
    {
        return Err("the genesis draw needs a genesis snapshot (every seat vacant)".into());
    }
    let mut draw = draw_vacated_seats(snapshot, beacon)?;
    if draw.outside_selection_model {
        return Err("the genesis draw cannot meet the constituency floors".into());
    }
    if !draw.successor_vacancies.is_empty() {
        return Err(format!(
            "too few activatable registrants to draw the genesis ring: {} of {} seats unfilled",
            draw.successor_vacancies.len(),
            snapshot.seat_count
        ));
    }
    // The genesis members start at the balanced offsets, in seat order (module docs, 2.).
    let offsets: BTreeMap<AccountId, u32> =
        genesis_tenure_offsets(beacon, &draw.successor_members, snapshot.tenure_handovers)
            .into_iter()
            .collect();
    draw.joiner_tenure = draw
        .joiners
        .iter()
        .map(|joiner| (*joiner, offsets.get(joiner).copied().unwrap_or(0)))
        .collect();
    Ok(draw)
}

/// Review r1 MAJOR-2: whether the genesis draw over `snapshot` can succeed, decided BEFORE the
/// snapshot is committed (a pending snapshot leaves only through a successful settlement, so an
/// infeasible one would block the ring's start for good). The genesis draw's errors do not depend
/// on the beacon: at genesis no member is seated and the fill set is every seat, so they come only
/// from `assign_seats`' counts over the snapshot's candidates (a floored constituency's pool below
/// its floor, or the pool below n), and without such an error every seat is filled and every floor
/// met. One probe draw therefore decides the draw for every beacon (a test checks the agreement over
/// many beacons and pool shapes).
pub fn check_genesis_draw_feasible(snapshot: &RingHandoverSnapshot) -> Result<(), String> {
    draw_genesis_ring(snapshot, &[0u8; 32]).map(|_| ())
}

/// Q4 (B1-R v1 M7 (i)): the seats' constituency labels the genesis draw assigns at R = 0 (the
/// floors sum to n): each seat is labelled with its genesis occupant's constituency (at R = 0 every
/// genesis seat is a floor seat, filled from its floor's pool). Empty when R >= 1. Fixed for the
/// ring's life.
pub fn genesis_seat_labels(
    floors: &[ConstituencyFloor],
    members_in_seat_order: &[AccountId],
    constituencies: &BTreeMap<AccountId, u32>,
) -> Result<Vec<u32>, String> {
    let floor_total: u64 = floors.iter().map(|floor| u64::from(floor.min_seats)).sum();
    if floor_total != members_in_seat_order.len() as u64 {
        return Ok(Vec::new());
    }
    members_in_seat_order
        .iter()
        .map(|member| {
            constituencies
                .get(member)
                .copied()
                .ok_or_else(|| "R = 0: a genesis member has no constituency".to_string())
        })
        .collect()
}

/// The balanced genesis tenure offsets (module docs, 2.), in seat order: a beacon-derived
/// permutation of the seats (Fisher-Yates, each step its own value), and the k-th seat of the
/// permutation starts at tenure ⌊k·T/n⌋. At most ⌈n/T⌉ seats share an offset.
pub fn genesis_tenure_offsets(
    beacon: &[u8; 32],
    members_in_seat_order: &[AccountId],
    tenure_handovers: u32,
) -> Vec<(AccountId, u32)> {
    let seats = members_in_seat_order.len();
    let mut order: Vec<usize> = (0..seats).collect();
    for step in (1..seats).rev() {
        let swap_with = uniform_index(
            beacon,
            b"aft::ring::genesis-offsets::v1",
            step as u64,
            step + 1,
        );
        order.swap(step, swap_with);
    }
    let mut offsets = vec![0u32; seats];
    for (rank, seat) in order.iter().enumerate() {
        offsets[*seat] = ((rank as u64 * u64::from(tenure_handovers)) / seats as u64) as u32;
    }
    members_in_seat_order.iter().copied().zip(offsets).collect()
}

/// The record a handover (or the genesis draw) leaves (SCQ-8.10).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingHandoverRecord {
    /// The version the handover activated.
    pub new_version: u64,
    /// The snapshot commitment the beacon is bound to.
    pub snapshot_commitment: [u8; 32],
    /// The beacon.
    pub beacon: [u8; 32],
    /// The beacon's source (REFERENCE until R11).
    pub beacon_source: RingBeaconSource,
    /// The departing members (exits, then forced rotations).
    pub vacated_set: Vec<AccountId>,
    /// Each seated member's tenure at the snapshot; for the genesis draw, the balanced offsets
    /// the genesis members start from, in seat order.
    pub tenure_counters: Vec<(AccountId, u32)>,
    /// The floors' canonical reference.
    pub floors_ref: [u8; 32],
    /// The successor's vacant seats.
    pub successor_vacancies: Vec<RingVacancy>,
    /// The alarms (a forced rotation's seat left vacant; a vacancy older than one handover).
    pub alarms: Vec<RingSelectionAlarm>,
    /// Outside the selection model (see [`RingSeatDraw`]).
    pub outside_selection_model: bool,
}

/// A rotated or exited member's bond, locked for W ring events (D2).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingBondLock {
    /// The member whose bond is locked.
    pub member: AccountId,
    /// The locked amount (as the configuration recorded it).
    pub amount: u128,
    /// The configuration version the member departed from.
    pub departed_version: u64,
    /// The first ring event at which the bond may release (custody succession still gates it).
    pub locked_until_event: u64,
}

impl RingBondLock {
    /// Whether the bond is still locked at `current_event`.
    pub fn is_locked_at(&self, current_event: u64) -> bool {
        current_event < self.locked_until_event
    }
}

/// The registry's pending draw: the committed snapshot and, once recorded, its beacon.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingPendingHandover {
    /// The eligibility snapshot.
    pub snapshot: RingHandoverSnapshot,
    /// Its commitment.
    pub commitment: [u8; 32],
    /// The recorded beacon, its source and the ring event it was recorded at.
    pub beacon: Option<([u8; 32], RingBeaconSource, u64)>,
}

/// A request to record the pending snapshot's beacon (`record_ring_handover_beacon@v1`). It names
/// the snapshot it is for and the source claimed; the registry derives the value itself.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingBeaconRecordRequest {
    /// The snapshot commitment the beacon is for.
    pub snapshot_commitment: [u8; 32],
    /// The source claimed. Only [`RingBeaconSource::Reference`] is accepted until R11.
    pub source: RingBeaconSource,
}

/// A request to release a rotated or exited member's bond (`release_ring_bond@v1`): custody
/// succession AND the D2 lock gate it.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RingBondReleaseRequest {
    /// The departed member.
    pub member: AccountId,
    /// The configuration version the member departed from.
    pub departed_version: u64,
    /// The custody handover receipt.
    pub custody_receipt: super::CustodyHandoverReceipt,
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], String> {
    use dcrypt::algorithms::hash::{HashFunction, Sha256};
    let mut material = Vec::with_capacity(domain.len() + payload.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(payload);
    let digest = Sha256::digest(&material).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

#[cfg(test)]
#[path = "ring_selection_tests.rs"]
mod tests;
