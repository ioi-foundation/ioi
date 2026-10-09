//! SCQ-8.10 (OBS-6; build Ruling 12, P7), with SCQ-8.10a-e: the ring registry's genesis draw,
//! its handover by vacated-seat sortition with an identity-blind tenure cap, and the re-entry
//! bound (D1-D3). The selection rule itself is `ioi_types::app::ring_selection`; this module is
//! its state machine:
//!
//! - `publish_ring_selection_params@v1`: the parameters, once (a genesis registry key; a later
//!   change is the governance timelock's, not built here). Validated against the live ring's n.
//!   Parameters with non-floor seats (R >= 1) are REFUSED in every chain configuration (rulings
//!   2026-10-08 Q4, 15:16): no checker family covers R >= 1 yet ([`RingSelectionAdmission`]).
//! - `register_ring_member@v1` (materialize.rs) requires the parameters: `bond ≥ b` (D1), `D_act`
//!   from the parameters (D3), and an account whose bond is LOCKED (D2) cannot re-register.
//! - `declare_ring_exit@v1`: a live member (the signer) declares its exit.
//! - `commit_ring_handover_snapshot@v1`: the registry computes and commits the eligibility
//!   snapshot. With no live ring it is the GENESIS snapshot (every one of the n seats vacant);
//!   otherwise it first refuses a seat ledger in which a seated member's tenure is not its seat's
//!   phase (INHERITED PHASE), then fixes the exits, EVERY forced rotation (never deferred), the
//!   vacancies, the seat offsets and the activatable registrants.
//! - `record_ring_handover_beacon@v1`: at least `snapshot_to_beacon_events` ring events later,
//!   the registry DERIVES the reference beacon itself from the snapshot commitment and the block;
//!   a beacon claimed from old-ring signatures (or a VDF before R11) is refused. The REFERENCE
//!   beacon is REFERENCE-UNBOUNDED (predictable at snapshot time and recorder-choosable; no
//!   grinding bound exists for it), so EVERY chain configuration refuses it (rulings 2026-10-08
//!   Q1 (C); SCQ-8.10 (a)) and the ring plane fails closed until a bounded, unique-output source
//!   lands (OBS-6b). Only this crate's TEST builds admit it ([`RingSelectionAdmission`]).
//! - `publish_ring_genesis_config@v1` (materialize.rs): the genesis ring must be EXACTLY the
//!   selector's draw from the genesis snapshot and its beacon (SCQ-8.10c (v)); the registry sets
//!   the balanced tenure offsets itself (SCQ-8.10b (2)), records them, and keeps them as the
//!   seats' phases for the ring's life.
//! - `publish_ring_handover@v1` (materialize.rs): the seated old ring's unanimity and the KEPT
//!   members' acceptance stay the ACCEPTANCE gate (the joiners accept on chain, Q2), but the
//!   registry RECOMPUTES the draw from
//!   (snapshot, beacon) and refuses any successor (members or vacancies) that differs. The
//!   handover record keeps everything a verifier needs, with the alarms. Each joiner's tenure is
//!   its seat's phase, computed by the draw (never supplied), and the new ledger is checked
//!   against the seats' phases BEFORE anything is written.
//! - `accept_ring_handover_seat@v1` (rulings 2026-10-08 Q2, PROVISIONAL; NET's conditions
//!   (a)-(d) and B3): a drawn joiner accepts its seat ON CHAIN by s_h + Δ_b + W_acc, never inside
//!   the publication. Until it accepts it is ABSENT; once its window closes it departs at the next
//!   snapshot (refilled in the same capped fill order), and the next snapshot is refused while any
//!   window is open. An acceptance never changes a draw.
//! - `release_ring_bond@v1`: custody succession AND the D2 lock gate a departed member's bond.

use super::*;
use ioi_types::app::{
    acceptance_deadline, check_genesis_draw_feasible, draw_genesis_ring, draw_vacated_seats, genesis_seat_labels,
    genesis_snapshot, genesis_tenure_offsets, guardian_ring_bond_release_key, guardian_ring_handover_record_key,
    plan_handover_vacancies, reference_handover_beacon, verify_seat_phases,
    RingBeaconRecordRequest, RingBeaconSource, RingBondLock, RingBondReleaseRequest,
    RingHandoverRecord, RingHandoverSnapshot, RingPendingHandover, RingSeatDraw, RingSeatLedger,
    RingSelectionParams, GUARDIAN_RING_BOND_LOCKS_KEY, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY,
    GUARDIAN_RING_PENDING_EXITS_KEY, GUARDIAN_RING_SEAT_LEDGER_KEY,
    GUARDIAN_RING_SELECTION_PARAMS_KEY,
};

fn load<T: parity_scale_codec::Decode>(
    state: &dyn StateAccess,
    key: &[u8],
) -> Result<Option<T>, TransactionError> {
    state
        .get(key)?
        .map(|bytes| codec::from_bytes_canonical::<T>(&bytes).map_err(StateError::InvalidValue))
        .transpose()
        .map_err(TransactionError::State)
}

fn store<T: parity_scale_codec::Encode>(
    state: &mut dyn StateAccess,
    key: &[u8],
    value: &T,
) -> Result<(), TransactionError> {
    state.insert(
        key,
        &codec::to_bytes_canonical(value).map_err(TransactionError::Serialization)?,
    )?;
    Ok(())
}

/// Rulings 2026-10-08 Q1 (C) (14:54, restated 15:16) and Q4 (15:16): what the ring plane admits
/// beyond a chain configuration's fail-closed rules.
///
/// Every registry, whatever chain configuration built it, runs under `Chain`: it REFUSES the
/// REFERENCE-UNBOUNDED handover beacon (predictable at snapshot time and recorder-choosable, so no
/// grinding bound exists for it) and REFUSES ring parameters with non-floor seats (R >= 1: no
/// checker family covers them yet). The ring plane therefore fails closed until a bounded beacon
/// (OBS-6b) and NET's R >= 1 checker family exist.
///
/// `TestOnly` admits both, labelled REFERENCE-UNBOUNDED. It exists only in this crate's TEST
/// builds: the variant itself is `cfg(test)`, and it is reached only while a
/// [`RingSelectionTestAdmission`] guard is held on the calling thread (each libtest test runs on its
/// own thread). No configuration key, constructor or field reaches it, and a non-test build
/// compiles `Chain` alone. The paths that need it: the ring plane's own unit tests
/// (`tests_parts/ring_membership_plane.rs`), and no other (no local, single-node or Alpha path
/// draws a ring).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RingSelectionAdmission {
    /// Every chain configuration.
    Chain,
    /// TEST builds only: the ring plane's own unit tests (REFERENCE-UNBOUNDED).
    #[cfg(test)]
    TestOnly,
}

impl RingSelectionAdmission {
    /// Whether the REFERENCE-UNBOUNDED beacon and R >= 1 parameters are admitted: never in a
    /// non-test build.
    pub(crate) fn admits_reference_unbounded(self) -> bool {
        match self {
            Self::Chain => false,
            #[cfg(test)]
            Self::TestOnly => true,
        }
    }
}

#[cfg(test)]
thread_local! {
    static RING_SELECTION_TEST_ADMISSIONS: std::cell::Cell<u32> = std::cell::Cell::new(0);
}

/// TEST builds only: while a guard lives, every registry call on this thread runs under
/// [`RingSelectionAdmission::TestOnly`]; dropping the last guard restores `Chain`.
#[cfg(test)]
pub(crate) struct RingSelectionTestAdmission(());

#[cfg(test)]
impl RingSelectionTestAdmission {
    pub(crate) fn hold() -> Self {
        RING_SELECTION_TEST_ADMISSIONS.with(|held| held.set(held.get() + 1));
        Self(())
    }
}

#[cfg(test)]
impl Drop for RingSelectionTestAdmission {
    fn drop(&mut self) {
        RING_SELECTION_TEST_ADMISSIONS.with(|held| held.set(held.get().saturating_sub(1)));
    }
}

impl GuardianRegistry {
    /// The admission this registry's ring plane runs under ([`RingSelectionAdmission`]): `Chain`
    /// in every non-test build.
    pub(super) fn ring_selection_admission(&self) -> RingSelectionAdmission {
        #[cfg(test)]
        let admission = if RING_SELECTION_TEST_ADMISSIONS.with(|held| held.get() > 0) {
            RingSelectionAdmission::TestOnly
        } else {
            RingSelectionAdmission::Chain
        };
        #[cfg(not(test))]
        let admission = RingSelectionAdmission::Chain;
        admission
    }

    /// The ring selection parameters, or a typed refusal when none are configured: NO production
    /// value is hard-coded (the numbers author sets them).
    pub(super) fn load_ring_selection_params(
        state: &dyn StateAccess,
    ) -> Result<RingSelectionParams, TransactionError> {
        load(state, GUARDIAN_RING_SELECTION_PARAMS_KEY)?.ok_or_else(|| {
            TransactionError::Invalid(
                "ring selection parameters are not configured (publish_ring_selection_params@v1); \
                 the ring registry has no default values"
                    .into(),
            )
        })
    }

    /// The live ring's seat ledger. The genesis draw writes the first one (with the balanced
    /// offsets) and every handover the next, so a ledger that does not describe the live ring is
    /// refused (never re-created at tenure 0, which would synchronize every seat's rotation).
    /// Its phases are checked separately ([`verify_seat_phases`], at the snapshot).
    pub(super) fn load_ring_seat_ledger(
        state: &dyn StateAccess,
        live: &BoundaryRingConfig,
    ) -> Result<RingSeatLedger, TransactionError> {
        match load::<RingSeatLedger>(state, GUARDIAN_RING_SEAT_LEDGER_KEY)? {
            Some(ledger) if ledger.version == live.version => Ok(ledger),
            _ => Err(TransactionError::Invalid(
                "the ring seat ledger does not describe the live ring version".into(),
            )),
        }
    }

    /// The ring plane's event counter, without advancing it.
    pub(super) fn current_ring_event(state: &dyn StateAccess) -> Result<u64, TransactionError> {
        Ok(load::<u64>(state, ioi_types::app::GUARDIAN_RING_EVENT_COUNTER_KEY)?.unwrap_or(0))
    }

    pub(super) fn load_ring_bond_locks(
        state: &dyn StateAccess,
    ) -> Result<Vec<RingBondLock>, TransactionError> {
        Ok(load(state, GUARDIAN_RING_BOND_LOCKS_KEY)?.unwrap_or_default())
    }

    /// `publish_ring_selection_params@v1`: once, validated against the live ring (if any). Q4:
    /// parameters with non-floor seats (R >= 1) are refused unless the admission is TEST-only.
    pub(super) fn materialize_ring_selection_params(
        state: &mut dyn StateAccess,
        params: RingSelectionParams,
        admission: RingSelectionAdmission,
    ) -> Result<(), TransactionError> {
        // Q4 (rulings 2026-10-08 15:16): non-floor seats (R >= 1) have no checker family yet, so
        // every chain configuration refuses them (fail closed). R = 0: the floors sum to n.
        let floor_total: u64 = params
            .floors
            .iter()
            .map(|floor| u64::from(floor.min_seats))
            .sum();
        if !admission.admits_reference_unbounded() && floor_total != u64::from(params.ring_seats) {
            return Err(TransactionError::Invalid(format!(
                "ring selection: R >= 1 (the floors cover {floor_total} of n={} seats) is refused in every chain configuration until NET's R >= 1 checker family exists (rulings 2026-10-08 Q4)",
                params.ring_seats
            )));
        }
        if state.get(GUARDIAN_RING_SELECTION_PARAMS_KEY)?.is_some() {
            return Err(TransactionError::Invalid(
                "ring selection parameters are already set; a change goes through the governance timelock"
                    .into(),
            ));
        }
        let seat_count = Self::load_live_ring_config(state)?.map(|live| live.seat_count());
        params
            .validate(seat_count)
            .map_err(TransactionError::Invalid)?;
        store(state, GUARDIAN_RING_SELECTION_PARAMS_KEY, &params)
    }

    /// `declare_ring_exit@v1`: the signer, a live member, declares its exit for the next handover.
    pub(super) fn materialize_ring_exit_declaration(
        state: &mut dyn StateAccess,
        member: AccountId,
        signer: AccountId,
    ) -> Result<(), TransactionError> {
        if member != signer {
            return Err(TransactionError::Invalid(
                "only the member itself may declare its ring exit".into(),
            ));
        }
        let Some(live) = Self::load_live_ring_config(state)? else {
            return Err(TransactionError::Invalid(
                "no live ring configuration exists".into(),
            ));
        };
        if !live.members.contains(&member) {
            return Err(TransactionError::Invalid(
                "only a live ring member may declare an exit".into(),
            ));
        }
        let mut exits: BTreeSet<AccountId> =
            load(state, GUARDIAN_RING_PENDING_EXITS_KEY)?.unwrap_or_default();
        exits.insert(member);
        Self::bump_ring_event_counter(state)?;
        store(state, GUARDIAN_RING_PENDING_EXITS_KEY, &exits)
    }

    /// `commit_ring_handover_snapshot@v1`: commits the eligibility snapshot the next draw uses
    /// (the genesis draw when no live ring exists). One pending snapshot at a time.
    pub(super) fn materialize_ring_handover_snapshot(
        state: &mut dyn StateAccess,
    ) -> Result<(), TransactionError> {
        if state.get(GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?.is_some() {
            return Err(TransactionError::Invalid(
                "a ring handover snapshot is already pending".into(),
            ));
        }
        let params = Self::load_ring_selection_params(state)?;
        let snapshot = match Self::load_live_ring_config(state)? {
            None => {
                params.validate(None).map_err(TransactionError::Invalid)?;
                // Review r1 MAJOR-2: a genesis snapshot the genesis draw cannot fill is refused, and
                // the refusal writes nothing (the event is bumped only after the check): a pending
                // snapshot leaves only through a successful settlement, so taking an infeasible one
                // would block the ring's start for good.
                let snapshot_event = Self::current_ring_event(state)?.saturating_add(1);
                let candidates: Vec<RingMemberRegistration> = Self::load_ring_queue(state)?
                    .activatable_at(snapshot_event)
                    .into_iter()
                    .cloned()
                    .collect();
                let snapshot =
                    genesis_snapshot(snapshot_event, params.ring_seats, candidates, &params)
                        .map_err(TransactionError::Invalid)?;
                check_genesis_draw_feasible(&snapshot).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "the genesis draw cannot succeed over this snapshot, so it is not taken: {e}"
                    ))
                })?;
                if Self::bump_ring_event_counter(state)? != snapshot_event {
                    return Err(TransactionError::Invalid(
                        "the ring event counter moved while the genesis snapshot was taken".into(),
                    ));
                }
                snapshot
            }
            Some(live) => Self::handover_snapshot(state, &params, &live)?,
        };
        let commitment = snapshot.commitment().map_err(TransactionError::Invalid)?;
        store(
            state,
            GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY,
            &RingPendingHandover {
                snapshot,
                commitment,
                beacon: None,
                accepted_joiners: Vec::new(),
            },
        )
    }

    fn handover_snapshot(
        state: &mut dyn StateAccess,
        params: &RingSelectionParams,
        live: &BoundaryRingConfig,
    ) -> Result<RingHandoverSnapshot, TransactionError> {
        params
            .validate(Some(live.seat_count()))
            .map_err(TransactionError::Invalid)?;
        live.seats().map_err(TransactionError::Invalid)?;
        let ledger = Self::load_ring_seat_ledger(state, live)?;
        // INHERITED PHASE: every seated member holds its seat's phase, or no snapshot is taken.
        verify_seat_phases(
            &live.members,
            &live.vacant_seats,
            &ledger.tenure,
            &ledger.seat_offsets,
            ledger.handover_index,
            params.tenure_handovers,
        )
        .map_err(TransactionError::Invalid)?;
        // Q2 (c) and B3: every acceptance decision of the previous handover is fixed BEFORE this
        // snapshot: while a joiner's window is open, no snapshot is taken.
        let now = Self::current_ring_event(state)?;
        if let Some((joiner, deadline)) = ledger
            .awaiting_acceptance
            .iter()
            .find(|(_, deadline)| now < *deadline)
        {
            return Err(TransactionError::Invalid(format!(
                "a drawn joiner's acceptance window is open until ring event {deadline} ({joiner:?}); the next snapshot waits for it"
            )));
        }
        // The declared exits, and (Q2 (b), (d)) every joiner that did not accept: a departure.
        let exits: BTreeSet<AccountId> =
            load::<BTreeSet<AccountId>>(state, GUARDIAN_RING_PENDING_EXITS_KEY)?
                .unwrap_or_default()
                .into_iter()
                .chain(ledger.awaiting_acceptance.iter().map(|(joiner, _)| *joiner))
                .filter(|member| live.members.contains(member))
                .collect();
        let snapshot_event = Self::bump_ring_event_counter(state)?;
        let candidates: Vec<RingMemberRegistration> = Self::load_ring_queue(state)?
            .activatable_at(snapshot_event)
            .into_iter()
            .filter(|entry| !live.members.contains(&entry.account_id))
            .cloned()
            .collect();
        let plan = plan_handover_vacancies(
            &live.members,
            &ledger.tenure,
            &exits,
            params.tenure_handovers,
        );
        let vacated_set = plan
            .exits
            .iter()
            .chain(plan.forced_rotations.iter())
            .copied()
            .collect();
        Ok(RingHandoverSnapshot {
            live_version: live.version,
            snapshot_event,
            seat_count: live.seat_count() as u32,
            members: live.members.clone(),
            vacancies: live.vacant_seats.clone(),
            handover_index: ledger.handover_index,
            seat_offsets: ledger.seat_offsets.clone(),
            tenure_counters: ledger.tenure.iter().map(|(a, t)| (*a, *t)).collect(),
            member_constituencies: ledger
                .constituencies
                .iter()
                .map(|(a, c)| (*a, *c))
                .collect(),
            seat_constituencies: ledger.seat_constituencies.clone(),
            exits: plan.exits,
            vacated_set,
            forced_rotations: plan.forced_rotations,
            churn_cap: params.churn_cap,
            tenure_handovers: params.tenure_handovers,
            candidates,
            floors: params.floors.clone(),
            floors_ref: params.floors_ref().map_err(TransactionError::Invalid)?,
        })
    }

    /// `record_ring_handover_beacon@v1`: records the pending snapshot's beacon, derived by the
    /// registry, strictly after the snapshot and at least `snapshot_to_beacon_events` later.
    pub(super) fn materialize_ring_handover_beacon(
        state: &mut dyn StateAccess,
        request: RingBeaconRecordRequest,
        block_height: u64,
        block_timestamp: u64,
        admission: RingSelectionAdmission,
    ) -> Result<(), TransactionError> {
        match request.source {
            // Q1 (C): fail closed in every chain configuration, before anything is read or written.
            RingBeaconSource::Reference if !admission.admits_reference_unbounded() => {
                return Err(TransactionError::Invalid(
                    "REFERENCE-UNBOUNDED: the reference handover beacon is predictable at snapshot \
                     time and recorder-choosable, so every chain configuration refuses it \
                     (SCQ-8.10 (a); rulings 2026-10-08 Q1 (C)); only a bounded, unique-output \
                     source may draw (OBS-6b)"
                        .into(),
                ))
            }
            RingBeaconSource::Reference => {}
            RingBeaconSource::OldRingSignatures => return Err(TransactionError::Invalid(
                "a ring handover beacon is never derived from old-ring signatures or approvals \
                     (a last revealer could grind it)"
                    .into(),
            )),
            RingBeaconSource::Vdf => return Err(TransactionError::Invalid(
                "the VDF beacon is R11's and is not available yet".into(),
            )),
        }
        let params = Self::load_ring_selection_params(state)?;
        let Some(mut pending) =
            load::<RingPendingHandover>(state, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?
        else {
            return Err(TransactionError::Invalid(
                "no ring handover snapshot is pending".into(),
            ));
        };
        if pending.commitment != request.snapshot_commitment {
            return Err(TransactionError::Invalid(
                "the beacon request names another snapshot".into(),
            ));
        }
        if pending.beacon.is_some() {
            return Err(TransactionError::Invalid(
                "the pending handover's beacon is already recorded".into(),
            ));
        }
        // The check precedes the event bump, so a refused attempt changes nothing (with or without
        // transaction rollback). The beacon's own event counts: with an interval k, k-1 other
        // ring transactions land between the snapshot and the beacon.
        let next_event = Self::current_ring_event(state)?.saturating_add(1);
        if next_event < pending.snapshot.snapshot_event + params.snapshot_to_beacon_events {
            return Err(TransactionError::Invalid(format!(
                "the beacon may be recorded only {} ring events after the snapshot",
                params.snapshot_to_beacon_events
            )));
        }
        let beacon_event = Self::bump_ring_event_counter(state)?;
        let beacon = reference_handover_beacon(&pending.commitment, block_height, block_timestamp)
            .map_err(TransactionError::Invalid)?;
        pending.beacon = Some((beacon, RingBeaconSource::Reference, beacon_event));
        store(state, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY, &pending)
    }

    /// `accept_ring_handover_seat@v1` (Q2, PROVISIONAL; module docs, 8.): the signer, a joiner
    /// drawn by the handover whose snapshot commitment it names, accepts its seat on chain while
    /// the ring event counter is below that handover's deadline: before the publication (the
    /// pending draw's joiner) or after it (a joiner the live ledger awaits). Only the joiner itself
    /// accepts; an acceptance never changes the draw or the fill (B3), only the joiner's absence.
    /// It is not a ring event.
    pub(super) fn materialize_ring_seat_acceptance(
        state: &mut dyn StateAccess,
        commitment: [u8; 32],
        signer: AccountId,
    ) -> Result<(), TransactionError> {
        let Some(live) = Self::load_live_ring_config(state)? else {
            return Err(TransactionError::Invalid(
                "no live ring: a genesis seat needs no acceptance".into(),
            ));
        };
        let params = Self::load_ring_selection_params(state)?;
        let now = Self::current_ring_event(state)?;
        let pending = load::<RingPendingHandover>(state, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?;
        if let Some(mut pending) = pending.filter(|p| p.commitment == commitment) {
            let (_, draw) = Self::recompute_ring_handover_draw(state, &live)?;
            if !draw.joiners.contains(&signer) {
                return Err(TransactionError::Invalid(
                    "only a joiner of the drawn handover accepts its own seat".into(),
                ));
            }
            if pending.accepted_joiners.contains(&signer) {
                return Err(TransactionError::Invalid(
                    "this joiner's acceptance is already recorded".into(),
                ));
            }
            if now >= acceptance_deadline(&params, pending.snapshot.snapshot_event) {
                return Err(TransactionError::Invalid(
                    "the acceptance deadline has passed".into(),
                ));
            }
            pending.accepted_joiners.push(signer);
            pending.accepted_joiners.sort();
            return store(state, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY, &pending);
        }
        let mut ledger = Self::load_ring_seat_ledger(state, &live)?;
        if ledger.acceptance_commitment != commitment {
            return Err(TransactionError::Invalid(
                "the acceptance names no handover awaiting it".into(),
            ));
        }
        let Some(at) = ledger
            .awaiting_acceptance
            .iter()
            .position(|(joiner, _)| *joiner == signer)
        else {
            return Err(TransactionError::Invalid(
                "only a joiner the live ring awaits accepts its own seat".into(),
            ));
        };
        if now >= ledger.awaiting_acceptance[at].1 {
            return Err(TransactionError::Invalid(
                "the acceptance deadline has passed".into(),
            ));
        }
        ledger.awaiting_acceptance.remove(at);
        store(state, GUARDIAN_RING_SEAT_LEDGER_KEY, &ledger)
    }

    fn pending_with_beacon(
        state: &dyn StateAccess,
    ) -> Result<(RingPendingHandover, [u8; 32]), TransactionError> {
        let Some(pending) =
            load::<RingPendingHandover>(state, GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?
        else {
            return Err(TransactionError::Invalid(
                "a ring draw needs a committed snapshot and its recorded beacon first".into(),
            ));
        };
        let Some((beacon, _, _)) = pending.beacon else {
            return Err(TransactionError::Invalid(
                "the pending snapshot's beacon is not recorded yet".into(),
            ));
        };
        Ok((pending, beacon))
    }

    /// The draw the pending handover's (snapshot, beacon) dictates; the handover publication must
    /// name exactly its successor ring (members and vacancies).
    pub(super) fn recompute_ring_handover_draw(
        state: &dyn StateAccess,
        live: &BoundaryRingConfig,
    ) -> Result<(RingPendingHandover, RingSeatDraw), TransactionError> {
        let (pending, beacon) = Self::pending_with_beacon(state)?;
        if pending.snapshot.is_genesis() || pending.snapshot.live_version != live.version {
            return Err(TransactionError::Invalid(
                "the pending snapshot is for another live ring version".into(),
            ));
        }
        let draw =
            draw_vacated_seats(&pending.snapshot, &beacon).map_err(TransactionError::Invalid)?;
        Ok((pending, draw))
    }

    /// The genesis draw the pending GENESIS snapshot and its beacon dictate (SCQ-8.10c (v)).
    pub(super) fn recompute_ring_genesis_draw(
        state: &dyn StateAccess,
    ) -> Result<(RingPendingHandover, RingSeatDraw), TransactionError> {
        let (pending, beacon) = Self::pending_with_beacon(state)?;
        if !pending.snapshot.is_genesis() {
            return Err(TransactionError::Invalid(
                "the pending snapshot is not a genesis snapshot".into(),
            ));
        }
        let draw =
            draw_genesis_ring(&pending.snapshot, &beacon).map_err(TransactionError::Invalid)?;
        Ok((pending, draw))
    }

    /// After a verified genesis draw: the seat ledger starts every member at its BALANCED offset
    /// (SCQ-8.10b (2)), computed here from the recorded beacon (never supplied), and the record
    /// keeps the offsets so a verifier recomputes them.
    pub(super) fn settle_ring_genesis(
        state: &mut dyn StateAccess,
        config: &BoundaryRingConfig,
        pending: &RingPendingHandover,
        draw: &RingSeatDraw,
    ) -> Result<(), TransactionError> {
        let params = Self::load_ring_selection_params(state)?;
        let (beacon, beacon_source, _) = pending
            .beacon
            .ok_or_else(|| TransactionError::Invalid("the beacon is not recorded".into()))?;
        // The balanced offsets, from the recorded beacon (the draw carries the same values).
        let offsets = genesis_tenure_offsets(&beacon, &config.members, params.tenure_handovers);
        let candidates: BTreeMap<AccountId, u32> = pending
            .snapshot
            .candidates
            .iter()
            .map(|c| (c.account_id, c.constituency_id))
            .collect();
        // The offsets are the seats' phases at the genesis draw (handover 0), kept for the
        // ring's life: every later occupant of a seat inherits the seat's phase.
        let ledger = RingSeatLedger {
            version: config.version,
            handover_index: 0,
            tenure: offsets.iter().copied().collect(),
            constituencies: config
                .members
                .iter()
                .filter_map(|member| candidates.get(member).map(|c| (*member, *c)))
                .collect(),
            seat_offsets: offsets.iter().map(|(_, offset)| *offset).collect(),
            // Q4: at R = 0 each seat's constituency label, fixed here for the ring's life.
            seat_constituencies: genesis_seat_labels(
                &pending.snapshot.floors,
                &config.members,
                &candidates,
            )
            .map_err(TransactionError::Invalid)?,
            ..Default::default()
        };
        verify_seat_phases(
            &config.members,
            &config.vacant_seats,
            &ledger.tenure,
            &ledger.seat_offsets,
            ledger.handover_index,
            params.tenure_handovers,
        )
        .map_err(TransactionError::Invalid)?;
        store(state, GUARDIAN_RING_SEAT_LEDGER_KEY, &ledger)?;
        store(
            state,
            &guardian_ring_handover_record_key(config.version),
            &RingHandoverRecord {
                new_version: config.version,
                snapshot_commitment: pending.commitment,
                beacon,
                beacon_source,
                vacated_set: Vec::new(),
                tenure_counters: offsets,
                floors_ref: pending.snapshot.floors_ref,
                successor_vacancies: Vec::new(),
                alarms: draw.alarms.clone(),
                outside_selection_model: draw.outside_selection_model,
            },
        )?;
        state.delete(GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?;
        Ok(())
    }

    /// After a verified handover: the record (with its alarms), the seat ledger, the exits, the
    /// D2 locks and the pending snapshot are settled. The new ledger is computed and checked
    /// against the seats' phases FIRST, so a refusal writes nothing.
    pub(super) fn settle_ring_handover(
        state: &mut dyn StateAccess,
        live: &BoundaryRingConfig,
        new_config: &BoundaryRingConfig,
        pending: &RingPendingHandover,
        draw: &RingSeatDraw,
        current_event: u64,
    ) -> Result<(), TransactionError> {
        let params = Self::load_ring_selection_params(state)?;
        let (beacon, beacon_source, _) = pending
            .beacon
            .ok_or_else(|| TransactionError::Invalid("the beacon is not recorded".into()))?;

        let old_ledger = Self::load_ring_seat_ledger(state, live)?;
        // Each joiner holds its seat's phase (the draw's `joiner_tenure`), never a value the
        // publisher supplies; a kept member's counter advances with its seat.
        let joined: BTreeMap<AccountId, u32> = draw.joiner_tenure.iter().copied().collect();
        let candidates: BTreeMap<AccountId, u32> = pending
            .snapshot
            .candidates
            .iter()
            .map(|c| (c.account_id, c.constituency_id))
            .collect();
        let mut ledger = RingSeatLedger {
            version: new_config.version,
            handover_index: old_ledger.handover_index.saturating_add(1),
            seat_offsets: old_ledger.seat_offsets.clone(),
            seat_constituencies: old_ledger.seat_constituencies.clone(),
            // Q2 (PROVISIONAL): the joiners that have not accepted on chain are ABSENT until they
            // do, each with this handover's deadline.
            awaiting_acceptance: draw
                .joiners
                .iter()
                .filter(|joiner| !pending.accepted_joiners.contains(joiner))
                .map(|joiner| {
                    (
                        *joiner,
                        acceptance_deadline(&params, pending.snapshot.snapshot_event),
                    )
                })
                .collect(),
            acceptance_commitment: pending.commitment,
            ..Default::default()
        };
        for member in &new_config.members {
            if let Some(start) = joined.get(member) {
                ledger.tenure.insert(*member, *start);
                if let Some(constituency) = candidates.get(member) {
                    ledger.constituencies.insert(*member, *constituency);
                }
            } else {
                let served = old_ledger.tenure.get(member).copied().unwrap_or(0);
                ledger.tenure.insert(*member, served.saturating_add(1));
                if let Some(constituency) = old_ledger.constituencies.get(member) {
                    ledger.constituencies.insert(*member, *constituency);
                }
            }
        }
        // INHERITED PHASE, checked before any write: every seated member of the successor holds
        // its seat's phase after this handover.
        verify_seat_phases(
            &new_config.members,
            &new_config.vacant_seats,
            &ledger.tenure,
            &ledger.seat_offsets,
            ledger.handover_index,
            params.tenure_handovers,
        )
        .map_err(TransactionError::Invalid)?;

        store(
            state,
            &guardian_ring_handover_record_key(new_config.version),
            &RingHandoverRecord {
                new_version: new_config.version,
                snapshot_commitment: pending.commitment,
                beacon,
                beacon_source,
                vacated_set: pending.snapshot.vacated_set.clone(),
                tenure_counters: pending.snapshot.tenure_counters.clone(),
                floors_ref: pending.snapshot.floors_ref,
                successor_vacancies: draw.successor_vacancies.clone(),
                alarms: draw.alarms.clone(),
                outside_selection_model: draw.outside_selection_model,
            },
        )?;
        store(state, GUARDIAN_RING_SEAT_LEDGER_KEY, &ledger)?;

        let mut exits: BTreeSet<AccountId> =
            load(state, GUARDIAN_RING_PENDING_EXITS_KEY)?.unwrap_or_default();
        for member in &draw.departed {
            exits.remove(member);
        }
        store(state, GUARDIAN_RING_PENDING_EXITS_KEY, &exits)?;

        let mut locks = Self::load_ring_bond_locks(state)?;
        for member in &draw.departed {
            locks.push(RingBondLock {
                member: *member,
                amount: live.member_bonds.get(member).copied().unwrap_or(0),
                departed_version: live.version,
                locked_until_event: current_event.saturating_add(params.bond_lock_events),
            });
        }
        store(state, GUARDIAN_RING_BOND_LOCKS_KEY, &locks)?;
        state.delete(GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)?;
        Ok(())
    }

    /// `release_ring_bond@v1`: a departed member's bond releases only after its D2 lock expires
    /// AND custody succession is shown (`authorize_bond_release`).
    pub(super) fn materialize_ring_bond_release(
        state: &mut dyn StateAccess,
        request: RingBondReleaseRequest,
    ) -> Result<(), TransactionError> {
        let mut locks = Self::load_ring_bond_locks(state)?;
        let Some(position) = locks.iter().position(|lock| {
            lock.member == request.member && lock.departed_version == request.departed_version
        }) else {
            return Err(TransactionError::Invalid(
                "no locked ring bond exists for that member and version".into(),
            ));
        };
        let next_event = Self::current_ring_event(state)?.saturating_add(1);
        if locks[position].is_locked_at(next_event) {
            return Err(TransactionError::Invalid(format!(
                "the ring bond is locked until ring event {} (D2)",
                locks[position].locked_until_event
            )));
        }
        let release = ioi_types::app::authorize_bond_release(
            &request.member,
            request.departed_version,
            &request.custody_receipt,
        )
        .map_err(TransactionError::Invalid)?;
        Self::bump_ring_event_counter(state)?;
        locks.remove(position);
        store(state, GUARDIAN_RING_BOND_LOCKS_KEY, &locks)?;
        store(
            state,
            &guardian_ring_bond_release_key(&request.member, request.departed_version),
            &release,
        )
    }
}
