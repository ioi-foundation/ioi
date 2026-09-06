//! Typed member-journal replay. Authenticated storage restores retained state;
//! none of these records can construct a process-local online authorization.
//! Shared by validated live staging and authenticated storage replay.
//! Persistence and online authority checks remain the caller's responsibility.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(super) enum MemberDelta {
    InsertCandidate(QuvCandidateV0),
    ReservePreparation {
        candidate: QuvCandidateV0,
        used: u16,
    },
    AcceptHead {
        slot: QuvSlotV0,
        candidate_hash: QuvHash,
    },
}

/// Apply to unpublished temporary memory after live admission validation, or
/// after the complete journal chain and independent bootstrap authenticate.
/// Rooted candidate authentication and preparation policy limits remain live
/// admission checks. This validates transition order, exact scope, retained
/// candidates and counters; it never constructs an online grant.
#[cfg(test)]
pub(super) fn apply_member_delta(
    state: &mut QuvStoreStateV0,
    generation: u64,
    delta: &MemberDelta,
) -> Result<(), QuvError> {
    prepare_member_delta(state, generation, delta)?.apply(state)
}

pub(super) struct PreparedMemberDelta<'a> {
    delta: &'a MemberDelta,
    generation: u64,
}

pub(super) fn prepare_member_delta<'a>(
    state: &QuvStoreStateV0,
    generation: u64,
    delta: &'a MemberDelta,
) -> Result<PreparedMemberDelta<'a>, QuvError> {
    if state.generation.checked_add(1) != Some(generation) {
        return Err(QuvError::RollbackOrFork);
    }
    match delta {
        MemberDelta::InsertCandidate(candidate) => {
            state
                .domains
                .get(&candidate.slot.domain_id)
                .ok_or(QuvError::UnexpectedHead)?
                .check_slot(&candidate.slot)?;
            let coordinate = QuvConflictSlotV0::from(&candidate.slot);
            let hash = quv_candidate_hash(candidate)?;
            let snapshot = state
                .slots
                .get(&coordinate)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if snapshot
                .iter()
                .any(|retained| quv_candidate_hash(retained).ok() == Some(hash))
            {
                return Err(QuvError::CorruptStore);
            }
            if snapshot.len() >= STORE_MAX_CANDIDATES_PER_SLOT {
                return Err(QuvError::SlotCapacityExceeded);
            }
            if !state.slots.contains_key(&coordinate) && state.slots.len() >= STORE_MAX_SLOTS {
                return Err(QuvError::StoreCapacityExceeded);
            }
        }
        MemberDelta::ReservePreparation { candidate, used } => {
            let domain = state
                .domains
                .get(&candidate.slot.domain_id)
                .ok_or(QuvError::UnexpectedHead)?;
            if domain.next_query_slot().as_ref() != Some(&candidate.slot) {
                return Err(QuvError::UnexpectedHead);
            }
            let snapshot = state
                .slots
                .get(&QuvConflictSlotV0::from(&candidate.slot))
                .ok_or(QuvError::InvalidAcceptedHistory)?;
            if !snapshot.contains(candidate) {
                return Err(QuvError::InvalidAcceptedHistory);
            }
            if candidate.slot.authority_mode == QuvAuthorityModeV0::Owned && snapshot.len() != 1 {
                return Err(QuvError::ConflictDisclosed);
            }
            let previous = state.preparation_attempts.get(&candidate.slot.domain_id);
            if previous.is_some_and(|attempts| attempts.slot != candidate.slot.slot)
                || previous.map_or(0, |attempts| attempts.used).checked_add(1) != Some(*used)
            {
                return Err(QuvError::CorruptStore);
            }
        }
        MemberDelta::AcceptHead {
            slot,
            candidate_hash,
        } => {
            if !state
                .slots
                .get(&QuvConflictSlotV0::from(slot))
                .is_some_and(|snapshot| {
                    snapshot.iter().any(|candidate| {
                        candidate.slot == *slot
                            && quv_candidate_hash(candidate).ok() == Some(*candidate_hash)
                    })
                })
            {
                return Err(QuvError::InvalidAcceptedHistory);
            }
            if state
                .domains
                .get(&slot.domain_id)
                .ok_or(QuvError::UnexpectedHead)?
                .projected_retained_growth(slot, *candidate_hash)?
                == 0
            {
                return Err(QuvError::InvalidAcceptedHistory);
            }
        }
    }
    Ok(PreparedMemberDelta { delta, generation })
}

impl PreparedMemberDelta<'_> {
    /// Exact logical SCALE size, using the caller's cached current size. This
    /// walks only the affected bounded candidate/coordinate, not retained state.
    pub(super) fn projected_size(
        &self,
        state: &QuvStoreStateV0,
        current: usize,
    ) -> Result<usize, QuvError> {
        match self.delta {
            MemberDelta::InsertCandidate(candidate) => projected_member_state_size_from_current(
                state,
                &QuvConflictSlotV0::from(&candidate.slot),
                candidate,
                current,
            ),
            MemberDelta::ReservePreparation { candidate, .. } => {
                let growth = if state
                    .preparation_attempts
                    .contains_key(&candidate.slot.domain_id)
                {
                    0
                } else {
                    42 + compact_length_size(state.preparation_attempts.len() + 1)?
                        - compact_length_size(state.preparation_attempts.len())?
                };
                current
                    .checked_add(growth)
                    .ok_or(QuvError::StoreCapacityExceeded)
            }
            MemberDelta::AcceptHead {
                slot,
                candidate_hash,
            } => {
                let growth = state
                    .domains
                    .get(&slot.domain_id)
                    .ok_or(QuvError::UnexpectedHead)?
                    .projected_retained_growth(slot, *candidate_hash)?;
                let retired = if state.preparation_attempts.contains_key(&slot.domain_id) {
                    42 + compact_length_size(state.preparation_attempts.len())?
                        - compact_length_size(state.preparation_attempts.len() - 1)?
                } else {
                    0
                };
                current
                    .checked_sub(retired)
                    .and_then(|size| size.checked_add(growth))
                    .ok_or(QuvError::StoreCapacityExceeded)
            }
        }
    }

    /// Apply only to the same exclusive state that was prepared. No authority
    /// check is performed here: live grants and authenticated replay custody
    /// are distinct caller obligations. A persistence caller must quarantine on
    /// any unexpected apply error after its durable commit.
    pub(super) fn apply(self, state: &mut QuvStoreStateV0) -> Result<(), QuvError> {
        if state.generation.checked_add(1) != Some(self.generation) {
            return Err(QuvError::RollbackOrFork);
        }
        match self.delta {
            MemberDelta::InsertCandidate(candidate) => {
                state
                    .slots
                    .entry(QuvConflictSlotV0::from(&candidate.slot))
                    .or_default()
                    .push(candidate.clone());
            }
            MemberDelta::ReservePreparation { candidate, used } => {
                state.preparation_attempts.insert(
                    candidate.slot.domain_id,
                    QuvPreparationAttemptsV0 {
                        slot: candidate.slot.slot,
                        used: *used,
                    },
                );
            }
            MemberDelta::AcceptHead {
                slot,
                candidate_hash,
            } => {
                state
                    .domains
                    .get_mut(&slot.domain_id)
                    .ok_or(QuvError::UnexpectedHead)?
                    .stage_retained_acceptance(slot, *candidate_hash)?;
                state.preparation_attempts.remove(&slot.domain_id);
            }
        }
        state.generation = self.generation;
        Ok(())
    }
}
