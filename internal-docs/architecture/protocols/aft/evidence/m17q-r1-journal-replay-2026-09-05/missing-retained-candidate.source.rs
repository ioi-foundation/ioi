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
pub(super) fn apply_member_delta(
    state: &mut QuvStoreStateV0,
    generation: u64,
    delta: &MemberDelta,
) -> Result<(), QuvError> {
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
            state
                .slots
                .entry(coordinate)
                .or_default()
                .push(candidate.clone());
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
    state.generation = generation;
    Ok(())
}
