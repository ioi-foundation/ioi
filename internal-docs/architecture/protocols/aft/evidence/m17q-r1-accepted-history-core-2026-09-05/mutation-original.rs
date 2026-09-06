//! Accepted-history transition state. Persistence is the member store's job;
//! neither a staged transition nor its encoded bytes authorize an executor.

use super::{QuvError, QuvHash, QuvOnlineAuthorizationV0, QuvSlotV0, STORE_MAX_SLOTS};
use parity_scale_codec::{Decode, Encode};
use std::time::Instant;

/// A provisioned initial coordinate and the accepted candidate at each later
/// position. Historical predecessors remain available after local advancement.
/// This type has no method accepting a remote audit or first-seen candidate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct QuvAcceptedHistoryV0 {
    initial: QuvSlotV0,
    accepted: Vec<QuvHash>,
}

impl QuvAcceptedHistoryV0 {
    /// Construct from an independently provisioned fixed bootstrap. The caller
    /// must not derive this coordinate from an incoming candidate or transcript.
    pub fn from_provisioned_initial(initial: QuvSlotV0) -> Result<Self, QuvError> {
        let state = Self {
            initial,
            accepted: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Check canonical state after authenticated decoding. This does not verify
    /// storage authentication, rollback custody, or the provenance of a bootstrap.
    pub fn validate(&self) -> Result<(), QuvError> {
        if self.initial.slot == 0
            || self.initial.configuration_root == [0; 32]
            || self.initial.policy_root == [0; 32]
            || self.initial.network_id == [0; 32]
            || self.initial.domain_id == [0; 32]
            || self.initial.predecessor == [0; 32]
            || self.accepted.len() > STORE_MAX_SLOTS
            || self.accepted.iter().any(|value| *value == [0; 32])
            || (!self.accepted.is_empty()
                && self
                    .initial
                    .slot
                    .checked_add((self.accepted.len() - 1) as u64)
                    .is_none())
        {
            return Err(QuvError::InvalidAcceptedHistory);
        }
        Ok(())
    }

    /// Return the next unaccepted slot, or None when the u64 slot space is used.
    pub fn next_slot(&self) -> Option<u64> {
        self.initial.slot.checked_add(self.accepted.len() as u64)
    }

    /// Derive a predecessor only for a retained historical slot or the next slot.
    pub fn expected_predecessor(&self, slot: u64) -> Result<QuvHash, QuvError> {
        let offset = slot
            .checked_sub(self.initial.slot)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(QuvError::UnexpectedHead)?;
        if offset > self.accepted.len() {
            return Err(QuvError::UnexpectedHead);
        }
        Ok(if offset == 0 {
            self.initial.predecessor
        } else {
            self.accepted[offset - 1]
        })
    }

    /// Validate exact scope and the locally derived historical/next predecessor.
    pub fn check_slot(&self, slot: &QuvSlotV0) -> Result<(), QuvError> {
        if slot.configuration_root != self.initial.configuration_root
            || slot.policy_root != self.initial.policy_root
            || slot.network_id != self.initial.network_id
            || slot.domain_id != self.initial.domain_id
            || slot.authority_mode != self.initial.authority_mode
            || slot.predecessor != self.expected_predecessor(slot.slot)?
        {
            return Err(QuvError::UnexpectedHead);
        }
        Ok(())
    }

    /// Stage an advancement from this relying member's own process-local grant.
    /// Returns false for an exact historical repeat. The caller must durably
    /// commit the staged state before exposing the advanced head. This does not
    /// consume the grant needed for the separate immediate T10 claim checks.
    pub fn record_live_authorization(
        &mut self,
        authorization: &QuvOnlineAuthorizationV0,
    ) -> Result<bool, QuvError> {
        self.record_live_authorization_at(authorization, Instant::now())
    }

    pub(super) fn record_live_authorization_at(
        &mut self,
        authorization: &QuvOnlineAuthorizationV0,
        observed: Instant,
    ) -> Result<bool, QuvError> {
        if observed >= authorization.expires_at {
            return Err(QuvError::ExpiredAuthorization);
        }
        self.check_slot(&authorization.slot)?;
        if authorization.candidate_hash == [0; 32] {
            return Err(QuvError::InvalidAcceptedHistory);
        }
        let offset = usize::try_from(authorization.slot.slot - self.initial.slot)
            .map_err(|_| QuvError::UnexpectedHead)?;
        if offset < self.accepted.len() {
            return if self.accepted[offset] == authorization.candidate_hash {
                Ok(false)
            } else {
                Err(QuvError::ConflictingAcceptedHistory)
            };
        }
        if self.accepted.len() >= STORE_MAX_SLOTS {
            return Err(QuvError::StoreCapacityExceeded);
        }
        self.accepted.push(authorization.candidate_hash);
        Ok(true)
    }
}
