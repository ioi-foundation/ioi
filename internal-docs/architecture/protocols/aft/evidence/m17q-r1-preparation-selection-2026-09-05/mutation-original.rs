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

/// Independently enrolled member domain. Handoff domains are one-shot boundary
/// queries; their exact predecessor still requires local boundary validation.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum QuvMemberDomainV0 {
    /// Fixed bootstrap and this member's retained accepted history.
    Fixed(QuvAcceptedHistoryV0),
    /// Provisioned activation coordinate. Its zero predecessor is a rule
    /// placeholder, never an accepted candidate or a permitted request value.
    HandoffBoundary(QuvSlotV0),
}

impl QuvMemberDomainV0 {
    /// Enroll from configured roots and a typed bootstrap, never request bytes.
    pub fn from_provisioned_bootstrap(
        configuration_root: QuvHash,
        policy_root: QuvHash,
        network_id: QuvHash,
        domain_id: QuvHash,
        authority_mode: super::QuvAuthorityModeV0,
        bootstrap: &ioi_types::app::QuvDomainBootstrapV0,
    ) -> Result<Self, QuvError> {
        use ioi_types::app::QuvDomainBootstrapV0;
        if !bootstrap.is_valid_for(authority_mode) {
            return Err(QuvError::InvalidAcceptedHistory);
        }
        let (slot, predecessor) = match bootstrap {
            QuvDomainBootstrapV0::Fixed {
                initial_slot,
                predecessor,
            } => (*initial_slot, *predecessor),
            QuvDomainBootstrapV0::HandoffBoundary { activation_height } => {
                (*activation_height, [0; 32])
            }
        };
        let initial = QuvSlotV0 {
            configuration_root,
            policy_root,
            network_id,
            domain_id,
            slot,
            predecessor,
            authority_mode,
        };
        let value = match bootstrap {
            QuvDomainBootstrapV0::Fixed { .. } => {
                Self::Fixed(QuvAcceptedHistoryV0::from_provisioned_initial(initial)?)
            }
            QuvDomainBootstrapV0::HandoffBoundary { .. } => Self::HandoffBoundary(initial),
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn initial(&self) -> &QuvSlotV0 {
        match self {
            Self::Fixed(history) => &history.initial,
            Self::HandoffBoundary(initial) => initial,
        }
    }

    pub(super) fn validate(&self) -> Result<(), QuvError> {
        match self {
            Self::Fixed(history) => history.validate(),
            Self::HandoffBoundary(initial) => {
                if initial.predecessor != [0; 32]
                    || initial.slot <= 1
                    || initial.authority_mode != super::QuvAuthorityModeV0::Owned
                {
                    return Err(QuvError::InvalidAcceptedHistory);
                }
                let mut syntax = initial.clone();
                syntax.predecessor = [1; 32];
                QuvAcceptedHistoryV0::from_provisioned_initial(syntax).map(|_| ())
            }
        }
    }

    pub(super) fn same_bootstrap(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
            && self.initial() == other.initial()
    }

    pub(super) fn is_initial(&self) -> bool {
        match self {
            Self::Fixed(history) => history.accepted.is_empty(),
            Self::HandoffBoundary(_) => true,
        }
    }

    pub(super) fn check_slot(&self, slot: &QuvSlotV0) -> Result<(), QuvError> {
        match self {
            Self::Fixed(history) => history.check_slot(slot),
            Self::HandoffBoundary(initial) => {
                let mut expected = initial.clone();
                expected.predecessor = slot.predecessor;
                if expected != *slot || slot.predecessor == [0; 32] {
                    return Err(QuvError::UnexpectedHead);
                }
                // The caller's rooted candidate validator must independently
                // match this predecessor to the local executed boundary.
                Ok(())
            }
        }
    }

    pub(super) fn next_query_slot(&self) -> Option<QuvSlotV0> {
        match self {
            Self::Fixed(history) => {
                let mut slot = history.initial.clone();
                slot.slot = history.next_slot()?;
                slot.predecessor = history.expected_predecessor(slot.slot).ok()?;
                Some(slot)
            }
            Self::HandoffBoundary(_) => None,
        }
    }

    pub(super) fn projected_record_growth(
        &self,
        authorization: &QuvOnlineAuthorizationV0,
    ) -> Result<usize, QuvError> {
        self.check_slot(authorization.slot())?;
        match self {
            Self::HandoffBoundary(_) => Ok(0),
            Self::Fixed(history) => {
                let offset = usize::try_from(authorization.slot.slot - history.initial.slot)
                    .map_err(|_| QuvError::UnexpectedHead)?;
                if offset < history.accepted.len() {
                    return if history.accepted[offset] == authorization.candidate_hash {
                        Ok(0)
                    } else {
                        Err(QuvError::ConflictingAcceptedHistory)
                    };
                }
                if history.accepted.len() >= STORE_MAX_SLOTS {
                    return Err(QuvError::StoreCapacityExceeded);
                }
                Ok(32 + super::compact_length_size(history.accepted.len() + 1)?
                    - super::compact_length_size(history.accepted.len())?)
            }
        }
    }

    pub(super) fn record_live_authorization(
        &mut self,
        authorization: &QuvOnlineAuthorizationV0,
    ) -> Result<bool, QuvError> {
        match self {
            Self::Fixed(history) => history.record_live_authorization(authorization),
            Self::HandoffBoundary(_) => {
                self.check_slot(authorization.slot())?;
                // Handoff acceptance is persisted by the dedicated install gate.
                Ok(false)
            }
        }
    }
}
