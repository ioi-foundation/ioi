//! Incremental production member persistence and its component test wrapper.

use super::{JournalLimits, MemberJournal};
use crate::aft::query_unanimity::{
    member_delta::{prepare_member_delta, MemberDelta},
    *,
};

pub(in crate::aft::query_unanimity) struct JournalMemberStore {
    state: QuvStoreStateV0,
    persistence: MemberJournalPersistence,
}

pub(in crate::aft::query_unanimity) struct MemberJournalPersistence {
    journal: MemberJournal,
    encoded_size: usize,
    limits: JournalLimits,
    failed: bool,
}

impl JournalMemberStore {
    pub(in crate::aft::query_unanimity) fn open(
        directory: &Path,
        anchor: &Path,
        key: QuvHash,
        root: QuvHash,
        domains: BTreeMap<QuvHash, QuvMemberDomainV0>,
        limits: JournalLimits,
    ) -> Result<Self, QuvError> {
        limits.validate()?;
        if key == [0; 32] || root == [0; 32] {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        validate_member_domains(&domains)?;
        if domains.values().any(|domain| !domain.is_initial()) {
            return Err(QuvError::InvalidStoreConfiguration);
        }
        let mut state = QuvStoreStateV0 {
            magic: STORE_MAGIC_V0,
            schema: STORE_SCHEMA_V0,
            generation: 0,
            previous_head: [0; 32],
            provisioning_root: root,
            domains,
            preparation_attempts: BTreeMap::new(),
            slots: BTreeMap::new(),
            authentication_tag: [0; 32],
        };
        let mut encoded_size = state.encoded_size();
        require_store_byte_capacity(encoded_size, limits.max_total_bytes)?;
        require_store_byte_capacity(encoded_size, limits.max_record_bytes)?;
        // Reserve encoded headroom for the complete independently rooted
        // lifetime before creating a journal or acknowledging its bootstrap.
        // This check is encoded accounting. After authenticated recovery,
        // open_reserved allocates the future record files before admission.
        let records = state.domains.values().try_fold(1_u64, |sum, domain| {
            sum.checked_add(domain.retained_record_capacity())
                .ok_or(QuvError::StoreCapacityExceeded)
        })?;
        let lifetime_bytes = (records - 1)
            .checked_mul(MEMBER_RECORD_BUDGET_BYTES)
            .and_then(|bytes| bytes.checked_add(encoded_size as u64))
            .and_then(|bytes| bytes.checked_add(MEMBER_RECORD_ENVELOPE_HEADROOM))
            // One unacknowledged temporary record may coexist with the prefix.
            .and_then(|bytes| bytes.checked_add(MEMBER_RECORD_BUDGET_BYTES))
            .ok_or(QuvError::StoreCapacityExceeded)?;
        if records > limits.max_records
            || lifetime_bytes > limits.max_total_bytes
            || limits.max_record_bytes < MEMBER_RECORD_BUDGET_BYTES
        {
            return Err(QuvError::StoreCapacityExceeded);
        }
        // This independently constructed bootstrap is matched byte-for-byte;
        // no snapshot or first-seen candidate can select enrollment on reopen.
        let bootstrap = codec::to_bytes_canonical(&state).map_err(QuvError::Codec)?;
        let journal = MemberJournal::open_reserved(
            directory,
            anchor,
            key,
            root,
            limits,
            super::ReservationLimits {
                records,
                record_bytes: MEMBER_RECORD_BUDGET_BYTES,
            },
            &bootstrap,
            |generation, raw| {
                let delta: MemberDelta =
                    codec::from_bytes_canonical(raw).map_err(QuvError::Codec)?;
                let prepared = prepare_member_delta(&state, generation, &delta)?;
                let next_size = prepared.projected_size(&state, encoded_size)?;
                require_store_byte_capacity(next_size, limits.max_total_bytes)?;
                prepared.apply(&mut state)?;
                encoded_size = next_size;
                Ok(())
            },
        )?;
        Ok(Self {
            state,
            persistence: MemberJournalPersistence {
                journal,
                encoded_size,
                limits,
                failed: false,
            },
        })
    }

    #[cfg(test)]
    pub(in crate::aft::query_unanimity) fn state(&self) -> Result<&QuvStoreStateV0, QuvError> {
        if self.persistence.requires_reopen() {
            return Err(QuvError::StoreRequiresReopen);
        }
        Ok(&self.state)
    }

    #[cfg(test)]
    pub(in crate::aft::query_unanimity) fn cached_logical_size(&self) -> usize {
        self.persistence.encoded_size
    }

    pub(in crate::aft::query_unanimity) fn into_parts(
        self,
    ) -> (QuvStoreStateV0, MemberJournalPersistence) {
        (self.state, self.persistence)
    }

    /// The caller has already validated its live operation. This commits only
    /// retained state. The final caller check preserves continuation expiry.
    #[cfg(test)]
    pub(in crate::aft::query_unanimity) fn commit(
        &mut self,
        delta: &MemberDelta,
        final_check: impl FnOnce() -> Result<(), QuvError>,
    ) -> Result<(), QuvError> {
        self.persistence.commit(
            &mut self.state,
            delta,
            self.persistence.limits.max_total_bytes,
            final_check,
        )
    }
}

impl MemberJournalPersistence {
    pub(in crate::aft::query_unanimity) fn requires_reopen(&self) -> bool {
        self.failed || self.journal.requires_reopen()
    }

    #[cfg(test)]
    pub(in crate::aft::query_unanimity) fn head(&self) -> QuvHash {
        self.journal.head
    }

    pub(in crate::aft::query_unanimity) fn commit(
        &mut self,
        state: &mut QuvStoreStateV0,
        delta: &MemberDelta,
        max_logical_bytes: u64,
        final_check: impl FnOnce() -> Result<(), QuvError>,
    ) -> Result<(), QuvError> {
        if self.requires_reopen() {
            return Err(QuvError::StoreRequiresReopen);
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(QuvError::GenerationExhausted)?;
        let prepared = prepare_member_delta(state, generation, delta)?;
        let next_size = prepared.projected_size(state, self.encoded_size)?;
        require_store_byte_capacity(
            next_size,
            self.limits.max_total_bytes.min(max_logical_bytes),
        )?;
        // Bound serialization before allocating the encoded transition. The
        // journal additionally checks the authenticated record's full size.
        require_store_byte_capacity(delta.encoded_size(), self.limits.max_record_bytes)?;
        let raw = codec::to_bytes_canonical(delta).map_err(QuvError::Codec)?;
        self.journal.append_with_prewrite_check(&raw, final_check)?;
        self.failed = true;
        prepared.apply(state)?;
        self.encoded_size = next_size;
        self.failed = false;
        Ok(())
    }
}
