//! Member persistence replacement under component qualification. This is not
//! yet the backend selected by DurableQuvMemberV0.

use super::{JournalLimits, MemberJournal};
use crate::aft::query_unanimity::{
    member_delta::{prepare_member_delta, MemberDelta},
    *,
};

pub(in crate::aft::query_unanimity) struct JournalMemberStore {
    journal: MemberJournal,
    state: QuvStoreStateV0,
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
            schema: 7,
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
        // This independently constructed bootstrap is matched byte-for-byte;
        // no snapshot or first-seen candidate can select enrollment on reopen.
        let bootstrap = codec::to_bytes_canonical(&state).map_err(QuvError::Codec)?;
        let journal = MemberJournal::open(
            directory,
            anchor,
            key,
            root,
            limits,
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
            journal,
            state,
            encoded_size,
            limits,
            failed: false,
        })
    }

    pub(in crate::aft::query_unanimity) fn state(&self) -> Result<&QuvStoreStateV0, QuvError> {
        if self.failed || self.journal.requires_reopen() {
            return Err(QuvError::StoreRequiresReopen);
        }
        Ok(&self.state)
    }

    pub(in crate::aft::query_unanimity) fn cached_logical_size(&self) -> usize {
        self.encoded_size
    }

    /// The caller has already validated its live operation. This commits only
    /// retained state. The final caller check preserves continuation expiry.
    pub(in crate::aft::query_unanimity) fn commit(
        &mut self,
        delta: &MemberDelta,
        final_check: impl FnOnce() -> Result<(), QuvError>,
    ) -> Result<(), QuvError> {
        self.state()?;
        let generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(QuvError::GenerationExhausted)?;
        let prepared = prepare_member_delta(&self.state, generation, delta)?;
        let next_size = prepared.projected_size(&self.state, self.encoded_size)?;
        require_store_byte_capacity(next_size, self.limits.max_total_bytes)?;
        // Bound serialization before allocating the encoded transition. The
        // journal additionally checks the authenticated record's full size.
        require_store_byte_capacity(delta.encoded_size(), self.limits.max_record_bytes)?;
        let raw = codec::to_bytes_canonical(delta).map_err(QuvError::Codec)?;
        self.journal.append_with_prewrite_check(&raw, final_check)?;
        self.failed = true;
        prepared.apply(&mut self.state)?;
        self.encoded_size = next_size;
        self.failed = false;
        Ok(())
    }
}
