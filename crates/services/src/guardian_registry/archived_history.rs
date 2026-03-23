use super::*;

impl GuardianRegistry {
    pub fn load_archived_recovered_history_segment(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<ArchivedRecoveredHistorySegment>, StateError> {
        match state.get(&aft_archived_recovered_history_segment_key(
            start_height,
            end_height,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_segments_for_start(
        state: &dyn StateAccess,
        start_height: u64,
    ) -> Result<Vec<ArchivedRecoveredHistorySegment>, StateError> {
        let prefix = aft_archived_recovered_history_segment_prefix(start_height);
        let mut segments = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let segment: ArchivedRecoveredHistorySegment = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            segments.push(segment);
        }
        segments.sort_unstable_by(|left, right| {
            left.end_height
                .cmp(&right.end_height)
                .then_with(|| left.segment_root_hash.cmp(&right.segment_root_hash))
        });
        Ok(segments)
    }

    pub fn load_archived_recovered_history_segment_by_hash(
        state: &dyn StateAccess,
        segment_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistorySegment>, StateError> {
        match state.get(&aft_archived_recovered_history_segment_hash_key(
            segment_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_active_archived_recovered_history_profile(
        state: &dyn StateAccess,
    ) -> Result<Option<ArchivedRecoveredHistoryProfile>, StateError> {
        match state.get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_profile_by_hash(
        state: &dyn StateAccess,
        profile_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistoryProfile>, StateError> {
        match state.get(&aft_archived_recovered_history_profile_hash_key(
            profile_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_profile_activation(
        state: &dyn StateAccess,
        profile_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>, StateError> {
        match state.get(&aft_archived_recovered_history_profile_activation_key(
            profile_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_profile_activation_by_hash(
        state: &dyn StateAccess,
        activation_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>, StateError> {
        match state.get(&aft_archived_recovered_history_profile_activation_hash_key(
            activation_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_profile_activation_for_end_height(
        state: &dyn StateAccess,
        activation_end_height: u64,
    ) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>, StateError> {
        match state.get(
            &aft_archived_recovered_history_profile_activation_height_key(activation_end_height),
        )? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    /// Publication-side convenience loader for the newest published archived
    /// recovered-history profile activation.
    ///
    /// Restart correctness must not depend on this latest-index key. Historical
    /// archived replay is validated from the canonical-collapse-anchored
    /// activation hash plus the predecessor/checkpoint chain it names.
    pub fn load_latest_archived_recovered_history_profile_activation(
        state: &dyn StateAccess,
    ) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>, StateError> {
        match state.get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    /// Publication-side convenience resolver for range admission and active
    /// profile-window checks.
    ///
    /// This walk intentionally starts from the latest published activation so
    /// publishers can decide which profile window currently governs one tip
    /// height. Archived restart correctness must not depend on it; restart uses
    /// the canonical-collapse-anchored activation hash and a backward
    /// predecessor/checkpoint walk instead.
    pub fn resolve_archived_recovered_history_profile_activation_for_tip_height(
        state: &dyn StateAccess,
        profile_hash: &[u8; 32],
        covered_end_height: u64,
    ) -> Result<
        (
            ArchivedRecoveredHistoryProfileActivation,
            Option<ArchivedRecoveredHistoryProfileActivation>,
        ),
        StateError,
    > {
        let Some(mut current_activation) =
            Self::load_latest_archived_recovered_history_profile_activation(state)?
        else {
            return Err(StateError::Validation(
                "latest archived recovered-history profile activation is missing from state".into(),
            ));
        };
        let mut successor_activation = None;
        loop {
            let profile = Self::load_archived_recovered_history_profile_by_hash(
                state,
                &current_activation.archived_profile_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "archived recovered-history profile activation references a missing archived profile hash"
                        .into(),
                )
            })?;
            validate_archived_recovered_history_profile_activation(&current_activation, &profile)
                .map_err(StateError::Validation)?;
            if let Some(successor_activation) = successor_activation.as_ref() {
                validate_archived_recovered_history_profile_activation_successor(
                    &current_activation,
                    successor_activation,
                )
                .map_err(StateError::Validation)?;
            }
            if current_activation.archived_profile_hash == *profile_hash {
                validate_archived_recovered_history_profile_activation_covering_tip_height(
                    &current_activation,
                    successor_activation.as_ref(),
                    covered_end_height,
                )
                .map_err(StateError::Validation)?;
                return Ok((current_activation, successor_activation));
            }
            if current_activation.previous_archived_profile_hash == [0u8; 32] {
                return Err(StateError::Validation(
                    "archived recovered-history profile activation chain does not contain the referenced profile hash"
                        .into(),
                ));
            }
            successor_activation = Some(current_activation.clone());
            current_activation = Self::load_archived_recovered_history_profile_activation(
                state,
                &current_activation.previous_archived_profile_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "archived recovered-history profile activation predecessor is missing from state"
                        .into(),
                )
            })?;
        }
    }

    /// Validates that one archived recovered-history profile activation governs
    /// the supplied checkpoint by walking backward through the published
    /// predecessor/checkpoint chain only.
    ///
    /// Unlike the publication-side latest-activation resolver above, this
    /// check is historical and index-free: it starts from the anchored
    /// activation object itself and never consults the latest activation tip.
    pub fn validate_archived_recovered_history_profile_activation_chain_for_checkpoint(
        state: &dyn StateAccess,
        activation: &ArchivedRecoveredHistoryProfileActivation,
        checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    ) -> Result<ArchivedRecoveredHistoryProfile, StateError> {
        let mut current_activation = activation.clone();
        let mut successor_activation = None::<ArchivedRecoveredHistoryProfileActivation>;
        let mut governed_profile = None::<ArchivedRecoveredHistoryProfile>;
        let mut seen_profiles = BTreeSet::new();
        loop {
            if !seen_profiles.insert(current_activation.archived_profile_hash) {
                return Err(StateError::Validation(
                    "archived recovered-history profile activation chain contains a cycle".into(),
                ));
            }
            let profile = Self::load_archived_recovered_history_profile_by_hash(
                state,
                &current_activation.archived_profile_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "archived recovered-history profile activation references a missing archived profile hash"
                        .into(),
                )
            })?;
            let activation_checkpoint = if current_activation.activation_checkpoint_hash
                == [0u8; 32]
            {
                None
            } else {
                Some(
                    Self::load_archived_recovered_history_checkpoint_by_hash(
                        state,
                        &current_activation.activation_checkpoint_hash,
                    )?
                    .ok_or_else(|| {
                        StateError::Validation(
                            "archived recovered-history profile activation checkpoint is missing from state"
                                .into(),
                        )
                    })?,
                )
            };
            if let Some(successor_activation) = successor_activation.as_ref() {
                validate_archived_recovered_history_profile_activation_successor(
                    &current_activation,
                    successor_activation,
                )
                .map_err(StateError::Validation)?;
                validate_archived_recovered_history_profile_activation_checkpoint(
                    &current_activation,
                    activation_checkpoint.as_ref(),
                    &profile,
                )
                .map_err(StateError::Validation)?;
            } else {
                validate_archived_recovered_history_profile_activation_against_checkpoint(
                    &current_activation,
                    activation_checkpoint.as_ref(),
                    checkpoint,
                    &profile,
                )
                .map_err(StateError::Validation)?;
                governed_profile = Some(profile.clone());
            }
            if current_activation.previous_archived_profile_hash == [0u8; 32] {
                return governed_profile.ok_or_else(|| {
                    StateError::Validation(
                        "archived recovered-history profile activation chain does not govern the referenced archived checkpoint"
                            .into(),
                    )
                });
            }
            successor_activation = Some(current_activation.clone());
            current_activation = Self::load_archived_recovered_history_profile_activation(
                state,
                &current_activation.previous_archived_profile_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "archived recovered-history profile activation predecessor is missing from state"
                        .into(),
                )
            })?;
        }
    }

    pub fn load_archived_recovered_history_profile_activation_successor(
        state: &dyn StateAccess,
        activation: &ArchivedRecoveredHistoryProfileActivation,
    ) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>, StateError> {
        let mut successor = None::<ArchivedRecoveredHistoryProfileActivation>;
        for item in
            state.prefix_scan(AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX)?
        {
            let (_, value) = item?;
            let candidate: ArchivedRecoveredHistoryProfileActivation =
                codec::from_bytes_canonical(&value)
                    .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            if candidate.previous_archived_profile_hash != activation.archived_profile_hash {
                continue;
            }
            let profile = Self::load_archived_recovered_history_profile_by_hash(
                state,
                &candidate.archived_profile_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "archived recovered-history profile activation successor references a missing archived profile hash"
                        .into(),
                )
            })?;
            let activation_checkpoint = if candidate.activation_checkpoint_hash == [0u8; 32] {
                None
            } else {
                Some(
                    Self::load_archived_recovered_history_checkpoint_by_hash(
                        state,
                        &candidate.activation_checkpoint_hash,
                    )?
                    .ok_or_else(|| {
                        StateError::Validation(
                            "archived recovered-history profile activation successor checkpoint is missing from state"
                                .into(),
                        )
                    })?,
                )
            };
            validate_archived_recovered_history_profile_activation_successor(
                activation, &candidate,
            )
            .map_err(StateError::Validation)?;
            validate_archived_recovered_history_profile_activation_checkpoint(
                &candidate,
                activation_checkpoint.as_ref(),
                &profile,
            )
            .map_err(StateError::Validation)?;
            if let Some(existing) = successor.as_ref() {
                if existing != &candidate {
                    return Err(StateError::Validation(
                        "archived recovered-history profile activation chain contains multiple successors for the same predecessor"
                            .into(),
                    ));
                }
            } else {
                successor = Some(candidate);
            }
        }
        Ok(successor)
    }

    pub fn validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
        state: &dyn StateAccess,
        activation_hash: &[u8; 32],
        archived_profile_hash: &[u8; 32],
        covered_end_height: u64,
    ) -> Result<
        (
            ArchivedRecoveredHistoryProfileActivation,
            ArchivedRecoveredHistoryProfile,
            Option<ArchivedRecoveredHistoryProfileActivation>,
        ),
        StateError,
    > {
        let activation = Self::load_archived_recovered_history_profile_activation_by_hash(
            state,
            activation_hash,
        )?
        .ok_or_else(|| {
            StateError::Validation(
                "archived recovered-history object references a missing archived profile activation hash"
                    .into(),
            )
        })?;
        if activation.archived_profile_hash != *archived_profile_hash {
            return Err(StateError::Validation(
                "archived recovered-history object activation hash does not match the archived profile hash"
                    .into(),
            ));
        }
        let profile = Self::load_archived_recovered_history_profile_by_hash(
            state,
            &activation.archived_profile_hash,
        )?
        .ok_or_else(|| {
            StateError::Validation(
                "archived recovered-history profile activation references a missing archived profile hash"
                    .into(),
            )
        })?;
        let activation_checkpoint = if activation.activation_checkpoint_hash == [0u8; 32] {
            None
        } else {
            Some(
                Self::load_archived_recovered_history_checkpoint_by_hash(
                    state,
                    &activation.activation_checkpoint_hash,
                )?
                .ok_or_else(|| {
                    StateError::Validation(
                        "archived recovered-history profile activation checkpoint is missing from state"
                            .into(),
                    )
                })?,
            )
        };
        validate_archived_recovered_history_profile_activation_checkpoint(
            &activation,
            activation_checkpoint.as_ref(),
            &profile,
        )
        .map_err(StateError::Validation)?;
        let successor =
            Self::load_archived_recovered_history_profile_activation_successor(state, &activation)?;
        validate_archived_recovered_history_profile_activation_covering_tip_height(
            &activation,
            successor.as_ref(),
            covered_end_height,
        )
        .map_err(StateError::Validation)?;
        Ok((activation, profile, successor))
    }

    pub fn load_archived_recovered_history_segment_for_range(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<ArchivedRecoveredHistorySegment>, StateError> {
        match state.get(&aft_archived_recovered_history_segment_key(
            start_height,
            end_height,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_previous_archived_recovered_history_segment(
        state: &dyn StateAccess,
        segment: &ArchivedRecoveredHistorySegment,
    ) -> Result<Option<ArchivedRecoveredHistorySegment>, StateError> {
        if segment.previous_archived_segment_hash == [0u8; 32] {
            return Ok(None);
        }

        let previous = Self::load_archived_recovered_history_segment_by_hash(
            state,
            &segment.previous_archived_segment_hash,
        )?
        .ok_or_else(|| {
            StateError::Validation(
                "archived recovered-history segment predecessor hash is missing from state".into(),
            )
        })?;
        validate_archived_recovered_history_segment_predecessor(&previous, segment)
            .map_err(StateError::Validation)?;
        Ok(Some(previous))
    }

    pub fn load_archived_recovered_history_segment_page(
        state: &dyn StateAccess,
        tip_segment_hash: &[u8; 32],
        max_segments: usize,
    ) -> Result<Vec<ArchivedRecoveredHistorySegment>, StateError> {
        if max_segments == 0 {
            return Err(StateError::Validation(
                "archived recovered-history segment page requires a non-zero segment budget".into(),
            ));
        }

        let Some(mut current) =
            Self::load_archived_recovered_history_segment_by_hash(state, tip_segment_hash)?
        else {
            return Err(StateError::Validation(
                "archived recovered-history segment page tip hash is missing from state".into(),
            ));
        };

        let mut visited = BTreeSet::new();
        let mut segments = Vec::new();
        loop {
            let current_hash = canonical_archived_recovered_history_segment_hash(&current)
                .map_err(StateError::Validation)?;
            if !visited.insert(current_hash) {
                return Err(StateError::Validation(
                    "archived recovered-history segment page encountered a duplicate segment hash while following predecessor links"
                        .into(),
                ));
            }

            let previous = Self::load_previous_archived_recovered_history_segment(state, &current)?;
            segments.push(current);
            if segments.len() >= max_segments {
                break;
            }
            let Some(previous) = previous else {
                break;
            };
            current = previous;
        }

        segments.reverse();
        Ok(segments)
    }

    pub fn load_archived_recovered_restart_page(
        state: &dyn StateAccess,
        segment_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredRestartPage>, StateError> {
        match state.get(&aft_archived_recovered_restart_page_key(segment_hash))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_restart_page_for_range(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<ArchivedRecoveredRestartPage>, StateError> {
        let Some(segment) = Self::load_archived_recovered_history_segment_for_range(
            state,
            start_height,
            end_height,
        )?
        else {
            return Ok(None);
        };
        let segment_hash = canonical_archived_recovered_history_segment_hash(&segment)
            .map_err(StateError::Validation)?;
        let page = Self::load_archived_recovered_restart_page(state, &segment_hash)?;
        if let Some(page) = &page {
            if page.segment_hash != segment_hash
                || page.start_height != segment.start_height
                || page.end_height != segment.end_height
            {
                return Err(StateError::Validation(format!(
                    "archived recovered restart page for range {}..={} does not match the archived segment descriptor",
                    start_height, end_height
                )));
            }
        }
        Ok(page)
    }

    pub fn load_archived_recovered_restart_page_chain(
        state: &dyn StateAccess,
        tip_segment_hash: &[u8; 32],
        max_segments: usize,
    ) -> Result<Vec<ArchivedRecoveredRestartPage>, StateError> {
        let segments = Self::load_archived_recovered_history_segment_page(
            state,
            tip_segment_hash,
            max_segments,
        )?;
        let mut pages = Vec::with_capacity(segments.len());
        for segment in &segments {
            let segment_hash = canonical_archived_recovered_history_segment_hash(segment)
                .map_err(StateError::Validation)?;
            let page = Self::load_archived_recovered_restart_page(state, &segment_hash)?
                .ok_or_else(|| {
                    StateError::Validation(format!(
                        "archived recovered restart page for segment {}..={} is missing from state",
                        segment.start_height, segment.end_height
                    ))
                })?;
            if page.segment_hash != segment_hash
                || page.start_height != segment.start_height
                || page.end_height != segment.end_height
            {
                return Err(StateError::Validation(format!(
                    "archived recovered restart page for segment {}..={} does not match the archived segment descriptor",
                    segment.start_height, segment.end_height
                )));
            }
            pages.push(page);
        }
        Ok(pages)
    }

    pub fn load_archived_recovered_history_checkpoint(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>, StateError> {
        match state.get(&aft_archived_recovered_history_checkpoint_key(
            start_height,
            end_height,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_checkpoint_by_hash(
        state: &dyn StateAccess,
        checkpoint_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>, StateError> {
        match state.get(&aft_archived_recovered_history_checkpoint_hash_key(
            checkpoint_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_latest_archived_recovered_history_checkpoint(
        state: &dyn StateAccess,
    ) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>, StateError> {
        match state.get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_archived_recovered_history_retention_receipt(
        state: &dyn StateAccess,
        checkpoint_hash: &[u8; 32],
    ) -> Result<Option<ArchivedRecoveredHistoryRetentionReceipt>, StateError> {
        match state.get(&aft_archived_recovered_history_retention_receipt_key(
            checkpoint_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_missing_recovery_share(
        state: &dyn StateAccess,
        height: u64,
        witness_manifest_hash: &[u8; 32],
    ) -> Result<Option<MissingRecoveryShare>, StateError> {
        match state.get(&aft_missing_recovery_share_key(
            height,
            witness_manifest_hash,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_recovery_threshold_status(
        state: &dyn StateAccess,
        height: u64,
        expected_witness_manifest_hashes: &[[u8; 32]],
        recovery_threshold: u16,
    ) -> Result<RecoveryThresholdStatus, StateError> {
        if recovery_threshold == 0 {
            return Err(StateError::InvalidValue(
                "recovery threshold must be non-zero".into(),
            ));
        }
        let expected_witnesses = expected_witness_manifest_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if expected_witnesses.is_empty() {
            return Err(StateError::InvalidValue(
                "recovery threshold status requires at least one expected witness".into(),
            ));
        }

        let mut support_by_block = BTreeMap::<[u8; 32], usize>::new();
        let mut pending_count = 0usize;
        for witness_manifest_hash in expected_witnesses {
            if Self::load_missing_recovery_share(state, height, &witness_manifest_hash)?.is_some() {
                continue;
            }

            let receipts =
                Self::load_recovery_share_receipts(state, height, &witness_manifest_hash)?;
            match receipts.len() {
                0 => pending_count += 1,
                1 => {
                    *support_by_block
                        .entry(receipts[0].block_commitment_hash)
                        .or_default() += 1;
                }
                _ => {
                    // Conflicting same-witness receipts remain visible, but do not
                    // contribute positive support to any single candidate block.
                }
            }
        }

        let threshold = usize::from(recovery_threshold);
        if let Some((&block_commitment_hash, &support_count)) = support_by_block
            .iter()
            .max_by_key(|(_, support_count)| *support_count)
        {
            if support_count >= threshold {
                return Ok(RecoveryThresholdStatus::Recoverable(block_commitment_hash));
            }
        }

        let best_existing_support = support_by_block.values().copied().max().unwrap_or(0);
        if pending_count + best_existing_support < threshold {
            return Ok(RecoveryThresholdStatus::Impossible);
        }

        Ok(RecoveryThresholdStatus::Pending)
    }

    pub fn load_canonical_collapse_object(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<CanonicalCollapseObject>, StateError> {
        match state.get(&aft_canonical_collapse_object_key(height))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub(super) fn validate_canonical_collapse_archived_history_anchor(
        state: &dyn StateAccess,
        collapse: &CanonicalCollapseObject,
    ) -> Result<(), TransactionError> {
        let Some((checkpoint_hash, activation_hash, receipt_hash)) =
            canonical_collapse_archived_recovered_history_anchor(collapse)
                .map_err(TransactionError::Invalid)?
        else {
            return Ok(());
        };

        let checkpoint = Self::load_archived_recovered_history_checkpoint_by_hash(
            state,
            &checkpoint_hash,
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "canonical collapse archived recovered-history checkpoint anchor is missing from state"
                    .into(),
            )
        })?;
        if checkpoint.covered_end_height > collapse.height {
            return Err(TransactionError::Invalid(
                "canonical collapse archived recovered-history checkpoint anchor exceeds the collapse height"
                    .into(),
            ));
        }
        let profile = Self::load_archived_recovered_history_profile_by_hash(
            state,
            &checkpoint.archived_profile_hash,
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "canonical collapse archived recovered-history checkpoint references a missing archived profile hash"
                    .into(),
            )
        })?;
        validate_archived_recovered_history_checkpoint_against_profile(&checkpoint, &profile)
            .map_err(TransactionError::Invalid)?;
        let receipt = Self::load_archived_recovered_history_retention_receipt(
            state,
            &checkpoint_hash,
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "canonical collapse archived recovered-history retention receipt anchor is missing from state"
                    .into(),
            )
        })?;
        let expected_receipt_hash =
            canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                .map_err(TransactionError::Invalid)?;
        if expected_receipt_hash != receipt_hash {
            return Err(TransactionError::Invalid(
                "canonical collapse archived recovered-history retention receipt anchor does not match the published receipt"
                    .into(),
            ));
        }
        validate_archived_recovered_history_retention_receipt_against_profile(
            &receipt,
            &checkpoint,
            &profile,
        )
        .map_err(TransactionError::Invalid)?;
        if checkpoint.archived_profile_activation_hash != activation_hash {
            return Err(TransactionError::Invalid(
                "canonical collapse archived recovered-history checkpoint activation anchor does not match the published checkpoint"
                    .into(),
            ));
        }
        if receipt.archived_profile_activation_hash != activation_hash {
            return Err(TransactionError::Invalid(
                "canonical collapse archived recovered-history retention receipt activation anchor does not match the published receipt"
                    .into(),
            ));
        }
        let activation = Self::load_archived_recovered_history_profile_activation_by_hash(
            state,
            &activation_hash,
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "canonical collapse archived recovered-history profile activation anchor is missing from state"
                    .into(),
            )
        })?;
        validate_archived_recovered_history_profile_activation(&activation, &profile)
            .map_err(TransactionError::Invalid)?;
        Self::validate_archived_recovered_history_profile_activation_for_tip_height_by_hash(
            state,
            &activation_hash,
            &checkpoint.archived_profile_hash,
            checkpoint.covered_end_height,
        )
        .map_err(TransactionError::State)?;
        Self::validate_archived_recovered_history_profile_activation_chain_for_checkpoint(
            state,
            &activation,
            &checkpoint,
        )
        .map_err(TransactionError::State)?;
        Ok(())
    }

    pub(super) fn load_latest_canonical_archived_history_anchor_hashes(
        state: &dyn StateAccess,
    ) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>, TransactionError> {
        let Some(checkpoint) = Self::load_latest_archived_recovered_history_checkpoint(state)?
        else {
            return Ok(None);
        };
        let checkpoint_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
            .map_err(TransactionError::Invalid)?;
        let receipt = Self::load_archived_recovered_history_retention_receipt(state, &checkpoint_hash)?
            .ok_or_else(|| {
                TransactionError::Invalid(
                    "latest archived recovered-history checkpoint references a missing retention receipt"
                        .into(),
                )
            })?;
        let receipt_hash = canonical_archived_recovered_history_retention_receipt_hash(&receipt)
            .map_err(TransactionError::Invalid)?;
        if receipt.archived_profile_activation_hash != checkpoint.archived_profile_activation_hash {
            return Err(TransactionError::Invalid(
                "latest archived recovered-history checkpoint retention receipt activation hash does not match the checkpoint activation hash"
                    .into(),
            ));
        }
        let activation = Self::load_archived_recovered_history_profile_activation_by_hash(
            state,
            &checkpoint.archived_profile_activation_hash,
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "latest archived recovered-history checkpoint references a missing profile activation"
                    .into(),
            )
        })?;
        let activation_hash =
            canonical_archived_recovered_history_profile_activation_hash(&activation)
                .map_err(TransactionError::Invalid)?;
        Ok(Some((checkpoint_hash, activation_hash, receipt_hash)))
    }

    pub fn load_aft_historical_retrievability_surface_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<AftHistoricalRetrievabilitySurface>, StateError> {
        let Some(collapse) = Self::load_canonical_collapse_object(state, height)? else {
            return Ok(None);
        };
        Self::load_aft_historical_retrievability_surface_for_collapse(state, &collapse)
    }

    pub(super) fn load_aft_historical_retrievability_surface_for_collapse(
        state: &dyn StateAccess,
        collapse: &CanonicalCollapseObject,
    ) -> Result<Option<AftHistoricalRetrievabilitySurface>, StateError> {
        let Some(anchor) = canonical_collapse_historical_continuation_anchor(collapse)
            .map_err(StateError::InvalidValue)?
        else {
            return Ok(None);
        };

        Self::validate_canonical_collapse_archived_history_anchor(state, collapse)
            .map_err(|error| StateError::InvalidValue(error.to_string()))?;

        let checkpoint = Self::load_archived_recovered_history_checkpoint_by_hash(
            state,
            &anchor.checkpoint_hash,
        )?
        .ok_or_else(|| {
            StateError::InvalidValue(
                "ordinary historical retrievability checkpoint is missing from state".into(),
            )
        })?;
        let activation = Self::load_archived_recovered_history_profile_activation_by_hash(
            state,
            &anchor.profile_activation_hash,
        )?
        .ok_or_else(|| {
            StateError::InvalidValue(
                "ordinary historical retrievability profile activation is missing from state"
                    .into(),
            )
        })?;
        let receipt = Self::load_archived_recovered_history_retention_receipt(
            state,
            &anchor.checkpoint_hash,
        )?
        .ok_or_else(|| {
            StateError::InvalidValue(
                "ordinary historical retrievability retention receipt is missing from state".into(),
            )
        })?;

        if checkpoint.archived_profile_activation_hash != anchor.profile_activation_hash {
            return Err(StateError::InvalidValue(
                "ordinary historical retrievability checkpoint activation hash does not match the canonical anchor"
                    .into(),
            ));
        }
        if receipt.archived_profile_activation_hash != anchor.profile_activation_hash {
            return Err(StateError::InvalidValue(
                "ordinary historical retrievability retention receipt activation hash does not match the canonical anchor"
                    .into(),
            ));
        }

        Ok(Some(AftHistoricalRetrievabilitySurface {
            anchor,
            checkpoint,
            profile_activation: activation,
            retention_receipt: receipt,
        }))
    }

    pub(super) fn load_latest_publication_frontier_before(
        state: &dyn StateAccess,
        height_exclusive: u64,
    ) -> Result<Option<PublicationFrontier>, StateError> {
        if height_exclusive <= 1 {
            return Ok(None);
        }
        let mut cursor = height_exclusive - 1;
        loop {
            if let Some(frontier) = Self::load_publication_frontier(state, cursor)? {
                return Ok(Some(frontier));
            }
            if cursor == 1 {
                break;
            }
            cursor -= 1;
        }
        Ok(None)
    }

    pub(super) fn load_effective_validator_set_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<ioi_types::app::ValidatorSetV1, StateError> {
        let Some(validator_set_bytes) = state.get(VALIDATOR_SET_KEY)? else {
            return Err(StateError::InvalidValue(
                "active validator set is missing from state".into(),
            ));
        };
        let validator_sets = read_validator_sets(&validator_set_bytes)
            .map_err(|error| StateError::InvalidValue(error.to_string()))?;
        Ok(effective_set_for_height(&validator_sets, height).clone())
    }

    pub(super) fn load_unique_recovered_publication_ancestry(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<([u8; 32], [u8; 32])>, StateError> {
        let recovered = Self::load_recovered_publication_bundles_for_height(state, height)?;
        let mut unique = recovered
            .into_iter()
            .map(|object| {
                (
                    object.block_commitment_hash,
                    object.parent_block_commitment_hash,
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        match unique.len() {
            0 => Ok(None),
            1 => Ok(unique.pop_first()),
            _ => Ok(None),
        }
    }

    pub(super) fn load_unique_recovered_publication_bundle_for_height(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<RecoveredPublicationBundle>, StateError> {
        let mut recovered = Self::load_recovered_publication_bundles_for_height(state, height)?;
        let Some(first) = recovered.first().cloned() else {
            return Ok(None);
        };
        let all_same_surface = recovered.iter().all(|candidate| {
            candidate.block_commitment_hash == first.block_commitment_hash
                && candidate.parent_block_commitment_hash == first.parent_block_commitment_hash
                && candidate.coding == first.coding
                && candidate.recoverable_slot_payload_hash == first.recoverable_slot_payload_hash
                && candidate.recoverable_full_surface_hash == first.recoverable_full_surface_hash
                && candidate.canonical_order_publication_bundle_hash
                    == first.canonical_order_publication_bundle_hash
                && candidate.canonical_bulletin_close_hash == first.canonical_bulletin_close_hash
        });
        if !all_same_surface {
            return Ok(None);
        }
        Ok(recovered.pop())
    }

    pub(super) fn load_supporting_recovery_share_materials_for_recovered_bundle(
        state: &dyn StateAccess,
        recovered: &RecoveredPublicationBundle,
    ) -> Result<Vec<RecoveryShareMaterial>, StateError> {
        let mut materials = Vec::with_capacity(recovered.supporting_witness_manifest_hashes.len());
        for witness_manifest_hash in &recovered.supporting_witness_manifest_hashes {
            let material = Self::load_recovery_share_material(
                state,
                recovered.height,
                witness_manifest_hash,
                &recovered.block_commitment_hash,
            )?
            .ok_or_else(|| {
                StateError::Validation(
                    "recovered publication bundle requires supporting recovery share material"
                        .into(),
                )
            })?;
            if material.coding != recovered.coding {
                return Err(StateError::Validation(
                    "recovered publication bundle materialization kind must match all supporting share reveals"
                        .into(),
                ));
            }
            materials.push(material);
        }
        Ok(materials)
    }

    pub(super) fn reconstruct_recovered_publication_surface(
        recovered: &RecoveredPublicationBundle,
        materials: &[RecoveryShareMaterial],
    ) -> Result<
        (
            ioi_types::app::RecoverableSlotPayloadV4,
            ioi_types::app::RecoverableSlotPayloadV5,
            CanonicalOrderPublicationBundle,
            CanonicalBulletinClose,
        ),
        StateError,
    > {
        let (payload, bundle, bulletin_close) =
            recover_canonical_order_artifact_surface_from_share_materials(materials)
                .map_err(StateError::Validation)?;
        let (full_surface, _, _, _) =
            recover_full_canonical_order_surface_from_share_materials(materials)
                .map_err(StateError::Validation)?;
        if payload.height != recovered.height
            || payload.block_commitment_hash != recovered.block_commitment_hash
        {
            return Err(StateError::Validation(
                "recovered publication bundle must reconstruct the bound slot height and block commitment"
                    .into(),
            ));
        }
        if full_surface.parent_block_hash != recovered.parent_block_commitment_hash {
            return Err(StateError::Validation(
                "recovered publication bundle must match the reconstructed parent block commitment"
                    .into(),
            ));
        }
        let payload_hash =
            canonical_recoverable_slot_payload_v4_hash(&payload).map_err(StateError::Validation)?;
        if payload_hash != recovered.recoverable_slot_payload_hash {
            return Err(StateError::Validation(
                "recovered publication bundle must match the reconstructed slot payload hash"
                    .into(),
            ));
        }
        let full_surface_hash = canonical_recoverable_slot_payload_v5_hash(&full_surface)
            .map_err(StateError::Validation)?;
        if full_surface_hash != recovered.recoverable_full_surface_hash {
            return Err(StateError::Validation(
                "recovered publication bundle must match the reconstructed full extractable surface hash"
                    .into(),
            ));
        }
        let bundle_hash =
            canonical_order_publication_bundle_hash(&bundle).map_err(StateError::Validation)?;
        if bundle_hash != recovered.canonical_order_publication_bundle_hash {
            return Err(StateError::Validation(
                "recovered publication bundle must match the reconstructed publication bundle hash"
                    .into(),
            ));
        }
        let bulletin_close_hash =
            canonical_bulletin_close_hash(&bulletin_close).map_err(StateError::Validation)?;
        if bulletin_close_hash != recovered.canonical_bulletin_close_hash {
            return Err(StateError::Validation(
                "recovered publication bundle must match the reconstructed bulletin-close hash"
                    .into(),
            ));
        }
        Ok((payload, full_surface, bundle, bulletin_close))
    }

    pub(super) fn recover_unique_recovered_canonical_header_entry(
        state: &dyn StateAccess,
        height: u64,
    ) -> Result<Option<RecoveredCanonicalHeaderEntry>, StateError> {
        let Some(recovered) =
            Self::load_unique_recovered_publication_bundle_for_height(state, height)?
        else {
            return Ok(None);
        };
        let collapse = Self::load_canonical_collapse_object(state, height)?.ok_or_else(|| {
            StateError::Validation(format!(
                "recovered canonical header prefix requires a canonical collapse object at height {}",
                height
            ))
        })?;
        let materials =
            Self::load_supporting_recovery_share_materials_for_recovered_bundle(state, &recovered)?;
        let (_, full_surface, _, _) =
            Self::reconstruct_recovered_publication_surface(&recovered, &materials)?;
        recovered_canonical_header_entry(&collapse, &full_surface)
            .map(Some)
            .map_err(StateError::Validation)
    }

    pub fn extract_canonical_replay_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<CanonicalReplayPrefixEntry>, StateError> {
        if start_height == 0 {
            return Err(StateError::Validation(
                "canonical replay prefix requires a non-zero start height".into(),
            ));
        }
        if end_height < start_height {
            return Err(StateError::Validation(
                "canonical replay prefix end height must be at least the start height".into(),
            ));
        }

        let mut previous_collapse = if start_height <= 1 {
            None
        } else {
            Self::load_canonical_collapse_object(state, start_height - 1)?
        };
        let mut previous_recovered_block_commitment_hash = if start_height <= 1 {
            None
        } else {
            Self::load_unique_recovered_publication_ancestry(state, start_height - 1)?
                .map(|(block_commitment_hash, _)| block_commitment_hash)
        };
        let mut latest_frontier =
            Self::load_latest_publication_frontier_before(state, start_height)?;
        let mut entries = Vec::with_capacity((end_height - start_height + 1) as usize);

        for height in start_height..=end_height {
            let collapse =
                Self::load_canonical_collapse_object(state, height)?.ok_or_else(|| {
                    StateError::Validation(format!(
                        "canonical replay prefix requires a canonical collapse object at height {}",
                        height
                    ))
                })?;
            verify_canonical_collapse_continuity(&collapse, previous_collapse.as_ref())
                .map_err(StateError::Validation)?;

            let ordering_resolution_hash = match collapse.ordering.kind {
                CanonicalCollapseKind::Close => {
                    let close = Self::load_canonical_bulletin_close(state, height)?.ok_or_else(|| {
                        StateError::Validation(format!(
                            "canonical replay prefix requires a canonical bulletin close at height {}",
                            height
                        ))
                    })?;
                    let close_hash =
                        canonical_bulletin_close_hash(&close).map_err(StateError::Validation)?;
                    if close_hash != collapse.ordering.bulletin_close_hash {
                        return Err(StateError::Validation(format!(
                            "canonical replay prefix bulletin-close hash mismatch at height {}",
                            height
                        )));
                    }
                    close_hash
                }
                CanonicalCollapseKind::Abort => {
                    let abort =
                        Self::load_canonical_order_abort(state, height)?.ok_or_else(|| {
                            StateError::Validation(format!(
                            "canonical replay prefix requires a canonical-order abort at height {}",
                            height
                        ))
                        })?;
                    canonical_order_abort_hash(&abort).map_err(StateError::Validation)?
                }
            };

            let extracted_bulletin_surface_present =
                Self::extract_published_bulletin_surface(state, height)?.is_some();
            if collapse.ordering.kind == CanonicalCollapseKind::Close
                && !extracted_bulletin_surface_present
            {
                return Err(StateError::Validation(format!(
                    "canonical replay prefix requires an extracted bulletin surface for close-valued slot {}",
                    height
                )));
            }

            let publication_frontier_hash = match Self::load_publication_frontier(state, height)? {
                Some(frontier) => {
                    if let Some(previous_frontier) = latest_frontier.as_ref() {
                        let expected_parent_hash =
                            canonical_publication_frontier_hash(previous_frontier)
                                .map_err(StateError::Validation)?;
                        if frontier.parent_frontier_hash != expected_parent_hash {
                            return Err(StateError::Validation(format!(
                                "canonical replay prefix publication frontier parent mismatch at height {}",
                                height
                            )));
                        }
                    } else if height > 1 && frontier.parent_frontier_hash != [0u8; 32] {
                        return Err(StateError::Validation(format!(
                            "canonical replay prefix frontier at height {} carries a non-zero parent without an earlier frontier",
                            height
                        )));
                    }
                    let hash = canonical_publication_frontier_hash(&frontier)
                        .map_err(StateError::Validation)?;
                    latest_frontier = Some(frontier);
                    Some(hash)
                }
                None => None,
            };

            let recovered_ancestry =
                Self::load_unique_recovered_publication_ancestry(state, height)?;
            if let (Some(expected_parent), Some((_, recovered_parent))) =
                (previous_recovered_block_commitment_hash, recovered_ancestry)
            {
                if height > 1 && recovered_parent != expected_parent {
                    return Err(StateError::Validation(format!(
                        "canonical replay prefix recovered parent-block hash mismatch at height {}",
                        height
                    )));
                }
            }

            entries.push(
                canonical_replay_prefix_entry(
                    &collapse,
                    recovered_ancestry.map(|(block_commitment_hash, _)| block_commitment_hash),
                    recovered_ancestry
                        .map(|(_, parent_block_commitment_hash)| parent_block_commitment_hash),
                    ordering_resolution_hash,
                    publication_frontier_hash,
                    extracted_bulletin_surface_present,
                )
                .map_err(StateError::Validation)?,
            );
            previous_recovered_block_commitment_hash =
                recovered_ancestry.map(|(block_commitment_hash, _)| block_commitment_hash);
            previous_collapse = Some(collapse);
        }

        Ok(entries)
    }

    pub fn extract_aft_recovered_replay_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<CanonicalReplayPrefixEntry>, StateError> {
        Self::extract_canonical_replay_prefix(state, start_height, end_height)
    }

    pub fn extract_recovered_canonical_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredCanonicalHeaderEntry>, StateError> {
        if start_height == 0 {
            return Err(StateError::Validation(
                "recovered canonical header prefix requires a non-zero start height".into(),
            ));
        }
        if end_height < start_height {
            return Err(StateError::Validation(
                "recovered canonical header prefix end height must be at least the start height"
                    .into(),
            ));
        }

        let mut previous_header = if start_height <= 1 {
            None
        } else {
            Self::recover_unique_recovered_canonical_header_entry(state, start_height - 1)?
        };
        let mut entries = Vec::with_capacity((end_height - start_height + 1) as usize);

        for height in start_height..=end_height {
            let entry = Self::recover_unique_recovered_canonical_header_entry(state, height)?
                .ok_or_else(|| {
                    StateError::Validation(format!(
                        "recovered canonical header prefix requires a uniquely recovered full surface at height {}",
                        height
                    ))
                })?;
            if let Some(previous) = previous_header.as_ref() {
                if height > 1
                    && entry.parent_block_commitment_hash
                        != previous.canonical_block_commitment_hash
                {
                    return Err(StateError::Validation(format!(
                        "recovered canonical header prefix parent-block hash mismatch at height {}",
                        height
                    )));
                }
            }
            previous_header = Some(entry.clone());
            entries.push(entry);
        }

        Ok(entries)
    }

    pub fn extract_aft_recovered_consensus_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredCanonicalHeaderEntry>, StateError> {
        Self::extract_recovered_canonical_header_prefix(state, start_height, end_height)
    }

    pub fn extract_recovered_certified_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        if start_height == 0 {
            return Err(StateError::Validation(
                "recovered certified header prefix requires a non-zero start height".into(),
            ));
        }
        if end_height < start_height {
            return Err(StateError::Validation(
                "recovered certified header prefix end height must be at least the start height"
                    .into(),
            ));
        }

        let previous = if start_height <= 1 {
            None
        } else {
            Self::recover_unique_recovered_canonical_header_entry(state, start_height - 1)?
        };
        let headers =
            Self::extract_recovered_canonical_header_prefix(state, start_height, end_height)?;
        recovered_certified_header_prefix(previous.as_ref(), &headers)
            .map_err(StateError::Validation)
    }

    pub fn extract_aft_recovered_certified_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        Self::extract_recovered_certified_header_prefix(state, start_height, end_height)
    }

    pub fn extract_recovered_restart_block_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        if start_height == 0 {
            return Err(StateError::Validation(
                "recovered restart block-header prefix requires a non-zero start height".into(),
            ));
        }
        if end_height < start_height {
            return Err(StateError::Validation(
                "recovered restart block-header prefix end height must be at least the start height"
                    .into(),
            ));
        }

        let mut previous = if start_height <= 1 {
            None
        } else {
            Self::recover_unique_recovered_canonical_header_entry(state, start_height - 1)?
        };
        let mut entries = Vec::new();

        for height in start_height..=end_height {
            let Some(recovered) =
                Self::load_unique_recovered_publication_bundle_for_height(state, height)?
            else {
                return Err(StateError::Validation(format!(
                    "recovered restart block-header prefix requires a unique recovered publication bundle at height {}",
                    height
                )));
            };
            let collapse = Self::load_canonical_collapse_object(state, height)?.ok_or_else(|| {
                StateError::Validation(format!(
                    "recovered restart block-header prefix requires a canonical collapse object at height {}",
                    height
                ))
            })?;
            let materials = Self::load_supporting_recovery_share_materials_for_recovered_bundle(
                state, &recovered,
            )?;
            let (_, full_surface, _, _) =
                Self::reconstruct_recovered_publication_surface(&recovered, &materials)?;
            let header = recovered_canonical_header_entry(&collapse, &full_surface)
                .map_err(StateError::Validation)?;
            let certified = recovered_certified_header_entry(&header, previous.as_ref())
                .map_err(StateError::Validation)?;
            let restart_entry = recovered_restart_block_header_entry(&full_surface, &certified)
                .map_err(StateError::Validation)?;
            previous = Some(header);
            entries.push(restart_entry);
        }

        Ok(entries)
    }

    pub fn extract_aft_recovered_restart_header_prefix(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        Self::extract_recovered_restart_block_header_prefix(state, start_height, end_height)
    }

    pub fn extract_aft_recovered_state_surface(
        state: &dyn StateAccess,
        start_height: u64,
        end_height: u64,
    ) -> Result<AftRecoveredStateSurface, StateError> {
        let replay_prefix =
            Self::extract_aft_recovered_replay_prefix(state, start_height, end_height)?;
        let consensus_headers =
            Self::extract_aft_recovered_consensus_header_prefix(state, start_height, end_height)?;
        let certified_headers =
            Self::extract_aft_recovered_certified_header_prefix(state, start_height, end_height)?;
        let restart_headers =
            Self::extract_aft_recovered_restart_header_prefix(state, start_height, end_height)?;
        let historical_retrievability = match replay_prefix.last() {
            Some(entry)
                if canonical_replay_prefix_historical_continuation_anchor(entry)
                    .map_err(StateError::InvalidValue)?
                    .is_some() =>
            {
                Self::load_aft_historical_retrievability_surface_for_height(state, end_height)?
            }
            _ => None,
        };

        Ok(AftRecoveredStateSurface {
            replay_prefix,
            consensus_headers,
            certified_headers,
            restart_headers,
            historical_retrievability,
        })
    }

    pub fn extract_stitched_recovered_canonical_header_prefix(
        state: &dyn StateAccess,
        windows: &[(u64, u64)],
    ) -> Result<Vec<RecoveredCanonicalHeaderEntry>, StateError> {
        if windows.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = windows
            .iter()
            .map(|(start_height, end_height)| {
                Self::extract_recovered_canonical_header_prefix(state, *start_height, *end_height)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_canonical_header_windows(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_canonical_header_segments(
        state: &dyn StateAccess,
        segments: &[&[(u64, u64)]],
    ) -> Result<Vec<RecoveredCanonicalHeaderEntry>, StateError> {
        if segments.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = segments
            .iter()
            .map(|windows| Self::extract_stitched_recovered_canonical_header_prefix(state, windows))
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_canonical_header_segments(&slices).map_err(StateError::Validation)
    }

    pub fn extract_recovered_canonical_header_page(
        state: &dyn StateAccess,
        page: &RecoveredSegmentFoldPage,
    ) -> Result<Vec<RecoveredCanonicalHeaderEntry>, StateError> {
        let segment_slices = page.segments.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let extracted =
            Self::extract_stitched_recovered_canonical_header_segments(state, &segment_slices)?;
        validate_recovered_page_coverage(
            page,
            &extracted,
            |entry| entry.height,
            "recovered canonical header",
        )
        .map_err(StateError::Validation)?;
        Ok(extracted)
    }

    pub fn extract_recovered_certified_header_page(
        state: &dyn StateAccess,
        page: &RecoveredSegmentFoldPage,
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        let segment_slices = page.segments.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let extracted =
            Self::extract_stitched_recovered_certified_header_segments(state, &segment_slices)?;
        validate_recovered_page_coverage(
            page,
            &extracted,
            |entry| entry.header.height,
            "recovered certified header",
        )
        .map_err(StateError::Validation)?;
        Ok(extracted)
    }

    pub fn extract_recovered_restart_block_header_page(
        state: &dyn StateAccess,
        page: &RecoveredSegmentFoldPage,
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        let segment_slices = page.segments.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let extracted =
            Self::extract_stitched_recovered_restart_block_header_segments(state, &segment_slices)?;
        validate_recovered_page_coverage(
            page,
            &extracted,
            |entry| entry.header.height,
            "recovered restart block header",
        )
        .map_err(StateError::Validation)?;
        Ok(extracted)
    }

    pub fn extract_stitched_recovered_certified_header_prefix(
        state: &dyn StateAccess,
        windows: &[(u64, u64)],
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        if windows.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = windows
            .iter()
            .map(|(start_height, end_height)| {
                Self::extract_recovered_certified_header_prefix(state, *start_height, *end_height)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_certified_header_windows(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_restart_block_header_prefix(
        state: &dyn StateAccess,
        windows: &[(u64, u64)],
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        if windows.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = windows
            .iter()
            .map(|(start_height, end_height)| {
                Self::extract_recovered_restart_block_header_prefix(
                    state,
                    *start_height,
                    *end_height,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_restart_block_header_windows(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_certified_header_segments(
        state: &dyn StateAccess,
        segments: &[&[(u64, u64)]],
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        if segments.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = segments
            .iter()
            .map(|windows| Self::extract_stitched_recovered_certified_header_prefix(state, windows))
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_certified_header_segments(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_restart_block_header_segments(
        state: &dyn StateAccess,
        segments: &[&[(u64, u64)]],
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        if segments.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = segments
            .iter()
            .map(|windows| {
                Self::extract_stitched_recovered_restart_block_header_prefix(state, windows)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_restart_block_header_segments(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_certified_header_segment_folds(
        state: &dyn StateAccess,
        segment_folds: &[Vec<Vec<(u64, u64)>>],
    ) -> Result<Vec<RecoveredCertifiedHeaderEntry>, StateError> {
        if segment_folds.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = segment_folds
            .iter()
            .map(|segments| {
                let segment_slices = segments.iter().map(Vec::as_slice).collect::<Vec<_>>();
                Self::extract_stitched_recovered_certified_header_segments(state, &segment_slices)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_certified_header_segments(&slices).map_err(StateError::Validation)
    }

    pub fn extract_stitched_recovered_restart_block_header_segment_folds(
        state: &dyn StateAccess,
        segment_folds: &[Vec<Vec<(u64, u64)>>],
    ) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, StateError> {
        if segment_folds.is_empty() {
            return Ok(Vec::new());
        }

        let extracted = segment_folds
            .iter()
            .map(|segments| {
                let segment_slices = segments.iter().map(Vec::as_slice).collect::<Vec<_>>();
                Self::extract_stitched_recovered_restart_block_header_segments(
                    state,
                    &segment_slices,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        stitch_recovered_restart_block_header_segments(&slices).map_err(StateError::Validation)
    }
}
