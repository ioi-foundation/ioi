/// Returns the canonical hash of a protocol-wide canonical collapse object.
pub fn canonical_collapse_object_hash(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(collapse)
}

/// Returns the succinct predecessor commitment for a canonical collapse object.
pub fn canonical_collapse_commitment(
    collapse: &CanonicalCollapseObject,
) -> CanonicalCollapseCommitment {
    CanonicalCollapseCommitment {
        height: collapse.height,
        continuity_accumulator_hash: collapse.continuity_accumulator_hash,
        resulting_state_root_hash: collapse.resulting_state_root_hash,
    }
}

/// Returns the canonical hash of a collapse predecessor commitment.
pub fn canonical_collapse_commitment_hash(
    commitment: &CanonicalCollapseCommitment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(commitment)
}

/// Returns the canonical hash of the collapse predecessor commitment implied by a full object.
pub fn canonical_collapse_commitment_hash_from_object(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    canonical_collapse_commitment_hash(&canonical_collapse_commitment(collapse))
}

/// Builds the ordinary AFT historical-continuation anchor when all three bootstrap hashes are
/// present, or `None` when all three are absent.
pub fn aft_historical_continuation_anchor(
    checkpoint_hash: [u8; 32],
    profile_activation_hash: [u8; 32],
    retention_receipt_hash: [u8; 32],
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    if checkpoint_hash == [0u8; 32]
        && profile_activation_hash == [0u8; 32]
        && retention_receipt_hash == [0u8; 32]
    {
        Ok(None)
    } else if checkpoint_hash == [0u8; 32]
        || profile_activation_hash == [0u8; 32]
        || retention_receipt_hash == [0u8; 32]
    {
        Err(
            "ordinary AFT historical continuation must carry either all bootstrap hashes or none"
                .into(),
        )
    } else {
        Ok(Some(AftHistoricalContinuationAnchor {
            checkpoint_hash,
            profile_activation_hash,
            retention_receipt_hash,
        }))
    }
}

/// Returns the archived recovered-history anchor named by a canonical collapse object when one is
/// present.
#[allow(clippy::type_complexity)]
pub fn canonical_collapse_archived_recovered_history_anchor(
    collapse: &CanonicalCollapseObject,
) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>, String> {
    let checkpoint_hash = collapse.archived_recovered_history_checkpoint_hash;
    let activation_hash = collapse.archived_recovered_history_profile_activation_hash;
    let receipt_hash = collapse.archived_recovered_history_retention_receipt_hash;
    if checkpoint_hash == [0u8; 32] && activation_hash == [0u8; 32] && receipt_hash == [0u8; 32] {
        Ok(None)
    } else if checkpoint_hash == [0u8; 32]
        || activation_hash == [0u8; 32]
        || receipt_hash == [0u8; 32]
    {
        Err(format!(
            "canonical collapse object at height {} must carry either all archived recovered-history anchor hashes or none",
            collapse.height
        ))
    } else {
        Ok(Some((checkpoint_hash, activation_hash, receipt_hash)))
    }
}

/// Returns the ordinary AFT historical-continuation anchor named by a canonical collapse object
/// when one is present.
pub fn canonical_collapse_historical_continuation_anchor(
    collapse: &CanonicalCollapseObject,
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    aft_historical_continuation_anchor(
        collapse.archived_recovered_history_checkpoint_hash,
        collapse.archived_recovered_history_profile_activation_hash,
        collapse.archived_recovered_history_retention_receipt_hash,
    )
    .map_err(|error| {
        format!(
            "canonical collapse object at height {} {error}",
            collapse.height
        )
    })
}

/// Attaches or clears the archived recovered-history anchor carried by ordinary canonical history.
pub fn set_canonical_collapse_archived_recovered_history_anchor(
    collapse: &mut CanonicalCollapseObject,
    checkpoint_hash: [u8; 32],
    profile_activation_hash: [u8; 32],
    retention_receipt_hash: [u8; 32],
) -> Result<(), String> {
    let all_zero = checkpoint_hash == [0u8; 32]
        && profile_activation_hash == [0u8; 32]
        && retention_receipt_hash == [0u8; 32];
    let all_non_zero = checkpoint_hash != [0u8; 32]
        && profile_activation_hash != [0u8; 32]
        && retention_receipt_hash != [0u8; 32];
    if !all_zero && !all_non_zero {
        return Err(format!(
            "canonical collapse object at height {} must carry either all archived recovered-history anchor hashes or none",
            collapse.height
        ));
    }
    collapse.archived_recovered_history_checkpoint_hash = checkpoint_hash;
    collapse.archived_recovered_history_profile_activation_hash = profile_activation_hash;
    collapse.archived_recovered_history_retention_receipt_hash = retention_receipt_hash;
    Ok(())
}

/// Returns the ordinary AFT historical-continuation anchor named by a replay-prefix entry when
/// one is present.
pub fn canonical_replay_prefix_historical_continuation_anchor(
    entry: &CanonicalReplayPrefixEntry,
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    aft_historical_continuation_anchor(
        entry
            .archived_recovered_history_checkpoint_hash
            .unwrap_or([0u8; 32]),
        entry
            .archived_recovered_history_profile_activation_hash
            .unwrap_or([0u8; 32]),
        entry
            .archived_recovered_history_retention_receipt_hash
            .unwrap_or([0u8; 32]),
    )
    .map_err(|error| {
        format!(
            "canonical replay prefix entry at height {} {error}",
            entry.height
        )
    })
}

/// Compares canonical collapse objects while ignoring only the archival-history anchor fields.
pub fn canonical_collapse_eq_ignoring_archived_recovered_history_anchor(
    left: &CanonicalCollapseObject,
    right: &CanonicalCollapseObject,
) -> bool {
    left.height == right.height
        && left.previous_canonical_collapse_commitment_hash
            == right.previous_canonical_collapse_commitment_hash
        && left.continuity_accumulator_hash == right.continuity_accumulator_hash
        && left.continuity_recursive_proof == right.continuity_recursive_proof
        && left.ordering == right.ordering
        && left.sealing == right.sealing
        && left.transactions_root_hash == right.transactions_root_hash
        && left.resulting_state_root_hash == right.resulting_state_root_hash
}

/// Compares canonical collapse objects on the subset of fields that are explicitly carried by a
/// block header.
///
/// This intentionally ignores the archived recovered-history anchor, current-step continuity
/// proof/accumulator material, same-slot sealing enrichment, and the materialized ordering-bundle
/// hashes that are reconstructible only from the full publication bundle rather than the
/// proof-carrying committed-block surface. That includes the canonical bulletin-close hash, because
/// the fully materialized close may be anchored with deterministic retrievability hashes that are
/// not present in the block surface available when successors extend the slot.
pub fn canonical_collapse_eq_on_header_surface(
    left: &CanonicalCollapseObject,
    right: &CanonicalCollapseObject,
) -> bool {
    left.height == right.height
        && left.previous_canonical_collapse_commitment_hash
            == right.previous_canonical_collapse_commitment_hash
        && left.ordering.height == right.ordering.height
        && left.ordering.kind == right.ordering.kind
        && left.ordering.bulletin_commitment_hash == right.ordering.bulletin_commitment_hash
        && left.ordering.bulletin_availability_certificate_hash
            == right.ordering.bulletin_availability_certificate_hash
        && left.ordering.canonical_order_certificate_hash
            == right.ordering.canonical_order_certificate_hash
        && left.transactions_root_hash == right.transactions_root_hash
        && left.resulting_state_root_hash == right.resulting_state_root_hash
}

/// Builds the compact durable prefix entry exposed to replay / checkpoint consumers.
pub fn canonical_replay_prefix_entry(
    collapse: &CanonicalCollapseObject,
    canonical_block_commitment_hash: Option<[u8; 32]>,
    parent_block_commitment_hash: Option<[u8; 32]>,
    ordering_resolution_hash: [u8; 32],
    publication_frontier_hash: Option<[u8; 32]>,
    extracted_bulletin_surface_present: bool,
) -> Result<CanonicalReplayPrefixEntry, String> {
    let archived_recovered_history_anchor =
        canonical_collapse_archived_recovered_history_anchor(collapse)?;
    Ok(CanonicalReplayPrefixEntry {
        height: collapse.height,
        resulting_state_root_hash: collapse.resulting_state_root_hash,
        canonical_block_commitment_hash,
        parent_block_commitment_hash,
        canonical_collapse_commitment_hash: canonical_collapse_commitment_hash_from_object(
            collapse,
        )?,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
        ordering_kind: collapse.ordering.kind,
        ordering_resolution_hash,
        publication_frontier_hash,
        extracted_bulletin_surface_present,
        archived_recovered_history_checkpoint_hash: archived_recovered_history_anchor
            .map(|(checkpoint_hash, _, _)| checkpoint_hash),
        archived_recovered_history_profile_activation_hash: archived_recovered_history_anchor
            .map(|(_, activation_hash, _)| activation_hash),
        archived_recovered_history_retention_receipt_hash: archived_recovered_history_anchor
            .map(|(_, _, receipt_hash)| receipt_hash),
    })
}

/// Builds the compact recovered header entry exposed to bounded ancestry consumers.
pub fn recovered_canonical_header_entry(
    collapse: &CanonicalCollapseObject,
    full_surface: &RecoverableSlotPayloadV5,
) -> Result<RecoveredCanonicalHeaderEntry, String> {
    if full_surface.height != collapse.height {
        return Err(format!(
            "recovered canonical header entry height mismatch: collapse {}, full surface {}",
            collapse.height, full_surface.height
        ));
    }
    if collapse.transactions_root_hash
        != full_surface
            .canonical_order_certificate
            .ordered_transactions_root_hash
    {
        return Err(format!(
            "recovered canonical header entry transactions-root mismatch at height {}",
            collapse.height
        ));
    }
    if collapse.resulting_state_root_hash
        != full_surface
            .canonical_order_certificate
            .resulting_state_root_hash
    {
        return Err(format!(
            "recovered canonical header entry state-root mismatch at height {}",
            collapse.height
        ));
    }

    Ok(RecoveredCanonicalHeaderEntry {
        height: collapse.height,
        view: full_surface.view,
        canonical_block_commitment_hash: full_surface.block_commitment_hash,
        parent_block_commitment_hash: full_surface.parent_block_hash,
        transactions_root_hash: full_surface
            .canonical_order_certificate
            .ordered_transactions_root_hash,
        resulting_state_root_hash: full_surface
            .canonical_order_certificate
            .resulting_state_root_hash,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
    })
}

/// Builds the compact recovered certified-header entry exposed to bounded restart consumers.
pub fn recovered_certified_header_entry(
    header: &RecoveredCanonicalHeaderEntry,
    previous: Option<&RecoveredCanonicalHeaderEntry>,
) -> Result<RecoveredCertifiedHeaderEntry, String> {
    if header.height == 0 {
        return Err("recovered certified header entry requires a non-zero height".into());
    }

    let (certified_parent_quorum_certificate, certified_parent_resulting_state_root_hash) =
        if header.height == 1 {
            (QuorumCertificate::default(), [0u8; 32])
        } else {
            let previous = previous.ok_or_else(|| {
                format!(
                    "recovered certified header entry at height {} requires a predecessor header",
                    header.height
                )
            })?;
            if previous.height + 1 != header.height {
                return Err(format!(
                    "recovered certified header entry height mismatch: previous {}, current {}",
                    previous.height, header.height
                ));
            }
            if previous.canonical_block_commitment_hash != header.parent_block_commitment_hash {
                return Err(format!(
                    "recovered certified header entry parent-block hash mismatch at height {}",
                    header.height
                ));
            }
            (
                previous.synthetic_quorum_certificate(),
                previous.resulting_state_root_hash,
            )
        };

    Ok(RecoveredCertifiedHeaderEntry {
        header: header.clone(),
        certified_parent_quorum_certificate,
        certified_parent_resulting_state_root_hash,
    })
}

/// Builds a bounded recovered certified-header prefix from consecutive recovered headers.
pub fn recovered_certified_header_prefix(
    previous: Option<&RecoveredCanonicalHeaderEntry>,
    headers: &[RecoveredCanonicalHeaderEntry],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    let mut certified_entries = Vec::with_capacity(headers.len());
    let mut previous_header = previous.cloned();

    for header in headers {
        let certified = recovered_certified_header_entry(header, previous_header.as_ref())?;
        previous_header = Some(header.clone());
        certified_entries.push(certified);
    }

    Ok(certified_entries)
}

fn stitch_recovered_windows<T, F>(
    windows: &[&[T]],
    height_of: F,
    label: &str,
) -> Result<Vec<T>, String>
where
    T: Clone + PartialEq,
    F: Fn(&T) -> u64,
{
    let mut merged = Vec::new();

    for (window_index, window) in windows.iter().enumerate() {
        if window.is_empty() {
            return Err(format!(
                "{label} window {} must not be empty",
                window_index + 1
            ));
        }

        for pair in window.windows(2) {
            let previous_height = height_of(&pair[0]);
            let next_height = height_of(&pair[1]);
            if next_height != previous_height + 1 {
                return Err(format!(
                    "{label} window {} must be consecutive: saw heights {} then {}",
                    window_index + 1,
                    previous_height,
                    next_height
                ));
            }
        }

        if merged.is_empty() {
            merged.extend(window.iter().cloned());
            continue;
        }

        let merged_start = height_of(&merged[0]);
        let merged_end = height_of(merged.last().expect("merged window tail"));
        let next_start = height_of(&window[0]);
        if next_start > merged_end {
            return Err(format!(
                "{label} window {} must overlap the previous window: previous ends at {}, next starts at {}",
                window_index + 1,
                merged_end,
                next_start
            ));
        }

        for entry in *window {
            let height = height_of(entry);
            if height < merged_start {
                return Err(format!(
                    "{label} window {} starts before the merged prefix at height {}",
                    window_index + 1,
                    merged_start
                ));
            }

            let offset = usize::try_from(height - merged_start)
                .map_err(|_| format!("{label} height offset overflow at {height}"))?;
            if offset < merged.len() {
                if merged[offset] != *entry {
                    return Err(format!(
                        "{label} overlap mismatch at height {} between windows {} and {}",
                        height,
                        window_index,
                        window_index + 1
                    ));
                }
            } else {
                let expected_next_height =
                    height_of(merged.last().expect("merged window tail")) + 1;
                if height != expected_next_height {
                    return Err(format!(
                        "{label} window {} does not continue consecutively after height {}",
                        window_index + 1,
                        height_of(merged.last().expect("merged window tail"))
                    ));
                }
                merged.push(entry.clone());
            }
        }
    }

    Ok(merged)
}

/// Stitches overlapping bounded recovered canonical-header windows into one longer prefix.
pub fn stitch_recovered_canonical_header_windows(
    windows: &[&[RecoveredCanonicalHeaderEntry]],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>, String> {
    stitch_recovered_windows(windows, |entry| entry.height, "recovered canonical header")
}

/// Stitches overlapping bounded recovered canonical-header segments into one
/// longer prefix.
pub fn stitch_recovered_canonical_header_segments(
    segments: &[&[RecoveredCanonicalHeaderEntry]],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>, String> {
    stitch_recovered_canonical_header_windows(segments)
}

/// Stitches overlapping bounded recovered certified-header windows into one longer prefix.
pub fn stitch_recovered_certified_header_windows(
    windows: &[&[RecoveredCertifiedHeaderEntry]],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    stitch_recovered_windows(
        windows,
        |entry| entry.header.height,
        "recovered certified header",
    )
}

/// Stitches overlapping bounded recovered certified-header segments into one
/// longer prefix.
pub fn stitch_recovered_certified_header_segments(
    segments: &[&[RecoveredCertifiedHeaderEntry]],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    stitch_recovered_certified_header_windows(segments)
}

/// Builds the restart-only synthetic block-header cache entry exposed to bounded
/// QC/header restart consumers.
pub fn recovered_restart_block_header_entry(
    full_surface: &RecoverableSlotPayloadV5,
    certified_header: &RecoveredCertifiedHeaderEntry,
) -> Result<RecoveredRestartBlockHeaderEntry, String> {
    if full_surface.height != certified_header.header.height {
        return Err(format!(
            "recovered restart block header height mismatch: payload {}, certified {}",
            full_surface.height, certified_header.header.height
        ));
    }
    if full_surface.view != certified_header.header.view {
        return Err(format!(
            "recovered restart block header view mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.block_commitment_hash != certified_header.header.canonical_block_commitment_hash
    {
        return Err(format!(
            "recovered restart block header block-commitment mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.parent_block_hash != certified_header.header.parent_block_commitment_hash {
        return Err(format!(
            "recovered restart block header parent-block mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.canonical_order_certificate.height != certified_header.header.height {
        return Err(format!(
            "recovered restart block header order-certificate height mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface
        .canonical_order_certificate
        .ordered_transactions_root_hash
        != certified_header.header.transactions_root_hash
    {
        return Err(format!(
            "recovered restart block header transactions-root mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface
        .canonical_order_certificate
        .resulting_state_root_hash
        != certified_header.header.resulting_state_root_hash
    {
        return Err(format!(
            "recovered restart block header state-root mismatch at height {}",
            full_surface.height
        ));
    }

    let parent_state_root_hash = if certified_header.header.height <= 1 {
        [0u8; 32]
    } else {
        certified_header.certified_parent_resulting_state_root_hash
    };
    let cutoff_timestamp_ms = full_surface
        .canonical_order_certificate
        .bulletin_commitment
        .cutoff_timestamp_ms;

    Ok(RecoveredRestartBlockHeaderEntry {
        certified_header: certified_header.clone(),
        header: BlockHeader {
            height: certified_header.header.height,
            view: certified_header.header.view,
            parent_hash: certified_header.header.parent_block_commitment_hash,
            parent_state_root: StateRoot(parent_state_root_hash.to_vec()),
            state_root: StateRoot(certified_header.header.resulting_state_root_hash.to_vec()),
            transactions_root: certified_header.header.transactions_root_hash.to_vec(),
            timestamp: timestamp_millis_to_legacy_seconds(cutoff_timestamp_ms),
            timestamp_ms: cutoff_timestamp_ms,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: full_surface.producer_account_id,
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0u8; 32],
            producer_pubkey: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: Some(full_surface.canonical_order_certificate.clone()),
            timeout_certificate: None,
            parent_qc: certified_header.certified_parent_quorum_certificate.clone(),
            previous_canonical_collapse_commitment_hash: certified_header
                .header
                .previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
    })
}

/// Stitches overlapping bounded recovered restart block-header windows into one longer prefix.
pub fn stitch_recovered_restart_block_header_windows(
    windows: &[&[RecoveredRestartBlockHeaderEntry]],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, String> {
    stitch_recovered_windows(
        windows,
        |entry| entry.header.height,
        "recovered restart block header",
    )
}

/// Stitches overlapping bounded recovered restart block-header segments into
/// one longer prefix.
pub fn stitch_recovered_restart_block_header_segments(
    segments: &[&[RecoveredRestartBlockHeaderEntry]],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, String> {
    stitch_recovered_restart_block_header_windows(segments)
}
