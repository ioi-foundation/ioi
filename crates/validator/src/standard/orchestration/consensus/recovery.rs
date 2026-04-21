use super::*;

pub(super) fn select_unique_recovered_publication_bundle(
    mut recovered: Vec<RecoveredPublicationBundle>,
) -> Option<RecoveredPublicationBundle> {
    let first = recovered.first()?.clone();
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
        return None;
    }
    recovered.pop()
}

pub(super) fn resolve_recovered_consensus_header_entry(
    recovered_headers: &[RecoveredCanonicalHeaderEntry],
    expected_height: u64,
) -> Option<RecoveredCanonicalHeaderEntry> {
    recovered_headers
        .iter()
        .rev()
        .find(|entry| entry.height == expected_height)
        .cloned()
}

pub(super) async fn load_recovered_consensus_header_for_height(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    height: u64,
) -> Result<Option<RecoveredCanonicalHeaderEntry>> {
    let Some((collapse, full_surface)) =
        load_recovered_full_surface_for_height(workload_client, height).await?
    else {
        return Ok(None);
    };

    recovered_canonical_header_entry(&collapse, &full_surface)
        .map(Some)
        .map_err(|e| {
            anyhow!("failed to derive recovered canonical header entry at height {height}: {e}")
        })
}

pub(super) async fn load_recovered_full_surface_for_height(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    height: u64,
) -> Result<Option<(CanonicalCollapseObject, RecoverableSlotPayloadV5)>> {
    let Some(collapse_bytes) = workload_client
        .query_raw_state(&aft_canonical_collapse_object_key(height))
        .await?
    else {
        return Ok(None);
    };
    let collapse: CanonicalCollapseObject =
        codec::from_bytes_canonical(&collapse_bytes).map_err(|e| {
            anyhow!("failed to decode canonical collapse object at height {height}: {e}")
        })?;

    let recovered_prefix = [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
    ]
    .concat();
    let recovered_rows = workload_client.prefix_scan(&recovered_prefix).await?;
    let mut recovered = Vec::with_capacity(recovered_rows.len());
    for (_, value) in recovered_rows {
        let object: RecoveredPublicationBundle =
            codec::from_bytes_canonical(&value).map_err(|e| {
                anyhow!("failed to decode recovered publication bundle at height {height}: {e}")
            })?;
        recovered.push(object);
    }
    let Some(recovered) = select_unique_recovered_publication_bundle(recovered) else {
        return Ok(None);
    };

    let mut materials = Vec::with_capacity(recovered.supporting_witness_manifest_hashes.len());
    for witness_manifest_hash in &recovered.supporting_witness_manifest_hashes {
        let Some(bytes) = workload_client
            .query_raw_state(&ioi_types::app::aft_recovery_share_material_key(
                height,
                witness_manifest_hash,
                &recovered.block_commitment_hash,
            ))
            .await?
        else {
            return Ok(None);
        };
        let material: RecoveryShareMaterial = codec::from_bytes_canonical(&bytes).map_err(|e| {
            anyhow!(
                "failed to decode recovery share material at height {} for witness {}: {}",
                height,
                hex::encode(witness_manifest_hash),
                e
            )
        })?;
        if material.coding != recovered.coding {
            return Ok(None);
        }
        materials.push(material);
    }

    let (full_surface, publication_bundle, bulletin_close, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials).map_err(|e| {
            anyhow!("failed to recover full canonical order surface at height {height}: {e}")
        })?;
    if full_surface.height != recovered.height
        || full_surface.block_commitment_hash != recovered.block_commitment_hash
        || full_surface.parent_block_hash != recovered.parent_block_commitment_hash
    {
        return Ok(None);
    }
    let full_surface_hash = canonical_recoverable_slot_payload_v5_hash(&full_surface)
        .map_err(|e| anyhow!("failed to hash recovered full surface at height {height}: {e}"))?;
    if full_surface_hash != recovered.recoverable_full_surface_hash {
        return Ok(None);
    }
    let publication_bundle_hash = canonical_order_publication_bundle_hash(&publication_bundle)
        .map_err(|e| {
            anyhow!("failed to hash recovered publication bundle at height {height}: {e}")
        })?;
    if publication_bundle_hash != recovered.canonical_order_publication_bundle_hash {
        return Ok(None);
    }
    let bulletin_close_hash = canonical_bulletin_close_hash(&bulletin_close)
        .map_err(|e| anyhow!("failed to hash recovered bulletin close at height {height}: {e}"))?;
    if bulletin_close_hash != recovered.canonical_bulletin_close_hash {
        return Ok(None);
    }

    Ok(Some((collapse, full_surface)))
}

pub(super) async fn load_canonical_collapse_object(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    height: u64,
) -> Result<Option<CanonicalCollapseObject>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_canonical_collapse_object_key(height))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode canonical collapse object at height {height}: {e}"))
}

pub(super) async fn load_archived_recovered_history_profile_activation_by_hash(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    activation_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_profile_activation_hash_key(
            activation_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes).map(Some).map_err(|e| {
        anyhow!("failed to decode archived recovered-history profile activation by hash: {e}")
    })
}

pub(super) async fn load_archived_recovered_history_anchor_from_canonical_collapse_tip(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    height: u64,
) -> Result<Option<AftHistoricalContinuationSurface>> {
    let Some(collapse) = load_canonical_collapse_object(workload_client, height).await? else {
        return Ok(None);
    };
    let Some(anchor) = canonical_collapse_historical_continuation_anchor(&collapse)
        .map_err(|error| anyhow!(error))?
    else {
        return Ok(None);
    };
    let checkpoint_hash = anchor.checkpoint_hash;
    let activation_hash = anchor.profile_activation_hash;
    let receipt_hash = anchor.retention_receipt_hash;
    let Some(checkpoint) =
        load_archived_recovered_history_checkpoint_by_hash(workload_client, &checkpoint_hash)
            .await?
    else {
        return Err(anyhow!(
            "canonical collapse archived recovered-history checkpoint anchor is missing from state"
        ));
    };
    let Some(activation) = load_archived_recovered_history_profile_activation_by_hash(
        workload_client,
        &activation_hash,
    )
    .await?
    else {
        return Err(anyhow!(
            "canonical collapse archived recovered-history profile activation anchor is missing from state"
        ));
    };
    let expected_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&checkpoint).map_err(|error| {
            anyhow!("failed to hash archived recovered-history checkpoint: {error}")
        })?;
    if expected_checkpoint_hash != checkpoint_hash {
        return Err(anyhow!(
            "canonical collapse archived recovered-history checkpoint anchor does not match the published checkpoint"
        ));
    }
    let expected_activation_hash = canonical_archived_recovered_history_profile_activation_hash(
        &activation,
    )
    .map_err(|error| {
        anyhow!("failed to hash archived recovered-history profile activation: {error}")
    })?;
    if expected_activation_hash != activation_hash {
        return Err(anyhow!(
            "canonical collapse archived recovered-history profile activation anchor does not match the published activation"
        ));
    }
    let Some(receipt) =
        load_archived_recovered_history_retention_receipt(workload_client, &checkpoint_hash)
            .await?
    else {
        return Err(anyhow!(
            "canonical collapse archived recovered-history retention receipt anchor is missing from state"
        ));
    };
    let expected_receipt_hash =
        canonical_archived_recovered_history_retention_receipt_hash(&receipt).map_err(|error| {
            anyhow!("failed to hash archived recovered-history retention receipt: {error}")
        })?;
    if expected_receipt_hash != receipt_hash {
        return Err(anyhow!(
            "canonical collapse archived recovered-history retention receipt anchor does not match the published receipt"
        ));
    }
    if checkpoint.covered_end_height > collapse.height {
        return Err(anyhow!(
            "canonical collapse archived recovered-history checkpoint anchor exceeds the collapse height"
        ));
    }
    Ok(Some(AftHistoricalContinuationSurface {
        anchor,
        checkpoint,
        profile_activation: activation,
        retention_receipt: receipt,
    }))
}

pub(super) async fn load_archived_recovered_history_profile_by_hash(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    profile_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryProfile>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_profile_hash_key(
            profile_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    let profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(&bytes)
        .map_err(|e| anyhow!("failed to decode archived recovered-history profile by hash: {e}"))?;
    validate_archived_recovered_history_profile(&profile).map_err(|error| anyhow!(error))?;
    Ok(Some(profile))
}

pub(super) async fn load_archived_recovered_history_profile_activation(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    profile_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_profile_activation_key(
            profile_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered-history profile activation: {e}"))
}

pub(super) async fn validate_archived_recovered_history_profile_activation_chain_for_checkpoint(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    activation: &ArchivedRecoveredHistoryProfileActivation,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
) -> Result<ArchivedRecoveredHistoryProfile> {
    // Archived replay correctness is historical and index-free: start from the
    // canonical-collapse-anchored activation object itself and walk backward
    // through predecessor/profile/checkpoint links without consulting any
    // latest-activation tip index.
    let mut current_activation = activation.clone();
    let mut successor_activation = None::<ArchivedRecoveredHistoryProfileActivation>;
    let mut governed_profile = None::<ArchivedRecoveredHistoryProfile>;
    let mut seen_profiles = BTreeSet::new();
    loop {
        if !seen_profiles.insert(current_activation.archived_profile_hash) {
            return Err(anyhow!(
                "archived recovered-history profile activation chain contains a cycle"
            ));
        }
        let Some(profile) = load_archived_recovered_history_profile_by_hash(
            workload_client,
            &current_activation.archived_profile_hash,
        )
        .await?
        else {
            return Err(anyhow!(
                "archived recovered-history profile activation references a missing archived profile hash"
            ));
        };
        let activation_checkpoint = if current_activation.activation_checkpoint_hash == [0u8; 32] {
            None
        } else {
            let Some(activation_checkpoint) = load_archived_recovered_history_checkpoint_by_hash(
                workload_client,
                &current_activation.activation_checkpoint_hash,
            )
            .await?
            else {
                return Err(anyhow!(
                    "archived recovered-history profile activation checkpoint is missing from state"
                ));
            };
            Some(activation_checkpoint)
        };
        if let Some(successor_activation) = successor_activation.as_ref() {
            validate_archived_recovered_history_profile_activation_successor(
                &current_activation,
                successor_activation,
            )
            .map_err(|error| anyhow!(error))?;
            validate_archived_recovered_history_profile_activation_checkpoint(
                &current_activation,
                activation_checkpoint.as_ref(),
                &profile,
            )
            .map_err(|error| anyhow!(error))?;
        } else {
            validate_archived_recovered_history_profile_activation_against_checkpoint(
                &current_activation,
                activation_checkpoint.as_ref(),
                checkpoint,
                &profile,
            )
            .map_err(|error| anyhow!(error))?;
            governed_profile = Some(profile.clone());
        }
        if current_activation.previous_archived_profile_hash == [0u8; 32] {
            return governed_profile.ok_or_else(|| {
                anyhow!(
                    "archived recovered-history profile activation chain does not govern the referenced archived checkpoint"
                )
            });
        }
        successor_activation = Some(current_activation.clone());
        let previous_profile_hash = current_activation.previous_archived_profile_hash;
        let Some(previous_activation) = load_archived_recovered_history_profile_activation(
            workload_client,
            &previous_profile_hash,
        )
        .await?
        else {
            return Err(anyhow!(
                "archived recovered-history profile activation predecessor is missing from state"
            ));
        };
        current_activation = previous_activation;
    }
}

pub(super) async fn load_archived_recovered_history_checkpoint_by_hash(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_checkpoint_hash_key(
            checkpoint_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered-history checkpoint: {e}"))
}

pub(super) async fn load_archived_recovered_history_retention_receipt(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryRetentionReceipt>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_retention_receipt_key(
            checkpoint_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered-history retention receipt: {e}"))
}

pub(super) async fn load_archived_recovered_history_segment_by_hash(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    segment_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistorySegment>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_segment_hash_key(
            segment_hash,
        ))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered-history segment by hash: {e}"))
}

pub(super) async fn load_archived_recovered_restart_page_by_hash(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    segment_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredRestartPage>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_restart_page_key(segment_hash))
        .await?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered restart page: {e}"))
}

pub(super) async fn load_bounded_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    if end_height == 0 || window == 0 {
        return Ok(Vec::new());
    }

    let start_height = end_height.saturating_sub(window.saturating_sub(1)).max(1);
    let mut recovered_headers = Vec::new();
    for height in start_height..=end_height {
        if let Some(entry) =
            load_recovered_consensus_header_for_height(workload_client, height).await?
        {
            recovered_headers.push(entry);
        }
    }
    Ok(recovered_headers)
}

pub(super) fn bounded_recovered_window_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
) -> Vec<(u64, u64)> {
    if start_height == 0 || end_height == 0 || window == 0 || end_height < start_height {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let mut ranges = Vec::new();
    let step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let mut next_start = start_height;

    loop {
        let next_end = next_start
            .saturating_add(window.saturating_sub(1))
            .min(end_height);
        ranges.push((next_start, next_end));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(step);
    }

    ranges
}

pub(super) fn bounded_recovered_window_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    window_count: u64,
) -> u64 {
    if end_height == 0 || window == 0 || window_count == 0 {
        return 0;
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let covered_span = window.saturating_add(step.saturating_mul(window_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
}

pub(super) fn bounded_recovered_segment_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Vec<Vec<(u64, u64)>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let mut next_start = start_height;
    let mut segments = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(segment_span.saturating_sub(1))
            .min(end_height);
        segments.push(bounded_recovered_window_ranges(
            next_start, next_end, window, overlap,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(segment_step);
    }

    segments
}

pub(super) fn bounded_recovered_segment_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segment_count: u64,
) -> u64 {
    if end_height == 0 || window == 0 || windows_per_segment == 0 || segment_count == 0 {
        return 0;
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let covered_span =
        segment_span.saturating_add(segment_step.saturating_mul(segment_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
}

pub(super) fn bounded_recovered_segment_fold_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Vec<Vec<Vec<(u64, u64)>>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let fold_span = segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1)));
    let fold_step = segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1);
    let mut next_start = start_height;
    let mut folds = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(fold_span.saturating_sub(1))
            .min(end_height);
        folds.push(bounded_recovered_segment_ranges(
            next_start,
            next_end,
            window,
            overlap,
            windows_per_segment,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(fold_step);
    }

    folds
}

pub(super) fn bounded_recovered_segment_fold_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> u64 {
    if end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || fold_count == 0
    {
        return 0;
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let fold_span = segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1)));
    let fold_step = segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1);
    let covered_span =
        fold_span.saturating_add(fold_step.saturating_mul(fold_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
}

pub(super) async fn load_window_stitched_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    window_count: u64,
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    let start_height =
        bounded_recovered_window_start_height(end_height, window, overlap, window_count);
    let ranges = bounded_recovered_window_ranges(start_height, end_height, window, overlap);
    if ranges.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(ranges.len());
    for (_, end) in &ranges {
        extracted.push(
            load_bounded_recovered_consensus_headers(workload_client, *end, window.min(*end))
                .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_canonical_header_windows(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered canonical-header windows: {error}"))
}

pub(super) async fn load_stitched_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segment_count: u64,
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    let start_height = bounded_recovered_segment_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segment_count,
    );
    let segments = bounded_recovered_segment_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
    );
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in &segments {
        let segment_end = windows
            .last()
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered consensus-header segment");
        extracted.push(
            load_window_stitched_recovered_consensus_headers(
                workload_client,
                segment_end,
                window,
                overlap,
                windows.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_canonical_header_segments(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered canonical-header segments: {error}"))
}

pub(super) async fn load_folded_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    let start_height = bounded_recovered_segment_fold_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        fold_count,
    );
    let folds = bounded_recovered_segment_fold_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
    );
    if folds.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(folds.len());
    for segments in &folds {
        let fold_end = segments
            .last()
            .and_then(|windows| windows.last())
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered canonical-header segment fold");
        extracted.push(
            load_stitched_recovered_consensus_headers(
                workload_client,
                fold_end,
                window,
                overlap,
                windows_per_segment,
                segments.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_canonical_header_segments(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered canonical-header segment folds: {error}")
    })
}

pub(super) async fn load_bounded_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    if end_height == 0 || window == 0 {
        return Ok(Vec::new());
    }

    let start_height = end_height.saturating_sub(window.saturating_sub(1)).max(1);
    let previous = if start_height <= 1 {
        None
    } else {
        load_recovered_consensus_header_for_height(workload_client, start_height - 1).await?
    };
    let headers =
        load_bounded_recovered_consensus_headers(workload_client, end_height, window).await?;
    recovered_certified_header_prefix(previous.as_ref(), &headers)
        .map_err(|error| anyhow!("failed to derive recovered certified-header prefix: {error}"))
}

pub(super) async fn load_window_stitched_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    window_count: u64,
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    let start_height =
        bounded_recovered_window_start_height(end_height, window, overlap, window_count);
    let ranges = bounded_recovered_window_ranges(start_height, end_height, window, overlap);
    if ranges.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(ranges.len());
    for (_, end) in &ranges {
        extracted.push(
            load_bounded_recovered_certified_headers(workload_client, *end, window.min(*end))
                .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_certified_header_windows(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered certified-header windows: {error}"))
}

pub(super) async fn load_stitched_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segment_count: u64,
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    let start_height = bounded_recovered_segment_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segment_count,
    );
    let segments = bounded_recovered_segment_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
    );
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in &segments {
        let segment_end = windows
            .last()
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered certified-header segment");
        extracted.push(
            load_window_stitched_recovered_certified_headers(
                workload_client,
                segment_end,
                window,
                overlap,
                windows.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_certified_header_segments(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered certified-header segments: {error}"))
}

pub(super) async fn load_folded_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    let start_height = bounded_recovered_segment_fold_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        fold_count,
    );
    let folds = bounded_recovered_segment_fold_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
    );
    if folds.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(folds.len());
    for segments in &folds {
        let fold_end = segments
            .last()
            .and_then(|windows| windows.last())
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered certified-header segment fold");
        extracted.push(
            load_stitched_recovered_certified_headers(
                workload_client,
                fold_end,
                window,
                overlap,
                windows_per_segment,
                segments.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_certified_header_segments(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered certified-header segment folds: {error}")
    })
}

pub(super) async fn load_bounded_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    if end_height == 0 || window == 0 {
        return Ok(Vec::new());
    }

    let start_height = end_height.saturating_sub(window.saturating_sub(1)).max(1);
    let previous = if start_height <= 1 {
        None
    } else {
        load_recovered_consensus_header_for_height(workload_client, start_height - 1).await?
    };

    let mut full_surfaces = Vec::new();
    let mut headers = Vec::new();
    for height in start_height..=end_height {
        if let Some((collapse, full_surface)) =
            load_recovered_full_surface_for_height(workload_client, height).await?
        {
            let header =
                recovered_canonical_header_entry(&collapse, &full_surface).map_err(|error| {
                    anyhow!(
                        "failed to derive recovered canonical header at height {height}: {error}"
                    )
                })?;
            full_surfaces.push(full_surface);
            headers.push(header);
        }
    }

    let certified_headers = recovered_certified_header_prefix(previous.as_ref(), &headers)
        .map_err(|error| anyhow!("failed to derive recovered certified-header prefix: {error}"))?;
    certified_headers
        .into_iter()
        .zip(full_surfaces)
        .map(|(certified_header, full_surface)| {
            recovered_restart_block_header_entry(&full_surface, &certified_header).map_err(
                |error| {
                    anyhow!(
                        "failed to derive recovered restart block-header entry at height {}: {error}",
                        certified_header.header.height
                    )
                },
            )
        })
        .collect()
}

pub(super) async fn load_window_stitched_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    window_count: u64,
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    let start_height =
        bounded_recovered_window_start_height(end_height, window, overlap, window_count);
    let ranges = bounded_recovered_window_ranges(start_height, end_height, window, overlap);
    if ranges.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(ranges.len());
    for (_, end) in &ranges {
        extracted.push(
            load_bounded_recovered_restart_block_headers(workload_client, *end, window.min(*end))
                .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_windows(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered restart block-header windows: {error}")
    })
}

pub(super) async fn load_stitched_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segment_count: u64,
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    let start_height = bounded_recovered_segment_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segment_count,
    );
    let segments = bounded_recovered_segment_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
    );
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in &segments {
        let segment_end = windows
            .last()
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered restart-header segment");
        extracted.push(
            load_window_stitched_recovered_restart_block_headers(
                workload_client,
                segment_end,
                window,
                overlap,
                windows.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_segments(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered restart block-header segments: {error}")
    })
}

pub(super) async fn load_folded_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    let start_height = bounded_recovered_segment_fold_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        fold_count,
    );
    let folds = bounded_recovered_segment_fold_ranges(
        start_height,
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
    );
    if folds.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(folds.len());
    for segments in &folds {
        let fold_end = segments
            .last()
            .and_then(|windows| windows.last())
            .map(|(_, end_height)| *end_height)
            .expect("non-empty recovered restart-header segment fold");
        extracted.push(
            load_stitched_recovered_restart_block_headers(
                workload_client,
                fold_end,
                window,
                overlap,
                windows_per_segment,
                segments.len() as u64,
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_segments(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered restart block-header segment folds: {error}")
    })
}

pub(super) async fn load_window_range_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    windows: &[(u64, u64)],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    if windows.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(windows.len());
    for (start_height, end_height) in windows {
        extracted.push(
            load_bounded_recovered_consensus_headers(
                workload_client,
                *end_height,
                end_height.saturating_sub(*start_height).saturating_add(1),
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_canonical_header_windows(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered canonical-header windows: {error}"))
}

pub(super) async fn load_segment_range_recovered_consensus_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    segments: &[Vec<(u64, u64)>],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>> {
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in segments {
        extracted
            .push(load_window_range_recovered_consensus_headers(workload_client, windows).await?);
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_canonical_header_segments(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered canonical-header segments: {error}"))
}

pub(super) async fn load_window_range_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    windows: &[(u64, u64)],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    if windows.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(windows.len());
    for (start_height, end_height) in windows {
        extracted.push(
            load_bounded_recovered_certified_headers(
                workload_client,
                *end_height,
                end_height.saturating_sub(*start_height).saturating_add(1),
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_certified_header_windows(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered certified-header windows: {error}"))
}

pub(super) async fn load_segment_range_recovered_certified_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    segments: &[Vec<(u64, u64)>],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>> {
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in segments {
        extracted
            .push(load_window_range_recovered_certified_headers(workload_client, windows).await?);
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_certified_header_segments(&slices)
        .map_err(|error| anyhow!("failed to stitch recovered certified-header segments: {error}"))
}

pub(super) async fn load_window_range_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    windows: &[(u64, u64)],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    if windows.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(windows.len());
    for (start_height, end_height) in windows {
        extracted.push(
            load_bounded_recovered_restart_block_headers(
                workload_client,
                *end_height,
                end_height.saturating_sub(*start_height).saturating_add(1),
            )
            .await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_windows(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered restart block-header windows: {error}")
    })
}

pub(super) async fn load_segment_range_recovered_restart_block_headers(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    segments: &[Vec<(u64, u64)>],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>> {
    if segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(segments.len());
    for windows in segments {
        extracted.push(
            load_window_range_recovered_restart_block_headers(workload_client, windows).await?,
        );
    }
    let slices = extracted.iter().map(Vec::as_slice).collect::<Vec<_>>();
    stitch_recovered_restart_block_header_segments(&slices).map_err(|error| {
        anyhow!("failed to stitch recovered restart block-header segments: {error}")
    })
}

#[derive(Debug)]
pub(super) struct LoadedRecoveredSegmentFoldPage {
    start_height: u64,
    end_height: u64,
    consensus_headers: Vec<RecoveredCanonicalHeaderEntry>,
    certified_headers: Vec<RecoveredCertifiedHeaderEntry>,
    restart_headers: Vec<RecoveredRestartBlockHeaderEntry>,
}

pub(super) async fn load_recovered_segment_fold_page(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    page: &RecoveredSegmentFoldPage,
) -> Result<LoadedRecoveredSegmentFoldPage> {
    let consensus_headers =
        load_segment_range_recovered_consensus_headers(workload_client, &page.segments).await?;
    validate_recovered_page_coverage(
        page,
        &consensus_headers,
        |entry| entry.height,
        "recovered canonical header",
    )
    .map_err(|error| anyhow!("{error}"))?;

    let certified_headers =
        load_segment_range_recovered_certified_headers(workload_client, &page.segments).await?;
    validate_recovered_page_coverage(
        page,
        &certified_headers,
        |entry| entry.header.height,
        "recovered certified header",
    )
    .map_err(|error| anyhow!("{error}"))?;

    let restart_headers =
        load_segment_range_recovered_restart_block_headers(workload_client, &page.segments).await?;
    validate_recovered_page_coverage(
        page,
        &restart_headers,
        |entry| entry.header.height,
        "recovered restart block header",
    )
    .map_err(|error| anyhow!("{error}"))?;

    Ok(LoadedRecoveredSegmentFoldPage {
        start_height: page.start_height,
        end_height: page.end_height,
        consensus_headers,
        certified_headers,
        restart_headers,
    })
}

pub(super) fn loaded_recovered_ancestry_start_height(
    recovered_consensus_headers: &[RecoveredCanonicalHeaderEntry],
    recovered_certified_headers: &[RecoveredCertifiedHeaderEntry],
    recovered_restart_block_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Option<u64> {
    recovered_consensus_headers
        .first()
        .map(|entry| entry.height)
        .into_iter()
        .chain(
            recovered_certified_headers
                .first()
                .map(|entry| entry.header.height),
        )
        .chain(
            recovered_restart_block_headers
                .first()
                .map(|entry| entry.header.height),
        )
        .min()
}

pub(super) fn loaded_recovered_ancestry_end_height(
    recovered_consensus_headers: &[RecoveredCanonicalHeaderEntry],
    recovered_certified_headers: &[RecoveredCertifiedHeaderEntry],
    recovered_restart_block_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Option<u64> {
    recovered_consensus_headers
        .last()
        .map(|entry| entry.height)
        .into_iter()
        .chain(
            recovered_certified_headers
                .last()
                .map(|entry| entry.header.height),
        )
        .chain(
            recovered_restart_block_headers
                .last()
                .map(|entry| entry.header.height),
        )
        .max()
}

pub(super) fn recovered_keep_ranges(
    base_range: Option<(u64, u64)>,
    paged_range: Option<(u64, u64)>,
) -> Vec<(u64, u64)> {
    base_range
        .into_iter()
        .chain(paged_range)
        .collect::<Vec<_>>()
}

#[derive(Debug)]
pub(super) struct RecoveredAncestryStreamReport {
    pub(super) loaded_pages: Vec<(u64, u64)>,
    pub(super) covered_target: bool,
    pub(super) exhausted: bool,
}

pub(super) async fn stream_archived_recovered_ancestry_to_height<CE>(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    target_height: u64,
    base_range: (u64, u64),
    mut oldest_loaded_height: u64,
) -> Result<RecoveredAncestryStreamReport>
where
    CE: ConsensusEngine<ChainTransaction>,
{
    let mut archived_range = None::<(u64, u64)>;
    let mut loaded_pages = Vec::new();
    let mut covered_target = false;
    let mut exhausted = false;
    let validator_set_commitment_hash = {
        let Some(validator_set_bytes) = workload_client.query_raw_state(VALIDATOR_SET_KEY).await?
        else {
            return Err(anyhow!(
                "active validator set missing while streaming archived recovered ancestry"
            ));
        };
        let validator_sets = read_validator_sets(&validator_set_bytes)
            .map_err(|error| anyhow!("failed to decode active validator set: {error}"))?;
        canonical_validator_sets_hash(&validator_sets)
            .map_err(|error| anyhow!("failed to hash active validator set: {error}"))?
    };
    let Some(historical_retrievability) =
        load_archived_recovered_history_anchor_from_canonical_collapse_tip(
            workload_client,
            base_range.1,
        )
        .await?
    else {
        return Ok(RecoveredAncestryStreamReport {
            loaded_pages,
            covered_target,
            exhausted: true,
        });
    };
    let mut checkpoint = historical_retrievability.checkpoint;
    let anchored_activation = historical_retrievability.profile_activation;
    let receipt = historical_retrievability.retention_receipt;
    let mut profile = validate_archived_recovered_history_profile_activation_chain_for_checkpoint(
        workload_client,
        &anchored_activation,
        &checkpoint,
    )
    .await?;
    let checkpoint_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
        .map_err(|error| anyhow!("failed to hash latest archived checkpoint: {error}"))?;
    validate_archived_recovered_history_checkpoint_against_profile(&checkpoint, &profile)
        .map_err(|error| anyhow!(error))?;
    if receipt.archived_checkpoint_hash != checkpoint_hash
        || receipt.covered_start_height != checkpoint.covered_start_height
        || receipt.covered_end_height != checkpoint.covered_end_height
    {
        return Err(anyhow!(
            "archived recovered-history retention receipt does not match the latest archived checkpoint tip"
        ));
    }
    if receipt.validator_set_commitment_hash != validator_set_commitment_hash {
        return Err(anyhow!(
            "archived recovered-history retention receipt validator-set commitment does not match the active validator set"
        ));
    }
    validate_archived_recovered_history_retention_receipt_against_profile(
        &receipt,
        &checkpoint,
        &profile,
    )
    .map_err(|error| anyhow!(error))?;
    if receipt.retained_through_height < base_range.1 {
        return Err(anyhow!(
            "archived recovered-history retention receipt does not cover the retained ancestry tip height {}",
            base_range.1
        ));
    }

    while target_height < oldest_loaded_height {
        validate_archived_recovered_history_checkpoint_against_profile(&checkpoint, &profile)
            .map_err(|error| anyhow!(error))?;
        let Some(archived_segment) = load_archived_recovered_history_segment_by_hash(
            workload_client,
            &checkpoint.latest_archived_segment_hash,
        )
        .await?
        else {
            exhausted = true;
            break;
        };
        if archived_segment.start_height != checkpoint.covered_start_height
            || archived_segment.end_height != checkpoint.covered_end_height
        {
            return Err(anyhow!(
                "archived recovered-history checkpoint {}..={} does not match archived segment {}..={}",
                checkpoint.covered_start_height,
                checkpoint.covered_end_height,
                archived_segment.start_height,
                archived_segment.end_height
            ));
        }
        let archived_segment_hash = canonical_archived_recovered_history_segment_hash(
            &archived_segment,
        )
        .map_err(|error| anyhow!("failed to hash archived recovered-history segment: {error}"))?;
        if archived_segment_hash != checkpoint.latest_archived_segment_hash {
            return Err(anyhow!(
                "archived recovered-history checkpoint segment hash does not match the archived segment descriptor for {}..={}",
                archived_segment.start_height,
                archived_segment.end_height
            ));
        }
        validate_archived_recovered_history_segment_against_profile(&archived_segment, &profile)
            .map_err(|error| anyhow!(error))?;
        let Some(archived_page) =
            load_archived_recovered_restart_page_by_hash(workload_client, &archived_segment_hash)
                .await?
        else {
            exhausted = true;
            break;
        };
        let archived_page_hash = canonical_archived_recovered_restart_page_hash(&archived_page)
            .map_err(|error| anyhow!("failed to hash archived recovered restart page: {error}"))?;
        if archived_page_hash != checkpoint.latest_archived_restart_page_hash {
            return Err(anyhow!(
                "archived recovered-history checkpoint page hash does not match the archived restart page for {}..={}",
                archived_page.start_height,
                archived_page.end_height
            ));
        }
        if archived_page.start_height != archived_segment.start_height
            || archived_page.end_height != archived_segment.end_height
        {
            return Err(anyhow!(
                "archived recovered restart page {}..={} does not match archived segment {}..={}",
                archived_page.start_height,
                archived_page.end_height,
                archived_segment.start_height,
                archived_segment.end_height
            ));
        }
        validate_archived_recovered_restart_page_against_profile(&archived_page, &profile)
            .map_err(|error| anyhow!(error))?;

        let archived_consensus_headers = archived_page
            .restart_headers
            .iter()
            .map(|entry| entry.certified_header.header.clone())
            .collect::<Vec<_>>();
        let archived_certified_headers = archived_page
            .restart_headers
            .iter()
            .map(|entry| entry.certified_header.clone())
            .collect::<Vec<_>>();
        let archived_recovered_state = AftRecoveredStateSurface {
            replay_prefix: Vec::new(),
            consensus_headers: archived_consensus_headers,
            certified_headers: archived_certified_headers,
            restart_headers: archived_page.restart_headers.clone(),
            historical_retrievability: None,
        };

        {
            let mut engine = consensus_engine_ref.lock().await;
            seed_aft_recovered_state_into_engine(&mut *engine, &archived_recovered_state);
            archived_range = Some(match archived_range {
                Some((start, end)) => (
                    archived_page.start_height.min(start),
                    archived_page.end_height.max(end),
                ),
                None => (archived_page.start_height, archived_page.end_height),
            });
            let keep_ranges = recovered_keep_ranges(Some(base_range), archived_range);
            engine.retain_recovered_ancestry_ranges(&keep_ranges);
        }

        loaded_pages.push((archived_page.start_height, archived_page.end_height));
        oldest_loaded_height = archived_page.start_height;
        if target_height >= archived_page.start_height {
            covered_target = true;
            break;
        }
        if checkpoint.previous_archived_checkpoint_hash == [0u8; 32] {
            exhausted = true;
            break;
        }
        let Some(previous_checkpoint) = load_archived_recovered_history_checkpoint_by_hash(
            workload_client,
            &checkpoint.previous_archived_checkpoint_hash,
        )
        .await?
        else {
            exhausted = true;
            break;
        };
        let previous_checkpoint_hash =
            canonical_archived_recovered_history_checkpoint_hash(&previous_checkpoint).map_err(
                |error| anyhow!("failed to hash archived recovered-history checkpoint: {error}"),
            )?;
        if previous_checkpoint_hash != checkpoint.previous_archived_checkpoint_hash {
            return Err(anyhow!(
                "archived recovered-history checkpoint predecessor hash does not match the published predecessor checkpoint"
            ));
        }
        let Some(previous_activation) = load_archived_recovered_history_profile_activation(
            workload_client,
            &previous_checkpoint.archived_profile_hash,
        )
        .await?
        else {
            return Err(anyhow!(
                "archived recovered-history checkpoint references a missing archived-history profile activation"
            ));
        };
        let previous_profile =
            validate_archived_recovered_history_profile_activation_chain_for_checkpoint(
                workload_client,
                &previous_activation,
                &previous_checkpoint,
            )
            .await?;
        checkpoint = previous_checkpoint;
        profile = previous_profile;
    }

    Ok(RecoveredAncestryStreamReport {
        loaded_pages,
        covered_target,
        exhausted,
    })
}

pub(super) async fn stream_recovered_ancestry_to_height<CE>(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    target_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    initial_fold_count: u64,
    recovered_consensus_headers: &[RecoveredCanonicalHeaderEntry],
    recovered_certified_headers: &[RecoveredCertifiedHeaderEntry],
    recovered_restart_block_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Result<RecoveredAncestryStreamReport>
where
    CE: ConsensusEngine<ChainTransaction>,
{
    let Some(base_start_height) = loaded_recovered_ancestry_start_height(
        recovered_consensus_headers,
        recovered_certified_headers,
        recovered_restart_block_headers,
    ) else {
        return Ok(RecoveredAncestryStreamReport {
            loaded_pages: Vec::new(),
            covered_target: false,
            exhausted: true,
        });
    };
    let Some(base_end_height) = loaded_recovered_ancestry_end_height(
        recovered_consensus_headers,
        recovered_certified_headers,
        recovered_restart_block_headers,
    ) else {
        return Ok(RecoveredAncestryStreamReport {
            loaded_pages: Vec::new(),
            covered_target: false,
            exhausted: true,
        });
    };
    if target_height >= base_start_height {
        let mut engine = consensus_engine_ref.lock().await;
        let keep_ranges = recovered_keep_ranges(Some((base_start_height, base_end_height)), None);
        engine.retain_recovered_ancestry_ranges(&keep_ranges);
        return Ok(RecoveredAncestryStreamReport {
            loaded_pages: Vec::new(),
            covered_target: true,
            exhausted: false,
        });
    }

    let mut cursor = RecoveredSegmentFoldCursor::new(
        base_end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        initial_fold_count,
    )
    .map_err(|error| anyhow!("failed to build recovered certified-branch cursor: {error}"))?;

    if target_height < base_start_height && cursor.oldest_loaded_height() < base_start_height {
        return stream_archived_recovered_ancestry_to_height(
            workload_client,
            consensus_engine_ref,
            target_height,
            (base_start_height, base_end_height),
            base_start_height,
        )
        .await;
    }

    let mut loaded_pages = Vec::new();
    let mut covered_target = false;
    let mut exhausted = false;

    while target_height < cursor.oldest_loaded_height() {
        let Some(page) = cursor
            .expected_next_page()
            .map_err(|error| anyhow!("failed to inspect recovered segment-fold cursor: {error}"))?
        else {
            exhausted = true;
            break;
        };
        let loaded_page = match load_recovered_segment_fold_page(workload_client, &page).await {
            Ok(loaded_page) => {
                cursor.accept_page(&page).map_err(|error| {
                    anyhow!("failed to advance recovered segment-fold cursor: {error}")
                })?;
                loaded_page
            }
            Err(_) => {
                let archived = stream_archived_recovered_ancestry_to_height(
                    workload_client,
                    consensus_engine_ref,
                    target_height,
                    (base_start_height, base_end_height),
                    cursor.oldest_loaded_height(),
                )
                .await?;
                loaded_pages.extend(archived.loaded_pages);
                covered_target = archived.covered_target;
                exhausted = archived.exhausted;
                break;
            }
        };

        {
            let mut engine = consensus_engine_ref.lock().await;
            let loaded_recovered_state = AftRecoveredStateSurface {
                replay_prefix: Vec::new(),
                consensus_headers: loaded_page.consensus_headers.clone(),
                certified_headers: loaded_page.certified_headers.clone(),
                restart_headers: loaded_page.restart_headers.clone(),
                historical_retrievability: None,
            };
            seed_aft_recovered_state_into_engine(&mut *engine, &loaded_recovered_state);
            let keep_ranges = recovered_keep_ranges(
                Some((base_start_height, base_end_height)),
                Some((loaded_page.start_height, loaded_page.end_height)),
            );
            engine.retain_recovered_ancestry_ranges(&keep_ranges);
        }

        loaded_pages.push((loaded_page.start_height, loaded_page.end_height));
        if target_height >= loaded_page.start_height {
            covered_target = true;
            break;
        }
    }

    Ok(RecoveredAncestryStreamReport {
        loaded_pages,
        covered_target,
        exhausted,
    })
}

pub(super) fn recovered_consensus_tip_anchor_from_parts(
    collapse: &CanonicalCollapseObject,
    recovered_headers: &[RecoveredCanonicalHeaderEntry],
) -> Option<RecoveredConsensusTipAnchor> {
    let recovered_header =
        resolve_recovered_consensus_header_entry(recovered_headers, collapse.height)?;
    Some(RecoveredConsensusTipAnchor {
        height: collapse.height,
        state_root: collapse.resulting_state_root_hash.to_vec(),
        block_hash: recovered_header.canonical_block_commitment_hash,
    })
}

pub(super) fn recovered_consensus_tip_anchor_from_header(
    header: &RecoveredCanonicalHeaderEntry,
) -> RecoveredConsensusTipAnchor {
    RecoveredConsensusTipAnchor {
        height: header.height,
        state_root: header.resulting_state_root_hash.to_vec(),
        block_hash: header.canonical_block_commitment_hash,
    }
}

pub(super) fn reconcile_recovered_tip_anchor_with_parent_qc(
    parent_ref: &StateRef,
    parent_qc: &QuorumCertificate,
    recovered_header: &RecoveredCanonicalHeaderEntry,
) -> Option<RecoveredConsensusTipAnchor> {
    if recovered_header.height != parent_ref.height
        || recovered_header.height != parent_qc.height
        || recovered_header.view != parent_qc.view
        || recovered_header.canonical_block_commitment_hash != parent_qc.block_hash
    {
        return None;
    }

    (parent_ref.state_root == recovered_header.resulting_state_root_hash.to_vec())
        .then(|| recovered_consensus_tip_anchor_from_header(recovered_header))
}

pub(super) fn advance_recovered_tip_anchor_with_certified_parent_qc(
    current_anchor: &RecoveredConsensusTipAnchor,
    parent_qc: &QuorumCertificate,
    recovered_header: &RecoveredCertifiedHeaderEntry,
) -> Option<RecoveredConsensusTipAnchor> {
    if recovered_header.header.height != current_anchor.height + 1
        || recovered_header.header.height != parent_qc.height
        || recovered_header.header.view != parent_qc.view
        || recovered_header.header.canonical_block_commitment_hash != parent_qc.block_hash
        || recovered_header.certified_parent_quorum_certificate.height != current_anchor.height
        || recovered_header
            .certified_parent_quorum_certificate
            .block_hash
            != current_anchor.block_hash
        || recovered_header
            .certified_parent_resulting_state_root_hash
            .to_vec()
            != current_anchor.state_root
    {
        return None;
    }

    Some(recovered_consensus_tip_anchor_from_header(
        &recovered_header.header,
    ))
}

pub(super) fn advance_recovered_tip_anchor_along_restart_headers(
    current_anchor: &RecoveredConsensusTipAnchor,
    parent_qc: &QuorumCertificate,
    recovered_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Option<RecoveredConsensusTipAnchor> {
    let mut headers_by_height = std::collections::BTreeMap::new();
    for entry in recovered_headers {
        headers_by_height.insert(entry.header.height, entry);
    }

    let mut anchor = current_anchor.clone();
    while anchor.height < parent_qc.height {
        let next = headers_by_height.get(&(anchor.height + 1))?;
        let certified = &next.certified_header;
        if certified.certified_parent_quorum_certificate.height != anchor.height
            || certified.certified_parent_quorum_certificate.block_hash != anchor.block_hash
            || certified
                .certified_parent_resulting_state_root_hash
                .to_vec()
                != anchor.state_root
            || next.header.parent_qc != certified.certified_parent_quorum_certificate
            || next.header.parent_hash != anchor.block_hash
            || next.header.parent_state_root.0 != anchor.state_root
        {
            return None;
        }

        let certified_qc = next.certified_quorum_certificate();
        if anchor.height + 1 == parent_qc.height && certified_qc != *parent_qc {
            return None;
        }

        anchor = recovered_consensus_tip_anchor_from_header(&certified.header);
    }

    (anchor.height == parent_qc.height && anchor.block_hash == parent_qc.block_hash)
        .then_some(anchor)
}

pub(super) async fn load_recovered_consensus_tip_anchor(
    workload_client: &dyn ioi_api::chain::WorkloadClientApi,
    height: u64,
    recovered_headers: &[RecoveredCanonicalHeaderEntry],
) -> Result<Option<RecoveredConsensusTipAnchor>> {
    let Some(collapse_bytes) = workload_client
        .query_raw_state(&aft_canonical_collapse_object_key(height))
        .await?
    else {
        return Ok(None);
    };
    let collapse: CanonicalCollapseObject =
        codec::from_bytes_canonical(&collapse_bytes).map_err(|e| {
            anyhow!("failed to decode canonical collapse object at height {height}: {e}")
        })?;

    Ok(recovered_consensus_tip_anchor_from_parts(
        &collapse,
        recovered_headers,
    ))
}

#[allow(dead_code)]
pub(super) fn seed_recovered_consensus_headers_into_engine<CE>(
    engine: &mut CE,
    recovered_headers: &[RecoveredCanonicalHeaderEntry],
) -> usize
where
    CE: ConsensusEngine<ChainTransaction>,
{
    recovered_headers
        .iter()
        .filter(|header| engine.observe_aft_recovered_consensus_header(header))
        .count()
}

#[allow(dead_code)]
pub(super) fn seed_recovered_certified_headers_into_engine<CE>(
    engine: &mut CE,
    recovered_headers: &[RecoveredCertifiedHeaderEntry],
) -> usize
where
    CE: ConsensusEngine<ChainTransaction>,
{
    recovered_headers
        .iter()
        .filter(|header| engine.observe_aft_recovered_certified_header(header))
        .count()
}

#[allow(dead_code)]
pub(super) fn seed_recovered_restart_block_headers_into_engine<CE>(
    engine: &mut CE,
    recovered_headers: &[RecoveredRestartBlockHeaderEntry],
) -> usize
where
    CE: ConsensusEngine<ChainTransaction>,
{
    recovered_headers
        .iter()
        .filter(|header| engine.observe_aft_recovered_restart_header(header))
        .count()
}

pub(super) fn seed_aft_recovered_state_into_engine<CE>(
    engine: &mut CE,
    recovered_state: &AftRecoveredStateSurface,
) -> AftRecoveredStateObservationStats
where
    CE: ConsensusEngine<ChainTransaction>,
{
    engine.observe_aft_recovered_state_surface(recovered_state)
}
