use super::*;

pub(super) fn default_archived_recovered_history_profile() -> Result<ArchivedRecoveredHistoryProfile> {
    build_archived_recovered_history_profile(
        DEFAULT_AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_HORIZON,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        recovered_consensus_header_stitch_window_budget(),
        recovered_consensus_header_stitch_segment_budget(),
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
    )
    .map_err(|error| anyhow!(error))
}

pub(super) async fn load_active_archived_recovered_history_profile(
    workload_client: &dyn WorkloadClientApi,
) -> Result<Option<ArchivedRecoveredHistoryProfile>> {
    let Some(bytes) = workload_client
        .query_raw_state(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
        .await
        .map_err(|error| {
            anyhow!("failed to query active archived recovered-history profile: {error}")
        })?
    else {
        return Ok(None);
    };
    let profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(&bytes)
        .map_err(|e| anyhow!("failed to decode active archived recovered-history profile: {e}"))?;
    validate_archived_recovered_history_profile(&profile).map_err(|error| anyhow!(error))?;
    Ok(Some(profile))
}

pub(super) async fn load_latest_archived_recovered_history_profile_activation(
    workload_client: &dyn WorkloadClientApi,
) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>> {
    let Some(bytes) = workload_client
        .query_raw_state(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
        .await
        .map_err(|error| {
            anyhow!("failed to query latest archived recovered-history profile activation: {error}")
        })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes).map(Some).map_err(|e| {
        anyhow!("failed to decode latest archived recovered-history profile activation: {e}")
    })
}

pub(super) async fn load_archived_recovered_history_profile_activation_by_hash(
    workload_client: &dyn WorkloadClientApi,
    activation_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryProfileActivation>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_profile_activation_hash_key(
            activation_hash,
        ))
        .await
        .map_err(|error| {
            anyhow!(
                "failed to query archived recovered-history profile activation by hash: {error}"
            )
        })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes).map(Some).map_err(|e| {
        anyhow!("failed to decode archived recovered-history profile activation by hash: {e}")
    })
}

pub(super) async fn load_latest_archived_recovered_history_checkpoint(
    workload_client: &dyn WorkloadClientApi,
) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>> {
    let Some(bytes) = workload_client
        .query_raw_state(ioi_types::app::AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
        .await
        .map_err(|error| {
            anyhow!("failed to query latest archived recovered-history checkpoint: {error}")
        })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode latest archived recovered-history checkpoint: {e}"))
}

pub(super) async fn load_archived_recovered_history_retention_receipt(
    workload_client: &dyn WorkloadClientApi,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<ArchivedRecoveredHistoryRetentionReceipt>> {
    let Some(bytes) = workload_client
        .query_raw_state(&aft_archived_recovered_history_retention_receipt_key(
            checkpoint_hash,
        ))
        .await
        .map_err(|error| {
            anyhow!("failed to query archived recovered-history retention receipt: {error}")
        })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical(&bytes)
        .map(Some)
        .map_err(|e| anyhow!("failed to decode archived recovered-history retention receipt: {e}"))
}

pub(super) async fn resolve_archived_recovered_history_anchor_hashes(
    publisher: &GuardianRegistryPublisher,
    checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
    receipt: Option<&ArchivedRecoveredHistoryRetentionReceipt>,
) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>> {
    let checkpoint = match checkpoint {
        Some(checkpoint) => Some(checkpoint.clone()),
        None => {
            load_latest_archived_recovered_history_checkpoint(&*publisher.workload_client).await?
        }
    };
    let Some(checkpoint) = checkpoint else {
        return Ok(None);
    };
    let checkpoint_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
        .map_err(|error| anyhow!(error))?;
    let receipt = match receipt {
        Some(receipt) => receipt.clone(),
        None => load_archived_recovered_history_retention_receipt(
            &*publisher.workload_client,
            &checkpoint_hash,
        )
        .await?
        .ok_or_else(|| {
            anyhow!(
                "archived recovered-history checkpoint references a retention receipt that is not yet available"
            )
        })?,
    };
    let receipt_hash = canonical_archived_recovered_history_retention_receipt_hash(&receipt)
        .map_err(|error| anyhow!(error))?;
    if receipt.archived_checkpoint_hash != checkpoint_hash {
        return Err(anyhow!(
            "archived recovered-history retention receipt does not match the referenced checkpoint"
        ));
    }
    if receipt.archived_profile_activation_hash != checkpoint.archived_profile_activation_hash {
        return Err(anyhow!(
            "archived recovered-history retention receipt activation hash does not match the referenced checkpoint"
        ));
    }
    let activation = load_archived_recovered_history_profile_activation_by_hash(
        &*publisher.workload_client,
        &checkpoint.archived_profile_activation_hash,
    )
    .await?
    .ok_or_else(|| {
        anyhow!(
            "archived recovered-history checkpoint references a profile activation that is not yet available"
        )
    })?;
    if activation.archived_profile_hash != checkpoint.archived_profile_hash {
        return Err(anyhow!(
            "archived recovered-history checkpoint profile hash does not match the referenced archived profile activation"
        ));
    }
    let activation_hash = canonical_archived_recovered_history_profile_activation_hash(&activation)
        .map_err(|error| anyhow!(error))?;
    Ok(Some((checkpoint_hash, activation_hash, receipt_hash)))
}

pub(super) async fn ensure_archived_recovered_history_profile(
    publisher: &GuardianRegistryPublisher,
) -> Result<(
    ArchivedRecoveredHistoryProfile,
    ArchivedRecoveredHistoryProfileActivation,
)> {
    let profile = if let Some(profile) =
        load_active_archived_recovered_history_profile(&*publisher.workload_client).await?
    {
        profile
    } else {
        let profile = default_archived_recovered_history_profile()?;
        publisher
            .enqueue_call(
                "publish_aft_archived_recovered_history_profile@v1",
                codec::to_bytes_canonical(&profile).map_err(|e| anyhow!(e))?,
            )
            .await?;
        profile
    };

    let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
        .map_err(|error| anyhow!(error))?;
    let latest_activation =
        load_latest_archived_recovered_history_profile_activation(&*publisher.workload_client)
            .await?;
    let activation = match latest_activation {
        Some(activation) if activation.archived_profile_hash == profile_hash => activation,
        Some(activation) => {
            return Err(anyhow!(
                "active archived recovered-history profile hash {} does not match the latest activation profile hash {}",
                hex::encode(profile_hash),
                hex::encode(activation.archived_profile_hash)
            ));
        }
        None => {
            let activation =
                build_archived_recovered_history_profile_activation(&profile, None, 1, None)
                    .map_err(|error| anyhow!(error))?;
            let activation_key =
                aft_archived_recovered_history_profile_activation_key(&profile_hash);
            if publisher
                .workload_client
                .query_raw_state(&activation_key)
                .await
                .map_err(|error| anyhow!("failed to query archived recovered-history profile activation state: {error}"))?
                .is_none()
            {
                publisher
                    .enqueue_call(
                        "publish_aft_archived_recovered_history_profile_activation@v1",
                        codec::to_bytes_canonical(&activation).map_err(|e| anyhow!(e))?,
                    )
                    .await?;
            }
            activation
        }
    };

    Ok((profile, activation))
}


pub(super) async fn publish_archived_recovered_history_segment(
    publisher: &GuardianRegistryPublisher,
    recovered: &RecoveredPublicationBundle,
    profile: &ArchivedRecoveredHistoryProfile,
    activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<Option<ArchivedRecoveredHistorySegment>> {
    let (segment_start_height, segment_end_height) =
        archived_recovered_restart_page_range_for_profile(recovered.height, profile)
            .map_err(|error| anyhow!(error))?;

    let mut recovered_bundles =
        Vec::with_capacity((segment_end_height - segment_start_height + 1) as usize);
    for height in segment_start_height..=segment_end_height {
        if height == recovered.height {
            recovered_bundles.push(recovered.clone());
            continue;
        }
        let Some(bundle) = load_unique_recovered_publication_bundle_for_height(
            &*publisher.workload_client,
            height,
        )
        .await?
        else {
            tracing::warn!(
                target: "consensus",
                archived_segment_start_height = segment_start_height,
                archived_segment_end_height = segment_end_height,
                missing_height = height,
                "Skipping archived recovered-history segment publication because a recovered publication bundle is missing from the bounded archived range."
            );
            return Ok(None);
        };
        recovered_bundles.push(bundle);
    }

    let previous_segment = if segment_end_height <= 1 {
        None
    } else {
        let (previous_start_height, previous_end_height) =
            archived_recovered_restart_page_range_for_profile(segment_end_height - 1, profile)
                .map_err(|error| anyhow!(error))?;
        let previous_key =
            aft_archived_recovered_history_segment_key(previous_start_height, previous_end_height);
        let Some(previous_segment_bytes) = publisher
            .workload_client
            .query_raw_state(&previous_key)
            .await
            .map_err(|error| {
                anyhow!("failed to query archived recovered-history segment state: {error}")
            })?
        else {
            tracing::warn!(
                target: "consensus",
                archived_segment_start_height = segment_start_height,
                archived_segment_end_height = segment_end_height,
                missing_predecessor_start_height = previous_start_height,
                missing_predecessor_end_height = previous_end_height,
                "Skipping archived recovered-history segment publication because the previous archived range is missing."
            );
            return Ok(None);
        };
        Some(
            codec::from_bytes_canonical::<ArchivedRecoveredHistorySegment>(&previous_segment_bytes)
                .map_err(|e| anyhow!("failed to decode archived recovered-history segment: {e}"))?,
        )
    };

    let overlap_range = previous_segment.as_ref().and_then(|previous| {
        let overlap_start_height = segment_start_height.max(previous.start_height);
        let overlap_end_height = segment_end_height
            .saturating_sub(1)
            .min(previous.end_height);
        (overlap_start_height <= overlap_end_height)
            .then_some((overlap_start_height, overlap_end_height))
    });

    let segment = build_archived_recovered_history_segment(
        &recovered_bundles,
        previous_segment.as_ref(),
        overlap_range,
        profile,
        activation,
    )
    .map_err(|error| anyhow!(error))?;
    let segment_key =
        aft_archived_recovered_history_segment_key(segment.start_height, segment.end_height);

    match publisher
        .workload_client
        .query_raw_state(&segment_key)
        .await
        .map_err(|error| {
            anyhow!("failed to query archived recovered-history segment state: {error}")
        })? {
        Some(existing_segment_bytes) => {
            let existing: ArchivedRecoveredHistorySegment =
                codec::from_bytes_canonical(&existing_segment_bytes).map_err(|e| {
                    anyhow!("failed to decode archived recovered-history segment: {e}")
                })?;
            if existing != segment {
                tracing::warn!(
                    target: "consensus",
                    start_height = segment.start_height,
                    end_height = segment.end_height,
                    "Skipping archived recovered-history segment publication because a conflicting descriptor is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(segment))
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_archived_recovered_history_segment@v1",
                    codec::to_bytes_canonical(&segment).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(segment))
        }
    }
}

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

pub(super) async fn load_unique_recovered_publication_bundle_for_height(
    workload_client: &dyn WorkloadClientApi,
    height: u64,
) -> Result<Option<RecoveredPublicationBundle>> {
    let recovered_prefix = [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
    ]
    .concat();
    let recovered_rows = workload_client
        .prefix_scan(&recovered_prefix)
        .await
        .map_err(|error| {
            anyhow!("failed to scan recovered publication bundles at height {height}: {error}")
        })?;
    let mut recovered = Vec::with_capacity(recovered_rows.len());
    for (_, value) in recovered_rows {
        let object: RecoveredPublicationBundle =
            codec::from_bytes_canonical(&value).map_err(|e| {
                anyhow!("failed to decode recovered publication bundle at height {height}: {e}")
            })?;
        recovered.push(object);
    }
    Ok(select_unique_recovered_publication_bundle(recovered))
}

pub(super) fn supporting_recovery_materials_for_recovered_bundle(
    recovered: &RecoveredPublicationBundle,
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<RecoveryShareMaterial>> {
    recovered
        .supporting_witness_manifest_hashes
        .iter()
        .map(|witness_manifest_hash| {
            materials
                .iter()
                .find(|material| {
                    material.height == recovered.height
                        && material.block_commitment_hash == recovered.block_commitment_hash
                        && material.witness_manifest_hash == *witness_manifest_hash
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "missing supporting recovery share material for witness {} at height {}",
                        hex::encode(witness_manifest_hash),
                        recovered.height
                    )
                })
        })
        .collect()
}

pub(super) async fn publish_archived_recovered_restart_page(
    publisher: &GuardianRegistryPublisher,
    segment: &ArchivedRecoveredHistorySegment,
    collapse: &CanonicalCollapseObject,
    recovered: &RecoveredPublicationBundle,
    materials: &[RecoveryShareMaterial],
) -> Result<Option<ArchivedRecoveredRestartPage>> {
    let supporting_materials =
        supporting_recovery_materials_for_recovered_bundle(recovered, materials)?;
    let (full_surface, publication_bundle, bulletin_close, _) =
        recover_full_canonical_order_surface_from_share_materials(&supporting_materials)
            .map_err(|error| anyhow!(error))?;
    if full_surface.height != recovered.height
        || full_surface.block_commitment_hash != recovered.block_commitment_hash
        || full_surface.parent_block_hash != recovered.parent_block_commitment_hash
    {
        tracing::warn!(
            target: "consensus",
            height = recovered.height,
            "Skipping archived recovered restart-page publication because the reconstructed full surface does not match the recovered publication bundle."
        );
        return Ok(None);
    }
    if canonical_recoverable_slot_payload_v5_hash(&full_surface).map_err(|e| anyhow!(e))?
        != recovered.recoverable_full_surface_hash
        || canonical_order_publication_bundle_hash(&publication_bundle).map_err(|e| anyhow!(e))?
            != recovered.canonical_order_publication_bundle_hash
        || canonical_bulletin_close_hash(&bulletin_close).map_err(|e| anyhow!(e))?
            != recovered.canonical_bulletin_close_hash
    {
        tracing::warn!(
            target: "consensus",
            height = recovered.height,
            "Skipping archived recovered restart-page publication because the reconstructed recovered surface hashes do not match the recovered publication bundle."
        );
        return Ok(None);
    }

    let mut restart_headers = Vec::new();
    let header = recovered_canonical_header_entry(collapse, &full_surface)
        .map_err(|error| anyhow!(error))?;
    let previous_header = if header.height <= 1 {
        None
    } else {
        let previous_page_key =
            aft_archived_recovered_restart_page_key(&segment.previous_archived_segment_hash);
        let Some(previous_page_bytes) = publisher
            .workload_client
            .query_raw_state(&previous_page_key)
            .await
            .map_err(|error| {
                anyhow!("failed to query previous archived recovered restart-page state: {error}")
            })?
        else {
            tracing::warn!(
                target: "consensus",
                height = header.height,
                "Skipping archived recovered restart-page publication because the predecessor archived restart page is missing."
            );
            return Ok(None);
        };
        let previous_page: ArchivedRecoveredRestartPage =
            codec::from_bytes_canonical(&previous_page_bytes)
                .map_err(|e| anyhow!("failed to decode previous archived restart page: {e}"))?;
        restart_headers.extend(
            previous_page
                .restart_headers
                .into_iter()
                .filter(|entry| entry.header.height >= segment.start_height),
        );
        restart_headers
            .last()
            .map(|entry| entry.certified_header.header.clone())
    };

    let certified = recovered_certified_header_entry(&header, previous_header.as_ref())
        .map_err(|error| anyhow!(error))?;
    let restart_entry = recovered_restart_block_header_entry(&full_surface, &certified)
        .map_err(|error| anyhow!(error))?;
    restart_headers.push(restart_entry);
    let page = build_archived_recovered_restart_page(segment, &restart_headers)
        .map_err(|error| anyhow!(error))?;
    let page_key = aft_archived_recovered_restart_page_key(&page.segment_hash);

    match publisher
        .workload_client
        .query_raw_state(&page_key)
        .await
        .map_err(|error| {
            anyhow!("failed to query archived recovered restart-page state: {error}")
        })? {
        Some(existing_page_bytes) => {
            let existing: ArchivedRecoveredRestartPage =
                codec::from_bytes_canonical(&existing_page_bytes).map_err(|e| {
                    anyhow!("failed to decode archived recovered restart page: {e}")
                })?;
            if existing != page {
                tracing::warn!(
                    target: "consensus",
                    start_height = page.start_height,
                    end_height = page.end_height,
                    "Skipping archived recovered restart-page publication because a conflicting page is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(page))
        }
        None => {
            publisher
                .enqueue_call(
                    "publish_aft_archived_recovered_restart_page@v1",
                    codec::to_bytes_canonical(&page).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(page))
        }
    }
}

pub(super) async fn publish_archived_recovered_history_checkpoint(
    publisher: &GuardianRegistryPublisher,
    segment: &ArchivedRecoveredHistorySegment,
    page: &ArchivedRecoveredRestartPage,
) -> Result<Option<ArchivedRecoveredHistoryCheckpoint>> {
    let latest_checkpoint = match publisher
        .workload_client
        .query_raw_state(ioi_types::app::AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
        .await
        .map_err(|error| {
            anyhow!("failed to query latest archived recovered-history checkpoint state: {error}")
        })? {
        Some(bytes) => Some(
            codec::from_bytes_canonical::<ArchivedRecoveredHistoryCheckpoint>(&bytes).map_err(
                |e| anyhow!("failed to decode latest archived recovered-history checkpoint: {e}"),
            )?,
        ),
        None => None,
    };

    let checkpoint =
        build_archived_recovered_history_checkpoint(segment, page, latest_checkpoint.as_ref())
            .map_err(|error| anyhow!(error))?;
    let checkpoint_key = aft_archived_recovered_history_checkpoint_key(
        checkpoint.covered_start_height,
        checkpoint.covered_end_height,
    );

    match publisher
        .workload_client
        .query_raw_state(&checkpoint_key)
        .await
        .map_err(|error| {
            anyhow!("failed to query archived recovered-history checkpoint state: {error}")
        })? {
        Some(existing_checkpoint_bytes) => {
            let existing: ArchivedRecoveredHistoryCheckpoint =
                codec::from_bytes_canonical(&existing_checkpoint_bytes).map_err(|e| {
                    anyhow!("failed to decode archived recovered-history checkpoint: {e}")
                })?;
            if existing != checkpoint {
                tracing::warn!(
                    target: "consensus",
                    start_height = checkpoint.covered_start_height,
                    end_height = checkpoint.covered_end_height,
                    "Skipping archived recovered-history checkpoint publication because a conflicting checkpoint is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(checkpoint))
        }
        None => {
            if let Some(existing_latest) = latest_checkpoint.as_ref() {
                let existing_latest_hash =
                    canonical_archived_recovered_history_checkpoint_hash(existing_latest)
                        .map_err(|e| anyhow!(e))?;
                if checkpoint.covered_end_height <= existing_latest.covered_end_height
                    && checkpoint.previous_archived_checkpoint_hash != existing_latest_hash
                {
                    tracing::warn!(
                        target: "consensus",
                        start_height = checkpoint.covered_start_height,
                        end_height = checkpoint.covered_end_height,
                        "Skipping archived recovered-history checkpoint publication because a newer archival checkpoint is already present in state."
                    );
                    return Ok(None);
                }
            }
            publisher
                .enqueue_call(
                    "publish_aft_archived_recovered_history_checkpoint@v1",
                    codec::to_bytes_canonical(&checkpoint).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(checkpoint))
        }
    }
}

pub(super) async fn publish_archived_recovered_history_retention_receipt(
    publisher: &GuardianRegistryPublisher,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<Option<ArchivedRecoveredHistoryRetentionReceipt>> {
    let validator_set_bytes = match publisher
        .workload_client
        .query_raw_state(VALIDATOR_SET_KEY)
        .await
        .map_err(|error| anyhow!("failed to query active validator set state: {error}"))?
    {
        Some(bytes) => bytes,
        None => {
            tracing::warn!(
                target: "consensus",
                start_height = checkpoint.covered_start_height,
                end_height = checkpoint.covered_end_height,
                "Skipping archived recovered-history retention receipt publication because the active validator set is not yet available in state."
            );
            return Ok(None);
        }
    };
    let validator_sets = read_validator_sets(&validator_set_bytes)
        .map_err(|error| anyhow!("failed to decode active validator set: {error}"))?;
    let validator_set_commitment_hash =
        canonical_validator_sets_hash(&validator_sets).map_err(|error| anyhow!(error))?;
    let receipt = build_archived_recovered_history_retention_receipt(
        checkpoint,
        validator_set_commitment_hash,
        archived_recovered_history_retained_through_height(checkpoint, profile)
            .map_err(|error| anyhow!(error))?,
    )
    .map_err(|error| anyhow!(error))?;
    let receipt_key =
        aft_archived_recovered_history_retention_receipt_key(&receipt.archived_checkpoint_hash);

    match publisher
        .workload_client
        .query_raw_state(&receipt_key)
        .await
        .map_err(|error| {
            anyhow!("failed to query archived recovered-history retention receipt state: {error}")
        })? {
        Some(existing_receipt_bytes) => {
            let existing: ArchivedRecoveredHistoryRetentionReceipt =
                codec::from_bytes_canonical(&existing_receipt_bytes).map_err(|e| {
                    anyhow!("failed to decode archived recovered-history retention receipt: {e}")
                })?;
            if existing != receipt {
                tracing::warn!(
                    target: "consensus",
                    start_height = checkpoint.covered_start_height,
                    end_height = checkpoint.covered_end_height,
                    "Skipping archived recovered-history retention receipt publication because a conflicting receipt is already present in state."
                );
                return Ok(None);
            }
            Ok(Some(receipt))
        }
        None => {
            let receipt_hash =
                canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                    .map_err(|error| anyhow!(error))?;
            if receipt_hash == [0u8; 32] {
                return Err(anyhow!(
                    "archived recovered-history retention receipt hash unexpectedly encoded to zero"
                ));
            }
            publisher
                .enqueue_call(
                    "publish_aft_archived_recovered_history_retention_receipt@v1",
                    codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
                )
                .await?;
            Ok(Some(receipt))
        }
    }
}

pub(super) async fn publish_canonical_collapse_object(
    publisher: &GuardianRegistryPublisher,
    collapse: &CanonicalCollapseObject,
) -> Result<()> {
    publisher
        .enqueue_call(
            "publish_aft_canonical_collapse_object@v1",
            codec::to_bytes_canonical(collapse).map_err(|e| anyhow!(e))?,
        )
        .await
}
