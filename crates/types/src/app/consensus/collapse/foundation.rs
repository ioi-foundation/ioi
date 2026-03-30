/// Succinct predecessor commitment used on the live proposal path.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseCommitment {
    /// Slot / height of the committed predecessor collapse object.
    pub height: u64,
    /// Recursive continuity accumulator already binding the predecessor to its prior chain.
    #[serde(default)]
    pub continuity_accumulator_hash: [u8; 32],
    /// Canonical post-state root produced by the predecessor collapse object.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
}

/// Reference proof system for recursive canonical-collapse continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub enum CanonicalCollapseContinuityProofSystem {
    /// Reference verifier: proof bytes are a canonical hash over the current statement and the
    /// previous recursive proof hash.
    #[default]
    HashPcdV1,
    /// Mock/native succinct verifier surface with explicit recursive public inputs.
    SuccinctSp1V1,
}

/// Recursive proof-carrying continuity witness for a canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseRecursiveProof {
    /// Succinct commitment to the collapse object this proof step certifies.
    #[serde(default)]
    pub commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical payload hash of the collapse object this proof certifies.
    #[serde(default)]
    pub payload_hash: [u8; 32],
    /// Proof-system variant used to interpret `proof_bytes`.
    #[serde(default)]
    pub proof_system: CanonicalCollapseContinuityProofSystem,
    /// Canonical hash of the previous recursive proof step.
    #[serde(default)]
    pub previous_recursive_proof_hash: [u8; 32],
    /// Opaque proof bytes for the current recursive step.
    #[serde(default)]
    pub proof_bytes: Vec<u8>,
}

/// Proof-carrying recursive-continuity certificate for live proposal extension.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseExtensionCertificate {
    /// Succinct predecessor commitment for the slot being extended.
    #[serde(default)]
    pub predecessor_commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the predecessor slot's recursive continuity proof.
    #[serde(default)]
    pub predecessor_recursive_proof_hash: [u8; 32],
}

/// Public inputs for a recursive canonical-collapse continuity proof step.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseContinuityPublicInputs {
    /// Succinct commitment to the collapse object this proof step certifies.
    #[serde(default)]
    pub commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical payload hash of the collapse object this proof certifies.
    #[serde(default)]
    pub payload_hash: [u8; 32],
    /// Canonical hash of the previous recursive proof step.
    #[serde(default)]
    pub previous_recursive_proof_hash: [u8; 32],
}

/// Succinct witness payload for the committed-surface canonical-order verifier.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CommittedSurfaceCanonicalOrderProof {
    /// Canonical hash of the bulletin availability certificate carried by the order certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical commitment over the omission set for the slot.
    #[serde(default)]
    pub omission_commitment_root: [u8; 32],
}

/// Objective proof that a candidate canonical order omitted an eligible transaction.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct OmissionProof {
    /// Slot / height the omission applies to.
    pub height: u64,
    /// Validator accountable for the conflicting candidate order this proof dominates.
    #[serde(default)]
    pub offender_account_id: AccountId,
    /// Canonical hash of the omitted transaction.
    pub tx_hash: [u8; 32],
    /// Bulletin commitment root that admitted the omitted transaction.
    pub bulletin_root: [u8; 32],
    /// Human-readable explanation for the omission.
    #[serde(default)]
    pub details: String,
}

/// Proof-carrying certificate for the canonical order of a slot.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderCertificate {
    /// Slot / height being certified.
    pub height: u64,
    /// Published bulletin-board commitment for the slot.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Explicit recoverability certificate for the slot's bulletin / order surface.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Public randomness beacon used to rank eligible transactions.
    #[serde(default)]
    pub randomness_beacon: [u8; 32],
    /// Canonical root of the ordered transaction set.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root hash of the resulting state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Compact proof binding the certificate to the canonical order inputs.
    #[serde(default)]
    pub proof: CanonicalOrderProof,
    /// Objective omission proofs, if any. A non-empty set dominates the candidate order.
    #[serde(default)]
    pub omission_proofs: Vec<OmissionProof>,
}

fn hash_consensus_bytes<T: Encode>(value: &T) -> Result<[u8; 32], String> {
    let bytes = value.encode();
    let digest = DcryptSha256::digest(&bytes).map_err(|e| e.to_string())?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| "invalid sha256 digest length".into())
}

/// Returns the canonical hash of a bulletin commitment.
pub fn canonical_bulletin_commitment_hash(
    commitment: &BulletinCommitment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(commitment)
}

/// Returns the canonical hash of a bulletin availability certificate.
pub fn canonical_bulletin_availability_certificate_hash(
    certificate: &BulletinAvailabilityCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of a bulletin retrievability profile.
pub fn canonical_bulletin_retrievability_profile_hash(
    profile: &BulletinRetrievabilityProfile,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(profile)
}

/// Returns the canonical hash of a bulletin shard manifest.
pub fn canonical_bulletin_shard_manifest_hash(
    manifest: &BulletinShardManifest,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(manifest)
}

/// Returns the canonical hash of a bulletin custody assignment.
pub fn canonical_bulletin_custody_assignment_hash(
    assignment: &BulletinCustodyAssignment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(assignment)
}

/// Returns the canonical hash of a bulletin custody receipt.
pub fn canonical_bulletin_custody_receipt_hash(
    receipt: &BulletinCustodyReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of a bulletin custody response.
pub fn canonical_bulletin_custody_response_hash(
    response: &BulletinCustodyResponse,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(response)
}

/// Returns the canonical hash of an objective bulletin retrievability challenge.
pub fn canonical_bulletin_retrievability_challenge_hash(
    challenge: &BulletinRetrievabilityChallenge,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(challenge)
}

/// Returns the canonical hash of a bulletin reconstruction-certificate object.
pub fn canonical_bulletin_reconstruction_certificate_hash(
    certificate: &BulletinReconstructionCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of a bulletin reconstruction-abort object.
pub fn canonical_bulletin_reconstruction_abort_hash(
    abort: &BulletinReconstructionAbort,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(abort)
}

/// Returns the canonical hash of an exploratory witness-coded recovery capsule.
pub fn canonical_recovery_capsule_hash(capsule: &RecoveryCapsule) -> Result<[u8; 32], String> {
    hash_consensus_bytes(capsule)
}

/// Returns the canonical hash of an exploratory recovery witness certificate.
pub fn canonical_recovery_witness_certificate_hash(
    certificate: &RecoveryWitnessCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of an exploratory recovery share receipt.
pub fn canonical_recovery_share_receipt_hash(
    receipt: &RecoveryShareReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of exploratory recovery share-reveal material.
pub fn canonical_recovery_share_material_hash(
    material: &RecoveryShareMaterial,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(material)
}

/// Returns the canonical hash of a compact recovered-publication bundle object.
pub fn canonical_recovered_publication_bundle_hash(
    recovered_bundle: &RecoveredPublicationBundle,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(recovered_bundle)
}

/// Returns the canonical root hash of the recovered-publication bundles named by one archived segment.
pub fn canonical_archived_recovered_history_segment_root(
    recovered_bundle_hashes: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if recovered_bundle_hashes.is_empty() {
        return Err("archived recovered-history segment requires at least one bundle hash".into());
    }
    hash_consensus_bytes(&recovered_bundle_hashes.to_vec())
}

/// Returns the canonical hash of an archived recovered-history segment descriptor.
pub fn canonical_archived_recovered_history_segment_hash(
    segment: &ArchivedRecoveredHistorySegment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(segment)
}

/// Returns the canonical hash of an archived recovered-history profile.
pub fn canonical_archived_recovered_history_profile_hash(
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(profile)
}

/// Returns the canonical hash of an archived recovered-history profile activation.
pub fn canonical_archived_recovered_history_profile_activation_hash(
    activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(activation)
}

/// Returns the canonical hash of an archived recovered restart-page payload.
pub fn canonical_archived_recovered_restart_page_hash(
    page: &ArchivedRecoveredRestartPage,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(page)
}

/// Returns the canonical hash of an archived recovered-history checkpoint.
pub fn canonical_archived_recovered_history_checkpoint_hash(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(checkpoint)
}

/// Returns the canonical hash of an archived recovered-history retention receipt.
pub fn canonical_archived_recovered_history_retention_receipt_hash(
    receipt: &ArchivedRecoveredHistoryRetentionReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of a decoded validator-set commitment.
pub fn canonical_validator_sets_hash(sets: &ValidatorSetsV1) -> Result<[u8; 32], String> {
    hash_consensus_bytes(sets)
}

/// Returns the canonical hash of one effective validator set.
pub fn canonical_validator_set_hash(set: &ValidatorSetV1) -> Result<[u8; 32], String> {
    hash_consensus_bytes(set)
}

/// Validates one archived recovered-history profile.
pub fn validate_archived_recovered_history_profile(
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    if profile.retention_horizon == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero retention horizon".into(),
        );
    }
    if profile.restart_page_window == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero restart-page window".into(),
        );
    }
    if profile.windows_per_segment == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero windows-per-segment value"
                .into(),
        );
    }
    if profile.segments_per_fold == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero segments-per-fold value".into(),
        );
    }
    let _ = archived_recovered_restart_page_range(
        1,
        profile.restart_page_window,
        profile.restart_page_overlap,
        profile.windows_per_segment,
        profile.segments_per_fold,
    )?;
    match profile.checkpoint_update_rule {
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1 => Ok(()),
    }
}

/// Builds an archived recovered-history profile after validating its geometry.
pub fn build_archived_recovered_history_profile(
    retention_horizon: u64,
    restart_page_window: u64,
    restart_page_overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    checkpoint_update_rule: ArchivedRecoveredHistoryCheckpointUpdateRule,
) -> Result<ArchivedRecoveredHistoryProfile, String> {
    let profile = ArchivedRecoveredHistoryProfile {
        retention_horizon,
        restart_page_window,
        restart_page_overlap,
        windows_per_segment,
        segments_per_fold,
        checkpoint_update_rule,
    };
    validate_archived_recovered_history_profile(&profile)?;
    Ok(profile)
}

/// Validates one archived recovered-history profile activation against its referenced profile.
pub fn validate_archived_recovered_history_profile_activation(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if activation.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history profile activation hash {:?} does not match the referenced profile hash {:?}",
            activation.archived_profile_hash, profile_hash
        ));
    }
    if activation.activation_end_height == 0 {
        return Err(
            "archived recovered-history profile activation requires a non-zero activation end height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation is a valid successor of
/// another.
pub fn validate_archived_recovered_history_profile_activation_successor(
    previous_activation: &ArchivedRecoveredHistoryProfileActivation,
    current_activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<(), String> {
    if current_activation.previous_archived_profile_hash
        != previous_activation.archived_profile_hash
    {
        return Err(
            "archived recovered-history profile activation predecessor hash does not match the previously active profile"
                .into(),
        );
    }
    if current_activation.activation_end_height <= previous_activation.activation_end_height {
        return Err(
            "archived recovered-history profile activation must advance to a strictly later archived tip height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation governs the supplied archived
/// tip height, optionally bounded above by a successor activation.
pub fn validate_archived_recovered_history_profile_activation_covering_tip_height(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    successor_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
    covered_end_height: u64,
) -> Result<(), String> {
    if covered_end_height < activation.activation_end_height {
        return Err(format!(
            "archived recovered-history object ending at height {} predates the governing profile activation tip {}",
            covered_end_height, activation.activation_end_height
        ));
    }
    if let Some(successor_activation) = successor_activation {
        if covered_end_height >= successor_activation.activation_end_height {
            return Err(format!(
                "archived recovered-history object ending at height {} crosses the successor profile activation tip {}",
                covered_end_height, successor_activation.activation_end_height
            ));
        }
    }
    Ok(())
}

/// Verifies the optional activation checkpoint named by one archived recovered-history profile
/// activation.
pub fn validate_archived_recovered_history_profile_activation_checkpoint(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    validate_archived_recovered_history_profile_activation(activation, profile)?;
    let checkpoint_hash = activation.activation_checkpoint_hash;
    if checkpoint_hash == [0u8; 32] {
        return if activation_checkpoint.is_none() {
            Ok(())
        } else {
            Err(
                "archived recovered-history profile activation unexpectedly received a checkpoint despite carrying no activation checkpoint hash"
                    .into(),
            )
        };
    }
    let Some(checkpoint) = activation_checkpoint else {
        return Err(
            "archived recovered-history profile activation references an activation checkpoint that is missing from state"
                .into(),
        );
    };
    let expected_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(checkpoint)?;
    if expected_checkpoint_hash != checkpoint_hash {
        return Err(
            "archived recovered-history profile activation checkpoint hash does not match the published activation checkpoint"
                .into(),
        );
    }
    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
        return Err(
            "archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                .into(),
        );
    }
    if checkpoint.covered_end_height != activation.activation_end_height {
        return Err(
            "archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation governs the supplied archived
/// checkpoint without consulting any current activation index.
pub fn validate_archived_recovered_history_profile_activation_against_checkpoint(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    validate_archived_recovered_history_profile_activation_checkpoint(
        activation,
        activation_checkpoint,
        profile,
    )?;
    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
        return Err(
            "archived recovered-history checkpoint profile hash does not match the governing activation profile"
                .into(),
        );
    }
    validate_archived_recovered_history_profile_activation_covering_tip_height(
        activation,
        None,
        checkpoint.covered_end_height,
    )
}

/// Builds one archived recovered-history profile activation, chaining it from the previously
/// active profile when present.
pub fn build_archived_recovered_history_profile_activation(
    profile: &ArchivedRecoveredHistoryProfile,
    previous_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
    activation_end_height: u64,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
) -> Result<ArchivedRecoveredHistoryProfileActivation, String> {
    let activation = ArchivedRecoveredHistoryProfileActivation {
        archived_profile_hash: canonical_archived_recovered_history_profile_hash(profile)?,
        previous_archived_profile_hash: previous_activation
            .map(|activation| activation.archived_profile_hash)
            .unwrap_or([0u8; 32]),
        activation_end_height,
        activation_checkpoint_hash: activation_checkpoint
            .map(canonical_archived_recovered_history_checkpoint_hash)
            .transpose()?
            .unwrap_or([0u8; 32]),
    };
    validate_archived_recovered_history_profile_activation(&activation, profile)?;
    if let Some(previous_activation) = previous_activation {
        validate_archived_recovered_history_profile_activation_successor(
            previous_activation,
            &activation,
        )?;
    }
    if let Some(checkpoint) = activation_checkpoint {
        if checkpoint.archived_profile_hash != activation.archived_profile_hash {
            return Err(
                "archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                    .into(),
            );
        }
        if checkpoint.covered_end_height != activation.activation_end_height {
            return Err(
                "archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                    .into(),
            );
        }
    }
    Ok(activation)
}

/// Builds a compact archived recovered-history segment descriptor from one contiguous recovered range.
pub fn build_archived_recovered_history_segment(
    recovered_bundles: &[RecoveredPublicationBundle],
    previous_segment: Option<&ArchivedRecoveredHistorySegment>,
    overlap_range: Option<(u64, u64)>,
    profile: &ArchivedRecoveredHistoryProfile,
    activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<ArchivedRecoveredHistorySegment, String> {
    validate_archived_recovered_history_profile(profile)?;
    validate_archived_recovered_history_profile_activation(activation, profile)?;
    if recovered_bundles.is_empty() {
        return Err(
            "archived recovered-history segment requires at least one recovered bundle".into(),
        );
    }

    for pair in recovered_bundles.windows(2) {
        if pair[1].height != pair[0].height + 1 {
            return Err(
                "archived recovered-history segment requires contiguous recovered heights".into(),
            );
        }
    }

    let start_height = recovered_bundles
        .first()
        .map(|bundle| bundle.height)
        .ok_or_else(|| {
            "archived recovered-history segment is missing a start height".to_string()
        })?;
    let end_height = recovered_bundles
        .last()
        .map(|bundle| bundle.height)
        .ok_or_else(|| "archived recovered-history segment is missing an end height".to_string())?;

    if let Some(previous) = previous_segment {
        match overlap_range {
            Some((overlap_start_height, overlap_end_height)) => {
                if previous.start_height > overlap_start_height
                    || previous.end_height < overlap_end_height
                {
                    return Err(
                        "archived recovered-history segment predecessor does not cover the declared overlap anchor"
                            .into(),
                    );
                }
                if previous.end_height >= end_height {
                    return Err(
                        "archived recovered-history segment predecessor must end before the current range ends"
                            .into(),
                    );
                }
            }
            None => {
                if previous.end_height >= start_height {
                    return Err(
                        "archived recovered-history segment predecessor must end before the current range starts"
                            .into(),
                    );
                }
            }
        }
    }

    let recovered_bundle_hashes = recovered_bundles
        .iter()
        .map(canonical_recovered_publication_bundle_hash)
        .collect::<Result<Vec<_>, _>>()?;
    let segment_root_hash =
        canonical_archived_recovered_history_segment_root(&recovered_bundle_hashes)?;
    let archived_profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    let archived_profile_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(activation)?;
    validate_archived_recovered_history_profile_activation_covering_tip_height(
        activation, None, end_height,
    )?;

    let previous_archived_segment_hash = previous_segment
        .map(canonical_archived_recovered_history_segment_hash)
        .transpose()?
        .unwrap_or([0u8; 32]);

    let (overlap_start_height, overlap_end_height, overlap_root_hash) = match overlap_range {
        Some((overlap_start_height, overlap_end_height)) => {
            if overlap_start_height == 0
                || overlap_end_height == 0
                || overlap_end_height < overlap_start_height
                || overlap_start_height < start_height
                || overlap_end_height > end_height
            {
                return Err(
                    "archived recovered-history segment overlap range must lie within the covered range"
                        .into(),
                );
            }
            let start_index = usize::try_from(overlap_start_height - start_height)
                .map_err(|_| "archived recovered-history segment overlap start overflow")?;
            let end_index = usize::try_from(overlap_end_height - start_height + 1)
                .map_err(|_| "archived recovered-history segment overlap end overflow")?;
            let overlap_root_hash = canonical_archived_recovered_history_segment_root(
                &recovered_bundle_hashes[start_index..end_index],
            )?;
            (overlap_start_height, overlap_end_height, overlap_root_hash)
        }
        None => (0, 0, [0u8; 32]),
    };

    Ok(ArchivedRecoveredHistorySegment {
        start_height,
        end_height,
        archived_profile_hash,
        archived_profile_activation_hash,
        first_recovered_publication_bundle_hash: recovered_bundle_hashes[0],
        last_recovered_publication_bundle_hash: *recovered_bundle_hashes.last().ok_or_else(
            || "archived recovered-history segment is missing a last bundle hash".to_string(),
        )?,
        previous_archived_segment_hash,
        segment_root_hash,
        overlap_start_height,
        overlap_end_height,
        overlap_root_hash,
    })
}

/// Verifies that one archived recovered-history segment is a structurally valid
/// predecessor of another.
pub fn validate_archived_recovered_history_segment_predecessor(
    previous_segment: &ArchivedRecoveredHistorySegment,
    current_segment: &ArchivedRecoveredHistorySegment,
) -> Result<(), String> {
    let previous_segment_hash =
        canonical_archived_recovered_history_segment_hash(previous_segment)?;
    if current_segment.previous_archived_segment_hash != previous_segment_hash {
        return Err(
            "archived recovered-history segment predecessor hash does not match the referenced predecessor"
                .into(),
        );
    }
    if current_segment.overlap_start_height != 0 || current_segment.overlap_end_height != 0 {
        if previous_segment.start_height > current_segment.overlap_start_height
            || previous_segment.end_height < current_segment.overlap_end_height
        {
            return Err(
                "archived recovered-history segment predecessor does not cover the declared overlap anchor"
                    .into(),
            );
        }
        if previous_segment.end_height >= current_segment.end_height {
            return Err(
                "archived recovered-history segment predecessor must end before the current range ends"
                    .into(),
            );
        }
        if previous_segment.start_height == current_segment.overlap_start_height
            && previous_segment.end_height == current_segment.overlap_end_height
            && previous_segment.segment_root_hash != current_segment.overlap_root_hash
        {
            return Err(
                "archived recovered-history segment full-overlap root does not match the predecessor segment root"
                    .into(),
            );
        }
    } else if previous_segment.end_height >= current_segment.start_height {
        return Err(
            "archived recovered-history segment predecessor must end before the current range starts"
                .into(),
        );
    }
    Ok(())
}

/// Returns the bounded archived restart-page range that mirrors one retained
/// exact-overlap recovered page ending at `end_height`.
pub fn archived_recovered_restart_page_range(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<(u64, u64), String> {
    if end_height == 0 {
        return Err("archived recovered restart page range requires a non-zero end height".into());
    }
    let start_height = recovered_segment_fold_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        1,
    );
    if start_height == 0 {
        return Err(
            "archived recovered restart page range could not derive a non-zero start height".into(),
        );
    }
    Ok((start_height, end_height))
}

/// Returns the bounded archived restart-page range implied by one active profile.
pub fn archived_recovered_restart_page_range_for_profile(
    end_height: u64,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(u64, u64), String> {
    validate_archived_recovered_history_profile(profile)?;
    archived_recovered_restart_page_range(
        end_height,
        profile.restart_page_window,
        profile.restart_page_overlap,
        profile.windows_per_segment,
        profile.segments_per_fold,
    )
}

/// Verifies that an archived recovered-history segment follows the active profile geometry.
pub fn validate_archived_recovered_history_segment_against_profile(
    segment: &ArchivedRecoveredHistorySegment,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if segment.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history segment profile hash {:?} does not match the active profile hash {:?}",
            segment.archived_profile_hash,
            profile_hash
        ));
    }
    let (expected_start_height, expected_end_height) =
        archived_recovered_restart_page_range_for_profile(segment.end_height, profile)?;
    if segment.start_height != expected_start_height || segment.end_height != expected_end_height {
        return Err(format!(
            "archived recovered-history segment range {}..={} does not match the active profile range {}..={}",
            segment.start_height, segment.end_height, expected_start_height, expected_end_height
        ));
    }
    Ok(())
}

/// Verifies that an archived recovered restart-page follows the active profile geometry.
pub fn validate_archived_recovered_restart_page_against_profile(
    page: &ArchivedRecoveredRestartPage,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if page.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered restart page profile hash {:?} does not match the active profile hash {:?}",
            page.archived_profile_hash,
            profile_hash
        ));
    }
    let (expected_start_height, expected_end_height) =
        archived_recovered_restart_page_range_for_profile(page.end_height, profile)?;
    if page.start_height != expected_start_height || page.end_height != expected_end_height {
        return Err(format!(
            "archived recovered restart page range {}..={} does not match the active profile range {}..={}",
            page.start_height, page.end_height, expected_start_height, expected_end_height
        ));
    }
    Ok(())
}

/// Builds a content-addressed archived recovered restart-page payload for one
/// archived recovered-history segment.
pub fn build_archived_recovered_restart_page(
    segment: &ArchivedRecoveredHistorySegment,
    restart_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Result<ArchivedRecoveredRestartPage, String> {
    if restart_headers.is_empty() {
        return Err("archived recovered restart page requires at least one restart header".into());
    }
    if restart_headers[0].header.height != segment.start_height
        || restart_headers
            .last()
            .map(|entry| entry.header.height)
            .ok_or_else(|| {
                "archived recovered restart page is missing its end height".to_string()
            })?
            != segment.end_height
    {
        return Err(
            "archived recovered restart page height coverage does not match the archived segment range"
                .into(),
        );
    }
    for pair in restart_headers.windows(2) {
        if pair[1].header.height != pair[0].header.height + 1 {
            return Err(
                "archived recovered restart page requires contiguous restart-header heights".into(),
            );
        }
    }

    Ok(ArchivedRecoveredRestartPage {
        segment_hash: canonical_archived_recovered_history_segment_hash(segment)?,
        archived_profile_hash: segment.archived_profile_hash,
        archived_profile_activation_hash: segment.archived_profile_activation_hash,
        start_height: segment.start_height,
        end_height: segment.end_height,
        restart_headers: restart_headers.to_vec(),
    })
}

/// Builds a compact archived recovered-history checkpoint for one published
/// archived segment/page tip.
pub fn build_archived_recovered_history_checkpoint(
    segment: &ArchivedRecoveredHistorySegment,
    page: &ArchivedRecoveredRestartPage,
    previous_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
) -> Result<ArchivedRecoveredHistoryCheckpoint, String> {
    let expected_page = build_archived_recovered_restart_page(segment, &page.restart_headers)?;
    if &expected_page != page {
        return Err(
            "archived recovered-history checkpoint page does not match the archived segment range"
                .into(),
        );
    }
    if page.archived_profile_hash != segment.archived_profile_hash {
        return Err(
            "archived recovered-history checkpoint page profile hash does not match the archived segment profile hash"
                .into(),
        );
    }
    if page.archived_profile_activation_hash != segment.archived_profile_activation_hash {
        return Err(
            "archived recovered-history checkpoint page activation hash does not match the archived segment activation hash"
                .into(),
        );
    }

    if let Some(previous) = previous_checkpoint {
        if previous.covered_end_height >= segment.end_height {
            return Err(
                "archived recovered-history checkpoint predecessor must end before the current archived tip end height"
                    .into(),
            );
        }
    }

    Ok(ArchivedRecoveredHistoryCheckpoint {
        covered_start_height: segment.start_height,
        covered_end_height: segment.end_height,
        archived_profile_hash: segment.archived_profile_hash,
        archived_profile_activation_hash: segment.archived_profile_activation_hash,
        latest_archived_segment_hash: canonical_archived_recovered_history_segment_hash(segment)?,
        latest_archived_restart_page_hash: canonical_archived_recovered_restart_page_hash(page)?,
        previous_archived_checkpoint_hash: previous_checkpoint
            .map(canonical_archived_recovered_history_checkpoint_hash)
            .transpose()?
            .unwrap_or([0u8; 32]),
    })
}

/// Builds a compact archived recovered-history retention receipt for one
/// published archived checkpoint under one active validator-set commitment.
pub fn build_archived_recovered_history_retention_receipt(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    validator_set_commitment_hash: [u8; 32],
    retained_through_height: u64,
) -> Result<ArchivedRecoveredHistoryRetentionReceipt, String> {
    if checkpoint.covered_start_height == 0
        || checkpoint.covered_end_height == 0
        || checkpoint.covered_end_height < checkpoint.covered_start_height
    {
        return Err(
            "archived recovered-history retention receipt requires a non-zero covered checkpoint range"
                .into(),
        );
    }
    if validator_set_commitment_hash == [0u8; 32] {
        return Err(
            "archived recovered-history retention receipt requires a non-zero validator-set commitment hash"
                .into(),
        );
    }
    if retained_through_height < checkpoint.covered_end_height {
        return Err(
            "archived recovered-history retention receipt retained-through height must cover the archived checkpoint tip"
                .into(),
        );
    }

    Ok(ArchivedRecoveredHistoryRetentionReceipt {
        covered_start_height: checkpoint.covered_start_height,
        covered_end_height: checkpoint.covered_end_height,
        archived_profile_hash: checkpoint.archived_profile_hash,
        archived_profile_activation_hash: checkpoint.archived_profile_activation_hash,
        archived_checkpoint_hash: canonical_archived_recovered_history_checkpoint_hash(checkpoint)?,
        validator_set_commitment_hash,
        retained_through_height,
    })
}

/// Verifies that an archived recovered-history checkpoint follows one profile.
pub fn validate_archived_recovered_history_checkpoint_against_profile(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if checkpoint.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history checkpoint profile hash {:?} does not match the active profile hash {:?}",
            checkpoint.archived_profile_hash,
            profile_hash
        ));
    }
    Ok(())
}

/// Verifies that an archived recovered-history retention receipt follows one profile.
pub fn validate_archived_recovered_history_retention_receipt_against_profile(
    receipt: &ArchivedRecoveredHistoryRetentionReceipt,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if checkpoint.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history checkpoint profile hash {:?} does not match the active profile hash {:?}",
            checkpoint.archived_profile_hash,
            profile_hash
        ));
    }
    if receipt.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history retention receipt profile hash {:?} does not match the active profile hash {:?}",
            receipt.archived_profile_hash,
            profile_hash
        ));
    }
    let expected_retained_through_height =
        archived_recovered_history_retained_through_height(checkpoint, profile)?;
    if receipt.retained_through_height != expected_retained_through_height {
        return Err(format!(
            "archived recovered-history retention receipt retained-through height {} does not match the active profile retained-through height {}",
            receipt.retained_through_height, expected_retained_through_height
        ));
    }
    Ok(())
}

/// Returns the retained-through height implied by one active archive profile.
pub fn archived_recovered_history_retained_through_height(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<u64, String> {
    validate_archived_recovered_history_profile(profile)?;
    Ok(checkpoint
        .covered_end_height
        .saturating_add(profile.retention_horizon))
}

